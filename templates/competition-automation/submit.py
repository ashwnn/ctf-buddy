#!/usr/bin/env python3
"""Bounded flag-submission template. Standard library only.

This is a template, not an event integration. It is disabled by default
(`dry_run: true`), talks to a mock endpoint in the shipped configuration, and
refuses any endpoint host that is not explicitly allowlisted. No organizer URL is
hardcoded anywhere.

Use it only if the event rules permit automation. Then:

    python mock_server.py --port 8099          # in another terminal
    python submit.py --config config.example.json --flags-file candidates.txt

Outcome model, one append-only JSONL record per state change:

    pending         written before the request is sent; a crash leaves this
                    behind and the flag is retried on the next run
    accepted        the response confirmed `accepted: true`; never resubmitted
    rejected-final  the response explicitly rejected the flag; never resubmitted
    retryable       timeout, connection error, 429/5xx or an ambiguous 2xx/4xx
                    response; retried on later runs

Only `accepted` and `rejected-final` suppress future attempts. HTTP success is
never treated as acceptance: the `accepted` field (or an explicit rejection) is
what decides. Retries within a run are bounded by `max_attempts`, and a
`Retry-After` header is honored but capped (see MAX_SLEEP_SECONDS).

Legacy state from an older version is migrated in memory only: `rejected` maps
to `rejected-final`, `failed` to `retryable`, and `submitted` to `retryable`
and unconfirmed, because the old writer emitted `submitted` for any
non-rejected 2xx even when the body never confirmed acceptance. Nothing on
disk is rewritten.

Exit codes: 0 all submissions settled (or a dry run), 1 some rejected or left
retryable, 2 usage or configuration error, 3 internal error.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

EXIT_OK = 0
EXIT_NEGATIVE = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
DEFAULT_REGEX = r"[A-Za-z0-9_]{2,20}\{[^}]{3,200}\}"
MAX_BODY_BYTES = 64 * 1024

# Outcome taxonomy and state handling
PENDING = "pending"
ACCEPTED = "accepted"
REJECTED_FINAL = "rejected-final"
RETRYABLE = "retryable"
TERMINAL_OUTCOMES = (ACCEPTED, REJECTED_FINAL)
# Record collapse is rank-based: accepted > rejected-final > retryable > pending.
# A later record wins ties (`>=` in _load_state), and only accepted /
# rejected-final records suppress future attempts (see run()).
OUTCOME_RANK = {PENDING: 0, RETRYABLE: 1, REJECTED_FINAL: 2, ACCEPTED: 3}
LEGACY_SUBMITTED_DETAIL = "migrated from legacy submitted (unconfirmed)"
LEGACY_OUTCOMES = {
    # The old writer emitted `submitted` for any non-rejected 2xx, including
    # bodies with no acceptance signal, so those were never confirmed and must
    # stay retryable rather than being silently treated as accepted.
    "submitted": RETRYABLE,
    "rejected": REJECTED_FINAL,
    "failed": RETRYABLE,
}

# Bounded retry timing: a Retry-After header can never cause an unbounded sleep
MAX_SLEEP_SECONDS = 30.0
BACKOFF_BASE_SECONDS = 0.5
MAX_BACKOFF_SECONDS = 8.0


class ConfigError(Exception):
    pass


class StateLockError(Exception):
    pass


def load_config(path: str) -> Dict[str, Any]:
    """Load and validate the config. Raises ConfigError with a reason."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: expected a JSON object")
    url = str(payload.get("submit_url") or "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"submit_url must be an http(s) URL with a host, got {url!r}")
    allow = [str(item).lower() for item in payload.get("allow_hosts") or []]
    if parsed.hostname.lower() not in allow:
        raise ConfigError(
            f"refusing endpoint host {parsed.hostname!r}: it is not in allow_hosts {allow}. "
            "Add the host deliberately after confirming the rules permit it."
        )
    regex = str(payload.get("flag_regex") or DEFAULT_REGEX)
    try:
        re.compile(regex)
    except re.error as exc:
        raise ConfigError(f"flag_regex does not compile: {exc}") from exc
    config = {
        "submit_url": url,
        "allow_hosts": allow,
        "flag_regex": regex,
        "timeout_seconds": float(payload.get("timeout_seconds") or 5),
        "max_attempts": max(1, int(payload.get("max_attempts") or 1)),
        "max_per_minute": max(1, int(payload.get("max_per_minute") or 20)),
        "dry_run": bool(payload.get("dry_run", True)),
        "state_file": str(payload.get("state_file") or "state/submit-seen.jsonl"),
    }
    return config


def extract_flags(text: str, regex: str) -> List[str]:
    pattern = re.compile(regex)
    seen: List[str] = []
    for match in pattern.finditer(text):
        value = match.group(0)
        if value not in seen:
            seen.append(value)
    return seen


def _digest(flag: str) -> str:
    return hashlib.sha256(flag.encode("utf-8")).hexdigest()


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _pid_alive(pid: int) -> bool:
    """Non-destructive process liveness probe.

    Anything that cannot be resolved to a definitely-dead process (access
    denied, an unopenable or unqueryable handle, an unexpected OS error) is
    reported as ALIVE so a live lock is never reclaimed. On Windows only
    ERROR_INVALID_PARAMETER (no such process) means dead; on POSIX only
    ProcessLookupError means dead (PermissionError means alive).

    On Windows os.kill is destructive for every signal, so the Win32 API is
    queried instead of sending signal 0.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.GetExitCodeProcess.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel32.OpenProcess(0x1000, False, int(pid))
            if not handle:
                # ERROR_INVALID_PARAMETER (87) is the only "no such process"
                # signal; access denied and everything else mean "assume alive".
                return ctypes.get_last_error() != 87
            try:
                code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return True  # cannot query: assume alive
                return code.value == 259  # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except (OSError, AttributeError):
            return True  # probe itself failed: assume alive
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True  # PermissionError and anything else: assume alive


def _stat_identity(path: str) -> Optional[Tuple[int, int, int, int]]:
    """(st_dev, st_ino, st_size, st_mtime_ns) or None when stat fails."""
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


class StateLock:
    """Single-writer lock for the state file.

    Same semantics as ctfctl's WriterLock, kept local so the template has no
    repository imports: flock where available, exclusive create otherwise, and
    stale locks left by a dead process are reclaimable.

    Reclaim protocol (exclusive-create path): a lock file is stale only when it
    is older than LOCK_STALE_SECONDS AND its recorded pid is dead. Its
    (dev, ino, size, mtime_ns) identity is captured with that stale decision,
    then re-checked immediately before the unlink; if the identity changed,
    reclaim is aborted, we back off briefly and retry acquisition. A lock whose
    identity changed is never unlinked. A residual TOCTOU window between the
    final identity check and the unlink is accepted for this local,
    single-operator template: exploiting it needs two submitters racing on one
    state file, which the documented "one submission path" rule forbids.
    """

    LOCK_STALE_SECONDS = 120.0
    LOCK_RECLAIM_RETRIES = 3
    LOCK_RECLAIM_BACKOFF_SECONDS = 0.1

    def __init__(self, state_file: str) -> None:
        self.path = state_file + ".lock"
        self._fd: Optional[int] = None
        self._created = False
        self.mode = "unknown"

    def acquire(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            import fcntl
        except ImportError:
            fcntl = None  # type: ignore[assignment]
        if fcntl is not None:
            self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(self._fd)
                self._fd = None
                raise StateLockError(
                    f"another submitter holds the lock {self.path}; wait for it "
                    "to finish and do not delete a live lock"
                )
            os.ftruncate(self._fd, 0)
            os.write(self._fd, f"pid={os.getpid()} at={_iso_now()}\n".encode("utf-8"))
            self.mode = "flock"
            return
        fd = -1
        reclaims = 0
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                break
            except FileExistsError:
                # A crashed run cannot hold a lock. Without flock the file is the
                # only signal, so a lock from a dead process must be reclaimable.
                identity = self._stale_identity()
                if identity is None:
                    raise StateLockError(
                        f"another submitter holds the lock {self.path}; if no "
                        "submit.py process is running, remove it"
                    )
                if _stat_identity(self.path) != identity:
                    # The lock changed since the stale decision (another process
                    # recreated it): never unlink what we did not inspect.
                    reclaims += 1
                    if reclaims > self.LOCK_RECLAIM_RETRIES:
                        raise StateLockError(
                            f"lock {self.path} kept changing while being reclaimed; "
                            "refusing to remove it"
                        )
                    time.sleep(self.LOCK_RECLAIM_BACKOFF_SECONDS)
                    continue
                try:
                    os.unlink(self.path)
                except OSError:
                    raise StateLockError(f"cannot reclaim stale lock {self.path}")
        self._created = True
        try:
            os.write(fd, f"pid={os.getpid()} at={_iso_now()}\n".encode("utf-8"))
        except OSError:
            self.release()
            raise
        finally:
            os.close(fd)
        self.mode = "exclusive-create"

    def _stale_identity(self) -> Optional[Tuple[int, int, int, int]]:
        """Lock identity when it is stale, else None.

        Stale means: the lock file is older than LOCK_STALE_SECONDS AND either
        it recorded a dead pid or (for a pid-less lock) it is twice as old. The
        returned identity is re-checked immediately before any unlink.
        """
        try:
            stat = os.stat(self.path)
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(200)
        except OSError:
            return None
        age = time.time() - stat.st_mtime
        if age < self.LOCK_STALE_SECONDS:
            return None
        match = re.search(r"pid=(\d+)", text)
        if not match:
            if age < self.LOCK_STALE_SECONDS * 2:
                return None
        elif _pid_alive(int(match.group(1))):
            return None
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def release(self) -> None:
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass
            os.close(self._fd)
            self._fd = None
        if self._created:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self._created = False

    def __enter__(self) -> "StateLock":
        self.acquire()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.release()


def _load_state(path: str) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, int]]:
    """Read the append-only log and collapse it by sha256.

    Malformed or torn lines (including an interrupted final line) are counted
    and skipped without losing earlier records. Collapse is rank-based:
    accepted > rejected-final > retryable > pending, and a later record wins
    ties; only accepted/rejected-final records suppress future attempts (see
    run()). Legacy outcomes are mapped in memory only; nothing is ever
    rewritten. A legacy `submitted` record was never confirmed by the old
    writer's loose 2xx rule, so it maps to retryable, is counted in
    legacy_unconfirmed, and carries a migration detail note. Returns
    (records, counters) where counters has malformed_lines, migrated,
    legacy_unconfirmed and unknown_outcomes.
    """
    stats = {
        "malformed_lines": 0,
        "migrated": 0,
        "legacy_unconfirmed": 0,
        "unknown_outcomes": 0,
    }
    records: Dict[str, Dict[str, Any]] = {}
    if not os.path.isfile(path):
        return records, stats
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return records, stats
    with fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                stats["malformed_lines"] += 1
                continue
            if not isinstance(raw, dict) or not raw.get("sha256"):
                stats["malformed_lines"] += 1
                continue
            record = dict(raw)
            raw_outcome = str(record.get("outcome") or "")
            if raw_outcome in LEGACY_OUTCOMES:
                record["legacy_outcome"] = raw_outcome
                outcome = LEGACY_OUTCOMES[raw_outcome]
                stats["migrated"] += 1
                if raw_outcome == "submitted":
                    # The old writer emitted `submitted` for any non-rejected
                    # 2xx, including bodies that never confirmed acceptance.
                    record["detail"] = LEGACY_SUBMITTED_DETAIL
                    stats["legacy_unconfirmed"] += 1
            elif raw_outcome in OUTCOME_RANK:
                outcome = raw_outcome
            elif raw_outcome not in OUTCOME_RANK:
                record["legacy_outcome"] = raw_outcome
                outcome = RETRYABLE
                stats["unknown_outcomes"] += 1
            record["outcome"] = outcome
            digest = str(record["sha256"])
            previous = records.get(digest)
            if (
                previous is None
                or OUTCOME_RANK[outcome] >= OUTCOME_RANK[previous["outcome"]]
            ):
                records[digest] = record
    return records, stats


def _append_state(path: str, flag: str, outcome: str, detail: str = "") -> None:
    """Append one complete JSON line and fsync it. Never truncates or rewrites.

    O_BINARY is added where available so the JSONL stays LF-only on Windows
    instead of gaining CRLF translations.

    If a crashed run left a torn final line without a newline, a separator is
    written first so the new record is not glued onto the fragment.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    record = {
        "sha256": _digest(flag),
        "flag": flag,
        "outcome": outcome,
        "at": _iso_now(),
    }
    if detail:
        record["detail"] = detail
    line = json.dumps(record, sort_keys=True) + "\n"
    separator = b""
    try:
        if os.path.getsize(path) > 0:
            with open(path, "rb") as fh:
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    separator = b"\n"
    except OSError:
        separator = b""
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if separator:
            os.write(fd, separator)
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


class RateLimiter:
    """Simple sliding window: at most `per_minute` submissions in 60 seconds."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = max(1, per_minute)
        self.stamps: List[float] = []

    def wait(self) -> float:
        now = time.time()
        self.stamps = [stamp for stamp in self.stamps if now - stamp < 60.0]
        if len(self.stamps) >= self.per_minute:
            sleep_for = 60.0 - (now - self.stamps[0]) + 0.05
            time.sleep(max(0.0, sleep_for))
            now = time.time()
            self.stamps = [stamp for stamp in self.stamps if now - stamp < 60.0]
        self.stamps.append(time.time())
        return time.time() - now


def _detail_of(payload: Optional[Dict[str, Any]], fallback: str) -> str:
    if payload:
        value = payload.get("detail")
        if value:
            return str(value)[:300]
    return fallback


def _explicitly_rejected(payload: Optional[Dict[str, Any]]) -> bool:
    """True only for an explicit flag-level boolean rejection.

    `accepted is false` or `rejected is true` are the only terminal signals.
    Status/result strings such as denied/invalid are deliberately NOT matched:
    they are ambiguous, so they stay retryable and unconfirmed.
    """
    if not payload:
        return False
    return payload.get("accepted") is False or payload.get("rejected") is True


def _interpret_response(status: int, raw: bytes) -> Dict[str, Any]:
    """Map an HTTP response to the outcome taxonomy.

    HTTP success is never equated with acceptance: only a parsed body with
    `accepted: true` is accepted, `accepted: false` (or `rejected: true`) is a
    final rejection, and anything ambiguous or unparseable is retryable and
    marked unconfirmed. 429 and 5xx are always retryable, even if the body
    claims acceptance; every other 4xx response (including 401/403) is
    retryable and unconfirmed unless the body carries an explicit boolean
    rejection.
    """
    payload: Optional[Dict[str, Any]] = None
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        parsed = None
    if isinstance(parsed, dict):
        payload = parsed
    excerpt = raw[:200].decode("utf-8", "replace")
    if status == 429 or status >= 500:
        return {
            "status": RETRYABLE,
            "detail": _detail_of(payload, f"HTTP {status} is retryable"),
        }
    if 400 <= status < 500:
        if _explicitly_rejected(payload):
            return {
                "status": REJECTED_FINAL,
                "detail": _detail_of(payload, f"HTTP {status} explicitly rejected"),
                "response": payload,
            }
        reason = (
            f"HTTP {status} did not explicitly reject"
            if payload is not None
            else f"HTTP {status} rejection not explicit: {excerpt!r}"
        )
        return {"status": RETRYABLE, "unconfirmed": True, "detail": reason}
    if payload is not None and payload.get("accepted") is True:
        return {
            "status": ACCEPTED,
            "detail": _detail_of(payload, "server confirmed acceptance"),
            "response": payload,
        }
    if payload is not None and payload.get("accepted") is False:
        return {
            "status": REJECTED_FINAL,
            "detail": _detail_of(payload, "server confirmed rejection"),
            "response": payload,
        }
    reason = (
        f"unconfirmed HTTP {status}: no accepted field"
        if payload is not None
        else f"unconfirmed HTTP {status}: unparseable body {excerpt!r}"
    )
    return {"status": RETRYABLE, "unconfirmed": True, "detail": reason}


def _retry_after_seconds(value: Optional[str]) -> Optional[float]:
    """Retry-After as seconds, capped at MAX_SLEEP_SECONDS. Never unbounded."""
    if not value:
        return None
    text = value.strip()
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, OverflowError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, min(seconds, MAX_SLEEP_SECONDS))


def submit_flag(
    config: Dict[str, Any], flag: str, limiter: Optional[RateLimiter] = None
) -> Dict[str, Any]:
    """Send one flag with bounded retries and return the final outcome.

    Every returned status is one of the taxonomy values; an HTTP 2xx alone is
    never acceptance. Transport exceptions, including
    `http.client.HTTPException` subclasses such as IncompleteRead,
    BadStatusLine and RemoteDisconnected, are mapped to retryable inside the
    bounded retry loop. When given, `limiter` is consulted before each request.
    """
    body = json.dumps({"flag": flag}).encode("utf-8")
    request = urllib.request.Request(
        config["submit_url"],
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ctfctl-template/1.1",
        },
    )
    max_attempts = config["max_attempts"]
    last: Dict[str, Any] = {
        "status": RETRYABLE,
        "attempt": 0,
        "detail": "no attempt was made",
    }
    for attempt in range(1, max_attempts + 1):
        if limiter is not None:
            limiter.wait()
        retry_after: Optional[float] = None
        try:
            with urllib.request.urlopen(
                request, timeout=config["timeout_seconds"]
            ) as resp:
                raw = resp.read(MAX_BODY_BYTES)
                status = int(getattr(resp, "status", 200))
            outcome = _interpret_response(status, raw)
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read(MAX_BODY_BYTES)
            except (OSError, http.client.HTTPException):
                raw = b""
            retry_after = _retry_after_seconds(
                exc.headers.get("Retry-After") if exc.headers else None
            )
            outcome = _interpret_response(int(exc.code), raw)
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
        ) as exc:
            outcome = {
                "status": RETRYABLE,
                "detail": f"{type(exc).__name__}: {exc}",
            }
        outcome["attempt"] = attempt
        last = outcome
        if outcome["status"] in TERMINAL_OUTCOMES:
            return outcome
        if attempt < max_attempts:
            delay = retry_after
            if delay is None:
                delay = min(
                    MAX_BACKOFF_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                )
            time.sleep(max(0.0, min(delay, MAX_SLEEP_SECONDS)))
    return last


def run(
    config: Dict[str, Any], flags: Iterable[str], *, dry_run: bool, state_file: str
) -> Dict[str, Any]:
    """Process candidate flags. Real runs take the state lock, dry runs do not.

    Only accepted/rejected-final records deduplicate. A pending or retryable
    record is retried, with a fresh pending written before the request.
    """
    candidates = list(flags)
    lock: Optional[StateLock] = None if dry_run else StateLock(state_file)
    if lock is not None:
        lock.acquire()
    try:
        records, stats = _load_state(state_file)
        handled = {
            digest
            for digest, record in records.items()
            if record["outcome"] in TERMINAL_OUTCOMES
        }
        limiter = RateLimiter(config["max_per_minute"])
        results: List[Dict[str, Any]] = []
        duplicates = 0
        for flag in candidates:
            digest = _digest(flag)
            if digest in handled:
                duplicates += 1
                results.append(
                    {
                        "flag": flag,
                        "status": "duplicate",
                        "detail": "already recorded as "
                        + str(records[digest]["outcome"]),
                    }
                )
                continue
            if dry_run:
                results.append(
                    {"flag": flag, "status": "dry-run", "detail": "not sent (dry run)"}
                )
                continue
            _append_state(state_file, flag, PENDING)
            result = submit_flag(config, flag, limiter)
            result["flag"] = flag
            results.append(result)
            detail = str(result.get("detail") or "")
            _append_state(state_file, flag, str(result["status"]), detail)
            if result["status"] in TERMINAL_OUTCOMES:
                handled.add(digest)
            records[digest] = {
                "sha256": digest,
                "flag": flag,
                "outcome": result["status"],
            }
    finally:
        if lock is not None:
            lock.release()

    accepted = sum(1 for item in results if item["status"] == ACCEPTED)
    rejected = sum(1 for item in results if item["status"] == REJECTED_FINAL)
    retryable = sum(1 for item in results if item["status"] == RETRYABLE)
    unconfirmed = sum(
        1 for item in results if item["status"] == RETRYABLE and item.get("unconfirmed")
    )
    return {
        "config": config["submit_url"],
        "dry_run": dry_run,
        "total": len(results),
        "accepted": accepted,
        "rejected": rejected,
        "failed": retryable,
        "duplicates": duplicates,
        "results": results,
        "retryable": retryable,
        "unconfirmed": unconfirmed,
        "migrated": stats["migrated"],
        "legacy_unconfirmed": stats["legacy_unconfirmed"],
        "unknown_outcomes": stats["unknown_outcomes"],
        "malformed_lines": stats["malformed_lines"],
        # `warnings` counts everything an operator should look at: unknown
        # outcomes plus legacy `submitted` records migrated as unconfirmed.
        "warnings": stats["unknown_outcomes"] + stats["legacy_unconfirmed"],
    }


def main(argv: List[str]) -> int:
    """CLI entry point.

    Usage errors keep exit code 2 (argparse), expected negatives keep 1/2, and
    any unexpected exception is converted at this boundary into exit 3 with a
    single-line stderr diagnostic instead of a traceback.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--flags-file", help="file with candidate flags/text")
    parser.add_argument("--state-file", help="override the dedup log path")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="force a dry run even if the config allows sending",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        return _main(args)
    except Exception as exc:  # noqa: BLE001 - boundary conversion, exit 3
        print(f"submit: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


def _main(args: argparse.Namespace) -> int:
    if not args.flags_file:
        print("submit: --flags-file is required", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"submit: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        text = open(args.flags_file, "r", encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"submit: cannot read {args.flags_file}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    flags = extract_flags(text, config["flag_regex"])
    if not flags:
        print("submit: no flags matched the configured pattern", file=sys.stderr)
        return EXIT_NEGATIVE

    dry_run = args.dry_run or config["dry_run"]
    state_file = args.state_file or config["state_file"]
    if not dry_run:
        print(
            f"submit: REAL submission to {config['submit_url']} "
            f"(rate {config['max_per_minute']}/min, {len(flags)} candidate flag(s))",
            file=sys.stderr,
        )
    try:
        summary = run(config, flags, dry_run=dry_run, state_file=state_file)
    except StateLockError as exc:
        print(f"submit: {exc}", file=sys.stderr)
        return EXIT_NEGATIVE
    if summary["legacy_unconfirmed"]:
        print(
            f"submit: {summary['legacy_unconfirmed']} legacy 'submitted' record(s) "
            "are unconfirmed and retryable; check the scoreboard before "
            "resubmitting",
            file=sys.stderr,
        )
    if summary["unknown_outcomes"]:
        print(
            f"submit: {summary['unknown_outcomes']} state record(s) had an unknown "
            "outcome and are treated as retryable",
            file=sys.stderr,
        )
    if summary["malformed_lines"]:
        print(
            f"submit: skipped {summary['malformed_lines']} malformed state line(s)",
            file=sys.stderr,
        )
    if summary["migrated"]:
        print(
            f"submit: migrated {summary['migrated']} legacy state record(s)",
            file=sys.stderr,
        )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for item in summary["results"]:
            print(f"  {item['status']:<10} {item['flag'][:60]}")
        print(
            f"accepted={summary['accepted']} rejected={summary['rejected']} "
            f"failed={summary['failed']} duplicates={summary['duplicates']}"
            + (" (dry run: nothing was sent)" if dry_run else "")
        )
    if summary["failed"] or summary["rejected"]:
        return EXIT_NEGATIVE
    return EXIT_OK


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("submit: interrupted", file=sys.stderr)
        raise SystemExit(EXIT_NEGATIVE)
