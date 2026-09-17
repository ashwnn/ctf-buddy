"""Competition automation template: taxonomy, retries, dedup, state, lock."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from helpers import (
    REPO_ROOT,
    Failure,
    check,
    check_eq,
    check_in,
    free_port,
    temp_dir,
)

TEMPLATE_DIR = os.path.join(REPO_ROOT, "templates", "competition-automation")


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(TEMPLATE_DIR, filename)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


submit = _load("ctfctl_submit_template", "submit.py")
mock = _load("ctfctl_mock_template", "mock_server.py")


def _config(port: int, state_file: str, **overrides: Any) -> Dict[str, Any]:
    config: Dict[str, Any] = {
        "submit_url": f"http://127.0.0.1:{port}/submit",
        "flag_regex": submit.DEFAULT_REGEX,
        "timeout_seconds": 5.0,
        "max_attempts": 1,
        "max_per_minute": 60,
        "dry_run": False,
        "state_file": state_file,
    }
    config.update(overrides)
    return config


def _reply(
    status: int,
    body: Any,
    *,
    gate: Optional[threading.Event] = None,
    close: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """One scripted reply.

    `gate` blocks the handler until the test releases the event, so a timeout
    test never races a sleep against `timeout_seconds`. `close` drops the
    connection before any response bytes are written, which makes the client
    raise `http.client.RemoteDisconnected`.
    """
    return {
        "status": status,
        "body": body,
        "gate": gate,
        "close_before_response": close,
        "headers": headers or {},
    }


ACCEPTED = _reply(200, {"accepted": True, "detail": "mock accepted"})
REJECTED = _reply(200, {"accepted": False, "detail": "mock rejected"})


class _ScriptedHandler(BaseHTTPRequestHandler):
    """Loopback handler answering from a per-server script of replies.

    The last script entry repeats, so a server can also stand in for a fault
    that never clears. Every request body is kept for exact-count assertions.
    """

    server_version = "ctfctl-test/1.0"

    def do_POST(self) -> None:  # noqa: N802
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        server.requests.append(body)
        index = len(server.requests) - 1
        entry = (
            server.script[index] if index < len(server.script) else server.script[-1]
        )
        gate = entry.get("gate")
        if gate is not None:
            gate.wait(5.0)
        if entry.get("close_before_response"):
            # FIN before any response bytes: the client sees RemoteDisconnected.
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            self.close_connection = True
            try:
                self.connection.close()
            except OSError:
                pass
            return
        data = entry["body"]
        if not isinstance(data, bytes):
            data = json.dumps(data).encode("utf-8")
        try:
            self.send_response(entry["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for key, value in entry["headers"].items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass  # client timed out or vanished; the attempt is still on record

    def log_message(self, fmt: str, *args: Any) -> None:  # keep output tidy
        return


@contextlib.contextmanager
def _server(script: List[Dict[str, Any]], port: Optional[int] = None):
    port = port or free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), _ScriptedHandler)
    server.script = list(script)
    server.requests = []
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        check_eq(
            server.server_address[0], "127.0.0.1", "the test server must bind loopback"
        )
        yield port, server
    finally:
        server.shutdown()
        server.server_close()


@contextlib.contextmanager
def _fast_backoff():
    """Keep bounded in-run retries measurable but not slow."""
    base, cap = submit.BACKOFF_BASE_SECONDS, submit.MAX_BACKOFF_SECONDS
    submit.BACKOFF_BASE_SECONDS, submit.MAX_BACKOFF_SECONDS = 0.01, 0.05
    try:
        yield
    finally:
        submit.BACKOFF_BASE_SECONDS, submit.MAX_BACKOFF_SECONDS = base, cap


def _records(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _outcomes(path: str) -> List[str]:
    return [str(record["outcome"]) for record in _records(path)]


def _record(flag: str, outcome: str, at: str = "2026-01-01T00:00:00Z") -> str:
    return json.dumps(
        {
            "sha256": submit._digest(flag),
            "flag": flag,
            "outcome": outcome,
            "at": at,
        },
        sort_keys=True,
    )


@contextlib.contextmanager
def _exclusive_lock_path():
    """Force StateLock onto its no-flock path so reclaim is testable on POSIX.

    Where `import fcntl` succeeds, StateLock uses flock and never has a stale
    lock to reclaim. A None entry in sys.modules makes the in-function import
    raise ImportError, selecting the exclusive-create path that the reclaim
    protocol belongs to.
    """
    had = "fcntl" in sys.modules
    saved = sys.modules.get("fcntl")
    sys.modules["fcntl"] = None
    try:
        yield
    finally:
        if had:
            sys.modules["fcntl"] = saved
        else:
            sys.modules.pop("fcntl", None)


def _dead_pid() -> int:
    """A pid that has certainly exited and been reaped on this platform."""
    with subprocess.Popen([sys.executable, "-c", "pass"]) as proc:
        proc.wait(timeout=30)
    check_eq(submit._pid_alive(proc.pid), False, "the fixture pid must be dead")
    return int(proc.pid)


def _plant_lock(state: str, pid: int, *, age: float = 0.0) -> str:
    lock_path = state + ".lock"
    with open(lock_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"pid={pid} at=2026-01-01T00:00:00Z\n")
    if age:
        when = time.time() - age
        os.utime(lock_path, (when, when))
    return lock_path


def test_config_refuses_unallowlisted_endpoint() -> None:
    with temp_dir() as root:
        path = os.path.join(root, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "submit_url": "http://evil.example/submit",
                    "allow_hosts": ["127.0.0.1"],
                },
                fh,
            )
        try:
            submit.load_config(path)
        except submit.ConfigError as exc:
            check_in("allow_hosts", str(exc), "the refusal must name the allowlist")
            return
        raise AssertionError("an unallowlisted endpoint host must be refused")


def test_config_defaults_to_dry_run() -> None:
    with temp_dir() as root:
        path = os.path.join(root, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "submit_url": "http://127.0.0.1:8099/submit",
                    "allow_hosts": ["127.0.0.1"],
                },
                fh,
            )
        config = submit.load_config(path)
        check_eq(config["dry_run"], True, "sending must be opt-in, not default")
        check_eq(config["max_attempts"], 1, "attempts default to one")


def test_flag_extraction_deduplicates() -> None:
    text = "noise FLAG{one} more noise FLAG{two}\nFLAG{one}\n"
    flags = submit.extract_flags(text, submit.DEFAULT_REGEX)
    check_eq(flags, ["FLAG{one}", "FLAG{two}"], "extract once, preserve order")


def test_accepted_flag_is_recorded_and_counted() -> None:
    with _server([ACCEPTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            summary = submit.run(
                config, ["FLAG{good_one}"], dry_run=False, state_file=state
            )
            check_eq(summary["accepted"], 1, "the confirmed flag must be accepted")
            check_eq(summary["rejected"], 0, "nothing was rejected")
            check_eq(summary["failed"], 0, "nothing is left retryable")
            check_eq(summary["duplicates"], 0, "there is nothing to deduplicate")
            check_eq(summary["total"], 1, "one candidate was processed")
            check_eq(summary["dry_run"], False, "a real run must not be marked dry")
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.ACCEPTED],
                "pending is written before the request and accepted after it",
            )
            check_eq(
                server.requests,
                [json.dumps({"flag": "FLAG{good_one}"}).encode("utf-8")],
                "exactly one request with the exact payload",
            )


def test_explicit_rejection_is_final_and_not_retried() -> None:
    with _server([REJECTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            first = submit.run(
                config, ["FLAG{bad_one}"], dry_run=False, state_file=state
            )
            check_eq(first["rejected"], 1, "accepted false must be a final rejection")
            check_eq(first["accepted"], 0, "a rejection is not an acceptance")
            check_eq(first["failed"], 0, "an explicit rejection is not retryable")
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.REJECTED_FINAL],
                "the rejection is recorded as rejected-final",
            )
            before = os.path.getsize(state)
            second = submit.run(
                config, ["FLAG{bad_one}"], dry_run=False, state_file=state
            )
            check_eq(second["duplicates"], 1, "rejected-final is terminal, not retried")
            check_eq(second["rejected"], 0, "the second run must not resend")
            check_eq(len(server.requests), 1, "exactly one request across both runs")
            check_eq(
                os.path.getsize(state), before, "a duplicate appends no state record"
            )


def test_timeout_is_retryable_and_retried_later() -> None:
    """The slow handler is gated on an event the test controls, so the outcome
    is asserted deterministically instead of racing a sleep against the
    timeout."""
    gate = threading.Event()
    script = [_reply(200, {"accepted": True}, gate=gate), ACCEPTED]
    with _server(script) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state, timeout_seconds=0.15)
            try:
                first = submit.run(
                    config, ["FLAG{slow}"], dry_run=False, state_file=state
                )
            finally:
                gate.set()  # let the blocked handler finish before teardown
            check_eq(first["failed"], 1, "a timeout leaves the flag retryable")
            check_eq(first["accepted"], 0, "a timeout is never acceptance")
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.RETRYABLE],
                "the timed-out attempt is recorded retryable",
            )
            second = submit.run(config, ["FLAG{slow}"], dry_run=False, state_file=state)
            check_eq(second["accepted"], 1, "the retryable flag is retried later")
            check_eq(second["duplicates"], 0, "retryable is not terminal")
            check_eq(len(server.requests), 2, "one timed-out attempt, one retry")
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.RETRYABLE, submit.PENDING, submit.ACCEPTED],
                "the second run appends a fresh pending and the acceptance",
            )


def test_connection_refused_is_retryable_and_retried_later() -> None:
    port = free_port()
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        config = _config(port, state, timeout_seconds=1.0)
        first = submit.run(config, ["FLAG{offline}"], dry_run=False, state_file=state)
        check_eq(first["failed"], 1, "a refused connection is retryable")
        check_eq(first["accepted"], 0, "a refused connection is never acceptance")
        check_eq(
            _outcomes(state),
            [submit.PENDING, submit.RETRYABLE],
            "the failed attempt is recorded retryable",
        )
    with _server([ACCEPTED], port=port) as (port, server):
        second = submit.run(config, ["FLAG{offline}"], dry_run=False, state_file=state)
        check_eq(second["accepted"], 1, "the retryable flag is retried later")
        check_eq(second["duplicates"], 0, "retryable is not terminal")
        check_eq(len(server.requests), 1, "the later run sends the flag once")
        check_eq(_outcomes(state)[-1], submit.ACCEPTED, "the acceptance is recorded")


def test_transient_5xx_retries_are_bounded_then_later_run_settles() -> None:
    with _server([_reply(503, {"detail": "try later"})]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state, max_attempts=3)
            with _fast_backoff():
                first = submit.run(
                    config, ["FLAG{flaky}"], dry_run=False, state_file=state
                )
            check_eq(first["failed"], 1, "a 5xx leaves the flag retryable")
            check_eq(first["retryable"], 1, "the summary counts it retryable")
            check_eq(
                len(server.requests),
                3,
                "in-run retries stop at max_attempts, no more",
            )
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.RETRYABLE],
                "one terminal record for the whole retried attempt",
            )
            server.script = [ACCEPTED]
            second = submit.run(
                config, ["FLAG{flaky}"], dry_run=False, state_file=state
            )
            check_eq(second["accepted"], 1, "the next run retries the retryable flag")
            check_eq(second["duplicates"], 0, "retryable is not terminal")
            check_eq(len(server.requests), 4, "three failed attempts then one success")


def test_ambiguous_2xx_is_retryable_not_accepted() -> None:
    with _server([_reply(200, {"detail": "queued"})]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            summary = submit.run(
                config, ["FLAG{maybe}"], dry_run=False, state_file=state
            )
            check_eq(summary["accepted"], 0, "a 2xx without accepted is not accepted")
            check_eq(summary["failed"], 1, "an ambiguous 2xx is retryable")
            check_eq(
                summary["unconfirmed"], 1, "an ambiguous 2xx is flagged unconfirmed"
            )
            check_eq(
                summary["results"][0]["status"],
                submit.RETRYABLE,
                "the per-flag result is retryable",
            )
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.RETRYABLE],
                "the state record says retryable, not accepted",
            )


def test_mock_accepts_valid_and_rejects_invalid() -> None:
    port = free_port()
    server = mock.build_server(port, pattern=r"FLAG\{[a-z_]+\}", accept_all=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        check_eq(server.server_address[0], "127.0.0.1", "the mock must bind loopback")
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            summary = submit.run(
                config, ["FLAG{good_one}", "NOTAFLAG"], dry_run=False, state_file=state
            )
            check_eq(summary["accepted"], 1, "the well-formed flag must be accepted")
            check_eq(summary["rejected"], 1, "the malformed flag must be rejected")
            check_eq(summary["duplicates"], 0, "no duplicates expected")
            check(os.path.isfile(state), "real submissions must record state")
            records = _records(state)
            check_eq(
                len(records),
                4,
                "pending and outcome lines are written per attempt",
            )
            check_eq(
                [record["outcome"] for record in records],
                [
                    submit.PENDING,
                    submit.ACCEPTED,
                    submit.PENDING,
                    submit.REJECTED_FINAL,
                ],
                "each flag gets a pending line then its outcome line",
            )
    finally:
        server.shutdown()
        server.server_close()


def test_duplicate_flags_are_submitted_once() -> None:
    with _server([ACCEPTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            first = submit.run(config, ["FLAG{dup}"], dry_run=False, state_file=state)
            check_eq(first["accepted"], 1, "first submission accepted")
            second = submit.run(config, ["FLAG{dup}"], dry_run=False, state_file=state)
            check_eq(second["accepted"], 0, "the duplicate must not be sent")
            check_eq(second["duplicates"], 1, "the duplicate must be reported")
            check_eq(len(server.requests), 1, "an accepted flag is never resent")
            same_run = submit.run(
                config, ["FLAG{twice}", "FLAG{twice}"], dry_run=False, state_file=state
            )
            check_eq(same_run["accepted"], 1, "the first occurrence is sent")
            check_eq(
                same_run["duplicates"],
                1,
                "a repeat inside one run is counted duplicate",
            )
            check_eq(
                [item["status"] for item in same_run["results"]],
                [submit.ACCEPTED, "duplicate"],
                "the second occurrence is not sent",
            )
            check_eq(len(server.requests), 2, "exactly one request for the pair")


def test_pending_and_retryable_records_are_retried_not_deduplicated() -> None:
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        with open(state, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_record("FLAG{left_pending}", submit.PENDING) + "\n")
            fh.write(_record("FLAG{left_retryable}", submit.RETRYABLE) + "\n")
        with _server([ACCEPTED]) as (port, server):
            config = _config(port, state)
            summary = submit.run(
                config,
                ["FLAG{left_pending}", "FLAG{left_retryable}"],
                dry_run=False,
                state_file=state,
            )
            check_eq(
                summary["accepted"], 2, "pending and retryable records are retried"
            )
            check_eq(summary["duplicates"], 0, "neither non-terminal state dedupes")
            check_eq(len(server.requests), 2, "both flags are sent again")


def test_dry_run_writes_nothing_and_takes_no_lock() -> None:
    with _server([ACCEPTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            summary = submit.run(config, ["FLAG{dry}"], dry_run=True, state_file=state)
            check_eq(summary["dry_run"], True, "the summary must mark a dry run")
            check_eq(summary["accepted"], 0, "a dry run accepts nothing")
            check_eq(summary["results"][0]["status"], "dry-run", "dry-run status")
            check_eq(server.requests, [], "a dry run must send no request")
            check(
                not os.path.exists(state),
                "a dry run must not write submission state",
            )
            check(
                not os.path.exists(state + ".lock"),
                "a dry run must not create the lock file",
            )
            held = submit.StateLock(state)
            held.acquire()
            try:
                again = submit.run(
                    config, ["FLAG{dry}"], dry_run=True, state_file=state
                )
            finally:
                held.release()
            check_eq(
                again["results"][0]["status"],
                "dry-run",
                "a dry run must not contend for the lock",
            )


def test_malformed_and_torn_state_lines_are_skipped_and_counted() -> None:
    with _server([ACCEPTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            kept = "FLAG{kept}"
            torn = '{"sha256": "deadbeef", "flag": "FLAG{torn}", "outcome": "acc'
            with open(state, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(_record(kept, submit.ACCEPTED) + "\n")
                fh.write("this is not json\n")
                fh.write("[1, 2, 3]\n")
                fh.write('{"flag": "FLAG{nosha256}", "outcome": "accepted"}\n')
                fh.write(torn)
            before = os.path.getsize(state)
            config = _config(port, state)
            summary = submit.run(
                config, [kept, "FLAG{fresh}"], dry_run=False, state_file=state
            )
            check_eq(
                summary["malformed_lines"],
                4,
                "garbage, non-object, missing sha256 and torn lines all count",
            )
            check_eq(
                summary["duplicates"], 1, "the valid earlier record is still honored"
            )
            check_eq(summary["accepted"], 1, "the fresh flag is submitted")
            check_eq(len(server.requests), 1, "the honored duplicate is not resent")
            check(
                os.path.getsize(state) > before,
                "new records are appended after the torn line",
            )
            records, stats = submit._load_state(state)
            check_eq(stats["malformed_lines"], 4, "the appended records stay clean")
            check_eq(
                records[submit._digest(kept)]["outcome"],
                submit.ACCEPTED,
                "the valid record survives the rewrite of nothing",
            )
            check_eq(
                records[submit._digest("FLAG{fresh}")]["outcome"],
                submit.ACCEPTED,
                "the fresh acceptance loads on the next pass",
            )


def test_torn_final_line_is_recovered_and_append_is_separated() -> None:
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        old = "FLAG{before_crash}"
        fragment = '{"sha256": "abc", "flag": "FLAG{crashed}", "outcome": "acc'
        with open(state, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_record(old, submit.ACCEPTED) + "\n")
            fh.write(fragment)
        records, stats = submit._load_state(state)
        check_eq(stats["malformed_lines"], 1, "the torn final line is skipped")
        check_eq(len(records), 1, "earlier records survive a torn write")
        check_eq(
            records[submit._digest(old)]["outcome"],
            submit.ACCEPTED,
            "the completed earlier record is kept",
        )
        submit._append_state(state, "FLAG{after_crash}", submit.PENDING)
        with open(state, "rb") as fh:
            raw = fh.read()
        marker = fragment.encode("utf-8")
        at = raw.find(marker)
        check(at > 0, "the torn fragment is still on disk")
        boundary = at + len(marker)
        check_eq(
            raw[boundary : boundary + 1],
            b"\n",
            "an append after a torn line starts with a bare LF separator",
        )
        boundary += 1
        check(b"\r" not in raw, "appends must not be CRLF-translated")
        tail = json.loads(raw[boundary:].decode("utf-8"))
        check_eq(
            tail["flag"], "FLAG{after_crash}", "the new record starts on a clean line"
        )
        records, stats = submit._load_state(state)
        check_eq(stats["malformed_lines"], 1, "the separator isolates the fragment")
        check_eq(len(records), 2, "both the old and the new record load")


def test_legacy_outcomes_migrate_in_memory_and_submitted_is_unconfirmed() -> None:
    """Legacy mapping: rejected -> rejected-final, failed -> retryable, and
    submitted -> retryable + unconfirmed. The old writer emitted `submitted`
    for any non-rejected 2xx, so those records were never confirmed and may be
    resubmitted; the mapping is in memory only."""
    with _server([ACCEPTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            legacy = [
                ("FLAG{legacy_submitted}", "submitted"),
                ("FLAG{legacy_rejected}", "rejected"),
                ("FLAG{legacy_failed}", "failed"),
            ]
            with open(state, "w", encoding="utf-8", newline="\n") as fh:
                for flag, outcome in legacy:
                    fh.write(_record(flag, outcome) + "\n")
            with open(state, "rb") as fh:
                original = fh.read()

            records, stats = submit._load_state(state)
            check_eq(stats["migrated"], 3, "every legacy outcome migrates")
            check_eq(stats["legacy_unconfirmed"], 1, "legacy submitted is unconfirmed")
            check_eq(
                stats["unknown_outcomes"], 0, "legacy names are not unknown values"
            )
            submitted = records[submit._digest("FLAG{legacy_submitted}")]
            check_eq(
                submitted["outcome"],
                submit.RETRYABLE,
                "submitted maps to retryable, not accepted",
            )
            check_eq(
                submitted["legacy_outcome"],
                "submitted",
                "the original legacy value is preserved",
            )
            check_eq(
                submitted["detail"],
                submit.LEGACY_SUBMITTED_DETAIL,
                "the unconfirmed migration note is recorded",
            )
            check_eq(
                records[submit._digest("FLAG{legacy_rejected}")]["outcome"],
                submit.REJECTED_FINAL,
                "rejected maps to rejected-final",
            )
            check_eq(
                records[submit._digest("FLAG{legacy_failed}")]["outcome"],
                submit.RETRYABLE,
                "failed maps to retryable",
            )
            with open(state, "rb") as fh:
                check_eq(fh.read(), original, "migration must not rewrite the file")

            config = _config(port, state)
            summary = submit.run(
                config,
                [flag for flag, _ in legacy],
                dry_run=False,
                state_file=state,
            )
            check_eq(summary["migrated"], 3, "the run reports the migration count")
            check_eq(
                summary["legacy_unconfirmed"],
                1,
                "the summary warns about unconfirmed legacy records",
            )
            check_eq(
                summary["warnings"],
                1,
                "legacy-unconfirmed records count as warnings",
            )
            check_eq(
                summary["duplicates"],
                1,
                "only the legacy rejected record deduplicates",
            )
            check_eq(
                summary["accepted"],
                2,
                "the submitted and failed legacy records are retried",
            )
            check_eq(
                len(server.requests),
                2,
                "the submitted and failed legacy flags are sent",
            )
            with open(state, "rb") as fh:
                after = fh.read()
            check(
                after.startswith(original),
                "migration never rewrites existing state lines",
            )
            check_eq(
                after.count(b"\n"),
                original.count(b"\n") + 4,
                "each retried flag appends pending and accepted",
            )


def test_state_lock_refuses_a_second_writer_without_traceback() -> None:
    port = free_port()
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        config_path = os.path.join(root, "config.json")
        flags_path = os.path.join(root, "flags.txt")
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "submit_url": f"http://127.0.0.1:{port}/submit",
                    "allow_hosts": ["127.0.0.1"],
                    "flag_regex": submit.DEFAULT_REGEX,
                    "max_attempts": 1,
                    "max_per_minute": 60,
                    "dry_run": False,
                    "state_file": state,
                },
                fh,
            )
        with open(flags_path, "w", encoding="utf-8") as fh:
            fh.write("FLAG{locked}\n")
        held = submit.StateLock(state)
        held.acquire()
        try:
            try:
                submit.run(
                    _config(port, state),
                    ["FLAG{locked}"],
                    dry_run=False,
                    state_file=state,
                )
            except submit.StateLockError as exc:
                check_in("lock", str(exc), "the refusal must name the lock")
            else:
                raise Failure("run() must refuse to start while the lock is held")
            code = submit.main(
                [
                    "--config",
                    config_path,
                    "--flags-file",
                    flags_path,
                    "--state-file",
                    state,
                ]
            )
            check_eq(
                code,
                submit.EXIT_NEGATIVE,
                "a held lock must exit with the expected negative result",
            )
        finally:
            held.release()


def test_response_mapping_matches_the_outcome_taxonomy() -> None:
    """Only an explicit `accepted: false` / `rejected: true` is terminal on a
    4xx; 401/403 and status/result strings are request-level denials, so they
    stay retryable and unconfirmed."""
    cases = [
        (200, b'{"accepted": true}', submit.ACCEPTED, False),
        (201, b'{"accepted": true, "detail": "created"}', submit.ACCEPTED, False),
        (200, b'{"accepted": false}', submit.REJECTED_FINAL, False),
        (200, b'{"detail": "queued"}', submit.RETRYABLE, True),
        (200, b"not json at all", submit.RETRYABLE, True),
        (400, b'{"accepted": false}', submit.REJECTED_FINAL, False),
        (400, b'{"rejected": true}', submit.REJECTED_FINAL, False),
        (400, b'{"detail": "cannot parse flag"}', submit.RETRYABLE, True),
        (401, b'{"status": "denied"}', submit.RETRYABLE, True),
        (403, b'{"status": "denied"}', submit.RETRYABLE, True),
        (403, b'{"status": "invalid"}', submit.RETRYABLE, True),
        (403, b'{"result": "denied"}', submit.RETRYABLE, True),
        (403, b'{"accepted": false}', submit.REJECTED_FINAL, False),
        (403, b'{"rejected": true}', submit.REJECTED_FINAL, False),
        (429, b'{"accepted": true}', submit.RETRYABLE, False),
        (500, b'{"accepted": false}', submit.RETRYABLE, False),
        (503, b'{"accepted": true}', submit.RETRYABLE, False),
    ]
    for status, raw, expected, unconfirmed in cases:
        outcome = submit._interpret_response(status, raw)
        check_eq(
            outcome["status"],
            expected,
            f"HTTP {status} with body {raw!r} must map to {expected}",
        )
        check_eq(
            bool(outcome.get("unconfirmed")),
            unconfirmed,
            f"HTTP {status} with body {raw!r} unconfirmed flag",
        )
    check_eq(submit._retry_after_seconds("2"), 2.0, "numeric Retry-After is honored")
    check_eq(
        submit._retry_after_seconds("9999"),
        submit.MAX_SLEEP_SECONDS,
        "Retry-After is capped",
    )
    check_eq(
        submit._retry_after_seconds("not-a-date"),
        None,
        "an unparseable Retry-After is ignored",
    )


def test_rate_limiter_respects_the_window() -> None:
    limiter = submit.RateLimiter(1)
    limiter.stamps = [time.time() - 59.6]
    started = time.time()
    limiter.wait()
    waited = time.time() - started
    check(waited >= 0.3, f"the limiter must wait for the window, waited {waited:.3f}s")


def test_request_level_denial_is_retryable_and_retried_later() -> None:
    """Only `accepted: false` / `rejected: true` are flag-level rejections; a
    403 with a status string is a request-level denial, so it stays retryable
    and unconfirmed and a later run must retry it."""
    script = [
        _reply(403, {"status": "denied", "detail": "denied by the front end"}),
        ACCEPTED,
    ]
    with _server(script) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            first = submit.run(
                config, ["FLAG{denied}"], dry_run=False, state_file=state
            )
            check_eq(first["failed"], 1, "a request-level 403 is retryable")
            check_eq(
                first["rejected"], 0, "a 403 without an explicit boolean is not final"
            )
            check_eq(first["unconfirmed"], 1, "the 403 denial is unconfirmed")
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.RETRYABLE],
                "the 403 attempt is recorded retryable",
            )
            second = submit.run(
                config, ["FLAG{denied}"], dry_run=False, state_file=state
            )
            check_eq(
                second["accepted"], 1, "the later run retries and settles the flag"
            )
            check_eq(second["duplicates"], 0, "retryable is not terminal")
            check_eq(len(server.requests), 2, "the denied attempt then the retry")


def test_unknown_state_outcome_is_retryable_and_preserved() -> None:
    """An outcome written by an unknown writer is retryable, counted, and keeps
    its original name in the in-memory `legacy_outcome` detail."""
    with _server([ACCEPTED]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            flag = "FLAG{odd_state}"
            with open(state, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(_record(flag, "flux-capacitor") + "\n")
            records, stats = submit._load_state(state)
            record = records[submit._digest(flag)]
            check_eq(stats["unknown_outcomes"], 1, "unknown outcomes are counted")
            check_eq(
                stats["migrated"], 0, "an unknown outcome is not a legacy migration"
            )
            check_eq(
                record["outcome"], submit.RETRYABLE, "unknown outcomes are retryable"
            )
            check_eq(
                record["legacy_outcome"],
                "flux-capacitor",
                "the original unknown value is preserved for the operator",
            )
            config = _config(port, state)
            summary = submit.run(config, [flag], dry_run=False, state_file=state)
            check_eq(
                summary["unknown_outcomes"], 1, "the run reports the unknown outcome"
            )
            check_eq(summary["warnings"], 1, "unknown outcomes count in warnings")
            check_eq(
                summary["accepted"], 1, "the unknown record is retried, not deduped"
            )
            check_eq(len(server.requests), 1, "the flag is sent once")


def test_state_collapse_prefers_accepted_over_later_retryable() -> None:
    """Documented collapse rule: accepted > rejected-final > retryable >
    pending, and a later record wins only ties. An accepted outcome therefore
    survives a later retryable line, and a later accepted line upgrades an
    earlier retryable one."""
    check(
        submit.OUTCOME_RANK[submit.ACCEPTED]
        > submit.OUTCOME_RANK[submit.REJECTED_FINAL]
        > submit.OUTCOME_RANK[submit.RETRYABLE]
        > submit.OUTCOME_RANK[submit.PENDING],
        "the rank table must match the documented collapse order",
    )
    flag = "FLAG{conflict}"
    digest = submit._digest(flag)
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        with open(state, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_record(flag, submit.ACCEPTED) + "\n")
            fh.write(_record(flag, submit.RETRYABLE) + "\n")
        records, _ = submit._load_state(state)
        check_eq(
            records[digest]["outcome"],
            submit.ACCEPTED,
            "an earlier accepted record must beat a later retryable one",
        )
        with open(state, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_record(flag, submit.RETRYABLE) + "\n")
            fh.write(_record(flag, submit.ACCEPTED) + "\n")
        records, _ = submit._load_state(state)
        check_eq(
            records[digest]["outcome"],
            submit.ACCEPTED,
            "a later accepted record must beat an earlier retryable one",
        )
        with open(state, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_record(flag, submit.REJECTED_FINAL) + "\n")
            fh.write(_record(flag, submit.RETRYABLE) + "\n")
        records, _ = submit._load_state(state)
        check_eq(
            records[digest]["outcome"],
            submit.REJECTED_FINAL,
            "rejected-final also beats a later retryable record",
        )


def test_pid_liveness_probe_and_stale_lock_reclaim() -> None:
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        dead = _dead_pid()
        check_eq(
            submit._pid_alive(os.getpid()), True, "the probe must see this process"
        )
        check_eq(
            submit._pid_alive(dead),
            False,
            "the probe must see the reaped child as dead",
        )
        check_eq(submit._pid_alive(0), False, "a non-pid is never alive")
        lock_path = _plant_lock(
            state, dead, age=submit.StateLock.LOCK_STALE_SECONDS + 60.0
        )
        with _exclusive_lock_path():
            lock = submit.StateLock(state)
            lock.acquire()
            try:
                check_eq(
                    lock.mode, "exclusive-create", "the reclaim path is under test"
                )
                with open(lock_path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                check_in(
                    f"pid={os.getpid()}",
                    content,
                    "the reclaiming process must own the lock",
                )
            finally:
                lock.release()
        check(not os.path.exists(lock_path), "release must remove the lock")


def test_live_lock_is_never_reclaimed() -> None:
    """A lock whose recorded pid is alive stays even when it is older than the
    stale threshold."""
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        lock_path = _plant_lock(
            state, os.getpid(), age=submit.StateLock.LOCK_STALE_SECONDS + 60.0
        )
        with open(lock_path, "rb") as fh:
            before = fh.read()
        with _exclusive_lock_path():
            lock = submit.StateLock(state)
            try:
                lock.acquire()
            except submit.StateLockError as exc:
                check_in("lock", str(exc), "the refusal must name the lock")
            else:
                lock.release()
                raise Failure("an old lock held by a live pid must never be reclaimed")
        with open(lock_path, "rb") as fh:
            check_eq(
                fh.read(), before, "the live lock must be left byte-for-byte intact"
            )


def test_lock_is_released_when_run_raises() -> None:
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        lock_path = state + ".lock"
        config = _config(free_port(), state)

        def explode(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            raise RuntimeError("injected mid-run failure")

        original = submit.submit_flag
        submit.submit_flag = explode
        try:
            with _exclusive_lock_path():
                try:
                    submit.run(config, ["FLAG{boom}"], dry_run=False, state_file=state)
                except RuntimeError:
                    pass
                else:
                    raise Failure("run() must propagate an unexpected failure")
                check(
                    not os.path.exists(lock_path),
                    "run() must release the lock when it raises",
                )
                probe = submit.StateLock(state)
                probe.acquire()
                probe.release()
        finally:
            submit.submit_flag = original


def test_lock_reclaim_aborts_when_the_lock_identity_changes() -> None:
    """A lock rewritten between the stale decision and the identity re-check
    must never be unlinked; acquisition backs off and refuses instead."""

    class RacingLock(submit.StateLock):
        def __init__(self, state_file: str) -> None:
            super().__init__(state_file)
            self.races = 0

        def _stale_identity(self) -> Optional[Any]:
            identity = super()._stale_identity()
            if identity is not None:
                self.races += 1
                with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(f"pid={os.getpid()} at=raced\n")
            return identity

    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        lock_path = _plant_lock(
            state, _dead_pid(), age=submit.StateLock.LOCK_STALE_SECONDS + 60.0
        )
        with _exclusive_lock_path():
            lock = RacingLock(state)
            try:
                lock.acquire()
            except submit.StateLockError as exc:
                check_in("lock", str(exc), "acquisition must refuse the churned lock")
            else:
                lock.release()
                raise Failure("reclaim must abort when the lock identity changed")
            check_eq(lock.races, 1, "the stale decision was made before the race")
        with open(lock_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        check_in("at=raced", content, "the changed lock was not unlinked")


def test_connection_closed_before_response_is_retryable_and_bounded() -> None:
    """A closed connection surfaces as http.client.HTTPException
    (RemoteDisconnected), which must be retryable inside the bounded loop and
    settled by a later run."""
    cut = _reply(200, {"accepted": True}, close=True)
    with _server([cut]) as (port, server):
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state, max_attempts=2)
            with _fast_backoff():
                first = submit.run(
                    config, ["FLAG{cut}"], dry_run=False, state_file=state
                )
            check_eq(first["failed"], 1, "a closed connection is retryable")
            check_eq(first["accepted"], 0, "a closed connection is never acceptance")
            detail = str(first["results"][0].get("detail") or "")
            check(
                any(
                    name in detail
                    for name in (
                        "RemoteDisconnected",
                        "IncompleteRead",
                        "BadStatusLine",
                        "HTTPException",
                    )
                ),
                f"the transport fault must be named, got {detail!r}",
            )
            check_eq(len(server.requests), 2, "in-run retries stop at max_attempts")
            check_eq(
                _outcomes(state),
                [submit.PENDING, submit.RETRYABLE],
                "one retryable outcome for the bounded attempts",
            )
            server.script = [ACCEPTED]
            second = submit.run(config, ["FLAG{cut}"], dry_run=False, state_file=state)
            check_eq(second["accepted"], 1, "a later run settles the flag")
            check_eq(second["duplicates"], 0, "the retryable record was not deduped")
            check_eq(len(server.requests), 3, "two failed attempts then one success")


def test_main_returns_exit_internal_on_unexpected_error() -> None:
    """The CLI boundary converts an unexpected exception into exit 3 with a
    one-line stderr diagnostic instead of a traceback."""

    def explode(path: str) -> Dict[str, Any]:
        raise RuntimeError("engine exploded")

    original = submit.load_config
    submit.load_config = explode
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            code = submit.main(
                ["--config", "unused.json", "--flags-file", "unused.txt"]
            )
    finally:
        submit.load_config = original
    check_eq(code, submit.EXIT_INTERNAL, "an unexpected exception must return exit 3")
    check_eq(submit.EXIT_INTERNAL, 3, "exit 3 is the internal-error code")
    check_in(
        "internal error", stderr.getvalue(), "the diagnostic must name the failure"
    )
    check_in(
        "RuntimeError",
        stderr.getvalue(),
        "the diagnostic must name the exception type",
    )


def test_state_appends_are_lf_only_and_torn_lines_recover() -> None:
    """O_BINARY keeps the JSONL LF-only on Windows, and a torn final line
    without a newline still gets a clean separator before the next record."""
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        flags = [f"FLAG{{lf_{index}}}" for index in range(4)]
        for flag in flags:
            submit._append_state(state, flag, submit.PENDING)
        with open(state, "rb") as fh:
            raw = fh.read()
        check(b"\r" not in raw, "state appends must not be CRLF-translated")
        check_eq(raw.count(b"\n"), 4, "one line per append")
        records, stats = submit._load_state(state)
        check_eq(stats["malformed_lines"], 0, "LF-only lines parse cleanly")
        check_eq(len(records), 4, "every append loads back")

        with open(state, "ab") as fh:
            fh.write(b'{"sha256": "torn", "outcome": "retry')
        submit._append_state(state, "FLAG{after_torn}", submit.RETRYABLE)
        with open(state, "rb") as fh:
            raw = fh.read()
        check(b"\r" not in raw, "the recovery separator must stay LF-only")
        records, stats = submit._load_state(state)
        check_eq(stats["malformed_lines"], 1, "the torn line stays malformed")
        check_eq(
            records[submit._digest("FLAG{after_torn}")]["outcome"],
            submit.RETRYABLE,
            "the record appended after the torn line is recovered",
        )
