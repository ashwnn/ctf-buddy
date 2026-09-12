#!/usr/bin/env python3
"""Bounded flag-submission template. Standard library only.

This is a template, not an event integration. It is disabled by default
(`dry_run: true`), talks to a mock endpoint in the shipped configuration, and
refuses any endpoint host that is not explicitly allowlisted. No organizer URL is
hardcoded anywhere.

Use it only if the event rules permit automation. Then:

    python mock_server.py --port 8099          # in another terminal
    python submit.py --config config.example.json --flags-file candidates.txt

Exit codes: 0 all submitted (or a dry run), 1 some rejected/failed,
2 usage or configuration error, 3 internal error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

EXIT_OK = 0
EXIT_NEGATIVE = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
DEFAULT_REGEX = r"[A-Za-z0-9_]{2,20}\{[^}]{3,200}\}"
MAX_BODY_BYTES = 64 * 1024


class ConfigError(Exception):
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


def _load_seen(path: str) -> Dict[str, str]:
    seen: Dict[str, str] = {}
    if not os.path.isfile(path):
        return seen
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("sha256"):
                seen[str(record["sha256"])] = str(record.get("flag", ""))[:16]
    return seen


def _append_seen(path: str, flag: str, outcome: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    digest = hashlib.sha256(flag.encode("utf-8")).hexdigest()
    record = {
        "sha256": digest,
        "flag": flag,
        "outcome": outcome,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


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


def submit_flag(config: Dict[str, Any], flag: str) -> Dict[str, Any]:
    body = json.dumps({"flag": flag}).encode("utf-8")
    request = urllib.request.Request(
        config["submit_url"],
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ctfctl-template/1.0",
        },
    )
    last_error = ""
    for attempt in range(1, config["max_attempts"] + 1):
        try:
            with urllib.request.urlopen(
                request, timeout=config["timeout_seconds"]
            ) as resp:
                raw = resp.read(MAX_BODY_BYTES)
            try:
                payload = json.loads(raw.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                payload = {
                    "accepted": None,
                    "detail": raw[:200].decode("utf-8", "replace"),
                }
            accepted = payload.get("accepted")
            if accepted is False:
                return {
                    "ok": False,
                    "attempt": attempt,
                    "status": "rejected",
                    "response": payload,
                    "detail": str(payload.get("detail") or "endpoint rejected"),
                }
            return {
                "ok": True,
                "attempt": attempt,
                "status": "submitted",
                "response": payload,
            }
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code < 500:
                return {
                    "ok": False,
                    "attempt": attempt,
                    "status": "rejected",
                    "detail": last_error,
                }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        if attempt < config["max_attempts"]:
            time.sleep(min(2.0, 0.5 * attempt))
    return {
        "ok": False,
        "attempt": config["max_attempts"],
        "status": "failed",
        "detail": last_error,
    }


def run(
    config: Dict[str, Any], flags: Iterable[str], *, dry_run: bool, state_file: str
) -> Dict[str, Any]:
    seen = _load_seen(state_file)
    limiter = RateLimiter(config["max_per_minute"])
    results: List[Dict[str, Any]] = []
    skipped = 0
    for flag in flags:
        digest = hashlib.sha256(flag.encode("utf-8")).hexdigest()
        if digest in seen:
            skipped += 1
            results.append({"flag": flag, "status": "duplicate"})
            continue
        if dry_run:
            results.append({"flag": flag, "status": "dry-run"})
            continue
        limiter.wait()
        result = submit_flag(config, flag)
        result["flag"] = flag
        results.append(result)
        _append_seen(state_file, flag, result["status"])
        seen[digest] = flag[:16]
    accepted = sum(
        1
        for item in results
        if item["status"] == "submitted"
        and (item.get("response") or {}).get("accepted") is not False
    )
    rejected = sum(1 for item in results if item["status"] == "rejected")
    failed = sum(1 for item in results if item["status"] == "failed")
    return {
        "config": config["submit_url"],
        "dry_run": dry_run,
        "total": len(results),
        "accepted": accepted,
        "rejected": rejected,
        "failed": failed,
        "duplicates": skipped,
        "results": results,
    }


def main(argv: List[str]) -> int:
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
    summary = run(config, flags, dry_run=dry_run, state_file=state_file)
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
