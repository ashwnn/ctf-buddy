"""Competition automation template: allowlist, dry-run, dedup, rate, mock I/O."""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import time

from helpers import REPO_ROOT, check, check_eq, check_in, free_port, temp_dir

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


def _config(port: int, state_file: str) -> dict:
    return {
        "submit_url": f"http://127.0.0.1:{port}/submit",
        "flag_regex": submit.DEFAULT_REGEX,
        "timeout_seconds": 5.0,
        "max_attempts": 2,
        "max_per_minute": 60,
        "dry_run": False,
        "state_file": state_file,
    }


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


def test_dry_run_sends_nothing() -> None:
    with temp_dir() as root:
        state = os.path.join(root, "seen.jsonl")
        config = _config(1, state)
        summary = submit.run(config, ["FLAG{dry}"], dry_run=True, state_file=state)
        check_eq(summary["accepted"], 0, "a dry run accepts nothing")
        check_eq(summary["results"][0]["status"], "dry-run", "dry-run status")
        check(not os.path.exists(state), "a dry run must not write submission state")


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
            check(summary["duplicates"] == 0, "no duplicates expected")
            check(os.path.isfile(state), "real submissions must record state")
            records = [json.loads(line) for line in open(state, encoding="utf-8")]
            check_eq(len(records), 2, "one state record per attempt")
    finally:
        server.shutdown()
        server.server_close()


def test_duplicate_flags_are_submitted_once() -> None:
    port = free_port()
    server = mock.build_server(port, pattern=r"FLAG\{[a-z_]+\}", accept_all=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with temp_dir() as root:
            state = os.path.join(root, "seen.jsonl")
            config = _config(port, state)
            first = submit.run(config, ["FLAG{dup}"], dry_run=False, state_file=state)
            check_eq(first["accepted"], 1, "first submission accepted")
            second = submit.run(config, ["FLAG{dup}"], dry_run=False, state_file=state)
            check_eq(second["accepted"], 0, "the duplicate must not be sent")
            check_eq(second["duplicates"], 1, "the duplicate must be reported")
    finally:
        server.shutdown()
        server.server_close()


def test_rate_limiter_respects_the_window() -> None:
    limiter = submit.RateLimiter(1)
    limiter.stamps = [time.time() - 59.6]
    started = time.time()
    limiter.wait()
    waited = time.time() - started
    check(waited >= 0.3, f"the limiter must wait for the window, waited {waited:.3f}s")
