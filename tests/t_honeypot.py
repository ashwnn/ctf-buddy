"""Honeypot lifecycle: port safety, both listener modes, log collection.

These tests start real local processes on free high ports and stop them again.
Nothing here touches a network interface beyond loopback, and no test ever binds
a port that something else is using.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.request
from typing import Any, Dict

from helpers import Failure, check, check_eq, check_in, free_port, repo_copy

from ctfctl import cli, honeypot, util


def _http_get(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as exc:  # 404 is a legitimate decoy answer
        return int(exc.code)


def _events(root: str, port: int, lines: int = 50) -> list:
    payload = honeypot.logs(root, lines=lines, port=port)
    out = []
    for entry in payload.get("listeners", []):
        for raw in entry.get("lines", []):
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
    return out


def test_http_honeypot_logs_hits_and_stops_cleanly() -> None:
    with repo_copy() as root:
        port = free_port()
        entry = honeypot.start(root, port=port, bind="127.0.0.1")
        try:
            check_eq(entry["port"], port, "the listener must use the requested port")
            check_eq(entry["mode"], "http", "default mode")
            check(os.path.isfile(os.path.join(root, entry["log_path"])),
                  "the log file must exist")
            check_eq(_http_get(f"http://127.0.0.1:{port}/admin"), 200,
                     "a configured lure path answers 200")
            check_eq(_http_get(f"http://127.0.0.1:{port}/nothing"), 404,
                     "anything else answers 404")
            status = honeypot.status(root)
            check_eq(len(status["running"]), 1, "status must report one listener")
            check_eq(status["running"][0]["state"], "running", "and it must be running")
            events = _events(root, port)
            check(any(e.get("event") == "decoy-http" and e.get("path") == "/admin"
                      for e in events), f"the hit must be logged, got {events}")
            check(all(e.get("decoy") is True for e in events if "event" in e),
                  "every event must be marked as a decoy")
        finally:
            honeypot.stop(root, all_listeners=True)
        check_eq(honeypot.status(root)["running"], [], "stop must clear the state file")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            check(sock.connect_ex(("127.0.0.1", port)) != 0, "the port must be free again")


def test_banner_honeypot_speaks_first() -> None:
    with repo_copy() as root:
        port = free_port()
        honeypot.start(root, port=port, bind="127.0.0.1", mode="banner", banner="ssh")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.settimeout(5)
                banner = sock.recv(128)
            check_in(b"SSH-2.0", banner, "the preset banner must be sent on connect")
            events = _events(root, port)
            check(any(e.get("event") == "decoy-banner" for e in events),
                  f"the connection must be logged, got {events}")
        finally:
            honeypot.stop(root, all_listeners=True)


def test_a_busy_port_is_refused() -> None:
    with repo_copy() as root:
        port = free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", port))
            blocker.listen(1)
            try:
                honeypot.start(root, port=port, bind="127.0.0.1")
            except util.CtfError as exc:
                check_in("in use", str(exc), "the refusal must name the conflict")
            else:
                honeypot.stop(root, all_listeners=True)
                raise Failure("a honeypot must never bind a port that is already in use")


def test_privileged_and_invalid_ports_are_refused() -> None:
    with repo_copy() as root:
        for port in (80, 0, 70000):
            try:
                honeypot.start(root, port=port, bind="127.0.0.1")
            except util.CtfError:
                continue
            honeypot.stop(root, all_listeners=True)
            raise Failure(f"port {port} must be refused")
        try:
            honeypot.start(root, port=free_port(), bind="127.0.0.1", mode="gopher")
        except util.CtfError as exc:
            check_in("mode", str(exc), "an unknown mode must be named")
        else:
            honeypot.stop(root, all_listeners=True)
            raise Failure("an unknown mode must be refused")


def test_listener_cap_is_enforced_from_state() -> None:
    with repo_copy() as root:
        fake = {"listeners": [
            {"pid": os.getpid(), "port": 10000 + index, "bind": "127.0.0.1",
             "mode": "http", "log_path": "captures/honeypot-1-x.jsonl"}
            for index in range(honeypot.MAX_LISTENERS)
        ]}
        os.makedirs(os.path.join(root, "state"), exist_ok=True)
        util.write_text_atomic(honeypot.state_path(root), util.dump_json(fake))
        try:
            honeypot.start(root, port=free_port(), bind="127.0.0.1")
        except util.CtfError as exc:
            check_in("refusing to add more", str(exc), "the cap must explain itself")
        else:
            honeypot.stop(root, all_listeners=True)
            raise Failure("the listener cap must be enforced")


def test_stop_by_port_leaves_other_listeners_alone() -> None:
    with repo_copy() as root:
        first, second = free_port(), free_port()
        honeypot.start(root, port=first, bind="127.0.0.1")
        honeypot.start(root, port=second, bind="127.0.0.1")
        try:
            payload = honeypot.stop(root, port=first)
            check_eq(len(payload["stopped"]), 1, "one listener stopped")
            check_eq([entry["port"] for entry in payload["remaining"]], [second],
                     "the other listener stays")
        finally:
            honeypot.stop(root, all_listeners=True)


def test_cli_honeypot_status_logs_and_stop() -> None:
    import io
    from contextlib import redirect_stderr, redirect_stdout

    cwd = os.getcwd()
    with repo_copy() as root:
        port = free_port()
        honeypot.start(root, port=port, bind="127.0.0.1")
        os.chdir(root)
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = cli.main(["honeypot", "status", "--json"])
            check_eq(code, 0, f"status must return 0: {err.getvalue()}")
            payload = json.loads(out.getvalue())
            check_eq(len(payload["running"]), 1, "status must list the listener")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = cli.main(["honeypot", "logs", "--json"])
            check_eq(code, 0, "logs must return 0")
            check_eq(len(json.loads(out.getvalue())["listeners"]), 1, "logs must find it")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = cli.main(["honeypot", "stop", "--all", "--json"])
            check_eq(code, 0, "stop must return 0")
        finally:
            os.chdir(cwd)
            honeypot.stop(root, all_listeners=True)
