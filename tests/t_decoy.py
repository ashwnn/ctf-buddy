"""Decoy: policy gate, port safety, resource bounds, inert responses."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from helpers import Failure, check, check_eq, check_in, free_port, repo_copy

from ctfctl import decoy, util


def _read_events(root: str, relative: str):
    path = os.path.join(root, relative)
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_decoy_is_disabled_until_rules_are_acknowledged() -> None:
    with repo_copy() as root:
        try:
            decoy.enable(root, ports=[free_port()], paths=[], bind="127.0.0.1",
                         notes="", acknowledge=False)
        except util.CtfError as exc:
            check("acknowledge" in str(exc).lower(), f"expected an ack requirement, got: {exc}")
        else:
            raise Failure("enabling without --ack-rules must fail")
        policy = decoy.load_policy(root)
        check(not policy.acknowledged, "policy must stay unacknowledged")


def test_privileged_port_is_refused() -> None:
    with repo_copy() as root:
        try:
            decoy.enable(root, ports=[80], paths=[], bind="127.0.0.1", notes="",
                         acknowledge=True)
        except util.CtfError as exc:
            check("privileged" in str(exc), f"expected a privileged-port refusal, got: {exc}")
        else:
            raise Failure("a low port must be refused")


def test_public_bind_address_is_refused() -> None:
    with repo_copy() as root:
        try:
            decoy.enable(root, ports=[free_port()], paths=[], bind="8.8.8.8", notes="",
                         acknowledge=True)
        except util.CtfError as exc:
            check("loopback" in str(exc) or "private" in str(exc), str(exc))
        else:
            raise Failure("the decoy must not bind a public address")


def test_port_already_in_use_is_refused() -> None:
    import http.server
    import threading

    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port),
                                             http.server.BaseHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with repo_copy() as root:
            try:
                decoy.enable(root, ports=[port], paths=[], bind="127.0.0.1", notes="",
                             acknowledge=True)
            except util.CtfError as exc:
                check("already listening" in str(exc), str(exc))
            else:
                raise Failure("a port that is already serving must never be taken over")
    finally:
        server.shutdown()
        server.server_close()


def test_start_status_stop_lifecycle() -> None:
    with repo_copy() as root:
        port = free_port()
        decoy.enable(root, ports=[port], paths=["/admin.php"], bind="127.0.0.1",
                     notes="unit test", acknowledge=True)
        state = decoy.start(root)
        try:
            check(decoy._pid_alive(int(state["pid"])), "the decoy process should be running")
            status = decoy.status(root)
            check(status["running"], f"status should report running: {status}")
            # A configured path answers 200, everything else 404, both inert.
            request = urllib.request.Request(f"http://127.0.0.1:{port}/admin.php",
                                             headers={"User-Agent": "unit-test"})
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read().decode()
                check_eq(response.status, 200, "configured path status")
                check_eq(response.headers.get("X-Decoy"), "ctfctl", "decoy marker header")
                check("<form" in body, "the decoy serves its own login page")
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nonexistent", timeout=5)
            except urllib.error.HTTPError as exc:
                check_eq(exc.code, 404, "unconfigured path status")
            # A request completed, so the event log must contain a marked event.
            events = _read_events(root, state["log_path"])
            check(events, "the decoy must log the request")
            check(all(e.get("decoy") is True for e in events),
                  "every decoy event must be marked decoy=true")
            check(any("/admin.php" in json.dumps(e) for e in events),
                  "the requested path should be recorded")
        finally:
            result = decoy.stop(root)
            check(result["verified"], f"stop must confirm the port is released: {result}")
        check(not decoy.any_port_listening(port), "the port must be free after stop")


def test_start_is_refused_for_a_port_outside_the_allowlist() -> None:
    with repo_copy() as root:
        allowed = free_port()
        other = free_port()
        decoy.enable(root, ports=[allowed], paths=[], bind="127.0.0.1", notes="",
                     acknowledge=True)
        try:
            decoy.start(root, port=other)
        except util.CtfError as exc:
            check("allowlist" in str(exc), str(exc))
        else:
            raise Failure("a port outside the acknowledged allowlist must be refused")


def test_control_characters_in_requests_are_escaped_in_the_log() -> None:
    with repo_copy() as root:
        port = free_port()
        decoy.enable(root, ports=[port], paths=["/admin"], bind="127.0.0.1", notes="",
                     acknowledge=True)
        state = decoy.start(root)
        try:
            # A newline and an ANSI escape inside the request line must not be able
            # to forge a log line or move the cursor when the log is viewed.
            import socket

            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(b"GET /admin?x=\x1b[31mred\x1b[0m HTTP/1.1\r\n"
                             b"Host: localhost\r\nConnection: close\r\n\r\n")
                sock.recv(4096)
            time.sleep(0.3)
            events = _read_events(root, state["log_path"])
            blob = json.dumps(events)
            check("\x1b" not in blob, "the raw escape byte must not appear in the log")
            check("\\x1b" in blob or "x1b" in blob,
                  "the escape should be recorded in an inert escaped form")
        finally:
            decoy.stop(root)


def test_input_is_never_reflected_into_the_response() -> None:
    with repo_copy() as root:
        port = free_port()
        decoy.enable(root, ports=[port], paths=["/login"], bind="127.0.0.1", notes="",
                     acknowledge=True)
        state = decoy.start(root)
        payload = "<script>alert(1)</script>"
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/login?next={payload}", headers={"User-Agent": payload})
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read().decode()
                check("<script>alert(1)</script>" not in body,
                      "the decoy must not reflect request data into the response")
        finally:
            decoy.stop(root)


def test_oversized_body_is_rejected_without_being_buffered() -> None:
    with repo_copy() as root:
        port = free_port()
        decoy.enable(root, ports=[port], paths=["/admin"], bind="127.0.0.1", notes="",
                     acknowledge=True)
        state = decoy.start(root)
        try:
            import socket

            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(b"POST /admin HTTP/1.1\r\nHost: x\r\n"
                             b"Content-Length: 100000000\r\n\r\n")
                data = sock.recv(512)
            check(b"413" in data, f"an oversized body must be refused, got: {data[:80]!r}")
            events = _read_events(root, state["log_path"])
            check(any("log-capped" not in json.dumps(e) for e in events),
                  "the decision should still be logged as an event")
        finally:
            decoy.stop(root)


def test_log_growth_is_capped() -> None:
    with repo_copy() as root:
        port = free_port()
        decoy.enable(root, ports=[port], paths=["/admin"], bind="127.0.0.1", notes="",
                     acknowledge=True)
        state = decoy.start(root)
        try:
            original = decoy.MAX_LOG_BYTES
            decoy.MAX_LOG_BYTES = 4096  # the running server reads this at import time
            log_path = os.path.join(root, state["log_path"])
            # Directly exercise the server-side cap using a stand-in server object.
            server = decoy.DecoyServer.__new__(decoy.DecoyServer)
            server.log_path = log_path
            server.marker = "test"
            server._written = 0
            server._stopped = False
            for index in range(400):
                server.record({"event": "decoy-http", "decoy": True, "index": index,
                               "path": "/admin-" + "x" * 40})
            check(server._stopped, "the writer must stop once the byte budget is reached")
            size = os.path.getsize(log_path)
            check(size <= decoy.MAX_LOG_BYTES + 2048,
                  f"the log must stay near its cap, got {size} bytes")
            decoy.MAX_LOG_BYTES = original
        finally:
            decoy.stop(root)


def test_stop_when_nothing_is_running_is_honest() -> None:
    with repo_copy() as root:
        result = decoy.stop(root)
        check_eq(result["stopped"], False, "there was nothing to stop")
        check_in("reason", result, "the result must explain itself")
