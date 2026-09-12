"""Shared helpers for the test suite.

The suite is deliberately stdlib-only and Docker-free: the engine, the index, the
decoy and the profile logic must all be testable offline on a laptop. Container
integration lives in tests/t_integration_docker.py and skips with a clear reason
when Docker is unavailable.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
from typing import Any, Dict, Iterator, List, Optional, Tuple

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
if os.path.join(REPO_ROOT, "tools") not in sys.path:
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))


class Failure(AssertionError):
    pass


def check(condition: Any, message: str) -> None:
    if not condition:
        raise Failure(message)


def check_eq(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise Failure(f"{message}: expected {expected!r}, got {actual!r}")


def check_in(needle: Any, haystack: Any, message: str) -> None:
    if needle not in haystack:
        raise Failure(f"{message}: {needle!r} not found in {haystack!r}")


@contextlib.contextmanager
def temp_dir(prefix: str = "ctfctl-test-") -> Iterator[str]:
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@contextlib.contextmanager
def repo_copy() -> Iterator[str]:
    """A throwaway copy of the tracked repository skeleton.

    Tests that need a repo root (plans, index, state) must never write into the
    real checkout, so they run against a copy of just the parts they need.
    """
    with temp_dir("ctfctl-repo-") as root:
        for name in ("kb", "sources", "profiles"):
            source = os.path.join(REPO_ROOT, name)
            if os.path.isdir(source):
                shutil.copytree(source, os.path.join(root, name))
        os.makedirs(os.path.join(root, "state"), exist_ok=True)
        with open(os.path.join(root, "AGENTS.md"), "w", encoding="utf-8") as fh:
            fh.write("test root\n")
        yield root


# --------------------------------------------------------------------------
# Fake inventory builder
# --------------------------------------------------------------------------
def inventory_with(*, containers: Optional[List[Dict[str, Any]]] = None,
                   listeners: Optional[List[Dict[str, Any]]] = None,
                   app_roots: Optional[List[Dict[str, Any]]] = None,
                   os_id: str = "debian",
                   tools: Optional[Dict[str, bool]] = None,
                   processes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Build an inventory document shaped exactly like discover.discover() output."""
    containers = containers or []
    listeners = listeners or []
    services = []
    for listener in listeners:
        services.append({
            "port": listener["port"],
            "address": listener.get("address", "0.0.0.0"),
            "proto": listener.get("proto", "tcp"),
            "exposure": listener.get("exposure", "all-interfaces"),
            "stack_candidates": listener.get("stack_candidates", []),
            "evidence": listener.get("evidence", [f"listener {listener['port']}"]),
            "confidence": listener.get("confidence", "high"),
            "process": listener.get("process"),
            "pid": listener.get("pid"),
            "unit": None,
            "container": listener.get("container"),
            "app_root": None,
            "unsupported_reason": None,
        })
    return {
        "schema": "ctfctl.inventory/1",
        "mode": "fixture-root",
        "system_root": "/",
        "generated_at": "2026-01-01T00:00:00Z",
        "host": {"kernel": "test", "arch": "x86_64", "os_id": os_id, "is_root": False,
                 "euid": 1000, "init_system": "systemd", "boot_id": "test-boot",
                 "tools": tools or {}},
        "evidence": [
            {"kind": "host", "status": "ok", "detail": "", "gaps": [],
             "data": {"os_id": os_id, "is_root": False, "kernel": "test"}},
            {"kind": "containers", "status": "ok", "detail": "", "gaps": [],
             "data": {"containers": containers, "count": len(containers)}},
            {"kind": "listeners", "status": "ok", "detail": "", "gaps": [],
             "data": {"listeners": listeners}},
            {"kind": "app_roots", "status": "ok", "detail": "", "gaps": [],
             "data": {"candidates": app_roots or []}},
            {"kind": "processes", "status": "ok", "detail": "", "gaps": [],
             "data": {"processes": processes or [], "count": len(processes or [])}},
        ],
        "graph": {"services": services, "containers": containers,
                  "reverse_proxies": [], "confidence_legend": {}},
        "gaps": [],
        "redactions": 0,
    }


def compose_container(name: str, project: str, service: str, image: str,
                      workdir: str, publish: Tuple[str, int, str],
                      state: str = "running") -> Dict[str, Any]:
    host_ip, host_port, container_port = publish
    return {
        "id": f"{abs(hash(name)) % 10**12:012d}",
        "name": name,
        "image": image,
        "state": state,
        "compose_project": project,
        "compose_service": service,
        "compose_working_dir": workdir,
        "compose_config_files": os.path.join(workdir, "compose.yaml"),
        "network_mode": f"{project}_default",
        "published": [{"container_port": container_port, "host_ip": host_ip,
                       "host_port": str(host_port)}],
        "mounts": [],
        "env_names": [],
    }


# --------------------------------------------------------------------------
# Tiny HTTP service used by engine tests (no Docker)
# --------------------------------------------------------------------------
class FakeService:
    """A legitimate CRUD service plus a deliberately vulnerable download route."""

    def __init__(self, *, vulnerable: bool = True, break_workflow: bool = False) -> None:
        self.vulnerable = vulnerable
        self.break_workflow = break_workflow
        self.download_root = "/files-root"
        self.canary = "FIXTURE_CANARY_test_value"
        self.notes: Dict[str, Dict[str, str]] = {}
        self._counter = 0
        self.port = 0
        self.server: Optional[http.server.ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> int:
        handler = self._make_handler()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # -- handler ----------------------------------------------------------
    def _make_handler(self):
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                return

            def _send(self, status: int, body: bytes = b"",
                      content_type: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                path, _, query = self.path.partition("?")
                if path == "/healthz":
                    self._send(200, b'{"status":"ok"}')
                    return
                if path == "/files":
                    name = ""
                    for part in query.split("&"):
                        key, _, value = part.partition("=")
                        if key == "name":
                            name = _unquote(value)
                    if service.vulnerable:
                        content = f"legit:{name}".encode()
                        if name.startswith("../") and "canary" in name:
                            self._send(200, service.canary.encode(), "text/plain")
                            return
                        self._send(200, content, "text/plain")
                        return
                    if "../" in name or name.startswith("/"):
                        self._send(404, b"not found", "text/plain")
                        return
                    self._send(200, f"legit:{name}".encode(), "text/plain")
                    return
                if path.startswith("/api/notes/"):
                    note_id = path.rsplit("/", 1)[-1]
                    note = service.notes.get(note_id)
                    if not note:
                        self._send(404, b'{"error":"not found"}')
                        return
                    self._send(200, json.dumps(note).encode())
                    return
                self._send(404, b'{"error":"unknown"}')

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/api/notes" or service.break_workflow:
                    self._send(500, b'{"error":"broken"}')
                    return
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                service._counter += 1
                note_id = f"note{service._counter}"
                service.notes[note_id] = {"id": note_id,
                                          "title": str(payload.get("title", "")),
                                          "body": str(payload.get("body", ""))}
                self._send(201, json.dumps({"id": note_id}).encode())

            def do_DELETE(self) -> None:  # noqa: N802
                note_id = self.path.rsplit("/", 1)[-1]
                if service.notes.pop(note_id, None) is None:
                    self._send(404, b'{"error":"not found"}')
                    return
                self._send(204)

        return Handler


def _unquote(value: str) -> str:
    from urllib.parse import unquote

    return unquote(value)


@contextlib.contextmanager
def fake_service(**kwargs: Any) -> Iterator[FakeService]:
    service = FakeService(**kwargs)
    service.start()
    try:
        yield service
    finally:
        service.stop()


# --------------------------------------------------------------------------
# Test runner support
# --------------------------------------------------------------------------
def case(fn):
    fn._ctfctl_case = True
    return fn


def run_module(module: Any) -> Tuple[int, List[str]]:
    failures: List[str] = []
    passed = 0
    names = [n for n in dir(module) if n.startswith("test_")]
    for name in names:
        fn = getattr(module, name)
        if not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"  ok    {module.__name__}.{name}")
        except Failure as exc:
            failures.append(f"{module.__name__}.{name}: {exc}")
            print(f"  FAIL  {module.__name__}.{name}: {exc}")
        except Exception as exc:  # unexpected error is a failure too
            import traceback

            detail = traceback.format_exc(limit=4).strip().splitlines()[-1]
            failures.append(f"{module.__name__}.{name}: {type(exc).__name__}: {exc} | {detail}")
            print(f"  ERROR {module.__name__}.{name}: {type(exc).__name__}: {exc}")
    return passed, failures


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def docker_available() -> bool:
    from ctfctl import util

    if not util.which("docker"):
        return False
    result = util.run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
    return result.ok
