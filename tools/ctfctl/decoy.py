"""Optional, unprivileged HTTP decoy.

Design constraints (all deliberate):

  * **disabled by default**. It will not start until a teammate has acknowledged
    the event rules and named the exact unused port(s) and path(s) it may use.
  * **isolated process**, unprivileged, with no backend, no database access, no
    credentials, no shell, and no outbound network capability of its own.
  * **resource bounded**: address-space and file-descriptor rlimits where the
    platform supports them, a bounded thread pool, bounded request parsing,
    bounded body reads, and a capped log file that stops growing.
  * **inert responses**: user input is never reflected into the response body, so
    the decoy cannot become an XSS or header-injection vector itself.
  * **never touches a real service**: it refuses to bind a port that is already
    listening, and it never modifies, proxies to, or replaces a scored service.
  * **distinctly marked**: every response carries `X-Decoy: ctfctl` and every
    logged event carries `"decoy": true`, so decoy hits are never mistaken for
    real service traffic.

A decoy is an observation aid, not a defence. It cannot protect a scored service
and it does not replace log review.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import util

POLICY_REL = os.path.join("state", "decoy-policy.json")
STATE_REL = os.path.join("state", "decoy.json")
MAX_BODY_BYTES = 64 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_THREADS = 8
REQUEST_TIMEOUT = 10

DEFAULT_PATHS = ["/admin", "/admin.php", "/.env", "/wp-login.php", "/backup.zip"]

DECOY_PAGE = (
    "<!doctype html><html><head><title>Sign in</title></head><body>"
    '<h1>Sign in</h1><form method="post"><input name="user"><input name="pass"'
    ' type="password"><button>Continue</button></form>'
    "<p>Internal use only.</p></body></html>"
)


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------
@dataclass
class DecoyPolicy:
    acknowledged: bool = False
    allowed_ports: List[int] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=lambda: list(DEFAULT_PATHS))
    bind: str = "127.0.0.1"
    notes: str = ""
    acknowledged_at: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at,
            "allowed_ports": self.allowed_ports,
            "allowed_paths": self.allowed_paths,
            "bind": self.bind,
            "notes": self.notes,
        }


def policy_path(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), POLICY_REL)


def load_policy(root: Optional[str] = None) -> DecoyPolicy:
    payload = util.load_json(policy_path(root), {})
    if not isinstance(payload, dict):
        return DecoyPolicy()
    return DecoyPolicy(
        acknowledged=bool(payload.get("acknowledged")),
        allowed_ports=[int(p) for p in payload.get("allowed_ports") or []],
        allowed_paths=[str(p) for p in payload.get("allowed_paths") or DEFAULT_PATHS],
        bind=str(payload.get("bind") or "127.0.0.1"),
        notes=str(payload.get("notes") or ""),
        acknowledged_at=str(payload.get("acknowledged_at") or ""),
    )


def save_policy(policy: DecoyPolicy, root: Optional[str] = None) -> str:
    path = policy_path(root)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    policy.acknowledged_at = policy.acknowledged_at or util.iso_now()
    util.write_text_atomic(path, util.dump_json(policy.as_dict()), mode=0o600)
    return path


def enable(
    root: Optional[str],
    *,
    ports: List[int],
    paths: List[str],
    bind: str,
    notes: str,
    acknowledge: bool,
) -> DecoyPolicy:
    if not acknowledge:
        raise util.CtfError(
            "decoy use requires explicit acknowledgement of the event rules",
            hint="re-run with --ack-rules after confirming decoys are permitted and these "
            "ports/paths are unused by scored services",
        )
    if not ports:
        raise util.CtfError("at least one unused port must be named with --port")
    if bind not in ("127.0.0.1", "::1") and not _is_private_address(bind):
        raise util.CtfError(
            f"refusing to bind the decoy to {bind!r}: use loopback or a private address that "
            "belongs to the team's own VM"
        )
    for port in ports:
        if port < 1024:
            raise util.CtfError(
                f"port {port} is privileged; the decoy runs unprivileged and must use a high port"
            )
        if _port_listening(bind, port):
            raise util.CtfError(
                f"port {port} is already listening on {bind}: it may be a scored service",
                hint="choose a port that nothing is using; never displace a scored service",
            )
    policy = DecoyPolicy(
        acknowledged=True,
        allowed_ports=sorted(set(ports)),
        allowed_paths=sorted(set(paths or DEFAULT_PATHS)),
        bind=bind,
        notes=notes,
        acknowledged_at=util.iso_now(),
    )
    save_policy(policy, root)
    return policy


def _is_private_address(address: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def _port_listening(host: str, port: int, timeout: float = 1.0) -> bool:
    if port <= 0:
        # Never probe port 0: on some platforms connect() to port 0 does not fail
        # fast, and "no configured port" is not a question worth asking the network.
        return False
    families = [socket.AF_INET]
    if ":" in host:
        families = [socket.AF_INET6]
    for family in families:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((host, port)) == 0
        except OSError:
            continue
    return False


def any_port_listening(port: int) -> List[str]:
    """Check the usual bind addresses: a decoy must not shadow any of them."""
    hits: List[str] = []
    if port <= 0:
        return hits
    for host in ("127.0.0.1", "::1"):
        if _port_listening(host, port):
            hits.append(host)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("0.0.0.0", port)) == 0:
                hits.append("0.0.0.0")
    except OSError:
        pass
    return hits


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------
class BoundedThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16
    _slots = threading.Semaphore(MAX_THREADS)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n"
                    b"Content-Length: 0\r\nX-Decoy: ctfctl\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)


class DecoyHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ctf-decoy/0.1"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT
    max_line = 8192
    max_headers = 50

    # -- request parsing limits -------------------------------------------
    def parse_request(self) -> bool:
        # BaseHTTPRequestHandler already enforces per-line (64 KiB) and header-count
        # limits via http.client.parse_headers; this adds the tighter caps this
        # decoy promises and refuses oversized bodies before reading them.
        if not super().parse_request():
            return False
        if len(self.requestline) > self.max_line:
            self._respond(414, "request line too long")
            return False
        length = self.headers.get("Content-Length") if self.headers else None
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            self._respond(413, "body too large")
            return False
        return True

    # -- responses --------------------------------------------------------
    def _respond(self, status: int, message: str, body: str = "") -> None:
        payload = body.encode("utf-8") if body else b""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Decoy", "ctfctl")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle("OPTIONS")

    def _handle(self, method: str) -> None:
        length = self.headers.get("Content-Length") if self.headers else None
        consumed = 0
        if method in ("POST", "PUT") and length and length.isdigit():
            want = min(int(length), MAX_BODY_BYTES)
            consumed = len(self.rfile.read(want))
        path = self.path.split("?", 1)[0]
        server: DecoyServer = self.server  # type: ignore[assignment]
        configured = path in server.allowed_paths
        server.record(
            {
                "event": "decoy-http",
                "decoy": True,
                "method": method,
                "path": path,
                # The full target is recorded, but escaped and length-capped: attacker
                # input must never be able to forge a log line or move a terminal cursor.
                "target": util.printable(self.path, 200),
                "query_present": "?" in self.path,
                "status": 200 if configured else 404,
                "configured_path": configured,
                "user_agent": self.headers.get("User-Agent", "")
                if self.headers
                else "",
                "body_bytes": consumed,
                "body_truncated": bool(
                    length and length.isdigit() and int(length) > MAX_BODY_BYTES
                ),
                "client": self.client_address[0],
                "marker": server.marker,
            }
        )
        if method == "HEAD":
            self.send_response(200 if configured else 404)
            self.send_header("Content-Length", "0")
            self.send_header("X-Decoy", "ctfctl")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if configured:
            self._respond(200, "ok", DECOY_PAGE)
        else:
            # Input is never reflected back, so the decoy cannot be abused as a
            # reflected-content vector against other participants.
            self._respond(404, "not found", "<!doctype html><h1>404 Not Found</h1>")

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return  # handled by structured events

    def log_error(self, fmt: str, *args: Any) -> None:
        server: DecoyServer = self.server  # type: ignore[assignment]
        server.record(
            {
                "event": "decoy-error",
                "decoy": True,
                "detail": util.printable(fmt % args, 200),
            }
        )


class DecoyServer(BoundedThreadingHTTPServer):
    allowed_paths: List[str] = []
    log_path: str = ""
    marker: str = ""
    _lock = threading.Lock()
    _written = 0
    _stopped = False

    def record(self, event: Dict[str, Any]) -> None:
        with self._lock:
            if self._stopped:
                return
            payload = {
                "at": util.iso_now(),
                **{
                    k: (util.printable(v, 300) if isinstance(v, str) else v)
                    for k, v in event.items()
                },
            }
            line = json.dumps(payload, sort_keys=True) + "\n"
            if self._written + len(line) > MAX_LOG_BYTES:
                self._stopped = True
                line = (
                    json.dumps(
                        {
                            "at": util.iso_now(),
                            "event": "decoy-log-capped",
                            "decoy": True,
                            "reason": f"log byte budget {MAX_LOG_BYTES} reached",
                        }
                    )
                    + "\n"
                )
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError:
                pass
            self._written += len(line)


def apply_rlimits() -> List[str]:
    notes: List[str] = []
    try:
        import resource
    except ImportError:
        return ["resource module unavailable: rlimits not applied"]
    limits = [
        ("RLIMIT_AS", 256 * 1024 * 1024, "address space"),
        ("RLIMIT_NOFILE", 128, "file descriptors"),
        ("RLIMIT_CPU", 300, "cpu seconds"),
    ]
    for name, value, label in limits:
        ident = getattr(resource, name, None)
        if ident is None:
            continue
        try:
            soft, hard = resource.getrlimit(ident)
            new = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(ident, (new, hard))
            notes.append(f"{label} limited to {new}")
        except (ValueError, OSError) as exc:
            notes.append(f"could not limit {label}: {exc}")
    return notes


def serve(port: int, bind: str, paths: List[str], log_path: str, marker: str) -> int:
    notes = apply_rlimits()
    server = DecoyServer((bind, port), DecoyHandler)
    server.allowed_paths = paths
    server.log_path = log_path
    server.marker = marker
    server.record(
        {
            "event": "decoy-started",
            "decoy": True,
            "bind": bind,
            "port": port,
            "paths": paths,
            "rlimits": notes,
            "warning": "decoy events are marked with decoy=true and X-Decoy: ctfctl",
        }
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.record({"event": "decoy-stopped", "decoy": True})
        server.server_close()
    return 0


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------
def state_path(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), STATE_REL)


def start(
    root: Optional[str], *, port: Optional[int] = None, bind: Optional[str] = None
) -> Dict[str, Any]:
    root = root or util.repo_root()
    policy = load_policy(root)
    if not policy.acknowledged:
        raise util.CtfError(
            "the decoy is disabled until the rules are acknowledged",
            hint="run: ctfctl decoy enable --ack-rules --port <UNUSED_PORT>",
        )
    chosen = int(port or (policy.allowed_ports[0] if policy.allowed_ports else 0))
    if not chosen:
        raise util.CtfError("no decoy port configured")
    if chosen not in policy.allowed_ports:
        raise util.CtfError(
            f"port {chosen} is not in the acknowledged allowlist {policy.allowed_ports}",
            hint="re-run: ctfctl decoy enable --ack-rules --port " + str(chosen),
        )
    bind_address = bind or policy.bind
    listening = any_port_listening(chosen)
    if listening:
        raise util.CtfError(
            f"port {chosen} is already listening ({', '.join(listening)}): refusing to start",
            hint="a decoy must never displace or shadow a scored service",
        )
    state_file = state_path(root)
    if os.path.isfile(state_file):
        existing = util.load_json(state_file, {})
        if existing.get("pid") and _pid_alive(int(existing["pid"])):
            raise util.CtfError(f"a decoy is already running (pid {existing['pid']})")

    log_path = os.path.join(
        util.captures_dir(root=root), f"decoy-{util.utc_stamp()}.jsonl"
    )
    marker = util.short_id("decoy", str(chosen), util.utc_stamp())
    argv = [
        sys.executable,
        "-m",
        "ctfctl.decoy",
        "--serve",
        "--port",
        str(chosen),
        "--bind",
        bind_address,
        "--log",
        log_path,
        "--marker",
        marker,
        "--paths",
        ",".join(policy.allowed_paths),
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        + os.pathsep
        + env.get("PYTHONPATH", "")
    )
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )
    time.sleep(1.0)
    if proc.poll() is not None:
        raise util.CtfError(
            "the decoy process exited immediately",
            hint=f"check for a bind error on {bind_address}:{chosen}",
        )
    state = {
        "pid": proc.pid,
        "port": chosen,
        "bind": bind_address,
        "log_path": os.path.relpath(log_path, root).replace(os.sep, "/"),
        "marker": marker,
        "started_at": util.iso_now(),
        "paths": policy.allowed_paths,
        "argv": argv,
    }
    util.write_text_atomic(state_file, util.dump_json(state), mode=0o600)
    return state


def _pid_alive(pid: int) -> bool:
    """Non-destructive liveness check.

    POSIX: signal 0 is a pure permission/existence probe. Windows: os.kill is
    destructive for every signal (it maps to TerminateProcess), and calling it
    on a process that is mid-termination can block, so query the exit code
    through the Win32 API instead.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _pid_alive_windows(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def status(root: Optional[str] = None) -> Dict[str, Any]:
    root = root or util.repo_root()
    policy = load_policy(root)
    state_file = state_path(root)
    state = util.load_json(state_file, {}) if os.path.isfile(state_file) else {}
    pid = int(state.get("pid") or 0)
    alive = _pid_alive(pid)
    listening = any_port_listening(int(state.get("port") or 0)) if state else []
    events = 0
    log_path = state.get("log_path")
    if log_path:
        absolute = os.path.join(root, log_path)
        if os.path.isfile(absolute):
            try:
                with open(absolute, "r", encoding="utf-8", errors="replace") as fh:
                    events = sum(1 for _ in fh)
            except OSError:
                events = -1
    return {
        "enabled": policy.acknowledged,
        "allowed_ports": policy.allowed_ports,
        "bind": policy.bind,
        "running": alive,
        "pid": pid if alive else None,
        "port": state.get("port"),
        "log_path": log_path,
        "events_logged": events,
        "port_listening": listening,
        "marker": state.get("marker"),
    }


def stop(root: Optional[str] = None) -> Dict[str, Any]:
    root = root or util.repo_root()
    state_file = state_path(root)
    if not os.path.isfile(state_file):
        return {"stopped": False, "reason": "no decoy state file"}
    state = util.load_json(state_file, {})
    pid = int(state.get("pid") or 0)
    port = int(state.get("port") or 0)
    stopped = False
    if pid and _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            return {"stopped": False, "reason": f"could not signal pid {pid}: {exc}"}
        for _ in range(20):
            if not _pid_alive(pid):
                stopped = True
                break
            time.sleep(0.25)
        if not stopped:
            try:
                # SIGKILL does not exist on Windows; SIGTERM is the strongest signal
                # available there, and TerminateProcess is what it maps to.
                hard_kill = getattr(signal, "SIGKILL", signal.SIGTERM)
                os.kill(pid, hard_kill)
                stopped = True
            except OSError:
                stopped = False
    remaining = any_port_listening(port) if port else []
    # Process teardown and socket release are not atomic on every platform
    # (Windows in particular reports the process gone a moment before the
    # listening socket disappears). Wait briefly before declaring the port free.
    if not remaining:
        pass
    else:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            time.sleep(0.25)
            remaining = any_port_listening(port)
            if not remaining:
                break
    try:
        os.unlink(state_file)
    except OSError:
        pass
    return {
        "stopped": stopped,
        "pid": pid,
        "port": port,
        "port_still_listening": remaining,
        "verified": not remaining,
    }


# --------------------------------------------------------------------------
# CLI entry for the isolated process
# --------------------------------------------------------------------------
def _main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="ctfctl.decoy", description="minimal unprivileged HTTP decoy"
    )
    parser.add_argument("--serve", action="store_true", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--paths", default=",".join(DEFAULT_PATHS))
    parser.add_argument("--log", required=True)
    parser.add_argument("--marker", default="decoy")
    args = parser.parse_args(argv)
    paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    return serve(args.port, args.bind, paths, args.log, args.marker)


def summarize(state: Dict[str, Any]) -> str:
    lines = [
        f"enabled   {state.get('enabled')}   allowed_ports={state.get('allowed_ports')}",
        f"running   {state.get('running')}   pid={state.get('pid')} port={state.get('port')}"
        f" bind={state.get('bind')}",
        f"events    {state.get('events_logged')}  log={state.get('log_path')}",
        f"marker    {state.get('marker')}",
    ]
    if not state.get("enabled"):
        lines.append("")
        lines.append(
            "The decoy is off. Read docs/decoy.md before enabling it: it must never"
        )
        lines.append(
            "shadow a scored service, and its events are only an observation aid."
        )
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
