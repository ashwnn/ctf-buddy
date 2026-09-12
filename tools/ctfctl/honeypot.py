"""Multi-listener honeypot lifecycle.

The listeners are `decoy.DecoyServer` (HTTP lure) and `decoy.BannerServer`
(TCP banner) launched as detached child processes, one per port. This module
only manages their lifecycle: naming unused ports, starting, reporting,
collecting logs and stopping.

Safety properties, all deliberate and enforced here rather than in prose:

  * **a honeypot never displaces a scored service.** A port is refused unless a
    bind test proves it free, and it is refused again if it is already claimed
    by a running listener in this state file.
  * **no privileged ports by default.** Below 1024 requires `--allow-privileged`
    (the caller is expected to be root, and the caller is the operator).
  * **bounded.** At most `MAX_LISTENERS` listeners, each decoy has its own byte
    budget for logs, and `logs`/`collect` read a bounded tail.
  * **marked.** Every event carries `"decoy": true`; `status` says so too, so a
    honeypot hit is never mistaken for scored-service traffic.

A honeypot is an observation aid and a distraction, not a defence: it must never
sit on a port the checker uses, and it does not protect anything.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from . import decoy
from . import util

STATE_REL = os.path.join("state", "honeypot.json")
MAX_LISTENERS = 4
MIN_UNPRIVILEGED_PORT = 1024
MODES = ("http", "banner")
DEFAULT_BIND = "0.0.0.0"
TAIL_BYTES = 128 * 1024


def state_path(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), STATE_REL)


def load_state(root: Optional[str] = None) -> Dict[str, Any]:
    payload = util.load_json(state_path(root), {})
    if not isinstance(payload, dict):
        return {"listeners": []}
    listeners = payload.get("listeners")
    return {"listeners": listeners if isinstance(listeners, list) else []}


def _save_state(state: Dict[str, Any], root: Optional[str] = None) -> None:
    path = state_path(root)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    util.write_text_atomic(path, util.dump_json(state), mode=0o600)


def _listener_alive(entry: Dict[str, Any]) -> bool:
    pid = int(entry.get("pid") or 0)
    return bool(pid) and util.pid_alive(pid)


def _port_free(bind: str, port: int) -> bool:
    """Definitive free-port check: the kernel decides, not a guess from files."""
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((bind, port))
    except OSError:
        return False
    return True


def _reachable(bind: str, port: int, timeout: float = 2.0) -> bool:
    host = "127.0.0.1" if bind in ("0.0.0.0", "::", "") else bind
    return decoy._port_listening(host, port, timeout)


def _validate(port: int, mode: str, bind: str, banner: str,
              allow_privileged: bool) -> None:
    if not 0 < int(port) <= 65535:
        raise util.CtfError(f"port {port} is not a valid TCP port")
    if int(port) < MIN_UNPRIVILEGED_PORT and not allow_privileged:
        raise util.CtfError(
            f"port {port} is privileged and the honeypot runs unprivileged by default",
            hint="pick a high port, or pass --allow-privileged after confirming you are root "
                 "on the target and no scored service listens there",
        )
    if mode not in MODES:
        raise util.CtfError(f"unknown honeypot mode {mode!r}",
                            hint="modes: " + ", ".join(MODES))
    if mode == "banner" and banner and banner.strip().lower() not in decoy.BANNER_PRESETS:
        if not 4 <= len(banner) <= 200:
            raise util.CtfError("a custom banner must be 4-200 characters")


def start(
    root: Optional[str] = None,
    *,
    port: int,
    mode: str = "http",
    bind: str = DEFAULT_BIND,
    banner: str = "",
    paths: Optional[List[str]] = None,
    allow_privileged: bool = False,
) -> Dict[str, Any]:
    root = root or util.repo_root()
    _validate(port, mode, bind, banner, allow_privileged)
    state = load_state(root)
    live = [item for item in state["listeners"] if _listener_alive(item)]
    state["listeners"] = live
    if len(live) >= MAX_LISTENERS:
        raise util.CtfError(
            f"{MAX_LISTENERS} honeypot listeners are already running: refusing to add more",
            hint="stop one first: ctfctl honeypot stop --port <PORT>",
        )
    if any(int(item.get("port") or 0) == int(port) for item in live):
        raise util.CtfError(f"a honeypot is already listening on port {port}")
    if not _port_free(bind, int(port)):
        raise util.CtfError(
            f"port {port} is already in use on {bind}: refusing to start",
            hint="a honeypot must never displace or shadow a scored service",
        )

    log_path = os.path.join(
        util.captures_dir(root=root),
        f"honeypot-{int(port)}-{util.utc_stamp()}.jsonl",
    )
    marker = util.short_id("honeypot", str(port), util.utc_stamp())
    argv = [
        sys.executable, "-m", "ctfctl.decoy", "--serve",
        "--port", str(int(port)),
        "--bind", bind,
        "--log", log_path,
        "--marker", marker,
        "--mode", mode,
    ]
    if mode == "banner":
        argv += ["--banner", banner]
    else:
        argv += ["--paths", ",".join(paths or decoy.DEFAULT_PATHS)]
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        + os.pathsep
        + env.get("PYTHONPATH", "")
    )
    proc = subprocess.Popen(
        argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        start_new_session=True,
    )
    time.sleep(1.0)
    if proc.poll() is not None:
        raise util.CtfError(
            f"the honeypot listener exited immediately on port {port}",
            hint=f"check for a bind error on {bind}:{port}",
        )
    if not _reachable(bind, int(port)):
        _terminate(proc.pid)
        raise util.CtfError(
            f"the honeypot process is alive but port {port} is not answering",
            hint="check the target's local firewall before trusting this honeypot",
        )
    entry = {
        "pid": proc.pid,
        "port": int(port),
        "bind": bind,
        "mode": mode,
        "banner": banner if mode == "banner" else "",
        "marker": marker,
        "log_path": os.path.relpath(log_path, root).replace(os.sep, "/"),
        "started_at": util.iso_now(),
    }
    state["listeners"] = live + [entry]
    _save_state(state, root)
    return entry


def _terminate(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not util.pid_alive(pid):
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def status(root: Optional[str] = None) -> Dict[str, Any]:
    root = root or util.repo_root()
    state = load_state(root)
    live: List[Dict[str, Any]] = []
    stale: List[Dict[str, Any]] = []
    for entry in state["listeners"]:
        if not _listener_alive(entry):
            stale.append({**entry, "state": "stopped"})
            continue
        live.append({**entry, "state": "running" if _reachable(
            str(entry.get("bind") or DEFAULT_BIND), int(entry.get("port") or 0)
        ) else "listening-socket-unreachable"})
    if stale:
        _save_state({"listeners": live}, root)
    return {
        "root": root,
        "running": live,
        "stopped": stale,
        "max_listeners": MAX_LISTENERS,
        "marker": "decoy events carry decoy=true",
    }


def _tail(path: str, lines: int) -> List[str]:
    if not os.path.isfile(path):
        return []
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > TAIL_BYTES:
            fh.seek(size - TAIL_BYTES)
        data = fh.read(TAIL_BYTES)
    text = data.decode("utf-8", "replace")
    return [line for line in text.splitlines()[-max(1, lines):]]


def logs(root: Optional[str] = None, *, lines: int = 50,
         port: Optional[int] = None) -> Dict[str, Any]:
    root = root or util.repo_root()
    state = load_state(root)
    out: List[Dict[str, Any]] = []
    for entry in state["listeners"]:
        if port and int(entry.get("port") or 0) != int(port):
            continue
        path = os.path.join(root, str(entry.get("log_path") or ""))
        out.append({
            "port": int(entry.get("port") or 0),
            "mode": entry.get("mode"),
            "log_path": str(entry.get("log_path") or ""),
            "running": _listener_alive(entry),
            "lines": _tail(path, lines),
        })
    return {"listeners": out}


def log_files(root: Optional[str] = None) -> List[str]:
    """Absolute paths of every honeypot log, for collection over ssh."""
    root = root or util.repo_root()
    files: List[str] = []
    for entry in load_state(root)["listeners"]:
        rel = str(entry.get("log_path") or "")
        path = os.path.join(root, rel)
        # Only paths this module created are ever returned.
        if rel.startswith("captures/") and os.path.isfile(path):
            files.append(path)
    return files


def stop(root: Optional[str] = None, *, port: Optional[int] = None,
         all_listeners: bool = False) -> Dict[str, Any]:
    root = root or util.repo_root()
    state = load_state(root)
    stopped: List[Dict[str, Any]] = []
    remaining: List[Dict[str, Any]] = []
    for entry in state["listeners"]:
        match = all_listeners or (port is not None and int(entry.get("port") or 0) == int(port))
        if not match:
            remaining.append(entry)
            continue
        if _listener_alive(entry):
            _terminate(int(entry["pid"]))
        stopped.append({**entry, "state": "stopped",
                        "alive_after": _listener_alive(entry)})
    _save_state({"listeners": remaining}, root)
    return {"root": root, "stopped": stopped, "remaining": remaining}


def summarize(payload: Dict[str, Any]) -> str:
    lines: List[str] = []
    running = payload.get("running") or []
    stopped = payload.get("stopped") or []
    if not running and not stopped:
        return ("no honeypot listeners. Start one with: ctfctl honeypot start --port <UNUSED_PORT> "
                "--mode http")
    for entry in running:
        mode = entry.get("mode") or "http"
        detail = f"banner={entry.get('banner')!r}" if mode == "banner" else "http lure"
        lines.append(
            f"running  port {entry.get('port')}  {mode}  bind {entry.get('bind')}"
            f"  {detail}  pid {entry.get('pid')}  state {entry.get('state')}"
        )
        lines.append(f"         log {entry.get('log_path')}")
    for entry in stopped:
        lines.append(f"stopped  port {entry.get('port')} (process gone)")
    lines.append("")
    lines.append("Hits are marked decoy=true. A honeypot is observation only: it must "
                 "never sit on a scored port.")
    return "\n".join(lines)


def logs_text(payload: Dict[str, Any], limit: int = 20) -> str:
    lines: List[str] = []
    for entry in payload.get("listeners") or []:
        lines.append(f"port {entry.get('port')} ({entry.get('mode')}) "
                     f"running={entry.get('running')} log={entry.get('log_path')}")
        for raw in entry.get("lines") or []:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                lines.append(f"  {util.printable(raw, 200)}")
                continue
            lines.append("  " + util.printable(
                f"{event.get('at')} {event.get('event')} {event.get('client', '')} "
                f"{event.get('path', event.get('preview', ''))} "
                f"{event.get('user_agent', '')}".strip(), 240))
        if not entry.get("lines"):
            lines.append("  (no events yet)")
    return "\n".join(lines) + ("" if lines else "no honeypot listeners")
