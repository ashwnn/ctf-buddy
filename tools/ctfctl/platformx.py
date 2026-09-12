"""Host capability detection with explicit degradation.

Everything in this module is read-only and offline. On non-Linux platforms the
functions return "unsupported" results instead of raising, so that `doctor`,
`discover` and `plan` can still produce an honest partial report.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import util

# Tools we care about, grouped by what their absence blocks.
TOOL_GROUPS: Dict[str, List[str]] = {
    "core": ["python3", "stat", "ps"],
    "inventory": ["ss", "lsof", "findmnt", "getent", "systemctl", "journalctl"],
    "network": ["ip", "nft", "iptables", "ufw", "firewall-cmd"],
    "containers": ["docker"],
    "capture": ["tcpdump", "tshark", "dumpcap"],
    "search": ["rg"],
    "web": ["curl", "openssl"],
    "metadata": ["getfacl", "setfacl"],
    "app": ["nginx", "php", "gunicorn", "python3"],
    "remote": ["ssh"],
}

TOOL_NOTES = {
    "ss": "listener inventory (fallback: /proc/net/tcp parsing)",
    "lsof": "port-to-process mapping (fallback: /proc/<pid>/fd)",
    "findmnt": "mount and filesystem inventory",
    "systemctl": "unit-to-process mapping and reload/restart actions",
    "journalctl": "service log observation",
    "nft": "nftables ruleset inspection and validation",
    "iptables": "legacy iptables ruleset inspection",
    "ufw": "Ubuntu firewall frontend state",
    "firewall-cmd": "firewalld runtime/permanent state",
    "docker": "container and Compose inventory",
    "tcpdump": "bounded packet capture",
    "tshark": "offline PCAP analysis",
    "rg": "literal/regex search fallback for the knowledge base",
    "getfacl": "ACL capture before mutation",
    "setfacl": "ACL restoration after rollback",
    "nginx": "reverse-proxy config validation",
    "php": "PHP syntax validation via php -l",
    "gunicorn": "Python WSGI service identification",
    "curl": "functional (tier 2/3) service checks",
    "ssh": "remote mode transport (OpenSSH client)",
}


@dataclass
class Capabilities:
    platform: str
    os_name: str
    is_linux: bool = False
    is_windows: bool = False
    is_macos: bool = False
    euid: int = -1
    is_root: bool = False
    has_proc: bool = False
    boot_id: str = ""
    init_system: str = "unknown"
    init_detail: str = ""
    python_version: str = ""
    sqlite_version: str = ""
    fts5: bool = False
    fts5_detail: str = ""
    fcntl_lock: bool = False
    pwd_grp: bool = False
    docker_socket: bool = False
    journal_readable: bool = False
    proc_visible: bool = False
    tools: Dict[str, bool] = field(default_factory=dict)
    tool_paths: Dict[str, str] = field(default_factory=dict)
    docker_compose: List[str] = field(default_factory=list)
    docker_compose_detail: str = ""
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "os_name": self.os_name,
            "is_linux": self.is_linux,
            "is_windows": self.is_windows,
            "is_macos": self.is_macos,
            "euid": self.euid,
            "is_root": self.is_root,
            "has_proc": self.has_proc,
            "boot_id": self.boot_id,
            "init_system": self.init_system,
            "init_detail": self.init_detail,
            "python_version": self.python_version,
            "sqlite_version": self.sqlite_version,
            "fts5": self.fts5,
            "fts5_detail": self.fts5_detail,
            "fcntl_lock": self.fcntl_lock,
            "pwd_grp": self.pwd_grp,
            "docker_socket": self.docker_socket,
            "journal_readable": self.journal_readable,
            "proc_visible": self.proc_visible,
            "tools": self.tools,
            "tool_paths": self.tool_paths,
            "docker_compose": self.docker_compose,
            "docker_compose_detail": self.docker_compose_detail,
            "limitations": self.limitations,
        }


def probe(quick: bool = False, system_root: str = "/") -> Capabilities:
    """Collect capability information. `quick=True` skips subprocess probes."""
    is_linux = sys.platform.startswith("linux")
    caps = Capabilities(
        platform=sys.platform,
        os_name=os.name,
        is_linux=is_linux,
        is_windows=os.name == "nt",
        is_macos=sys.platform == "darwin",
        python_version=sys.version.split()[0],
        euid=_euid(),
    )
    caps.is_root = caps.euid == 0

    proc_path = os.path.join(system_root, "proc") if system_root != "/" else "/proc"
    caps.has_proc = os.path.isdir(proc_path)
    if caps.has_proc:
        boot = os.path.join(proc_path, "sys/kernel/random/boot_id")
        try:
            with open(boot, "r", encoding="utf-8") as fh:
                caps.boot_id = fh.read().strip()
        except OSError:
            caps.boot_id = ""
    if not caps.has_proc:
        caps.limitations.append(
            "no /proc: process, listener and unit mapping is unavailable"
        )

    caps.init_system, caps.init_detail = _detect_init(proc_path)

    try:
        import sqlite3

        caps.sqlite_version = sqlite3.sqlite_version
        caps.fts5, caps.fts5_detail = _probe_fts5(sqlite3)
    except Exception as exc:  # pragma: no cover - defensive
        caps.fts5 = False
        caps.fts5_detail = f"sqlite3 import failed: {exc}"
        caps.limitations.append(
            "python sqlite3 module unavailable: knowledge-base index disabled"
        )

    try:
        import fcntl  # noqa: F401

        caps.fcntl_lock = True
    except Exception:
        caps.fcntl_lock = False
        caps.limitations.append(
            "fcntl unavailable: falling back to exclusive-create lock files (weaker on NFS)"
        )

    try:
        import pwd  # noqa: F401
        import grp  # noqa: F401

        caps.pwd_grp = True
    except Exception:
        caps.pwd_grp = False

    if not quick:
        for group, names in TOOL_GROUPS.items():
            for name in names:
                path = util.which(name)
                caps.tools[name] = path is not None
                if path:
                    caps.tool_paths[name] = path
        caps.docker_compose, caps.docker_compose_detail = _probe_compose()
        if caps.tools.get("docker"):
            for candidate in ("/var/run/docker.sock", "/run/docker.sock"):
                if os.path.exists(candidate):
                    caps.docker_socket = os.access(candidate, os.R_OK)
                    break
        caps.proc_visible = caps.has_proc and os.access(
            os.path.join(proc_path, "1"), os.R_OK
        )
        caps.journal_readable = _probe_journal()

    if not caps.is_linux:
        caps.limitations.append(
            "non-Linux platform: discovery reports an unsupported/read-only inventory; "
            "no host mutation is available"
        )
    elif not caps.is_root:
        caps.limitations.append(
            "running unprivileged: firewall, SSH config and other root-owned state may be unreadable"
        )
    if caps.is_linux and not caps.docker_socket and caps.tools.get("docker"):
        caps.limitations.append(
            "docker CLI present but the daemon socket is not readable: container inventory limited"
        )
    return caps


def _euid() -> int:
    if hasattr(os, "geteuid"):
        try:
            return int(os.geteuid())
        except OSError:
            return -1
    return -1


def _probe_fts5(sqlite3_module: Any) -> tuple:
    try:
        conn = sqlite3_module.connect(":memory:")
    except Exception as exc:
        return False, f"cannot open in-memory database: {exc}"
    try:
        try:
            conn.execute("CREATE VIRTUAL TABLE probe USING fts5(x)")
        except Exception as exc:
            return False, f"fts5 unavailable: {exc}"
        try:
            opts = [row[0] for row in conn.execute("PRAGMA compile_options")]
        except Exception:
            opts = []
        return True, "fts5 available" + (
            f" ({', '.join(o for o in opts if 'FTS' in o)})" if opts else ""
        )
    finally:
        conn.close()


def _detect_init(proc_path: str) -> tuple:
    comm_path = os.path.join(proc_path, "1", "comm") if proc_path else ""
    comm = ""
    if comm_path and os.path.isfile(comm_path):
        try:
            with open(comm_path, "r", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            comm = ""
    if comm == "systemd" or os.path.isdir("/run/systemd/system"):
        detail = "systemd"
        if util.which("systemctl"):
            res = util.run(["systemctl", "--version"], timeout=5, max_output=4096)
            if res.ok:
                detail = "systemd: " + res.stdout.splitlines()[0].strip()
        return "systemd", detail
    if comm:
        return "other", f"PID 1 is '{comm}'"
    if os.name == "nt":
        return "unsupported", "no /proc/PID/1 on this platform"
    return "unknown", "could not identify PID 1"


def _probe_journal() -> bool:
    """Can we read another service's journal entries?"""
    if not util.which("journalctl"):
        return False
    res = util.run(
        ["journalctl", "-n", "1", "--no-pager", "--output", "cat"],
        timeout=8,
        max_output=8192,
    )
    return res.ok


def _probe_compose() -> tuple:
    if not util.which("docker"):
        return [], "docker not installed"
    res = util.run(["docker", "compose", "version", "--short"], timeout=10)
    if res.ok and res.stdout.strip():
        return ["docker", "compose"], f"docker compose {res.stdout.strip()}"
    res = util.run(["docker-compose", "version", "--short"], timeout=10)
    if res.ok and res.stdout.strip():
        return ["docker-compose"], f"docker-compose {res.stdout.strip()}"
    return [], "docker compose plugin not available"


def summary_lines(caps: Capabilities) -> List[str]:
    lines = [
        f"platform            {caps.platform}  (linux={caps.is_linux} root={caps.is_root} "
        f"euid={caps.euid})",
        f"init                {caps.init_system}  {caps.init_detail}",
        f"python / sqlite     {caps.python_version} / {caps.sqlite_version}",
        f"fts5 index          {'available' if caps.fts5 else 'UNAVAILABLE'}  {caps.fts5_detail}",
        f"file locking        {'fcntl.flock' if caps.fcntl_lock else 'exclusive-create fallback'}",
        f"containers          {caps.docker_compose_detail}",
    ]
    missing = [name for name, ok in sorted(caps.tools.items()) if not ok]
    if missing:
        lines.append("missing tools       " + ", ".join(missing))
    for note in caps.limitations:
        lines.append(f"LIMITATION          {note}")
    return lines
