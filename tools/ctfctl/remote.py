"""Remote operation over SSH: the transport the rest of the toolkit lacks.

Design rules:
  * `ssh` is the only transport. No passwords are stored, no keys are copied,
    no server is modified to accept us. Key/agent auth is used when available,
    and an interactive prompt is allowed when the caller has a terminal.
  * Host strings are validated against a strict pattern before they ever reach
    an argv: a hostname is data, never a shell fragment.
  * Remote shell commands are fixed constants. Where an argument must be
    interpolated (a validated profile id, a plan id, an absolute path) each
    argument is shell-quoted with shlex and originates from our own state.
  * The remote engine is this same toolkit, uploaded to ~/.ctfctl. That keeps
    one mutation implementation with one set of backups, locks and rollbacks.
  * Read-only work can run with zero remote dependencies (a POSIX shell probe).
    Anything that mutates or explores content needs python3 on the target and
    says so honestly when it is missing.

Everything a user sees here is bounded: output caps, input caps, timeouts and
a hard refusal to follow a host string into option territory.
"""

from __future__ import annotations

import base64
import getpass
import gzip
import io
import json
import os
import re
import shlex
import sys
import tarfile
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import files as files_mod
from . import util

SCHEMA = "ctfctl.remote-probe/1"
REMOTE_DIRNAME = ".ctfctl"
REMOTE_VERSION_FILE = "CTFCTL_VERSION"
STATE_DIRNAME = "remote"
PROBE_TIMEOUT = 120.0
INSTALL_TIMEOUT = 240.0
DEFAULT_REMOTE_TIMEOUT = 60.0
PROBE_MAX_OUTPUT = 1024 * 1024
REMOTE_MAX_OUTPUT = 512 * 1024

#: Read-only ctfctl subcommands that `remote run` may proxy.
READ_ONLY_SUBCOMMANDS = (
    "doctor",
    "discover",
    "plan",
    "verify",
    "watch",
    "files",
    "profiles",
    "kb",
    "recover",
)

Runner = Callable[..., util.ProcResult]


# --------------------------------------------------------------------------
# Connection model
# --------------------------------------------------------------------------
@dataclass
class Conn:
    host: str
    user: str = ""
    port: Optional[int] = None
    identity: str = ""
    timeout: float = DEFAULT_REMOTE_TIMEOUT

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    @property
    def slug(self) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_") or "host"


_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")
_IPV6_RE = re.compile(r"^\[[0-9A-Fa-f:]{2,45}\]$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")


def parse_host(value: str, *, user: str = "", port: Optional[int] = None) -> Conn:
    """Parse `[user@]host[:port]` with a strict allowlist. Raises UsageError."""
    if not value or len(value) > 300:
        raise util.UsageError("a host is required (example: 10.10.5.3)")
    raw = value.strip()
    if raw.startswith("-") or any(ch in raw for ch in " \t\r\n'\"`$;&|<>(){}!\\*?"):
        raise util.UsageError(
            f"refusing host {value!r}: only letters, digits, dots, colons, at-signs, "
            "hyphens, underscores and IPv6 brackets are allowed",
        )
    inline_user = ""
    if "@" in raw:
        inline_user, raw = raw.split("@", 1)
        if not _USER_RE.match(inline_user):
            raise util.UsageError(f"refusing user {inline_user!r}")
    inline_port: Optional[int] = None
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0 or not _IPV6_RE.match(raw[: end + 1]):
            raise util.UsageError(f"refusing IPv6 host {value!r}")
        rest = raw[end + 1 :]
        if rest:
            if not rest.startswith(":") or not _PORT_RE.match(rest[1:]):
                raise util.UsageError(f"refusing port suffix in {value!r}")
            inline_port = int(rest[1:])
        host = raw[: end + 1]
    else:
        host = raw
        if ":" in raw:
            host, _, port_text = raw.rpartition(":")
            if not _PORT_RE.match(port_text):
                raise util.UsageError(f"refusing port in {value!r}")
            inline_port = int(port_text)
        if not _HOST_RE.match(host):
            raise util.UsageError(f"refusing host {host!r}")
    chosen_port = port if port is not None else inline_port
    if chosen_port is not None and not (1 <= chosen_port <= 65535):
        raise util.UsageError(f"port {chosen_port} is outside 1-65535")
    return Conn(host=host, user=user or inline_user, port=chosen_port, identity="")


# --------------------------------------------------------------------------
# SSH execution
# --------------------------------------------------------------------------
def _default_runner(
    argv: Sequence[str], *, input_text: Optional[str], timeout: float, max_output: int
) -> util.ProcResult:
    return util.run(
        list(argv), input_text=input_text, timeout=timeout, max_output=max_output
    )


#: Tests replace this to exercise command construction without a network.
SSH_RUNNER: Runner = _default_runner


def ssh_argv(
    conn: Conn,
    remote_command: Optional[str] = None,
    *,
    batch: Optional[bool] = None,
    tty: bool = False,
) -> List[str]:
    if batch is None:
        batch = not sys.stdin.isatty()
    argv = [
        "ssh",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "BatchMode=" + ("yes" if batch else "no"),
    ]
    if conn.port:
        argv += ["-p", str(conn.port)]
    if conn.identity:
        argv += ["-i", conn.identity]
    if tty:
        argv += ["-t"]
    argv += [conn.target]
    if remote_command is not None:
        argv += [remote_command]
    return argv


def _ssh_result(
    conn: Conn,
    remote_command: str,
    *,
    input_text: Optional[str] = None,
    timeout: Optional[float] = None,
    max_output: int = REMOTE_MAX_OUTPUT,
    what: str = "command",
) -> util.ProcResult:
    """Run remote_command and return the result. Only transport failures raise.

    Exit code 1 is a normal "expected negative result" all over this toolkit
    (a plan with no match, a refused mutation), so it is preserved for callers.
    """
    argv = ssh_argv(conn, remote_command)
    result = SSH_RUNNER(
        argv,
        input_text=input_text,
        timeout=timeout or conn.timeout,
        max_output=max_output,
    )
    if result.unavailable:
        raise util.CtfError(
            "ssh is not available on this machine",
            hint="install an OpenSSH client (Arch: pacman -S openssh) and retry",
        )
    if result.timed_out:
        raise util.CtfError(
            f"ssh {what} to {conn.target} timed out after {result.duration_s:.0f}s",
            hint="check reachability, then raise the limit with --timeout",
        )
    if result.returncode == 255:
        detail = util.redact(result.stderr.strip())[-400:]
        raise util.CtfError(
            f"ssh could not connect to {conn.target}: {detail or 'connection failed'}",
            hint="verify the address and that your key/agent is unlocked; "
            "nothing is retried automatically",
        )
    return result


def _ssh(
    conn: Conn,
    remote_command: str,
    *,
    input_text: Optional[str] = None,
    timeout: Optional[float] = None,
    max_output: int = REMOTE_MAX_OUTPUT,
    what: str = "command",
) -> util.ProcResult:
    result = _ssh_result(
        conn,
        remote_command,
        input_text=input_text,
        timeout=timeout,
        max_output=max_output,
        what=what,
    )
    if result.returncode not in (0, 1):
        detail = util.redact(result.stderr.strip())[-400:]
        raise util.CtfError(
            f"remote {what} failed on {conn.target} (exit {result.returncode}): "
            f"{detail or 'no stderr'}",
        )
    return result


def _remote_ctfctl(
    conn: Conn,
    args: Sequence[str],
    *,
    timeout: Optional[float] = None,
    max_output: int = REMOTE_MAX_OUTPUT,
    input_text: Optional[str] = None,
) -> util.ProcResult:
    quoted = " ".join(shlex.quote(str(a)) for a in args)
    command = (
        f'cd "$HOME/{REMOTE_DIRNAME}" && PYTHONPATH=tools python3 -m ctfctl {quoted}'
    )
    return _ssh(
        conn,
        command,
        input_text=input_text,
        timeout=timeout,
        max_output=max_output,
        what="ctfctl " + (args[0] if args else "run"),
    )


def _maybe_json(text: str) -> Optional[Dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return None
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        payload = json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


# --------------------------------------------------------------------------
# Remote toolkit bundle
# --------------------------------------------------------------------------
def toolkit_files(root: Optional[str] = None) -> List[Tuple[str, str]]:
    """(archive name, local path) pairs for the self-contained remote toolkit."""
    root = root or util.repo_root()
    pairs: List[Tuple[str, str]] = []
    tools = os.path.join(root, "tools", "ctfctl")
    for name in sorted(os.listdir(tools)):
        if name.endswith(".py"):
            pairs.append(("tools/ctfctl/" + name, os.path.join(tools, name)))
    profiles = os.path.join(root, "profiles")
    if os.path.isdir(profiles):
        for name in sorted(os.listdir(profiles)):
            if name.endswith(".json"):
                pairs.append(("profiles/" + name, os.path.join(profiles, name)))
    return pairs


def toolkit_fingerprint(root: Optional[str] = None) -> str:
    parts: List[str] = []
    for name, path in toolkit_files(root):
        parts.append(name)
        parts.append(util.sha256_file(path))
    return util.sha256_text("\n".join(parts))[:16]


def build_bundle(root: Optional[str] = None) -> bytes:
    """Deterministic gzipped tar of the remote toolkit.

    ``tarfile`` mode ``w:gz`` stamps the wall-clock time into the gzip header,
    so the same tree would hash differently from second to second. The gzip
    layer is therefore opened explicitly with ``mtime=0``.
    """
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w:", format=tarfile.PAX_FORMAT) as tar:
            marker = (
                "ctfctl remote toolkit root\n"
                "Generated by `ctfctl remote install`; this directory is disposable and can be\n"
                "re-uploaded at any time. Runtime state lives in ./state/ and is never pushed back.\n"
            ).encode("utf-8")
            info = tarfile.TarInfo("AGENTS.md")
            info.size = len(marker)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(marker))
            for name, path in toolkit_files(root):
                info = tar.gettarinfo(path, arcname=name)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
    return buf.getvalue()


def _remote_version(conn: Conn) -> str:
    result = SSH_RUNNER(
        ssh_argv(
            conn, f'cat "$HOME/{REMOTE_DIRNAME}/{REMOTE_VERSION_FILE}" 2>/dev/null'
        ),
        input_text=None,
        timeout=conn.timeout,
        max_output=4096,
    )
    return (result.stdout or "").strip() if result.returncode == 0 else ""


def install(
    conn: Conn, *, root: Optional[str] = None, force: bool = False
) -> Dict[str, Any]:
    """Upload the toolkit to ~/.ctfctl. Idempotent when the fingerprint matches."""
    fingerprint = toolkit_fingerprint(root)
    existing = _remote_version(conn)
    if existing == fingerprint and not force:
        return {
            "host": conn.target,
            "installed": False,
            "reason": "already current",
            "fingerprint": fingerprint,
        }
    bundle = build_bundle(root)
    encoded = base64.b64encode(bundle).decode("ascii")
    command = (
        f'mkdir -p "$HOME/{REMOTE_DIRNAME}" && '
        f'base64 -d | tar -xzf - -C "$HOME/{REMOTE_DIRNAME}" && '
        f"printf '%s\\n' {shlex.quote(fingerprint)} > "
        f'"$HOME/{REMOTE_DIRNAME}/{REMOTE_VERSION_FILE}"'
    )
    try:
        result = SSH_RUNNER(
            ssh_argv(conn, command),
            input_text=encoded,
            timeout=INSTALL_TIMEOUT,
            max_output=64 * 1024,
        )
    except TypeError:  # a runner that does not take input_text
        raise util.CtfError("the ssh runner cannot stream the toolkit bundle")
    if result.unavailable:
        raise util.CtfError(
            "ssh is not available on this machine",
            hint="install an OpenSSH client and retry",
        )
    if result.timed_out:
        raise util.CtfError(f"uploading the toolkit to {conn.target} timed out")
    if result.returncode != 0:
        detail = util.redact(result.stderr.strip())[-400:]
        raise util.CtfError(
            f"toolkit upload to {conn.target} failed: {detail or 'unknown error'}",
            hint="the target needs a POSIX shell with base64 and tar; "
            "python3 is required for plan/apply/files",
        )
    return {
        "host": conn.target,
        "installed": True,
        "fingerprint": fingerprint,
        "bytes": len(bundle),
    }


def ensure_toolkit(conn: Conn, *, root: Optional[str] = None) -> Dict[str, Any]:
    return install(conn, root=root)


def _prepare(conn: Conn, *, root: Optional[str] = None) -> Dict[str, Any]:
    """Everything the remote engine needs: uploaded toolkit plus python3."""
    state = ensure_toolkit(conn, root=root)
    _ensure_python3(conn)
    return state


def _ensure_python3(conn: Conn) -> str:
    result = SSH_RUNNER(
        ssh_argv(conn, "command -v python3 2>/dev/null"),
        input_text=None,
        timeout=conn.timeout,
        max_output=4096,
    )
    version = (result.stdout or "").strip()
    if result.returncode != 0 or not version:
        raise util.CtfError(
            f"python3 is not installed on {conn.target}",
            hint="the read-only `remote probe` works without it; for plan/apply/files "
            "install python3 on the target or copy the toolkit and run it there",
        )
    return version


# --------------------------------------------------------------------------
# Read-only probe (no remote python required)
# --------------------------------------------------------------------------
PROBE_SCRIPT = r"""
have_timeout=0
command -v timeout >/dev/null 2>&1 && have_timeout=1
run10() {
  if [ "$have_timeout" = 1 ]; then timeout 10 "$@" 2>/dev/null || true; else "$@" 2>/dev/null || true; fi
}
section() { printf '###ctfctl:%s###\n' "$1"; }

section meta
printf '__user=%s\n' "$(id -un 2>/dev/null || whoami 2>/dev/null || echo unknown)"
printf '__uid=%s\n' "$(id -u 2>/dev/null || echo unknown)"
printf '__hostname=%s\n' "$(hostname 2>/dev/null || echo unknown)"
printf '__kernel=%s\n' "$(uname -srmo 2>/dev/null || uname -a 2>/dev/null || echo unknown)"

section os-release
cat /etc/os-release 2>/dev/null | head -n 30
cat /etc/lsb-release 2>/dev/null | head -n 10

section init
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  printf '__init=systemd\n'
else
  printf '__init=other\n'
fi
cat /proc/1/comm 2>/dev/null | head -n 1

section listeners
if command -v ss >/dev/null 2>&1; then
  printf '__tool=ss\n'
  run10 ss -lntup
elif command -v netstat >/dev/null 2>&1; then
  printf '__tool=netstat\n'
  run10 netstat -lntup
else
  printf '__tool=proc\n'
  printf '###tcp###\n'
  cat /proc/net/tcp 2>/dev/null | head -n 200
  printf '###tcp6###\n'
  cat /proc/net/tcp6 2>/dev/null | head -n 200
fi

section processes
run10 ps axww -o pid,ppid,user,etime,args | head -n 400

section services
if command -v systemctl >/dev/null 2>&1; then
  run10 systemctl list-units --type=service --state=running --no-legend --no-pager | head -n 200
  run10 systemctl list-timers --no-legend --no-pager | head -n 50
fi

section containers
if command -v docker >/dev/null 2>&1; then
  printf '__docker=present\n'
  run10 docker ps --no-trunc --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}|{{.Status}}' | head -n 60
  run10 docker compose ls --format json | head -n 20
else
  printf '__docker=absent\n'
fi
if command -v podman >/dev/null 2>&1; then
  printf '__podman=present\n'
  run10 podman ps --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}|{{.Status}}' | head -n 60
else
  printf '__podman=absent\n'
fi
printf '__cgroup=%s\n' "$(head -n 1 /proc/1/cgroup 2>/dev/null || echo unknown)"

section compose-files
run10 find /opt /srv /var/www /home -maxdepth 4 \
  \( -name 'docker-compose.y*ml' -o -name 'compose.y*ml' \) -type f 2>/dev/null | head -n 40

section web-roots
for d in /var/www /srv/www /opt /srv /usr/share/nginx /etc/nginx; do
  [ -d "$d" ] && ls -ld "$d" 2>/dev/null
done
ls -l /etc/nginx/sites-enabled 2>/dev/null | head -n 40
ls -l /etc/nginx/conf.d 2>/dev/null | head -n 40
command -v nginx >/dev/null 2>&1 && nginx -v 2>&1 | head -n 1
if command -v apache2 >/dev/null 2>&1; then
  apache2 -v 2>&1 | head -n 2
elif command -v httpd >/dev/null 2>&1; then
  httpd -v 2>&1 | head -n 2
fi
php -v 2>/dev/null | head -n 1

section firewall
if command -v nft >/dev/null 2>&1; then
  printf '__nft=present\n'
  run10 nft list ruleset | head -n 150
else
  printf '__nft=absent\n'
fi
if command -v iptables >/dev/null 2>&1; then
  printf '__iptables=present\n'
  run10 iptables -S | head -n 100
else
  printf '__iptables=absent\n'
fi
command -v ufw >/dev/null 2>&1 && ufw status verbose 2>/dev/null | head -n 30
command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null

section scheduled
crontab -l 2>/dev/null | head -n 100
ls -l /etc/cron.d /etc/crontab 2>/dev/null | head -n 60

section resources
run10 df -hP | head -n 30
free -m 2>/dev/null | head -n 5
uptime 2>/dev/null
printf 'nproc=%s\n' "$(nproc 2>/dev/null || echo unknown)"

section python
printf '__python3=%s\n' "$(command -v python3 2>/dev/null || echo absent)"
python3 -V 2>&1 | head -n 1

section end
"""


_SECTION_RE = re.compile(r"^###ctfctl:([a-z0-9-]+)###$")


def _split_sections(text: str) -> Dict[str, Dict[str, Any]]:
    sections: Dict[str, Dict[str, Any]] = {}
    current: Optional[Dict[str, Any]] = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        match = _SECTION_RE.match(line.strip())
        if match:
            current = {"meta": {}, "lines": []}
            sections[match.group(1)] = current
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("__") and "=" in stripped:
            key, _, value = stripped.partition("=")
            current["meta"][key[2:]] = util.printable(value, 200)
            continue
        if stripped:
            current["lines"].append(util.printable(line, 1000))
    return sections


_SS_USER_RE = re.compile(r'\("([^"]+)",pid=(\d+)')
_ADDR_RE = re.compile(r"^(\[?[0-9A-Fa-f:.*]+\]?):(\d+)$")


def _split_address(value: str) -> Tuple[str, Optional[int]]:
    value = value.strip()
    if not value:
        return "", None
    match = _ADDR_RE.match(value)
    if not match:
        return value, None
    return match.group(1), int(match.group(2))


def _parse_ss_listeners(lines: Sequence[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        local = next((p for p in parts[3:5] if ":" in p), "")
        address, port = _split_address(local)
        if port is None:
            continue
        users = _SS_USER_RE.findall(line)
        process = users[0][0] if users else ""
        pid = int(users[0][1]) if users else 0
        out.append(
            {
                "proto": parts[0][:3],
                "address": address or "*",
                "port": port,
                "process": util.printable(process, 80),
                "pid": pid,
                "evidence": "ss -lntup",
            }
        )
    return out


def _parse_netstat_listeners(lines: Sequence[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or not parts[0].startswith(("tcp", "udp")):
            continue
        local = next((p for p in parts if _ADDR_RE.match(p)), "")
        if not local:
            continue
        address, port = _split_address(local)
        if port is None:
            continue
        process = ""
        pid = 0
        tail = parts[-1]
        match = re.match(r"^(\d+)/(.+)$", tail)
        if match:
            pid, process = int(match.group(1)), match.group(2)
        out.append(
            {
                "proto": parts[0][:3],
                "address": address or "*",
                "port": port,
                "process": util.printable(process, 80),
                "pid": pid,
                "evidence": "netstat -lntup",
            }
        )
    return out


def _decode_proc_addr(hex_address: str, v6: bool) -> str:
    if not v6:
        raw = bytes.fromhex(hex_address)
        if len(raw) != 4:
            return hex_address
        return ".".join(str(b) for b in reversed(raw))
    groups = [hex_address[i : i + 8] for i in range(0, len(hex_address), 8)]
    if len(groups) != 4:
        return hex_address
    words = []
    for group in groups:
        raw = bytes.fromhex(group)
        words.extend(f"{raw[i + 1]:02x}{raw[i]:02x}" for i in range(0, len(raw), 2))
    return ":".join(words)


def _parse_proc_listeners(sections: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    listeners = sections.get("listeners", {"lines": []})
    mode = "tcp"
    for line in listeners["lines"]:
        if line.startswith("###tcp6###"):
            mode = "tcp6"
            continue
        if line.startswith("###tcp###"):
            mode = "tcp"
            continue
        parts = line.split()
        if len(parts) < 4 or parts[0] == "sl":
            continue
        try:
            local, port_hex = parts[1].split(":")
            state = parts[3]
        except ValueError:
            continue
        if state.upper() != "0A":
            continue
        out.append(
            {
                "proto": "tcp",
                "address": _decode_proc_addr(local, mode == "tcp6"),
                "port": int(port_hex, 16),
                "process": "",
                "pid": 0,
                "evidence": "proc_net",
            }
        )
    return out


def _parse_processes(lines: Sequence[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in lines:
        parts = line.split(None, 5)
        if len(parts) < 4:
            continue
        pid = parts[0]
        if not pid.isdigit():
            continue
        args = parts[5] if len(parts) > 5 else ""
        out.append(
            {
                "pid": int(pid),
                "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                "user": util.printable(parts[2], 64),
                "etime": util.printable(parts[3], 32),
                "command": util.redact(util.printable(args, 300)),
            }
        )
    return out


def _parse_containers(lines: Sequence[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in lines:
        parts = line.split("|")
        if len(parts) < 3:
            continue
        out.append(
            {
                "id": util.printable(parts[0], 32),
                "image": util.printable(parts[1], 160),
                "names": util.printable(parts[2], 160),
                "ports": util.printable(parts[3] if len(parts) > 3 else "", 200),
                "status": util.printable(parts[4] if len(parts) > 4 else "", 120),
            }
        )
    return out


def parse_probe(text: str, *, host: str = "") -> Dict[str, Any]:
    """Parse the probe script output into a bounded, redacted inventory."""
    sections = _split_sections(text)
    meta = sections.get("meta", {}).get("meta", {})
    os_release = list(sections.get("os-release", {}).get("lines", []))
    init = sections.get("init", {})
    listeners_section = sections.get("listeners", {"meta": {}, "lines": []})
    tool = str(listeners_section.get("meta", {}).get("tool") or "")
    if tool == "ss":
        listeners = _parse_ss_listeners(listeners_section.get("lines", []))
    elif tool == "netstat":
        listeners = _parse_netstat_listeners(listeners_section.get("lines", []))
    elif tool == "proc":
        listeners = _parse_proc_listeners(sections)
    else:
        listeners = []
    processes = _parse_processes(sections.get("processes", {}).get("lines", []))
    containers = _parse_containers(sections.get("containers", {}).get("lines", []))
    services = list(sections.get("services", {}).get("lines", []))
    compose_files = [
        util.redact(l) for l in sections.get("compose-files", {}).get("lines", [])
    ]
    web_roots = [util.redact(l) for l in sections.get("web-roots", {}).get("lines", [])]
    firewall_meta = sections.get("firewall", {}).get("meta", {})
    firewall_lines = [
        util.redact(l) for l in sections.get("firewall", {}).get("lines", [])
    ]
    scheduled = [util.redact(l) for l in sections.get("scheduled", {}).get("lines", [])]
    resources = list(sections.get("resources", {}).get("lines", []))
    python_lines = sections.get("python", {})
    python_meta = python_lines.get("meta", {}) if isinstance(python_lines, dict) else {}

    user = str(meta.get("user") or "unknown")
    gaps: List[str] = []
    if not listeners and tool in ("", "proc"):
        gaps.append(
            "no listener evidence: ss/netstat absent and /proc/net/tcp unreadable "
            "(run as root or install iproute2)"
        )
    elif not listeners:
        gaps.append("no TCP/UDP listeners were reported by the target")
    if user not in ("root", "0"):
        gaps.append(
            "probe ran unprivileged: listener process attribution and some service files "
            "may be missing; that is reported as a gap, not guessed"
        )
    if not processes:
        gaps.append(
            "no process list: ps is missing or does not accept the probe's option set; "
            "listener-to-process mapping may be incomplete"
        )
    if init.get("meta", {}).get("init") == "other":
        gaps.append("systemd not detected: unit-to-service mapping is unavailable")
    if not services:
        gaps.append("no running systemd services were listed")
    if not compose_files:
        gaps.append("no compose files found in the bounded search roots")

    container_meta = sections.get("containers", {}).get("meta", {})
    notes: List[str] = []
    if container_meta.get("docker") == "absent":
        notes.append("docker CLI not present; container inventory is inherently empty")
    if container_meta.get("podman") == "absent":
        notes.append("podman CLI not present")
    if (
        firewall_meta.get("nft") == "absent"
        and firewall_meta.get("iptables") == "absent"
    ):
        gaps.append(
            "neither nft nor iptables available: firewall state is unknown, not empty"
        )

    web_roots_note = "path list only; file contents are never dumped by the probe"
    payload: Dict[str, Any] = {
        "schema": SCHEMA,
        "host": host,
        "retrieved_at": util.iso_now(),
        "identity": {
            "user": util.printable(user, 64),
            "uid": str(meta.get("uid") or "unknown"),
            "hostname": util.printable(str(meta.get("hostname") or "unknown"), 120),
            "kernel": util.printable(str(meta.get("kernel") or "unknown"), 200),
            "os_release": os_release[:20],
            "init": init.get("meta", {}).get("init") or "unknown",
            "python3": util.printable(str(python_meta.get("python3") or "absent"), 200),
        },
        "listeners": listeners[:300],
        "processes": processes[:400],
        "services": [util.redact(s) for s in services[:200]],
        "containers": containers[:60],
        "compose_files": compose_files[:40],
        "web_roots": web_roots[:80],
        "web_roots_note": web_roots_note,
        "firewall_lines": firewall_lines[:200],
        "scheduled": scheduled[:120],
        "resources": resources[:80],
        "gaps": gaps,
        "notes": notes,
        "limitations": [
            "read-only: nothing on the target was changed by this probe",
            "a listening port is not a confirmed stack; the plan step adds stack evidence",
            "process and service lists are bounded and may be truncated",
        ],
    }
    return payload


def summarize_probe(payload: Dict[str, Any]) -> str:
    identity = payload.get("identity", {})
    lines = [
        f"host        {payload.get('host')}  ({identity.get('hostname', '?')})",
        f"os          {identity.get('os_release', ['?'])[0] if identity.get('os_release') else '?'}",
        f"kernel      {identity.get('kernel', '?')}",
        f"user        {identity.get('user', '?')} (uid {identity.get('uid', '?')})  "
        f"init={identity.get('init', '?')}  python3={identity.get('python3', '?')}",
        f"listeners   {len(payload.get('listeners', []))} "
        f"containers={len(payload.get('containers', []))} "
        f"services={len(payload.get('services', []))}",
    ]
    for listener in payload.get("listeners", [])[:40]:
        process = listener.get("process") or "?"
        pid = f" pid={listener['pid']}" if listener.get("pid") else ""
        lines.append(
            f"  {listener.get('proto', '?'):4} {listener.get('address', '?'):<24}"
            f":{listener.get('port', '?'):<6} {process}{pid}"
        )
    if len(payload.get("listeners", [])) > 40:
        lines.append(f"  ... {len(payload['listeners']) - 40} more listeners")
    for path in payload.get("compose_files", [])[:10]:
        lines.append(f"compose     {path}")
    for root in payload.get("web_roots", [])[:10]:
        lines.append(f"web         {root}")
    for gap in payload.get("gaps", []):
        lines.append(f"gap         {gap}")
    for note in payload.get("notes", []):
        lines.append(f"note        {note}")
    return "\n".join(lines)


def render_plan(entry: Dict[str, Any], *, verbose: bool = False) -> str:
    """Human rendering of a plan JSON document pulled from a remote host."""
    authorization = entry.get("authorization") or {}
    detection = entry.get("detection") or {}
    facts = detection.get("facts") or {}
    fingerprint = entry.get("host_fingerprint") or {}
    lines = [
        f"plan        {entry.get('plan_id', '?')}",
        f"profile     {entry.get('profile', '?')} "
        f"(support={entry.get('profile_support_level', '?')})",
        f"created     {entry.get('created_at', '?')}",
        f"host        {fingerprint.get('os_id') or '?'} / "
        f"{fingerprint.get('init_system') or '?'}",
        f"authorized  {authorization.get('scope', '?')} "
        f"allows_mutation={authorization.get('allows_mutation')}",
        f"policy      acknowledged={authorization.get('policy_acknowledged')}",
        f"matched     {detection.get('matched')}",
    ]
    if facts:
        likely = ", ".join(
            f"{k}={v}"
            for k, v in sorted(facts.items())[:8]
            if isinstance(v, (str, int, bool))
        )
        if likely:
            lines.append(f"facts       {likely}")
    for reason in detection.get("reasons", [])[:10]:
        lines.append(f"  reason    {util.printable(str(reason), 220)}")
    auto = [a for a in entry.get("actions", []) if a.get("eligibility") == "auto"]
    review = [
        a
        for a in entry.get("actions", [])
        if a.get("eligibility") not in (None, "auto")
    ]
    if not auto and not review:
        lines.append("actions     none")
    for label, group in (("auto", auto), ("review", review)):
        for action in group:
            lines.append("")
            lines.append(
                f"[{label}] {action.get('key', '?')}  ({action.get('action_id', '?')})"
            )
            if action.get("target_path"):
                lines.append(f"  target    {action['target_path']}")
            for note in action.get("notes", [])[:6]:
                lines.append(f"  note      {util.printable(str(note), 240)}")
            if action.get("skipped_reason"):
                lines.append(
                    f"  SKIPPED   {util.printable(str(action['skipped_reason']), 240)}"
                )
            diff = str(action.get("diff") or "")
            if diff:
                lines.append("  diff:")
                diff_lines = diff.splitlines()
                shown = diff_lines if verbose else diff_lines[:80]
                for diff_line in shown:
                    lines.append("    " + util.printable(diff_line, 300))
                if len(diff_lines) > len(shown):
                    lines.append(
                        f"    ... {len(diff_lines) - len(shown)} more diff lines "
                        "(use --verbose)"
                    )
    for item in entry.get("skipped", [])[:20]:
        lines.append(
            f"skipped     {item.get('key', '?')}: "
            f"{util.printable(str(item.get('reason', '')), 240)}"
        )
    for verifier in entry.get("verifiers", [])[:10]:
        lines.append(
            f"verifier    [{verifier.get('tier', '?')}] "
            f"{verifier.get('description') or verifier.get('verifier', '?')}"
        )
    probe = entry.get("exploit_probe") or {}
    if probe:
        lines.append(
            f"probe       [exploit] {probe.get('description') or probe.get('verifier', '?')}"
        )
    rollback = entry.get("rollback") or {}
    if rollback:
        text = (
            rollback.get("description")
            or rollback.get("notes")
            or util.dump_json(rollback)
        )
        lines.append(f"rollback    {util.printable(str(text), 300)}")
    for risk in entry.get("risks", [])[:15]:
        lines.append(f"risk        {util.printable(str(risk), 260)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Targets and policy (local declarations gate every mutation)
# --------------------------------------------------------------------------
TARGETS_REL = os.path.join("state", "targets.json")
POLICY_REL = os.path.join("state", "policy.json")


def targets_path(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), TARGETS_REL)


def policy_path(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), POLICY_REL)


def load_targets(root: Optional[str] = None) -> List[Dict[str, Any]]:
    payload = util.load_json(targets_path(root), {})
    if isinstance(payload, dict):
        items = payload.get("targets") or []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []
    return [item for item in items if isinstance(item, dict)]


def is_policy_acknowledged(root: Optional[str] = None) -> bool:
    payload = util.load_json(policy_path(root), {})
    return bool(isinstance(payload, dict) and payload.get("acknowledged"))


def find_declaration(host: str, root: Optional[str] = None) -> Optional[Dict[str, Any]]:
    wanted = host.strip().lower()
    for item in load_targets(root):
        candidates = [
            str(item.get("host") or "").lower(),
            str(item.get("hostname") or "").lower(),
        ]
        if wanted and wanted in candidates:
            return item
    return None


def require_declaration(host: str, root: Optional[str] = None) -> Dict[str, Any]:
    declaration = find_declaration(host, root)
    if declaration:
        return declaration
    raise util.CtfError(
        f"target {host} is not declared as team-owned",
        hint=f"declare it first: ctfctl targets declare {host} --label '<what it is>' "
        "(add --ack-policy once you have confirmed the event rules)",
    )


def declare_target(
    host: str,
    *,
    label: str,
    role: str = "vulnbox",
    notes: str = "",
    ack_policy: bool = False,
    root: Optional[str] = None,
) -> Dict[str, Any]:
    root = root or util.repo_root()
    host = host.strip()
    if not host:
        raise util.UsageError("a host is required")
    payload = util.load_json(targets_path(root), {})
    items: List[Dict[str, Any]] = []
    if isinstance(payload, dict) and isinstance(payload.get("targets"), list):
        items = [i for i in payload["targets"] if isinstance(i, dict)]
    elif isinstance(payload, list):
        items = [i for i in payload if isinstance(i, dict)]
    record = {
        "host": host,
        "label": label or host,
        "role": role,
        "declared_at": util.iso_now(),
        "declared_by": getpass.getuser() or "unknown",
        "notes": util.redact(notes, redact_flags=False),
    }
    replaced = False
    for index, item in enumerate(items):
        if str(item.get("host") or "").lower() == host.lower():
            items[index] = record
            replaced = True
            break
    if not replaced:
        items.append(record)
    util.write_text_atomic(
        targets_path(root), util.dump_json({"targets": items}) + "\n", mode=0o600
    )
    result: Dict[str, Any] = {
        "host": host,
        "label": record["label"],
        "replaced": replaced,
        "targets_file": TARGETS_REL,
        "policy_acknowledged": is_policy_acknowledged(root),
    }
    if ack_policy:
        policy = util.load_json(policy_path(root), {})
        existing_notes = policy.get("notes") if isinstance(policy, dict) else []
        notes_list = [str(n) for n in (existing_notes or [])]
        note = (
            f"policy acknowledged {util.iso_now()} by {record['declared_by']} for "
            f"target {host}"
        )
        if note not in notes_list:
            notes_list.append(note)
        util.write_text_atomic(
            policy_path(root),
            util.dump_json(
                {
                    "acknowledged": True,
                    "acknowledged_at": util.iso_now(),
                    "notes": notes_list[-20:],
                }
            )
            + "\n",
            mode=0o600,
        )
        result["policy_acknowledged"] = True
    return result


# --------------------------------------------------------------------------
# Probe / plan / apply / verify / rollback wrappers
# --------------------------------------------------------------------------
def _state_dir(conn: Conn, root: Optional[str] = None) -> str:
    path = os.path.join(
        root or util.repo_root(),
        "state",
        STATE_DIRNAME,
        conn.slug.replace("@", "_at_").replace("[", "").replace("]", ""),
    )
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _save_json(path: str, payload: Dict[str, Any]) -> None:
    util.write_text_atomic(path, util.dump_json(payload) + "\n", mode=0o600)


def probe(
    conn: Conn,
    *,
    save: bool = False,
    keep_raw: bool = False,
    root: Optional[str] = None,
) -> Dict[str, Any]:
    require_declaration(conn.host, root)
    result = _ssh(
        conn,
        "sh -s",
        input_text=PROBE_SCRIPT,
        timeout=PROBE_TIMEOUT,
        max_output=PROBE_MAX_OUTPUT,
        what="probe",
    )
    payload = parse_probe(result.stdout, host=conn.target)
    payload["ssh_argv_preview"] = util.redact(
        " ".join(ssh_argv(conn, "<probe script>"))
    )
    if keep_raw:
        state = _state_dir(conn, root)
        raw_path = os.path.join(state, f"probe-raw-{util.utc_stamp()}.txt")
        util.write_text_atomic(raw_path, util.redact(result.stdout), mode=0o600)
        payload["raw_saved_to"] = os.path.relpath(
            raw_path, root or util.repo_root()
        ).replace(os.sep, "/")
    if save:
        state = _state_dir(conn, root)
        _save_json(os.path.join(state, "probe-latest.json"), payload)
        payload["saved_to"] = os.path.relpath(
            os.path.join(state, "probe-latest.json"), root or util.repo_root()
        ).replace(os.sep, "/")
    return payload


def _run_plan(conn: Conn, profile: Optional[str], *, save: bool) -> Dict[str, Any]:
    args = ["plan", "--json"]
    if not save:
        args.append("--no-save")
    if profile:
        args += ["--profile", profile]
    result = _remote_ctfctl(conn, args)
    payload = _maybe_json(result.stdout)
    if payload is None:
        raise util.CtfError(
            f"remote plan on {conn.target} produced no readable JSON",
            hint=util.redact(result.stderr.strip())[-300:] or "check remote python3",
        )
    return payload


def _authorization_files(plans: Sequence[Dict[str, Any]], conn: Conn) -> Dict[str, str]:
    paths: List[str] = []
    projects: List[str] = []
    for plan in plans:
        for action in plan.get("actions", []):
            path = action.get("target_path")
            if path:
                paths.append(str(path))
        detection = plan.get("detection") or {}
        facts = detection.get("facts") or {}
        project = facts.get("compose_project")
        if project:
            projects.append(str(project))
    entries = [
        {
            "path": path,
            "label": f"remote plan target on {conn.target}",
            "declared_at": util.iso_now(),
            "declared_by": "ctfctl remote (mirrored from local declaration)",
            "host": conn.host,
        }
        for path in sorted(set(paths))
    ]
    targets = {
        "targets": entries,
        "mirrored_for": conn.target,
        "mirrored_at": util.iso_now(),
    }
    policy = {
        "acknowledged": True,
        "acknowledged_at": util.iso_now(),
        "notes": [
            f"mirrored from the operator's local policy acknowledgement for "
            f"{conn.target}"
        ],
    }
    return {
        "state/targets.json": util.dump_json(targets) + "\n",
        "state/policy.json": util.dump_json(policy) + "\n",
    }


def _upload_files(conn: Conn, files: Dict[str, str]) -> None:
    for relative, text in files.items():
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        # Remote paths are POSIX by construction: never os.path.join here, or a
        # Windows laptop would send state\\targets.json to a Linux target.
        directory = relative.rsplit("/", 1)[0] if "/" in relative else "."
        # Only module constants are interpolated here; double quotes let the
        # remote shell expand $HOME while keeping the literal path intact.
        command = (
            f'mkdir -p "$HOME/{REMOTE_DIRNAME}/{directory}" && '
            f'base64 -d > "$HOME/{REMOTE_DIRNAME}/{relative}"'
        )
        result = SSH_RUNNER(
            ssh_argv(conn, command),
            input_text=encoded,
            timeout=conn.timeout,
            max_output=16 * 1024,
        )
        if result.returncode != 0:
            raise util.CtfError(
                f"could not write {relative} on {conn.target}: "
                f"{util.redact(result.stderr.strip())[-200:]}",
            )


def plan(
    conn: Conn, *, profile: Optional[str] = None, root: Optional[str] = None
) -> Dict[str, Any]:
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    install_state = _prepare(conn, root=root)
    payload = _run_plan(conn, profile, save=False)
    matched = [
        p for p in payload.get("plans", []) if p.get("detection", {}).get("matched")
    ]
    authorized = False
    if matched and is_policy_acknowledged(root):
        _upload_files(conn, _authorization_files(matched, conn))
        payload = _run_plan(conn, profile, save=True)
        matched = [
            p for p in payload.get("plans", []) if p.get("detection", {}).get("matched")
        ]
        authorized = True
    payload["remote"] = {
        "host": conn.target,
        "toolkit": install_state.get("fingerprint", ""),
        "installed": install_state.get("installed", False),
        "authorization_mirrored": authorized,
        "policy_acknowledged": is_policy_acknowledged(root),
    }
    state = _state_dir(conn, root)
    _save_json(os.path.join(state, "plan-latest.json"), payload)
    plans_dir = os.path.join(state, "plans")
    os.makedirs(plans_dir, mode=0o700, exist_ok=True)
    for entry in matched:
        plan_id = str(entry.get("plan_id") or "")
        if plan_id:
            _save_json(os.path.join(plans_dir, _plan_filename(plan_id)), entry)
    return payload


# --------------------------------------------------------------------------
# Honeypot (decoy listeners on the target)
# --------------------------------------------------------------------------
_LOG_REL_RE = re.compile(r"^captures/honeypot-[0-9]{1,5}-[0-9]{8}T[0-9]{6}Z\.jsonl$")

HONEYPOT_ACTIONS = ("start", "status", "logs", "stop", "collect")


def honeypot(
    conn: Conn,
    action: str,
    *,
    port: Optional[int] = None,
    mode: str = "http",
    bind: str = "0.0.0.0",
    banner: str = "",
    lines: int = 50,
    all_listeners: bool = False,
    yes: bool = False,
    root: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Drive the remote honeypot lifecycle. Mutations need policy ack + --yes."""
    root = root or util.repo_root()
    if action not in HONEYPOT_ACTIONS:
        raise util.UsageError(f"unknown honeypot action {action!r}",
                              hint="actions: " + ", ".join(HONEYPOT_ACTIONS))
    require_declaration(conn.host, root)
    if action in ("start", "stop"):
        if not is_policy_acknowledged(root):
            raise util.CtfError(
                "the event policy is not acknowledged on this machine",
                hint=f"re-run: ctfctl targets declare {conn.host} --label <label> --ack-policy",
            )
        if not yes:
            raise util.CtfError(
                f"refusing to {action} a honeypot without --yes",
                hint="a honeypot is a mutation on a scored host: confirm with --yes after "
                     "checking the port is unused by every scored service",
            )
    _prepare(conn, root=root)
    args = ["honeypot", action, "--json"]
    if action == "start":
        if not port:
            raise util.UsageError("honeypot start needs --port <UNUSED_PORT>")
        args += ["--port", str(int(port)), "--mode", mode, "--bind", bind]
        if banner:
            args += ["--banner", banner]
    if action == "logs":
        args += ["--lines", str(int(lines))]
        if port:
            args += ["--port", str(int(port))]
    if action == "stop":
        if port:
            args += ["--port", str(int(port))]
        elif all_listeners:
            args.append("--all")
        else:
            raise util.UsageError("honeypot stop needs --port or --all")
    result = _remote_ctfctl(conn, args, timeout=max(conn.timeout, 90.0))
    payload = _maybe_json(result.stdout)
    if payload is None:
        payload = {"ok": False,
                   "stderr": util.redact(result.stderr.strip())[-600:]}
    payload["host"] = conn.target
    return result.returncode, payload


def render_honeypot_status(payload: Dict[str, Any]) -> str:
    host = payload.get("host") or "target"
    running = payload.get("running") or []
    stopped = payload.get("stopped") or []
    if not running and not stopped:
        return (f"{host}: no honeypot listeners. Start one with: ctfctl remote honeypot "
                f"{host} start --port <UNUSED_PORT> --yes")
    lines = [f"{host}: {len(running)} listening, {len(stopped)} stopped"]
    for entry in running:
        lines.append(
            f"  port {entry.get('port'):<6} {entry.get('mode')} bind={entry.get('bind')} "
            f"pid={entry.get('pid')} state={entry.get('state')}"
        )
        lines.append(f"         log {entry.get('log_path')}")
        if entry.get("mode") == "banner" and entry.get("banner"):
            lines.append(f"         banner {entry.get('banner')!r}")
    for entry in stopped:
        lines.append(f"  port {entry.get('port'):<6} stopped (process gone)")
    lines.append("Hits carry decoy=true. Observation only: never bind a scored port.")
    return "\n".join(lines)


def render_honeypot_logs(payload: Dict[str, Any]) -> str:
    lines: List[str] = []
    for entry in payload.get("listeners") or []:
        lines.append(
            f"port {entry.get('port')} ({entry.get('mode')}) "
            f"running={entry.get('running')} log={entry.get('log_path')}"
        )
        events = entry.get("lines") or []
        if not events:
            lines.append("  (no events yet)")
        for raw in events:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                lines.append("  " + util.printable(raw, 200))
                continue
            detail = event.get("path") or event.get("preview") or ""
            lines.append("  " + util.printable(
                f"{event.get('at')} {event.get('event')} client={event.get('client', '')} "
                f"{detail} {event.get('user_agent', '')}".strip(), 240))
    return "\n".join(lines) or "no honeypot listeners"


def honeypot_collect(conn: Conn, *, root: Optional[str] = None) -> Dict[str, Any]:
    """Copy every remote honeypot log into the local captures/ directory.

    Read-only on the target: `cat` of paths this toolkit created, validated
    against the honeypot log naming scheme before they reach an ssh argv.
    """
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    _prepare(conn, root=root)
    code, status = honeypot(conn, "status", root=root)
    if code != util.EXIT_OK:
        return {"ok": False, "host": conn.target, "error": status.get("stderr") or
                "honeypot status failed on the target", "collected": []}
    collected: List[Dict[str, Any]] = []
    for entry in status.get("running", []) + status.get("stopped", []):
        rel = str(entry.get("log_path") or "")
        if not _LOG_REL_RE.match(rel):
            continue
        result = SSH_RUNNER(
            ssh_argv(conn, f'cat "$HOME/{REMOTE_DIRNAME}/{rel}"'),
            timeout=conn.timeout,
            max_output=4 * 1024 * 1024,
        )
        if result.returncode != 0 or not result.stdout:
            collected.append({"port": entry.get("port"), "log_path": rel,
                              "bytes": 0, "error": "not collected"})
            continue
        local = os.path.join(
            util.captures_dir(root=root),
            f"honeypot-{conn.host}-{util.utc_stamp()}-{int(entry.get('port') or 0)}.jsonl",
        )
        util.write_text_atomic(local, result.stdout, mode=0o600)
        collected.append({
            "port": entry.get("port"),
            "remote_log": rel,
            "bytes": len(result.stdout),
            "saved_to": os.path.relpath(local, root).replace(os.sep, "/"),
        })
    return {"ok": True, "host": conn.target, "collected": collected}


# --------------------------------------------------------------------------
# Lockdown planning (operator-supplied allowlist, review-only actions)
# --------------------------------------------------------------------------
CLIENT_IP_SCRIPT = r"""
set -- $SSH_CONNECTION
printf 'client_ip=%s\n' "${1:-}"
printf 'ssh_user=%s\n' "$(id -un 2>/dev/null || echo unknown)"
printf 'uid=%s\n' "$(id -u 2>/dev/null || echo unknown)"
home="${HOME:-/root}"
printf 'home=%s\n' "$home"
for f in "$home/.ssh/authorized_keys" /root/.ssh/authorized_keys; do
  if [ -s "$f" ]; then printf 'authorized_keys=%s\n' "$f"; fi
done
command -v nft >/dev/null 2>&1 && printf 'nft=present\n' || printf 'nft=absent\n'
command -v sshd >/dev/null 2>&1 && printf 'sshd=present\n' || printf 'sshd=absent\n'
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  for unit in ssh sshd; do
    systemctl list-unit-files "$unit.service" --no-legend --no-pager 2>/dev/null | \
      grep -q "^$unit\.service" && printf 'unit=%s\n' "$unit"
  done
fi
[ -f /etc/nftables.conf ] && printf 'nftables_conf=present\n'
printf 'sshd_config=%s\n' "$( [ -f /etc/ssh/sshd_config ] && echo /etc/ssh/sshd_config || echo '' )"
"""


def lockdown_facts(conn: Conn, *, root: Optional[str] = None) -> Dict[str, Any]:
    """Read-only: what the target can tell us about its own access paths."""
    result = _ssh(conn, "sh -s", input_text=CLIENT_IP_SCRIPT, timeout=30.0,
                  max_output=64 * 1024, what="lockdown facts")
    facts: Dict[str, Any] = {"client_ip": "", "authorized_keys": [], "units": []}
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "client_ip":
            facts["client_ip"] = value
        elif key in ("ssh_user", "uid", "home", "nft", "sshd", "sshd_config"):
            facts[key] = value
        elif key == "unit":
            facts["units"].append(value)
        elif key == "authorized_keys":
            facts["authorized_keys"].append(value)
    return facts


def lockdown(
    conn: Conn,
    *,
    operator_cidr: str = "",
    allow_cidrs: Sequence[str] = (),
    allow_ports: Sequence[int] = (),
    allow_udp_ports: Sequence[int] = (),
    include_firewall: bool = True,
    include_ssh: bool = True,
    log_drops: bool = False,
    sshd_port: int = 22,
    root: Optional[str] = None,
) -> Dict[str, Any]:
    """Pull a review-only lockdown plan built on the target.

    The target supplies the ports it currently listens on and the operator
    supplies the allowlist; both end up in the plan the operator reviews.
    """
    import ipaddress

    root = root or util.repo_root()
    require_declaration(conn.host, root)
    install_state = _prepare(conn, root=root)
    facts = lockdown_facts(conn, root=root)
    client_ip = str(facts.get("client_ip") or "")
    if not operator_cidr:
        if not client_ip:
            raise util.CtfError(
                "could not read the operator's SSH source address from the target",
                hint=f"pass --operator-cidr explicitly (your address as the target sees it); "
                     f"this value is added to the allowlist so the lockdown cannot lock you out",
            )
        operator_cidr = client_ip
    try:
        network = ipaddress.ip_network(operator_cidr.split("/")[0] + (
            "/" + operator_cidr.split("/", 1)[1] if "/" in operator_cidr else ""), strict=False)
    except ValueError:
        raise util.CtfError(f"--operator-cidr {operator_cidr!r} is not an IP address or network")
    normalized_operator = str(network)

    # Every port the target currently listens on stays reachable; a scored
    # service the operator forgot is not worth a zero.
    listen_ports: List[int] = []
    probe_path = os.path.join(_state_dir(conn, root), "probe-latest.json")
    probe = util.load_json(probe_path, {}) or {}
    for listener in probe.get("listeners") or []:
        try:
            listen_ports.append(int(listener.get("port")))
        except (TypeError, ValueError):
            continue
    ports = sorted(set(listen_ports + [int(p) for p in allow_ports] + [int(sshd_port)]))
    cidrs = [str(c) for c in allow_cidrs if str(c).strip()]
    cidrs.append(normalized_operator)

    args = [
        "lockdown", "plan", "--json",
        "--operator-cidr", normalized_operator,
        "--allow-ports", ",".join(str(p) for p in ports),
    ]
    for cidr in dict.fromkeys(cidrs):
        args += ["--allow-cidr", cidr]
    if allow_udp_ports:
        args += ["--allow-udp-ports", ",".join(str(p) for p in allow_udp_ports)]
    if log_drops:
        args.append("--log-drops")
    if not include_firewall:
        args.append("--no-firewall")
    if not include_ssh:
        args.append("--no-ssh")
    if facts.get("sshd_config"):
        args += ["--sshd-path", str(facts["sshd_config"])]
    keys = [str(k) for k in facts.get("authorized_keys") or []]
    if keys:
        args += ["--authorized-keys", keys[0]]
    if facts.get("units"):
        args += ["--service-unit", str(facts["units"][0])]

    result = _remote_ctfctl(conn, args, timeout=max(conn.timeout, 120.0))
    payload = _maybe_json(result.stdout)
    if payload is None:
        raise util.CtfError(
            f"remote lockdown plan on {conn.target} produced no readable JSON",
            hint=util.redact(result.stderr.strip())[-300:] or "check remote python3 and nft",
        )
    plans = list(payload.get("plans") or [])
    matched = [p for p in plans if (p.get("detection") or {}).get("matched")]
    authorized = False
    if matched and is_policy_acknowledged(root):
        _mirror_authorization(conn, matched[0], root)
        result = _remote_ctfctl(conn, args, timeout=max(conn.timeout, 120.0))
        rebuilt = _maybe_json(result.stdout) or payload
        plans = list(rebuilt.get("plans") or plans)
        matched = [p for p in plans if (p.get("detection") or {}).get("matched")]
        payload = rebuilt
        authorized = True

    state = _state_dir(conn, root)
    _save_json(os.path.join(state, "lockdown-latest.json"), payload)
    plans_dir = os.path.join(state, "plans")
    os.makedirs(plans_dir, mode=0o700, exist_ok=True)
    for entry in matched:
        plan_id = str(entry.get("plan_id") or "")
        if plan_id:
            _save_json(os.path.join(plans_dir, _plan_filename(plan_id)), entry)
    payload["remote"] = {
        "host": conn.target,
        "toolkit": install_state.get("fingerprint", ""),
        "installed": install_state.get("installed", False),
        "authorization_mirrored": authorized,
        "policy_acknowledged": is_policy_acknowledged(root),
        "operator_cidr": normalized_operator,
        "allowed_ports": ports,
        "listen_ports": sorted(set(listen_ports)),
        "client_ip": client_ip,
    }
    return payload


# --------------------------------------------------------------------------
# Access-preserving safety net
# --------------------------------------------------------------------------
def touches_access(plan_json: Dict[str, Any]) -> bool:
    """True when a plan can plausibly cut the operator's own ssh session."""
    for action in plan_json.get("actions") or []:
        path = str(action.get("target_path") or "").lower()
        if any(needle in path for needle in ("sshd", "ssh_config", "nft", "iptables",
                                             "firewall", "nftables")):
            return True
        for effect in action.get("effects") or []:
            kind = str(effect.get("kind") or "")
            argv = " ".join(str(a) for a in (effect.get("argv") or []))
            if kind.startswith("nft") or "ssh" in argv.lower():
                return True
    return False


def reconnect_probe(conn: Conn, *, timeout: float = 15.0) -> Dict[str, Any]:
    """Open a fresh SSH connection from the operator. Never raises."""
    argv = ssh_argv(conn, "true", batch=True)
    result = SSH_RUNNER(argv, timeout=timeout + 10.0, max_output=4096)
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "detail": util.redact((result.stderr or result.stdout).strip())[-300:],
    }


def _plan_filename(plan_id: str) -> str:
    """Plan ids are `sha256:<hex>`; the colon is illegal in Windows filenames."""
    return str(plan_id).replace("sha256:", "").replace(":", "_") + ".json"


def load_saved_plan(
    conn: Conn, plan_id: str, *, root: Optional[str] = None
) -> Dict[str, Any]:
    state = _state_dir(conn, root)
    if plan_id in ("", "latest"):
        payload = util.load_json(os.path.join(state, "plan-latest.json"), None)
        if not isinstance(payload, dict):
            raise util.CtfError(
                f"no saved plan for {conn.target}",
                hint=f"run: ctfctl remote plan {conn.target}",
            )
        matched = [
            p for p in payload.get("plans", []) if p.get("detection", {}).get("matched")
        ]
        if not matched:
            raise util.CtfError(
                f"the saved plan for {conn.target} has no matched profile",
                hint=f"run: ctfctl remote plan {conn.target} --profile <id>",
            )
        return matched[0]
    path = os.path.join(state, "plans", _plan_filename(plan_id))
    entry = util.load_json(path, None)
    if not isinstance(entry, dict):
        raise util.CtfError(
            f"plan {plan_id} is not saved locally for {conn.target}",
            hint=f"run: ctfctl remote plan {conn.target}  (plans are pulled when they are made)",
        )
    return entry


def _mirror_authorization(conn: Conn, plan_json: Dict[str, Any], root: str) -> None:
    declaration = require_declaration(conn.host, root)
    if not is_policy_acknowledged(root):
        raise util.CtfError(
            "the event policy is not acknowledged on this machine",
            hint=f"re-run: ctfctl targets declare {conn.host} --label "
            f"{shlex.quote(str(declaration.get('label') or 'vulnbox'))} --ack-policy",
        )
    _upload_files(conn, _authorization_files([plan_json], conn))


def apply(
    conn: Conn,
    plan_id: str,
    *,
    yes: bool = False,
    dry_run: bool = False,
    approve_review: bool = False,
    no_functional: bool = False,
    root: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    entry = load_saved_plan(conn, plan_id, root=root)
    if not yes and not dry_run:
        raise util.CtfError(
            "refusing to apply remotely without --yes",
            hint=f"read the plan first: ctfctl remote plan {conn.target} --verbose, "
            "then remote apply --yes",
        )
    if not entry.get("actions"):
        raise util.CtfError("the saved plan has no actions")
    _prepare(conn, root=root)
    _mirror_authorization(conn, entry, root)
    args = ["apply", str(entry.get("plan_id") or "latest"), "--json"]
    if yes:
        args.append("--yes")
    if dry_run:
        args.append("--dry-run")
    if approve_review:
        args.append("--approve-review")
    if no_functional:
        args.append("--no-functional")
    result = _remote_ctfctl(conn, args, timeout=max(conn.timeout, 180.0))
    payload = _maybe_json(result.stdout)
    if payload is None:
        payload = {"ok": False, "stderr": util.redact(result.stderr.strip())[-600:]}
    if (payload.get("phase") == "COMMITTED" and not payload.get("dry_run")
            and touches_access(entry)):
        payload["access_recheck"] = _access_recheck(conn, entry, payload, root=root)
    return result.returncode, payload


def _access_recheck(conn: Conn, plan_json: Dict[str, Any], payload: Dict[str, Any],
                    *, root: str) -> Dict[str, Any]:
    """After a change that can cut ssh, prove the operator can still get in.

    The health checks run *on the target*; this is the only check that runs from
    the operator's side, so it is the one that catches a firewall or sshd
    mistake that the target cannot see. On failure the transaction is rolled
    back immediately (which itself needs the connection, so a console may still
    be required -- that requirement is stated in the plan before apply).
    """
    probe = reconnect_probe(conn)
    if probe["ok"]:
        probe["action"] = "reconnected; no rollback needed"
        return probe
    tx_id = str(payload.get("tx_id") or "")
    rolled_back: Optional[Dict[str, Any]] = None
    if tx_id:
        try:
            code, result = rollback(conn, tx_id=tx_id, yes=True, root=root)
            rolled_back = {"attempted": True, "ok": code == util.EXIT_OK, "result": result}
        except util.CtfError as exc:
            rolled_back = {"attempted": True, "ok": False, "error": str(exc)}
    probe["action"] = (
        "rollback attempted automatically" if rolled_back
        else "no transaction id in the apply result: roll back by hand"
    )
    if rolled_back:
        probe["rollback"] = rolled_back
    probe["recovery"] = (
        "If ssh is unreachable, use the out-of-band console: `ctfctl rollback "
        f"{tx_id or '<tx-id>'} --yes` on the host, or delete the nftables table with "
        "`nft delete table inet ctfctl_lockdown` and restore the sshd_config backup "
        "under state/tx/"
    )
    return probe


def verify(
    conn: Conn, plan_id: str, *, no_functional: bool = False, root: Optional[str] = None
) -> Tuple[int, Dict[str, Any]]:
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    entry = load_saved_plan(conn, plan_id, root=root)
    _prepare(conn, root=root)
    args = ["verify", str(entry.get("plan_id") or "latest"), "--json"]
    if no_functional:
        args.append("--no-functional")
    result = _remote_ctfctl(conn, args, timeout=max(conn.timeout, 120.0))
    payload = _maybe_json(result.stdout) or {
        "ok": False,
        "stderr": util.redact(result.stderr.strip())[-600:],
    }
    return result.returncode, payload


def rollback(
    conn: Conn,
    *,
    tx_id: Optional[str] = None,
    list_only: bool = False,
    yes: bool = False,
    root: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    _prepare(conn, root=root)
    args = ["rollback", "--json"]
    if list_only or not tx_id:
        args.append("--list")
    else:
        args.append(str(tx_id))
        if yes:
            args.append("--yes")
        else:
            raise util.CtfError(
                "refusing to roll back remotely without --yes",
                hint="list first: ctfctl remote rollback <host> --list",
            )
    result = _remote_ctfctl(conn, args, timeout=max(conn.timeout, 120.0))
    payload = _maybe_json(result.stdout) or {
        "ok": False,
        "stderr": util.redact(result.stderr.strip())[-600:],
    }
    return result.returncode, payload


def recover(conn: Conn, *, root: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    _prepare(conn, root=root)
    result = _remote_ctfctl(
        conn, ["recover", "--json"], timeout=max(conn.timeout, 60.0)
    )
    payload = _maybe_json(result.stdout) or {
        "ok": False,
        "stderr": util.redact(result.stderr.strip())[-600:],
    }
    return result.returncode, payload


def run_read_only(
    conn: Conn, args: Sequence[str], *, root: Optional[str] = None
) -> int:
    """Proxy an allowlisted read-only ctfctl subcommand and stream its output."""
    if not args:
        raise util.UsageError(
            "remote run needs a subcommand, e.g. `remote run <host> doctor`"
        )
    if args[0] not in READ_ONLY_SUBCOMMANDS:
        raise util.UsageError(
            f"`{args[0]}` is not a read-only subcommand; allowed: "
            + ", ".join(READ_ONLY_SUBCOMMANDS),
            hint="mutations must use `remote apply` or `remote rollback`",
        )
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    _prepare(conn, root=root)
    # Stream the remote process output and exit code as-is: `remote run` is a
    # proxy, so a subcommand's own negative result must reach the operator.
    quoted = " ".join(shlex.quote(str(a)) for a in args)
    command = (
        f'cd "$HOME/{REMOTE_DIRNAME}" && PYTHONPATH=tools python3 -m ctfctl {quoted}'
    )
    result = _ssh_result(conn, command, timeout=max(conn.timeout, 300.0), what="run")
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def remote_files(
    conn: Conn,
    action: str,
    path: str,
    *,
    depth: int = 1,
    limit: int = 200,
    name: str = "",
    max_bytes: int = files_mod.DEFAULT_READ_BYTES,
    max_depth: int = files_mod.MAX_DEPTH,
    as_json: bool = False,
    root: Optional[str] = None,
) -> int:
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    # Absolute-only before anything reaches ssh: a relative path would resolve
    # against a cwd the operator cannot see.
    files_mod.validate_path(path)
    _prepare(conn, root=root)
    if action == "list":
        args = [
            "files",
            "list",
            path,
            "--depth",
            str(depth),
            "--limit",
            str(limit),
            "--json",
        ]
    elif action == "read":
        args = ["files", "read", path, "--max-bytes", str(max_bytes), "--json"]
    elif action == "find":
        if not name:
            raise util.UsageError("remote files find needs --name GLOB")
        args = [
            "files",
            "find",
            path,
            "--name",
            name,
            "--limit",
            str(limit),
            "--max-depth",
            str(max_depth),
            "--json",
        ]
    else:
        raise util.UsageError(f"unknown files action {action!r}")
    result = _remote_ctfctl(conn, args)
    payload = _maybe_json(result.stdout)
    if payload is None:
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return result.returncode or util.EXIT_NEGATIVE
    if as_json:
        util.emit_json(payload)
    elif action == "list":
        print(files_mod.render_listing(payload))
    elif action == "read":
        print(files_mod.render_read(payload))
    else:
        print(files_mod.render_matches(payload))
    return result.returncode




# --------------------------------------------------------------------------
# One-command pipeline: probe -> discover -> plan -> (apply) -> (honeypot)
# --------------------------------------------------------------------------
HONEYPOT_PORT_CANDIDATES = (2222, 8080, 8443, 3306, 5432, 6379, 9200, 10000)


def auto(
    conn: Conn,
    *,
    apply_mutations: bool = False,
    approve_review: bool = False,
    honeypot_port: int = 0,
    honeypot_mode: str = "http",
    honeypot_banner: str = "",
    lockdown_requested: bool = False,
    allow_cidrs: Sequence[str] = (),
    yes: bool = False,
    root: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the whole read-only pipeline for one IP, then optionally act.

    Read-only by default: probe, discovery, plan, bounded file recon and a
    written report. Mutations happen only when asked for *and* confirmed with
    --yes, and they reuse exactly the same gated paths as the individual
    commands (declaration, policy, review-only approval, auto-rollback).

    Order when everything is requested: patch first, honeypot second, lockdown
    last (with the honeypot port in its allowlist, or the honeypot would be
    dropped by the very rules meant to protect it).
    """
    root = root or util.repo_root()
    require_declaration(conn.host, root)
    if (apply_mutations or honeypot_port or lockdown_requested) and not yes:
        raise util.CtfError(
            "refusing to change anything without --yes",
            hint="the read-only pipeline runs by itself; add --yes when you have read the plan "
                 "and want the mutations applied",
        )
    if lockdown_requested and not approve_review:
        raise util.CtfError(
            "--lockdown applies a review-only plan, so it needs --approve-review",
            hint="run `ctfctl remote lockdown <host> --allow-cidr <TEAM_RANGE>` first, read "
                 "the diff and the allowlist, then re-run with --lockdown --approve-review "
                 "--yes while the console is open",
        )
    report: Dict[str, Any] = {
        "schema": "ctfctl.auto/1",
        "host": conn.target,
        "started_at": util.iso_now(),
        "mutations_requested": bool(apply_mutations or honeypot_port or lockdown_requested),
        "steps": {},
        "gaps": [],
        "next_actions": [],
    }

    # 1. Read-only probe: works with only a POSIX shell on the target.
    report["steps"]["probe"] = probe(conn, save=True, root=root)

    # 2. Toolkit + full discovery + plan (needs python3 on the target).
    try:
        install_state = install(conn, root=root)
        report["steps"]["install"] = {
            "fingerprint": install_state.get("fingerprint"),
            "installed": install_state.get("installed"),
        }
        result = _remote_ctfctl(conn, ["discover", "--json"],
                                timeout=max(conn.timeout, 120.0))
        report["steps"]["discover"] = _maybe_json(result.stdout) or {}
        report["steps"]["plan"] = plan(conn, root=root)
    except util.CtfError as exc:
        report["gaps"].append("planning needs python3 on the target: " + str(exc))
        report["next_actions"].append(
            f"install python3 on {conn.target}, then re-run: ctfctl remote plan {conn.target}"
        )

    # 3. Bounded read-only file recon of the usual application roots.
    roots = ("/var/www", "/srv", "/opt", "/home")
    listings: Dict[str, Any] = {}
    for path in roots:
        try:
            result = _remote_ctfctl(
                conn, ["files", "list", path, "--depth", "1", "--limit", "50", "--json"],
                timeout=max(conn.timeout, 60.0),
            )
            payload = _maybe_json(result.stdout)
            if payload:
                listings[path] = payload
        except util.CtfError as exc:
            listings[path] = {"error": str(exc)}
    report["steps"]["files"] = listings

    # 4. Free-port suggestions for a honeypot, from what the probe actually saw.
    seen = {
        int(item.get("port"))
        for item in (report["steps"]["probe"].get("listeners") or [])
        if str(item.get("port", "")).isdigit()
    }
    free = [p for p in HONEYPOT_PORT_CANDIDATES if p not in seen]
    report["honeypot_suggestions"] = free[:3]
    if free:
        report["next_actions"].append(
            f"distract attackers without touching a scored port: ctfctl remote honeypot "
            f"{conn.target} start --port {free[0]} --yes"
        )

    # 5. Optional mutations, through the normal gated paths.
    if apply_mutations:
        plans = report["steps"].get("plan") or {}
        matched = [
            entry for entry in (plans.get("plans") or [])
            if (entry.get("detection") or {}).get("matched") and entry.get("actions")
        ]
        if not matched:
            report["steps"]["apply"] = {
                "applied": False,
                "reason": "no profile with actions matched this host; see the plan evidence",
            }
        elif not is_policy_acknowledged(root):
            raise util.CtfError(
                "the event policy is not acknowledged on this machine",
                hint=f"re-run: ctfctl targets declare {conn.host} --label <label> --ack-policy",
            )
        else:
            entry = matched[0]
            code, payload = apply(
                conn, str(entry.get("plan_id") or "latest"), yes=True,
                approve_review=approve_review, root=root,
            )
            report["steps"]["apply"] = payload
            report["apply_exit_code"] = code
            if code != util.EXIT_OK:
                report["next_actions"].append(
                    "read the apply result before retrying: nothing is retried automatically"
                )

    if honeypot_port:
        code, payload = honeypot(
            conn, "start", port=int(honeypot_port), mode=honeypot_mode,
            banner=honeypot_banner, yes=True, root=root,
        )
        report["steps"]["honeypot"] = payload
        report["honeypot_exit_code"] = code
        if code != util.EXIT_OK:
            report["next_actions"].append(
                "the honeypot did not start: pick a free port and check the target's firewall"
            )

    if lockdown_requested:
        # The honeypot port must survive the lockdown, or the distraction is
        # dropped by the rules meant to protect the box.
        extra_ports = [int(honeypot_port)] if honeypot_port else []
        plan_payload = lockdown(
            conn, allow_cidrs=list(allow_cidrs), allow_ports=extra_ports, root=root,
        )
        report["steps"]["lockdown_plan"] = plan_payload
        entries = [
            entry for entry in (plan_payload.get("plans") or [])
            if (entry.get("detection") or {}).get("matched") and entry.get("actions")
        ]
        if not entries:
            report["steps"]["lockdown_apply"] = {
                "applied": False,
                "reason": "no lockdown action could be rendered on this host; "
                          "see the plan's skipped entries",
            }
        elif not is_policy_acknowledged(root):
            raise util.CtfError(
                "the event policy is not acknowledged on this machine",
                hint=f"re-run: ctfctl targets declare {conn.host} --label <label> --ack-policy",
            )
        else:
            entry = entries[0]
            code, payload = apply(
                conn, str(entry.get("plan_id") or "latest"), yes=True,
                approve_review=True, root=root,
            )
            report["steps"]["lockdown_apply"] = payload
            report["lockdown_exit_code"] = code
            if code != util.EXIT_OK:
                report["next_actions"].append(
                    "the lockdown did not commit: read the apply result, then decide whether "
                    "to retry or leave the box as it is"
                )

    # 6. Persist a report an operator can read and hand over.
    report["finished_at"] = util.iso_now()
    reports_dir = os.path.join(root, "state", "reports")
    os.makedirs(reports_dir, mode=0o700, exist_ok=True)
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", conn.host)
    stamp = util.utc_stamp()
    json_path = os.path.join(reports_dir, f"auto-{safe_host}-{stamp}.json")
    util.write_text_atomic(json_path, util.dump_json(report) + "\n", mode=0o600)
    md_path = os.path.join(reports_dir, f"auto-{safe_host}-{stamp}.md")
    util.write_text_atomic(md_path, render_auto_report(report), mode=0o600)
    report["report_json"] = os.path.relpath(json_path, root).replace(os.sep, "/")
    report["report_markdown"] = os.path.relpath(md_path, root).replace(os.sep, "/")
    return report


def render_auto_report(report: Dict[str, Any]) -> str:
    """Human-readable handover for one `remote auto` run."""
    host = report.get("host")
    probe_payload = (report.get("steps") or {}).get("probe") or {}
    lines = [
        f"# Recon report - {host}",
        "",
        f"Run at {report.get('started_at')} by `ctfctl remote auto`.",
        "Read-only unless a step below says otherwise.",
        "",
        "## Identity",
        "",
    ]
    identity = probe_payload.get("identity") or {}
    lines.append(f"- **host**: {probe_payload.get('host')}")
    for key in ("hostname", "kernel", "user", "uid"):
        if identity.get(key):
            lines.append(f"- **{key}**: {identity[key]}")
    for line in (identity.get("os_release") or [])[:2]:
        lines.append(f"- **os**: {line}")
    if identity.get("init"):
        lines.append(f"- **init**: {identity['init']}")
    lines += ["", "## Listeners", ""]
    listeners = probe_payload.get("listeners") or []
    if not listeners:
        lines.append("No listeners were parsed from the probe (check the gaps below).")
    else:
        lines += ["| port | address | proto | process | who can reach it |", "|---|---|---|---|---|"]
        for item in listeners[:60]:
            address = str(item.get("address") or "")
            reach = ("loopback only" if address.startswith("127.") or address == "::1"
                     else "any network that can route to this host")
            lines.append(
                f"| {item.get('port')} | {address} "
                f"| {item.get('proto', '')} "
                f"| {item.get('process') or item.get('pid') or ''} "
                f"| {reach} |"
            )
    containers = probe_payload.get("containers") or []
    if containers:
        lines += ["", "## Containers", ""]
        for item in containers[:20]:
            lines.append(
                f"- {item.get('names') or item.get('name')}  image={item.get('image')}  "
                f"ports={item.get('ports')}"
            )
    firewall_lines = probe_payload.get("firewall_lines") or []
    if firewall_lines:
        lines += ["", "## Firewall posture (read-only)", "", "```"]
        lines += [util.printable(line, 200) for line in firewall_lines[:20]]
        lines.append("```")
    gaps = list(report.get("gaps") or [])
    probe_gaps = probe_payload.get("gaps") or []
    gaps += [f"probe: {gap}" for gap in probe_gaps[:10]]
    lines += ["", "## Evidence gaps", ""]
    lines += [f"- {gap}" for gap in gaps] or ["- none reported"]
    suggestions = report.get("honeypot_suggestions") or []
    if suggestions:
        lines += [
            "",
            "## Suggested honeypot ports",
            "",
            "Unused by anything the probe saw: " + ", ".join(str(p) for p in suggestions),
        ]
    plan_payload = (report.get("steps") or {}).get("plan") or {}
    matched = [
        entry for entry in (plan_payload.get("plans") or [])
        if (entry.get("detection") or {}).get("matched")
    ]
    lines += ["", "## Plans", ""]
    if not matched:
        lines.append(
            "No shipped profile matched. The probe evidence is the deliverable; do not improvise "
            "a patch from it."
        )
    for entry in matched:
        lines.append(f"### {entry.get('profile_id')} (plan {entry.get('plan_id')})")
        for action in entry.get("actions") or []:
            skip = action.get("skipped_reason")
            lines.append(
                f"- {action.get('key')}: {action.get('action_id')}"
                + (f" - skipped: {skip}" if skip else f" [{action.get('eligibility')}]")
            )
    applied = (report.get("steps") or {}).get("apply")
    if applied:
        lines += [
            "",
            "## Apply",
            "",
            f"phase={applied.get('phase')} ok={applied.get('ok')} tx={applied.get('tx_id')}",
        ]
        recheck = applied.get("access_recheck")
        if recheck:
            lines.append(
                f"- operator reconnect after the change: {recheck.get('ok')} "
                f"({recheck.get('action')})"
            )
    lockdown_plan = (report.get("steps") or {}).get("lockdown_plan")
    if lockdown_plan:
        meta = lockdown_plan.get("remote") or {}
        lines += ["", "## Lockdown plan", "",
                  f"- operator address kept reachable: {meta.get('operator_cidr')}",
                  f"- ports kept reachable: {meta.get('allowed_ports')}"]
        for entry in lockdown_plan.get("plans") or []:
            for action in entry.get("actions") or []:
                skip = action.get("skipped_reason")
                lines.append(
                    f"- {action.get('key')}: {action.get('action_id')}"
                    + (f" - skipped: {skip}" if skip else f" [{action.get('eligibility')}]")
                )
    lockdown_apply = (report.get("steps") or {}).get("lockdown_apply")
    if lockdown_apply:
        lines += ["", "## Lockdown apply", "",
                  f"phase={lockdown_apply.get('phase')} ok={lockdown_apply.get('ok')} "
                  f"tx={lockdown_apply.get('tx_id')}"]
        recheck = lockdown_apply.get("access_recheck")
        if recheck:
            lines.append(
                f"- operator reconnect after the lockdown: {recheck.get('ok')} "
                f"({recheck.get('action')})"
            )
    honeypot_state = (report.get("steps") or {}).get("honeypot")
    if honeypot_state:
        lines += ["", "## Honeypot", ""]
        if honeypot_state.get("port"):
            lines.append(
                f"- running on port {honeypot_state.get('port')} "
                f"({honeypot_state.get('mode')}), log {honeypot_state.get('log_path')}"
            )
        else:
            lines.append(f"- not started: {util.printable(str(honeypot_state), 300)}")
    next_actions = report.get("next_actions") or []
    if next_actions:
        lines += ["", "## Next actions", ""] + [f"- {item}" for item in next_actions]
    lines += [
        "",
        "---",
        "",
        "Every functional check in this report is *our* check; it is not proof that an unseen "
        "organizer checker passes.",
    ]
    return "\n".join(lines) + "\n"
