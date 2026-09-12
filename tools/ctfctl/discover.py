"""Read-only, bounded host inventory.

Rules encoded here:

  * discovery never mutates anything and never installs anything;
  * every collector is independently bounded and independently allowed to fail;
  * missing permission produces an explicit *evidence gap*, never a guess;
  * a port number is never equated with a confirmed stack -- the graph records
    the evidence and a confidence level, and the profile decides;
  * file contents are stat-ed, not dumped: no private keys, no password files,
    no environment values by default (only variable *names*);
  * traversal is depth- and count-bounded, and subprocess output is capped.

`--system-root <dir>` runs path-based collectors against a synthetic root (used
by the test suite). Subprocess collectors are skipped in that mode unless
`--allow-subprocess` is given, and the skip is recorded as a gap.
"""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import platformx, util

MAX_WALK_ENTRIES = 4000
MAX_WALK_DEPTH = 4
MAX_RULESET_LINES = 400
MAX_UNITS = 300
MAX_PROC_SCAN = 4000

# Paths we never read contents of, only stat.
SENSITIVE_NAMES = {
    "shadow", "gshadow", "passwd", "sudoers", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", ".pgpass", ".my.cnf", "authorized_keys", "known_hosts",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
# Well-known port -> candidate stack. Candidates only; never a conclusion.
PORT_HINTS = {
    22: ["ssh"], 25: ["smtp"], 53: ["dns"], 80: ["http"], 443: ["https"], 3000: ["node"],
    3306: ["mysql", "mariadb"], 5000: ["flask", "python-wsgi"], 5432: ["postgres"],
    6379: ["redis"], 8000: ["python-wsgi", "django"], 8080: ["http-alt", "tomcat", "web"],
    8081: ["http-alt"], 8443: ["https-alt"], 9000: ["php-fpm", "portainer"],
    27017: ["mongodb"], 5672: ["rabbitmq"], 9200: ["elasticsearch"], 11211: ["memcached"],
}
WEB_PATHS = ("/srv", "/var/www", "/opt", "/usr/share/nginx/html", "/app", "/code")
CONFIG_CANDIDATES = (
    "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/caddy", "/etc/php",
    "/etc/systemd/system", "/etc/supervisor", "/etc/init.d",
)
DB_HINTS = ("postgres", "mysqld", "mariadb", "redis-server", "mongod", "memcached")


# --------------------------------------------------------------------------
@dataclass
class Evidence:
    kind: str
    status: str = "ok"  # ok | partial | unsupported | refused
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    gaps: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "status": self.status,
            "detail": self.detail,
            "gaps": self.gaps,
            "data": self.data,
        }


@dataclass
class Inventory:
    mode: str
    system_root: str
    generated_at: str
    host: Dict[str, Any]
    evidence: List[Evidence]
    graph: Dict[str, Any] = field(default_factory=dict)
    redactions: int = 0

    def gaps(self) -> List[str]:
        out: List[str] = []
        for item in self.evidence:
            out.extend(item.gaps)
        return out

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": "ctfctl.inventory/1",
            "mode": self.mode,
            "system_root": self.system_root,
            "generated_at": self.generated_at,
            "host": self.host,
            "evidence": [e.as_dict() for e in self.evidence],
            "graph": self.graph,
            "gaps": self.gaps(),
            "redactions": self.redactions,
            "notice": (
                "Read-only inventory. Absence of evidence is recorded as a gap, not as "
                "a conclusion. Port numbers are candidates, never confirmed stacks."
            ),
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _rooted(system_root: str, path: str) -> str:
    if system_root in ("/", "", None):
        return path
    return os.path.join(system_root, path.lstrip("/"))


def _read_small(path: str, limit: int = 64 * 1024) -> Optional[str]:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


def _bounded_walk(root: str, max_entries: int = MAX_WALK_ENTRIES,
                  max_depth: int = MAX_WALK_DEPTH) -> Tuple[List[str], bool]:
    """Return (relative paths, truncated?). Never follows symlinks."""
    out: List[str] = []
    truncated = False
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if len(out) >= max_entries:
                truncated = True
                break
            out.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
        if truncated:
            break
    return out, truncated


def _is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return lowered in SENSITIVE_NAMES or lowered.endswith(SENSITIVE_SUFFIXES)


# --------------------------------------------------------------------------
# Collectors
# --------------------------------------------------------------------------
def collect_host(caps: platformx.Capabilities, system_root: str) -> Evidence:
    ev = Evidence("host")
    uname = os.uname() if hasattr(os, "uname") else None
    os_release = _read_small(_rooted(system_root, "/etc/os-release")) or ""
    fields: Dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')
    ev.data = {
        "kernel": (uname.release if uname else caps.platform),
        "kernel_version": (uname.version if uname else ""),
        "arch": (uname.machine if uname else ""),
        "nodename": (uname.nodename if uname else ""),
        "os_pretty_name": fields.get("PRETTY_NAME", ""),
        "os_id": fields.get("ID", ""),
        "os_version_id": fields.get("VERSION_ID", ""),
        "init_system": caps.init_system,
        "init_detail": caps.init_detail,
        "boot_id": caps.boot_id,
        "uptime_s": _uptime(system_root),
        "is_root": caps.is_root,
        "euid": caps.euid,
        "platform": caps.platform,
    }
    if not fields:
        ev.status = "partial"
        ev.gaps.append("/etc/os-release unavailable: distribution unknown")
    if not caps.is_linux:
        ev.status = "unsupported"
        ev.gaps.append("non-Linux host: only a read-only partial inventory is possible")
    return ev


def _uptime(system_root: str) -> Optional[float]:
    text = _read_small(_rooted(system_root, "/proc/uptime"))
    if not text:
        return None
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def collect_resources(system_root: str) -> Evidence:
    ev = Evidence("resources")
    meminfo = _read_small(_rooted(system_root, "/proc/meminfo")) or ""
    mem: Dict[str, int] = {}
    for line in meminfo.splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            value = parts[1].strip().split()[0]
            if value.isdigit():
                mem[parts[0].strip()] = int(value) * 1024
    loadavg = _read_small(_rooted(system_root, "/proc/loadavg")) or ""
    disks = {}
    for path in ("/", "/tmp", "/var", "/srv"):
        real = _rooted(system_root, path)
        if os.path.isdir(real):
            try:
                disks[path] = util.disk_free(real)
            except OSError:
                continue
    ev.data = {
        "mem_total_bytes": mem.get("MemTotal"),
        "mem_available_bytes": mem.get("MemAvailable"),
        "swap_total_bytes": mem.get("SwapTotal"),
        "loadavg": loadavg.split()[:3] if loadavg else None,
        "disks": disks,
    }
    if not mem:
        ev.status = "partial"
        ev.gaps.append("/proc/meminfo unavailable: memory pressure unknown")
    return ev


def parse_proc_net(system_root: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse /proc/net/{tcp,tcp6,udp,udp6} into socket records (no root needed)."""
    sockets: List[Dict[str, Any]] = []
    gaps: List[str] = []
    files = {
        "tcp": "/proc/net/tcp", "tcp6": "/proc/net/tcp6",
        "udp": "/proc/net/udp", "udp6": "/proc/net/udp6",
    }
    for proto, path in files.items():
        text = _read_small(_rooted(system_root, path), 512 * 1024)
        if text is None:
            if proto in ("tcp", "tcp6"):
                gaps.append(f"{path} unreadable: TCP listener inventory incomplete")
            continue
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local = parts[1]
                state = parts[3]
                inode = parts[9]
                address, port = _decode_proc_addr(local, proto.endswith("6"))
            except (IndexError, ValueError):
                continue
            sockets.append({
                "proto": proto,
                "family": "ipv6" if proto.endswith("6") else "ipv4",
                "address": address,
                "port": port,
                "state": _tcp_state(state) if proto.startswith("tcp") else "udp",
                "inode": inode,
                "source": f"{path} (unprivileged)",
            })
    return sockets, gaps


def _decode_proc_addr(value: str, ipv6: bool) -> Tuple[str, int]:
    addr_hex, _, port_hex = value.partition(":")
    port = int(port_hex, 16)
    if not ipv6:
        raw = bytes.fromhex(addr_hex)
        address = ".".join(str(b) for b in raw[::-1])
    else:
        words = [addr_hex[i:i + 8] for i in range(0, len(addr_hex), 8)]
        raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
        address = socket.inet_ntop(socket.AF_INET6, raw) if len(raw) == 16 else addr_hex
    return address, port


def _tcp_state(code: str) -> str:
    return {"01": "established", "02": "syn-sent", "0A": "listen", "06": "time-wait"}.get(code, code)


def collect_listeners(caps: platformx.Capabilities, system_root: str,
                      allow_subprocess: bool) -> Evidence:
    ev = Evidence("listeners")
    records: List[Dict[str, Any]] = []
    used_ss = False
    if allow_subprocess and util.which("ss"):
        res = util.run(["ss", "-lntupH"], timeout=15, max_output=512 * 1024)
        if res.ok:
            used_ss = True
            records = _parse_ss(res.stdout)
            ev.detail = "ss -lntupH"
        else:
            ev.gaps.append(f"ss failed ({res.reason or res.returncode}): falling back to /proc")
    if not used_ss:
        sockets, gaps = parse_proc_net(system_root)
        ev.gaps.extend(gaps)
        listening = [s for s in sockets if s["state"] in ("listen", "udp")]
        records = [{**s, "process": None, "pid": None} for s in listening]
        ev.detail = "parsed /proc/net/{tcp,tcp6,udp,udp6} (no process attribution)"
        if listening and all(not s.get("pid") for s in listening):
            ev.gaps.append(
                "socket ownership requires root (or a matching /proc/<pid>/fd entry): "
                "port-to-process mapping is incomplete"
            )
    records = _dedupe_listeners(records)
    for record in records:
        record["stack_candidates"] = PORT_HINTS.get(record.get("port") or -1, [])
        record["exposure"] = _exposure(record.get("address") or "")
    ev.data = {"listeners": sorted(records, key=lambda r: (r.get("port") or 0, r.get("proto") or ""))}
    if not records:
        ev.status = "partial"
        ev.gaps.append(
            "the socket probe found no listeners (container-published ports, when Docker is "
            "available, are reported separately in the service graph)"
        )
    return ev


def _parse_ss(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        state = parts[1]
        local = parts[4]
        address, port = _split_local(local)
        process_field = parts[6] if len(parts) > 6 else ""
        name, pid = _parse_process_field(process_field)
        out.append({
            "proto": proto,
            "family": "ipv6" if "v6" in proto else "ipv4",
            "address": address,
            "port": port,
            "state": state,
            "process": name,
            "pid": pid,
            "source": "ss",
        })
    return out


def _split_local(value: str) -> Tuple[str, int]:
    host, _, port_text = value.rpartition(":")
    port = int(port_text) if port_text.isdigit() else -1
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.replace("%", "%")
    return host or "*", port


def _parse_process_field(value: str) -> Tuple[Optional[str], Optional[int]]:
    match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', value)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


def _dedupe_listeners(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for record in records:
        key = (record.get("proto"), record.get("address"), record.get("port"))
        if key not in seen:
            seen[key] = record
        else:
            existing = seen[key]
            if not existing.get("process") and record.get("process"):
                seen[key] = record
    return list(seen.values())


def _exposure(address: str) -> str:
    if address in ("0.0.0.0", "*", "::", "[::]"):
        return "all-interfaces"
    if address in ("127.0.0.1", "::1", "localhost"):
        return "loopback-only"
    return "specific-address"


def collect_processes(caps: platformx.Capabilities, system_root: str,
                      allow_subprocess: bool, pids_of_interest: Sequence[int]) -> Evidence:
    ev = Evidence("processes")
    if allow_subprocess and util.which("ps"):
        res = util.run(["ps", "-eo", "pid=,ppid=,uid=,etimes=,comm="], timeout=15,
                       max_output=1024 * 1024)
        if res.ok:
            procs = []
            for line in res.stdout.splitlines():
                parts = line.split(None, 4)
                if len(parts) < 5:
                    continue
                procs.append({
                    "pid": int(parts[0]), "ppid": int(parts[1]), "uid": int(parts[2]),
                    "etimes": int(parts[3]), "comm": parts[4][:64],
                })
            procs.sort(key=lambda p: p["pid"])
            ev.data = {"count": len(procs), "processes": procs[:400],
                       "truncated": len(procs) > 400}
            ev.detail = "ps -eo pid,ppid,uid,etimes,comm"
            ev.data["start_ticks"] = _start_ticks(system_root, pids_of_interest)
            if len(procs) > 400:
                ev.gaps.append("process list truncated at 400 entries")
            return ev
        ev.gaps.append(f"ps failed ({res.reason or res.returncode})")
    # /proc fallback
    proc_root = _rooted(system_root, "/proc")
    procs = []
    if os.path.isdir(proc_root):
        for entry in sorted(os.listdir(proc_root))[:MAX_PROC_SCAN]:
            if not entry.isdigit():
                continue
            comm = _read_small(os.path.join(proc_root, entry, "comm"), 256)
            if comm is None:
                continue
            stat_text = _read_small(os.path.join(proc_root, entry, "stat"), 4096) or ""
            ppid = 0
            try:
                ppid = int(stat_text.rsplit(")", 1)[1].split()[1])
            except (IndexError, ValueError):
                pass
            procs.append({"pid": int(entry), "ppid": ppid, "uid": -1, "etimes": None,
                          "comm": comm.strip()[:64]})
    ev.data = {"count": len(procs), "processes": procs, "start_ticks":
               _start_ticks(system_root, pids_of_interest)}
    ev.detail = "parsed /proc/<pid>/comm (no uid or start time)"
    if not procs:
        ev.status = "partial"
        ev.gaps.append("process table unreadable: process attribution unavailable")
    return ev


def _start_ticks(system_root: str, pids: Sequence[int]) -> Dict[str, int]:
    """Process start time (field 22 of /proc/<pid>/stat) for stable identity."""
    out: Dict[str, int] = {}
    for pid in pids:
        text = _read_small(_rooted(system_root, f"/proc/{pid}/stat"), 8192)
        if not text:
            continue
        try:
            rest = text.rsplit(")", 1)[1].split()
            out[str(pid)] = int(rest[19])
        except (IndexError, ValueError):
            continue
    return out


def collect_socket_owners(caps: platformx.Capabilities, system_root: str,
                          listeners: List[Dict[str, Any]]) -> Evidence:
    """Map socket inodes to PIDs via /proc/<pid>/fd (works unprivileged for own procs)."""
    ev = Evidence("socket_owners")
    wanted = {rec.get("inode") for rec in listeners if rec.get("inode")}
    if not wanted:
        ev.status = "unsupported"
        ev.detail = "no socket inodes available (ss already provided process attribution)"
        return ev
    proc_root = _rooted(system_root, "/proc")
    mapping: Dict[str, List[int]] = {}
    denied = 0
    if os.path.isdir(proc_root):
        for entry in sorted(os.listdir(proc_root))[:MAX_PROC_SCAN]:
            if not entry.isdigit():
                continue
            fd_dir = os.path.join(proc_root, entry, "fd")
            try:
                fds = os.listdir(fd_dir)
            except PermissionError:
                denied += 1
                continue
            except OSError:
                continue
            for fd in fds:
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                match = re.match(r"socket:\[(\d+)\]", target)
                if match and match.group(1) in wanted:
                    mapping.setdefault(match.group(1), []).append(int(entry))
    ev.data = {"socket_to_pids": mapping, "denied_processes": denied}
    if denied:
        ev.status = "partial"
        ev.gaps.append(
            f"{denied} process(es) were not readable: socket ownership is incomplete "
            "(unprivileged discovery cannot see other users' file descriptors)"
        )
    return ev


def collect_units(caps: platformx.Capabilities, allow_subprocess: bool,
                  pids: Sequence[int]) -> Evidence:
    ev = Evidence("units")
    if not allow_subprocess:
        ev.status = "unsupported"
        ev.detail = "subprocess collectors disabled"
        return ev
    if not util.which("systemctl"):
        ev.status = "unsupported"
        ev.detail = "systemctl not installed"
        if caps.init_system != "systemd":
            ev.gaps.append("no systemd: unit-to-process mapping unavailable")
        return ev
    res = util.run(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager",
         "--plain", "--no-legend", "--full"],
        timeout=20, max_output=512 * 1024,
    )
    if not res.ok:
        ev.status = "partial"
        ev.gaps.append(f"systemctl list-units failed: {util.printable(res.stderr.strip(), 200)}")
        return ev
    units = []
    for line in res.stdout.splitlines()[:MAX_UNITS]:
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        units.append({"unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3],
                      "description": util.printable(parts[4] if len(parts) > 4 else "", 160)})
    by_pid: Dict[str, Dict[str, Any]] = {}
    for pid in pids:
        show = util.run(
            ["systemctl", "show", "--no-pager", "-p", "FragmentPath", "-p", "ExecStart",
             "-p", "WorkingDirectory", "-p", "User", "-p", "MainPID", f"{pid}"],
            timeout=10, max_output=64 * 1024,
        )
        if not show.ok:
            continue
        props: Dict[str, str] = {}
        for line in show.stdout.splitlines():
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
        if props.get("MainPID") not in (None, "", "0", str(pid)):
            continue
        by_pid[str(pid)] = {
            "unit": _unit_from_properties(props, pid),
            "fragment_path": props.get("FragmentPath", ""),
            "working_directory": props.get("WorkingDirectory", ""),
            "user": props.get("User", ""),
            # ExecStart can embed credentials in some services; redact.
            "exec_start": util.printable(util.redact(props.get("ExecStart", "")), 300),
        }
    ev.data = {"units": units, "by_pid": by_pid}
    ev.detail = "systemctl list-units + systemctl show per candidate pid"
    return ev


def _unit_from_properties(props: Dict[str, str], pid: int) -> str:
    fragment = props.get("FragmentPath", "")
    if fragment:
        return os.path.basename(fragment)
    exec_start = props.get("ExecStart", "")
    match = re.search(r"argv\[\]=(?:/[^ ]*/)?([^ ;]+)", exec_start)
    if match:
        return f"{match.group(1)} (pid {pid})"
    return f"pid-{pid}"


def collect_containers(caps: platformx.Capabilities, allow_subprocess: bool) -> Evidence:
    ev = Evidence("containers")
    if not allow_subprocess:
        ev.status = "unsupported"
        ev.detail = "subprocess collectors disabled"
        return ev
    if not util.which("docker"):
        ev.status = "unsupported"
        ev.detail = "docker not installed"
        return ev
    res = util.run(["docker", "ps", "--no-trunc", "--format", "{{json .}}"], timeout=20,
                   max_output=1024 * 1024)
    if not res.ok:
        ev.status = "unsupported"
        ev.detail = "docker daemon unreachable"
        ev.gaps.append(
            "docker CLI present but the daemon is not reachable: container inventory, Compose "
            "project mapping and published-port attribution are unavailable"
        )
        return ev
    containers = []
    for line in res.stdout.splitlines():
        try:
            row = util.json.loads(line)
        except ValueError:
            continue
        cid = row.get("ID", "")
        inspect = util.run(["docker", "inspect", cid], timeout=15, max_output=2 * 1024 * 1024)
        detail: Dict[str, Any] = {}
        if inspect.ok:
            try:
                payload = util.json.loads(inspect.stdout)
                if isinstance(payload, list) and payload:
                    detail = payload[0]
            except ValueError:
                detail = {}
        config = (detail.get("Config") or {})
        host_config = (detail.get("HostConfig") or {})
        network = (detail.get("NetworkSettings") or {})
        labels = config.get("Labels") or {}
        containers.append({
            "id": cid[:24],
            "name": (row.get("Names") or "").lstrip("/"),
            "image": row.get("Image", ""),
            "state": row.get("State", ""),
            "ports": util.printable(row.get("Ports", ""), 300),
            "compose_project": labels.get("com.docker.compose.project"),
            "compose_service": labels.get("com.docker.compose.service"),
            "compose_config_files": labels.get("com.docker.compose.project.config_files"),
            "compose_working_dir": labels.get("com.docker.compose.project.working_dir"),
            "network_mode": host_config.get("NetworkMode"),
            "published": _published_ports(network),
            "mounts": [
                {
                    "type": m.get("Type"), "source": m.get("Source"), "target": m.get("Destination"),
                    "name": m.get("Name"), "rw": m.get("RW"),
                }
                for m in (detail.get("Mounts") or [])
            ][:40],
            "entrypoint_preview": util.printable(util.redact(
                " ".join(config.get("Entrypoint") or [])), 200),
            "cmd_preview": util.printable(util.redact(" ".join(config.get("Cmd") or [])), 200),
            # Variable names only -- never values.
            "env_names": sorted({
                item.split("=", 1)[0] for item in (config.get("Env") or []) if "=" in item
            })[:80],
        })
    ev.data = {"containers": containers, "count": len(containers)}
    ev.detail = "docker ps + docker inspect (env values intentionally not collected)"
    compose_projects = sorted({c["compose_project"] for c in containers if c.get("compose_project")})
    ev.data["compose_projects"] = compose_projects
    if util.which("docker"):
        ls = util.run(["docker", "compose", "ls", "--format", "json"], timeout=15,
                      max_output=256 * 1024)
        if ls.ok:
            configs = []
            for line in ls.stdout.splitlines():
                try:
                    configs.append(util.json.loads(line))
                except ValueError:
                    continue
            ev.data["compose_ls"] = configs
    return ev


def _published_ports(network: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for port, bindings in (network.get("Ports") or {}).items():
        for binding in bindings or []:
            out.append({
                "container_port": port,
                "host_ip": binding.get("HostIp"),
                "host_port": binding.get("HostPort"),
            })
    return out[:40]


def collect_app_roots(caps: platformx.Capabilities, system_root: str,
                      cwd_pids: Sequence[int],
                      containers: Optional[Sequence[Dict[str, Any]]] = None) -> Evidence:
    """Candidate application roots. Directory listings only; no file contents."""
    ev = Evidence("app_roots")
    roots: List[Dict[str, Any]] = []
    for pid in cwd_pids:
        link = _rooted(system_root, f"/proc/{pid}/cwd")
        try:
            target = os.readlink(link)
        except OSError:
            continue
        roots.append({"path": target, "source": f"/proc/{pid}/cwd", "pid": pid})
    for container in containers or []:
        project_dir = container.get("compose_working_dir")
        if not project_dir or not os.path.isdir(project_dir):
            continue
        entries, truncated = _bounded_walk(project_dir, max_entries=400, max_depth=3)
        roots.append({
            "path": project_dir,
            "source": f"compose project of container {container.get('name')}",
            "sample": entries[:80],
            "truncated": truncated,
        })
        for mount in container.get("mounts") or []:
            source_path = mount.get("source")
            if mount.get("type") == "bind" and source_path and os.path.isdir(source_path):
                entries, truncated = _bounded_walk(source_path, max_entries=200, max_depth=2)
                roots.append({
                    "path": source_path,
                    "source": f"bind mount of container {container.get('name')}",
                    "sample": entries[:40],
                    "truncated": truncated,
                })
    for base in WEB_PATHS:
        real = _rooted(system_root, base)
        if not os.path.isdir(real):
            continue
        entries, truncated = _bounded_walk(real, max_entries=800, max_depth=2)
        roots.append({
            "path": base,
            "source": "well-known web path",
            "sample": entries[:40],
            "truncated": truncated,
        })
    for base in CONFIG_CANDIDATES:
        real = _rooted(system_root, base)
        if os.path.isdir(real):
            entries, _ = _bounded_walk(real, max_entries=200, max_depth=2)
            roots.append({"path": base, "source": "config location", "sample": entries[:30]})
    seen = set()
    unique = []
    for item in roots:
        key = item["path"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    ev.data = {"candidates": unique}
    if not unique:
        ev.status = "partial"
        ev.gaps.append("no application root candidates found")
    return ev


def collect_proxy_config(system_root: str) -> Evidence:
    ev = Evidence("reverse_proxy")
    found: List[Dict[str, Any]] = []
    nginx_root = _rooted(system_root, "/etc/nginx")
    if os.path.isdir(nginx_root):
        servers = []
        for path in util.iter_files(nginx_root, extensions=(".conf", ".vhost"), max_files=200):
            text = _read_small(path, 256 * 1024)
            if text is None:
                continue
            for match in re.finditer(
                r"server\s*\{(?:[^{}]|\{[^{}]*\})*\}", text, re.S
            ):
                block = match.group(0)
                if "proxy_pass" not in block and "listen" not in block:
                    continue
                servers.append({
                    "file": os.path.relpath(path, system_root).replace(os.sep, "/"),
                    "listen": re.findall(r"listen\s+([^;]+);", block)[:5],
                    "server_name": re.findall(r"server_name\s+([^;]+);", block)[:5],
                    "proxy_pass": re.findall(r"proxy_pass\s+([^;]+);", block)[:5],
                    "root": re.findall(r"\broot\s+([^;]+);", block)[:3],
                })
        found.append({"kind": "nginx", "config_root": "/etc/nginx", "servers": servers[:40]})
    apache_dirs = [d for d in ("/etc/apache2/sites-enabled", "/etc/httpd/conf.d")
                   if os.path.isdir(_rooted(system_root, d))]
    for directory in apache_dirs:
        vhosts = []
        for path in util.iter_files(_rooted(system_root, directory), max_files=100):
            text = _read_small(path, 128 * 1024)
            if not text:
                continue
            vhosts.append({
                "file": os.path.relpath(path, system_root).replace(os.sep, "/"),
                "listen": re.findall(r"Listen\s+([^\n]+)", text)[:5],
                "server_name": re.findall(r"ServerName\s+([^\n]+)", text)[:5],
                "proxypass": re.findall(r"ProxyPass\s+([^\n]+)", text)[:5],
                "document_root": re.findall(r"DocumentRoot\s+([^\n]+)", text)[:3],
            })
        found.append({"kind": "apache", "config_root": directory, "vhosts": vhosts[:40]})
    ev.data = {"reverse_proxies": found}
    if not found:
        ev.status = "partial"
        ev.gaps.append("no nginx/apache configuration found: reverse-proxy topology unknown")
    ev.detail = "parsed server blocks for listen/proxy_pass/root only"
    return ev


def collect_databases(caps: platformx.Capabilities, system_root: str, listeners: List[Dict[str, Any]],
                      processes: List[Dict[str, Any]]) -> Evidence:
    ev = Evidence("databases")
    hints: List[Dict[str, Any]] = []
    for record in listeners:
        port = record.get("port")
        candidates = PORT_HINTS.get(port or -1, [])
        if any(c in ("mysql", "mariadb", "postgres", "redis", "mongodb", "elasticsearch",
                     "memcached") for c in candidates):
            hints.append({"kind": "listener", "detail": f"port {port}", "candidates": candidates,
                          "address": record.get("address"), "exposure": record.get("exposure")})
    for proc in processes:
        comm = (proc.get("comm") or "").lower()
        if any(h in comm for h in DB_HINTS):
            hints.append({"kind": "process", "detail": comm, "pid": proc.get("pid")})
    for path in ("/var/lib/postgresql", "/var/lib/mysql", "/var/lib/redis", "/var/lib/mongodb"):
        if os.path.isdir(_rooted(system_root, path)):
            hints.append({"kind": "datadir", "detail": path})
    ev.data = {"hints": hints}
    if not hints:
        ev.detail = "no database indicators found"
    else:
        ev.detail = f"{len(hints)} database indicator(s); each is a hint, not a confirmed engine"
    return ev


def collect_filesystem_risk(system_root: str, app_roots: Sequence[str]) -> Evidence:
    """Targeted permission findings. Stats only -- never reads contents."""
    ev = Evidence("filesystem_permissions")
    findings: List[Dict[str, Any]] = []
    inspected = 0
    for root in list(app_roots)[:6]:
        real_root = _rooted(system_root, root) if root.startswith("/") else root
        if not os.path.isdir(real_root):
            continue
        for rel in _bounded_walk(real_root, max_entries=600, max_depth=3)[0]:
            path = os.path.join(real_root, rel)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            inspected += 1
            if not os.path.isfile(path):
                continue
            name = os.path.basename(path)
            mode = st.st_mode & 0o777
            if mode & 0o002:
                findings.append({"path": path, "issue": "world-writable", "mode": oct(mode)})
            elif mode & 0o020:
                findings.append({"path": path, "issue": "group-writable", "mode": oct(mode)})
            if _is_sensitive(name):
                findings.append({
                    "path": path,
                    "issue": "sensitive-looking filename",
                    "mode": oct(mode),
                    "note": "stat only; contents were not read",
                })
    ev.data = {"findings": findings[:200], "inspected_files": inspected,
               "truncated": len(findings) > 200}
    ev.detail = (
        "permission findings are candidates for review, never automatic change targets: "
        "a writable file may be deliberate"
    )
    return ev


def collect_firewall(caps: platformx.Capabilities, allow_subprocess: bool) -> Evidence:
    ev = Evidence("firewall")
    if not allow_subprocess:
        ev.status = "unsupported"
        ev.detail = "subprocess collectors disabled"
        return ev
    if not caps.is_linux:
        ev.status = "unsupported"
        ev.detail = "firewall inspection is Linux-only in this toolkit"
        return ev
    state: Dict[str, Any] = {}
    if util.which("ufw"):
        res = util.run(["ufw", "status", "verbose"], timeout=15, max_output=64 * 1024)
        state["ufw"] = {
            "available": True,
            "readable": res.ok,
            "status": util.printable(res.stdout.splitlines()[0] if res.ok and res.stdout else "", 80),
            "detail": util.printable(res.stderr.strip(), 200) if not res.ok else "",
        }
        if not res.ok:
            ev.gaps.append("ufw state requires root: current firewall policy is unknown")
    if util.which("firewall-cmd"):
        res = util.run(["firewall-cmd", "--state"], timeout=10, max_output=4096)
        running = res.ok and "running" in res.stdout
        listing = ""
        if running:
            listing = util.run(["firewall-cmd", "--list-all"], timeout=15,
                               max_output=64 * 1024).stdout
        state["firewalld"] = {"available": True, "running": running,
                              "runtime_listing": util.printable(listing, 1200)}
    if util.which("nft"):
        res = util.run(["nft", "list", "ruleset"], timeout=15, max_output=256 * 1024)
        lines = res.stdout.splitlines() if res.ok else []
        state["nftables"] = {
            "available": True, "readable": res.ok, "tables": sum(1 for l in lines if l.startswith("table")),
            "rules_shown": min(len(lines), MAX_RULESET_LINES), "truncated": len(lines) > MAX_RULESET_LINES,
        }
        if not res.ok:
            ev.gaps.append("nftables ruleset requires root: raw rules unknown")
    if util.which("iptables"):
        res = util.run(["iptables", "-S"], timeout=15, max_output=128 * 1024)
        state["iptables"] = {"available": True, "readable": res.ok,
                             "rule_lines": len(res.stdout.splitlines()) if res.ok else 0}
    if not state:
        ev.status = "unsupported"
        ev.detail = "no firewall frontend or ruleset tool found"
        ev.gaps.append("no firewall tooling detected; exposure may be unmanaged or managed elsewhere")
        return ev
    ev.data = state
    ev.detail = (
        "reported for review only. This toolkit never enables a default-deny policy and never "
        "flushes rules automatically."
    )
    return ev


def collect_scheduled(system_root: str, allow_subprocess: bool) -> Evidence:
    ev = Evidence("scheduled")
    entries: List[Dict[str, Any]] = []
    for directory in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/var/spool/cron"):
        real = _rooted(system_root, directory)
        if not os.path.isdir(real):
            continue
        names, _ = _bounded_walk(real, max_entries=120, max_depth=2)
        for name in names:
            entries.append({"kind": "cron-file", "path": f"{directory}/{name}".replace("//", "/")})
    crontab = _read_small(_rooted(system_root, "/etc/crontab"), 32 * 1024)
    if crontab:
        active = [line.strip() for line in crontab.splitlines()
                  if line.strip() and not line.strip().startswith("#")]
        entries.append({"kind": "crontab", "path": "/etc/crontab", "active_lines": len(active)})
    if allow_subprocess and util.which("systemctl"):
        res = util.run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
                       timeout=15, max_output=256 * 1024)
        if res.ok:
            timers = [line.split()[0] for line in res.stdout.splitlines() if line.strip()]
            entries.append({"kind": "systemd-timers", "count": len(timers),
                            "names": timers[:60]})
    ev.data = {"entries": entries}
    ev.detail = "provenance is intentionally not guessed: scheduled jobs are reported, not judged"
    if not entries:
        ev.status = "partial"
        ev.gaps.append("no scheduled-job evidence found (may simply be none)")
    return ev


def collect_env_names(caps: platformx.Capabilities, system_root: str,
                      pids: Sequence[int]) -> Evidence:
    """Variable NAMES only, never values. Presence of DATABASE_URL is the signal."""
    ev = Evidence("service_env_names")
    out: Dict[str, List[str]] = {}
    for pid in pids:
        path = _rooted(system_root, f"/proc/{pid}/environ")
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > 256 * 1024:
            continue
        try:
            with open(path, "rb") as fh:
                raw = fh.read(256 * 1024)
        except OSError:
            continue
        names = sorted({
            item.split(b"=", 1)[0].decode("utf-8", "replace")
            for item in raw.split(b"\x00") if b"=" in item
        })
        out[str(pid)] = names[:100]
    ev.data = {"by_pid": out}
    ev.detail = "environment variable names only; values were never read into the report"
    if not out:
        ev.status = "partial"
        ev.gaps.append("/proc/<pid>/environ not readable: service configuration inferred from files only")
    return ev


# --------------------------------------------------------------------------
# Graph construction
# --------------------------------------------------------------------------
def build_graph(inventory: Inventory) -> Dict[str, Any]:
    """Derive service candidates with explicit confidence and evidence."""
    by_kind = {e.kind: e for e in inventory.evidence}
    listeners = (by_kind.get("listeners").data.get("listeners") if by_kind.get("listeners") else []) or []
    owners = (by_kind.get("socket_owners").data.get("socket_to_pids")
              if by_kind.get("socket_owners") else {}) or {}
    units_by_pid = (by_kind.get("units").data.get("by_pid") if by_kind.get("units") else {}) or {}
    processes = {}
    if by_kind.get("processes"):
        for proc in by_kind["processes"].data.get("processes", []) or []:
            processes[str(proc.get("pid"))] = proc
    containers = (by_kind.get("containers").data.get("containers")
                  if by_kind.get("containers") else []) or []
    proxies = (by_kind.get("reverse_proxy").data.get("reverse_proxies")
               if by_kind.get("reverse_proxy") else []) or []

    # Container port publications are listener evidence in their own right: the
    # host really is accepting connections on that port, whether or not an
    # unprivileged socket listing can see it (Docker NAT, or a platform without
    # /proc). They are added only when no socket record already covers the port.
    covered = {(rec.get("proto"), rec.get("port")) for rec in listeners}
    for container in containers:
        for published in container.get("published") or []:
            try:
                host_port = int(published.get("host_port"))
            except (TypeError, ValueError):
                continue
            container_port = str(published.get("container_port") or "")
            proto = "tcp"
            port_part = container_port.split("/")
            if len(port_part) == 2:
                proto = port_part[1] or "tcp"
            if (proto, host_port) in covered:
                continue
            covered.add((proto, host_port))
            host_ip = published.get("host_ip") or "0.0.0.0"
            listeners.append({
                "proto": proto,
                "family": "ipv6" if ":" in str(host_ip) else "ipv4",
                "address": host_ip,
                "port": host_port,
                "state": "listen",
                "process": None,
                "pid": None,
                "inode": None,
                "exposure": _exposure(str(host_ip)),
                "stack_candidates": PORT_HINTS.get(host_port, []),
                "published_container_port": container_port,
                "source": f"docker inspect: {container.get('name')} publishes "
                          f"{host_ip}:{host_port} -> {container_port}",
            })

    services: List[Dict[str, Any]] = []
    for record in listeners:
        entry: Dict[str, Any] = {
            "port": record.get("port"),
            "address": record.get("address"),
            "proto": record.get("proto"),
            "exposure": record.get("exposure"),
            "stack_candidates": record.get("stack_candidates", []),
            "evidence": [f"listener {record.get('proto')} {record.get('address')}:{record.get('port')}"
                         f" via {record.get('source')}"],
            "confidence": "low",
            "process": record.get("process"),
            "pid": record.get("pid"),
            "unit": None,
            "container": None,
            "app_root": None,
            "unsupported_reason": None,
        }
        inode = record.get("inode")
        if not entry["pid"] and inode and owners.get(str(inode)):
            entry["pid"] = owners[str(inode)][0]
            entry["evidence"].append(f"socket inode {inode} owned by pid {entry['pid']}")
        if entry["pid"]:
            proc = processes.get(str(entry["pid"]))
            if proc:
                entry["process"] = proc.get("comm")
                entry["confidence"] = "medium"
                entry["evidence"].append(f"pid {entry['pid']} comm '{proc.get('comm')}'")
            unit = units_by_pid.get(str(entry["pid"]))
            if unit:
                entry["unit"] = unit.get("unit")
                entry["app_root"] = unit.get("working_directory") or None
                entry["confidence"] = "high"
                entry["evidence"].append(
                    f"systemd unit {unit.get('unit')} (fragment {unit.get('fragment_path')})"
                )
        for container in containers:
            for published in container.get("published", []) or []:
                if str(published.get("host_port")) == str(entry["port"]) or (
                    published.get("container_port", "").startswith(str(entry["port"]) + "/")
                ):
                    entry["container"] = {
                        "name": container.get("name"), "image": container.get("image"),
                        "compose_project": container.get("compose_project"),
                        "compose_service": container.get("compose_service"),
                        "network_mode": container.get("network_mode"),
                        "container_port": published.get("container_port"),
                    }
                    if entry["confidence"] != "high":
                        entry["confidence"] = "high"
                    entry["evidence"].append(
                        f"docker published {published.get('host_ip')}:{published.get('host_port')}"
                        f" -> {container.get('name')} {published.get('container_port')}"
                    )
        for proxy in proxies:
            for server in proxy.get("servers", []) or []:
                for upstream in server.get("proxy_pass", []) or []:
                    port_match = re.search(r":(\d+)", upstream)
                    if port_match and int(port_match.group(1)) == entry["port"]:
                        entry["evidence"].append(
                            f"nginx {server.get('file')} proxies to {upstream}"
                        )
                        if entry["confidence"] == "low":
                            entry["confidence"] = "medium"
        if not entry["process"] and not entry["container"]:
            entry["unsupported_reason"] = (
                "no process or container attribution: an unknown listener is never a mutation target"
            )
        services.append(entry)

    return {
        "services": sorted(services, key=lambda s: (s.get("port") or 0, s.get("proto") or "")),
        "containers": containers,
        "reverse_proxies": proxies,
        "confidence_legend": {
            "high": "process/unit or container attribution plus a corroborating source",
            "medium": "process attribution without unit/container, or proxy evidence",
            "low": "listener only: stack unknown, do not mutate",
        },
    }


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def discover(*, system_root: str = "/", allow_subprocess: bool = True,
             quick: bool = False) -> Inventory:
    caps = platformx.probe(quick=quick, system_root=system_root)
    fixture_mode = system_root not in ("/", "")
    if fixture_mode and not allow_subprocess:
        pass
    evidence: List[Evidence] = []
    host = collect_host(caps, system_root)
    evidence.append(host)
    evidence.append(collect_resources(system_root))
    listeners_ev = collect_listeners(caps, system_root, allow_subprocess)
    evidence.append(listeners_ev)
    listener_records = listeners_ev.data.get("listeners", [])
    pids = sorted({rec.get("pid") for rec in listener_records if rec.get("pid")})
    processes_ev = collect_processes(caps, system_root, allow_subprocess, pids)
    evidence.append(processes_ev)
    evidence.append(collect_socket_owners(caps, system_root, listener_records))
    evidence.append(collect_units(caps, allow_subprocess, pids[:20]))
    containers_ev = collect_containers(caps, allow_subprocess)
    evidence.append(containers_ev)
    containers = containers_ev.data.get("containers", []) or []
    evidence.append(collect_app_roots(caps, system_root, pids[:10], containers))
    evidence.append(collect_proxy_config(system_root))
    evidence.append(collect_databases(caps, system_root, listener_records,
                                      processes_ev.data.get("processes", [])))
    roots = [item["path"] for item in
             (evidence[-4].data.get("candidates") or []) if str(item.get("path", "")).startswith("/")]
    evidence.append(collect_filesystem_risk(system_root, roots))
    evidence.append(collect_firewall(caps, allow_subprocess))
    evidence.append(collect_scheduled(system_root, allow_subprocess))
    evidence.append(collect_env_names(caps, system_root, pids[:10]))

    inventory = Inventory(
        mode="fixture-root" if fixture_mode else "live",
        system_root=system_root,
        generated_at=util.iso_now(),
        host=host.data,
        evidence=evidence,
    )
    inventory.graph = build_graph(inventory)
    if not caps.is_root:
        inventory.graph["privilege_note"] = (
            "Discovery ran unprivileged. Port-to-process mapping, firewall state, container "
            "inventory and unit properties may be incomplete; each gap is listed in 'gaps'."
        )
    return inventory


def summary(inventory: Inventory, limit: int = 25) -> str:
    lines: List[str] = []
    host = inventory.host
    lines.append(
        f"host      {host.get('os_pretty_name') or host.get('platform')} "
        f"kernel={host.get('kernel')} arch={host.get('arch')} init={host.get('init_system')}"
    )
    lines.append(
        f"mode      {inventory.mode}  root={host.get('is_root')}  generated={inventory.generated_at}"
    )
    services = inventory.graph.get("services", [])
    lines.append("")
    lines.append(f"listeners ({len(services)}):")
    lines.append(f"  {'port':>6}  {'exposure':<16} {'confidence':<10} {'process / container':<28} evidence")
    for service in services[:limit]:
        who = service.get("process") or (
            f"container:{service['container']['compose_service']}"
            if service.get("container") else "-"
        )
        lines.append(
            f"  {str(service.get('port')):>6}  {str(service.get('exposure')):<16} "
            f"{str(service.get('confidence')):<10} {who[:28]:<28} "
            f"{(service.get('evidence') or [''])[0][:70]}"
        )
    if len(services) > limit:
        lines.append(f"  ... {len(services) - limit} more")
    containers = inventory.graph.get("containers", [])
    if containers:
        lines.append("")
        lines.append(f"containers ({len(containers)}):")
        for container in containers[:12]:
            lines.append(
                f"  {container.get('name')}  image={container.get('image')}  "
                f"project={container.get('compose_project')}  service={container.get('compose_service')}"
                f"  net={container.get('network_mode')}"
            )
    gaps = inventory.gaps()
    lines.append("")
    lines.append(f"evidence gaps ({len(gaps)}):")
    for gap in gaps[:12]:
        lines.append(f"  - {gap}")
    if len(gaps) > 12:
        lines.append(f"  ... {len(gaps) - 12} more (see JSON)")
    lines.append("")
    lines.append(
        "reminder: a port is not a stack. Confidence 'low' means unknown -- the planner will "
        "refuse to propose mutations for it."
    )
    return "\n".join(lines)
