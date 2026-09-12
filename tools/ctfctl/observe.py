"""Bounded log and network observation.

Default posture is "lightweight logs and short, rotating captures", not a SIEM:

  * every source has a byte/time budget and stops cleanly when it is reached;
  * log lines are escaped before display so terminal control sequences in
    attacker-supplied data cannot do anything;
  * captures are written under captures/ (git-ignored) with rotation limits;
  * packet capture is never promiscuous, never "any" by default, and refuses to
    start without an explicit interface or a safe default.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import platformx, util

DEFAULT_LOG_LINES = 500
MAX_LOG_LINES = 5000
DEFAULT_SECONDS = 60
MAX_SECONDS = 1800
MAX_EVENT_BYTES = 512 * 1024


@dataclass
class ObservationConfig:
    log_paths: List[str] = field(default_factory=list)
    journal_units: List[str] = field(default_factory=list)
    include_regex: Optional[str] = None
    exclude_regex: Optional[str] = None
    seconds: int = DEFAULT_SECONDS
    max_lines: int = DEFAULT_LOG_LINES
    max_bytes: int = 4 * 1024 * 1024
    net_interface: Optional[str] = None
    net_filter: str = "tcp or udp"
    net_count: int = 500
    net_snaplen: int = 256
    net_rotate_seconds: int = 30
    net_files: int = 4
    dry_run: bool = False
    output_dir: Optional[str] = None


def event_path(config: ObservationConfig, root: str, kind: str) -> str:
    directory = config.output_dir or os.path.join(root, util.CAPTURES_DIRNAME)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    return os.path.join(directory, f"obs-{kind}-{util.utc_stamp()}.jsonl")


class EventWriter:
    """JSONL writer with a hard size cap and escaped, redacted fields."""

    def __init__(self, path: str, max_bytes: int = MAX_EVENT_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.written = 0
        self.stopped = False
        self._fh = open(path, "a", encoding="utf-8")

    def emit(self, kind: str, **fields: Any) -> None:
        if self.stopped:
            return
        record = {"at": util.iso_now(), "kind": kind}
        for key, value in fields.items():
            if isinstance(value, str):
                record[key] = util.printable(util.redact(value), 600)
            else:
                record[key] = value
        line = json.dumps(record, sort_keys=True) + "\n"
        if self.written + len(line) > self.max_bytes:
            self.stopped = True
            self._fh.write(json.dumps({
                "at": util.iso_now(), "kind": "observation-stopped",
                "reason": f"byte budget {self.max_bytes} reached",
            }) + "\n")
            self._fh.flush()
            return
        self._fh.write(line)
        self.written += len(line)
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


def observe_logs(config: ObservationConfig, writer: EventWriter,
                 caps: Optional[platformx.Capabilities] = None) -> Dict[str, Any]:
    """Follow files and/or journald for a bounded window."""
    include = re.compile(config.include_regex) if config.include_regex else None
    exclude = re.compile(config.exclude_regex) if config.exclude_regex else None
    deadline = time.time() + max(1, min(config.seconds, MAX_SECONDS))
    lines_seen = 0
    bytes_seen = 0
    sources: List[Dict[str, Any]] = []

    streams: List[Any] = []
    for path in config.log_paths:
        if not os.path.isfile(path):
            sources.append({"source": path, "status": "missing"})
            continue
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
            fh.seek(0, os.SEEK_END)
            streams.append((path, fh, None))
            sources.append({"source": path, "status": "tailing"})
        except OSError as exc:
            sources.append({"source": path, "status": f"unreadable: {exc}"})

    journal_proc: Optional[subprocess.Popen] = None
    if config.journal_units and util.which("journalctl"):
        argv = ["journalctl", "--follow", "--no-pager", "--output", "short-iso"]
        for unit in config.journal_units:
            argv += ["-u", unit]
        journal_proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True)
        sources.append({"source": "journalctl", "units": config.journal_units, "status": "tailing"})
    elif config.journal_units:
        sources.append({"source": "journalctl", "status": "unavailable"})

    def handle(line: str, origin: str) -> bool:
        nonlocal lines_seen, bytes_seen
        if include and not include.search(line):
            return True
        if exclude and exclude.search(line):
            return True
        lines_seen += 1
        bytes_seen += len(line)
        severity = "error" if re.search(r"\b(error|500|exception|traceback)\b", line, re.I) else \
            "info"
        writer.emit("log", origin=origin, severity=severity, line=line.rstrip())
        if lines_seen >= config.max_lines or bytes_seen >= config.max_bytes or writer.stopped:
            return False
        return True

    try:
        while time.time() < deadline:
            progressed = False
            for origin, fh, _ in streams:
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    progressed = True
                    if not handle(line, origin):
                        raise KeyboardInterrupt
            if journal_proc and journal_proc.stdout:
                import selectors

                selector = selectors.DefaultSelector()
                selector.register(journal_proc.stdout, selectors.EVENT_READ)
                while selector.select(timeout=0.2):
                    line = journal_proc.stdout.readline()
                    if not line:
                        break
                    progressed = True
                    if not handle(line, "journalctl"):
                        raise KeyboardInterrupt
                selector.close()
            if not progressed:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for _, fh, _ in streams:
            fh.close()
        if journal_proc:
            journal_proc.terminate()
            try:
                journal_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                journal_proc.kill()

    return {
        "lines": lines_seen,
        "bytes": bytes_seen,
        "sources": sources,
        "events_file": writer.path,
        "stopped_by_budget": writer.stopped or lines_seen >= config.max_lines,
    }


def capture_command(config: ObservationConfig, root: str) -> List[str]:
    """Build the tcpdump argv. Never promiscuous, never 'any'."""
    interface = config.net_interface or default_interface()
    directory = config.output_dir or os.path.join(root, util.CAPTURES_DIRNAME)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    prefix = os.path.join(directory, "cap-" + util.utc_stamp())
    argv = [
        "tcpdump",
        "-i", interface,
        "-p",                       # never promiscuous
        "-s", str(config.net_snaplen),
        "-c", str(config.net_count),
        "-G", str(config.net_rotate_seconds),
        "-W", str(config.net_files),
        "-w", prefix + "-%Y%m%dT%H%M%SZ.pcap",
        "-z", "gzip",
    ]
    if config.net_filter:
        argv += config.net_filter.split()
    return argv


def default_interface() -> str:
    for candidate in ("eth0", "ens3", "ens18", "enp0s3"):
        if os.path.exists(f"/sys/class/net/{candidate}"):
            return candidate
    if os.path.exists("/sys/class/net"):
        try:
            names = [n for n in sorted(os.listdir("/sys/class/net")) if n != "lo"]
            if names:
                return names[0]
        except OSError:
            pass
    return "eth0"


def observe_net(config: ObservationConfig, root: str,
                writer: EventWriter) -> Dict[str, Any]:
    argv = capture_command(config, root)
    if config.dry_run:
        writer.emit("capture-planned", argv=argv, filter=config.net_filter,
                    interface=config.net_interface or default_interface())
        return {"dry_run": True, "argv": argv}
    if not util.which("tcpdump"):
        writer.emit("capture-unavailable", reason="tcpdump is not installed")
        return {"error": "tcpdump is not installed",
                "hint": "install it during online preparation, or use --logs only"}
    writer.emit("capture-started", argv=argv, interface=argv[2],
                filter=config.net_filter, snaplen=config.net_snaplen,
                files=config.net_files, rotate_seconds=config.net_rotate_seconds)
    started = time.time()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        while True:
            if proc.poll() is not None:
                break
            if time.time() - started > max(5, min(config.seconds, MAX_SECONDS)):
                proc.send_signal(signal.SIGINT)
                break
            time.sleep(0.5)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    finally:
        if proc.poll() is None:
            proc.kill()
    output = ""
    if proc.stdout:
        output = util.printable(proc.stdout.read(4096), 600)
    writer.emit("capture-stopped", returncode=proc.returncode, tail=output,
                duration_s=round(time.time() - started, 1))
    return {"returncode": proc.returncode, "duration_s": round(time.time() - started, 1),
            "events_file": writer.path}


def run(config: ObservationConfig, *, root: Optional[str] = None,
        caps: Optional[platformx.Capabilities] = None) -> Dict[str, Any]:
    root = root or util.repo_root()
    caps = caps or platformx.probe(quick=True)
    results: Dict[str, Any] = {"logs": None, "net": None, "events_files": []}
    if config.log_paths or config.journal_units:
        writer = EventWriter(event_path(config, root, "logs"))
        try:
            results["logs"] = observe_logs(config, writer, caps)
            results["events_files"].append(writer.path)
        finally:
            writer.close()
    if config.net_interface or config.net_filter:
        writer = EventWriter(event_path(config, root, "net"))
        try:
            results["net"] = observe_net(config, root, writer)
            results["events_files"].append(writer.path)
        finally:
            writer.close()
    if not config.log_paths and not config.journal_units and not config.net_interface:
        results["note"] = (
            "nothing observed: pass --logs <path> / --unit <name> and/or --iface <name>. "
            "This command never starts a capture on its own."
        )
    return results


def summarize(results: Dict[str, Any]) -> str:
    lines: List[str] = []
    logs = results.get("logs")
    if logs:
        lines.append(f"logs      {logs['lines']} line(s), {util.human_bytes(logs['bytes'])}"
                     f" -> {logs['events_file']}")
        for source in logs["sources"]:
            lines.append(f"          {source.get('source')}: {source.get('status')}")
        if logs.get("stopped_by_budget"):
            lines.append("          stopped early: line/byte budget reached")
    net = results.get("net")
    if net:
        if net.get("dry_run"):
            lines.append("capture   dry run (not started):")
            lines.append("          " + " ".join(net["argv"]))
        elif net.get("error"):
            lines.append(f"capture   {net['error']}")
        else:
            lines.append(f"capture   finished rc={net.get('returncode')} "
                         f"in {net.get('duration_s')}s")
    if results.get("note"):
        lines.append(results["note"])
    lines.append("")
    lines.append("captures live in captures/ and are git-ignored. Raw packets are never committed.")
    return "\n".join(lines)
