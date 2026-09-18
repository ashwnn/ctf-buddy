"""Bounded, read-only log triage for nginx/Apache access logs and SSH auth logs.

This is triage, not proof. Every stored match is a candidate (an "indicator")
that a human must confirm against the challenge; the absence of a match is not
the absence of activity, and a truncated scan says nothing about the lines it
did not read.

Input handling:
  * one local regular file is read line by line; nothing is executed, nothing
    is written and no network is used;
  * the scan stops at the first cap (bytes, lines or wall-clock seconds) and
    ``stopped_by_limit`` names which one; ``complete`` is true only when the
    whole file was read under the configured caps;
  * each line is scanned for at most ``MAX_LINE_SCAN_BYTES`` bytes; longer
    lines are counted in ``counts.truncated_lines``, add ``max-line-length``
    to ``limits.reasons`` and make the report incomplete;
  * a line that matches no known format is counted as unparsed and never
    aborts the scan;
  * stored examples are capped (per category and in total) while the counters
    for stored keys stay exact; a capped counter reports ``distinct``,
    ``stored`` and ``other_hits`` so the truncation is visible.

Formats recognized (permissive per-line regexes):
  * nginx/Apache common and combined access logs: source IP, status, request
    and the optional referer/user-agent fields;
  * OpenSSH auth lines: ``Failed password``/``Failed publickey``,
    ``Accepted password``/``Accepted publickey`` and ``Invalid user``.

Access lines are checked for candidate attack indicators: path traversal
(plain and encoded), SQLi markers, XSS markers, SSTI markers, Log4Shell
``${jndi:`` forms, webshell-like paths and known scanner user agents. Each
category counts matching lines (at most once per line), deduplicates evidence,
and stores a few escaped examples. SSH failures above ``--brute-threshold``
from a single source produce a brute-force indicator. Both are labels, not
proof.

Flag-regex matches are candidates, not proof. The default pattern is
``[A-Za-z0-9_]{2,32}\\{[^\\s{}]{3,200}\\}``; matches are deduplicated, escaped
and capped, and a custom pattern runs over untrusted input, so keep it linear
(no nested quantifiers).

Default limits: 64 MiB, 200000 lines, 60 s, 64 KiB scanned per line, 50
distinct stored values per counter, 5 stored examples per indicator category,
200 stored examples in total, 50 distinct flag candidates and ``--top`` 10
list entries. Nothing is executed; no shell; no writes.
"""

from __future__ import annotations

import os
import re
import stat
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Pattern, Set, Tuple

from . import util

SCHEMA = "ctfctl.logtriage/1"

DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_]{2,32}\{[^\s{}]{3,200}\}"
MAX_FLAG_REGEX = 512
MAX_FLAG_MATCHES = 50

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_LINES = 200_000
DEFAULT_MAX_SECONDS = 60.0
MAX_SECONDS_CAP = 3600.0
DEFAULT_BRUTE_THRESHOLD = 10
DEFAULT_TOP = 10
MAX_TOP = 100

MAX_LINE_SCAN_BYTES = 64 * 1024
MAX_SUBJECT_CHARS = 4096
MAX_DISTINCT = 50
MAX_EXAMPLES = 5
MAX_FINDINGS = 200
PREVIEW_CHARS = 200

NOTE = (
    "log triage is triage, not proof: indicator labels and flag-regex matches "
    "are candidates to verify, and a truncated scan says nothing about the "
    "lines it did not read."
)

_ACCESS_RE = re.compile(
    r"^\s*(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]*)\]\s+"
    r'(?P<request>"(?:\\.|[^"\\])*")\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r"(?P<rest>.*)$"
)
_ACCESS_QUOTED = re.compile(r'"((?:\\.|[^"\\])*)"')
_HTTP_METHOD_RE = re.compile(r"[A-Z]{3,10}\Z")

_SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|none|keyboard-interactive(?:/pam)?) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
_SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")

_REQUEST_INDICATORS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("path-traversal", re.compile(r"(?:\.\.[/\\]|%252e|%c0%ae)", re.IGNORECASE)),
    (
        "sqli",
        re.compile(
            r"(?:\bunion\b[\s/*%]{0,16}\bselect\b"
            r"|\bselect\b.{0,40}\bfrom\b"
            r"|\bor\b\s+[\w'\"]{1,16}\s*=\s*[\w'\"]{1,16}"
            r"|\bsleep\s*\(|\bbenchmark\s*\(|information_schema"
            r"|\bload_file\s*\(|into\s+outfile|\bxp_cmdshell\b"
            r"|waitfor\s+delay|;\s*--)",
            re.IGNORECASE,
        ),
    ),
    (
        "xss",
        re.compile(
            r"(?:<script\b|%3cscript|on(?:error|load|mouseover|focus)\s*="
            r"|<img\b|<svg\b|javascript:|document\.cookie|alert\s*\()",
            re.IGNORECASE,
        ),
    ),
    ("ssti", re.compile(r"(?:\{\{.{0,40}\}\}|\$\{[^}\n]{1,80}\}|<%[=-]|#\{)")),
    (
        "log4shell",
        re.compile(
            r"(?:\$\{jndi:(?:ldap|rmi|dns|http|iiop)"
            r"|\$\{env:|\$\{lower:|\$\{upper:|\$\{sys:|\$\{date:)"
            r"|%24%7bjndi",
            re.IGNORECASE,
        ),
    ),
    (
        "webshell",
        re.compile(
            r"[/\\](?:shell|cmd|webshell|backdoor|c99|r57|b374k|wso|alfa|eval"
            r"|upload|admin|adminer|phpinfo|mysql|db)\w{0,16}"
            r"\.(?:php\d?|phtml|jspx?|asp|aspx)\b",
            re.IGNORECASE,
        ),
    ),
)
_SCANNER_UA_RE = re.compile(
    r"(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|feroxbuster"
    r"|wfuzz|ffuf|nuclei|wpscan|whatweb|hydra|patator|medusa|acunetix"
    r"|nessus|openvas|metasploit)",
    re.IGNORECASE,
)


class LogTriageError(util.CtfError):
    """Expected negative result: input missing, unreadable or not a file."""


# --------------------------------------------------------------------------
# Bounded counters and findings
# --------------------------------------------------------------------------
class _CappedCounts:
    """At most ``limit`` distinct keys; counts stay exact per stored key.

    Keys beyond the limit roll into ``other_hits`` while ``distinct`` keeps the
    exact number of distinct keys seen.
    """

    def __init__(self, limit: int = MAX_DISTINCT) -> None:
        self.limit = limit
        self.counts: Dict[str, int] = {}
        self.distinct = 0
        self.other_hits = 0

    def add(self, key: str, amount: int = 1) -> None:
        current = self.counts.get(key)
        if current is not None:
            self.counts[key] = current + amount
            return
        self.distinct += 1
        if len(self.counts) < self.limit:
            self.counts[key] = amount
        else:
            self.other_hits += amount

    def payload(self, top: int, key_name: str) -> Dict[str, Any]:
        ranked = sorted(self.counts.items(), key=lambda item: (-item[1], item[0]))
        return {
            "values": [
                {key_name: util.printable(name, 160), "count": count}
                for name, count in ranked[:top]
            ],
            "distinct": self.distinct,
            "stored": len(self.counts),
            "other_hits": self.other_hits,
            "truncated": self.distinct > len(self.counts) or len(ranked) > top,
        }


@dataclass
class _Indicator:
    category: str
    count: int = 0
    examples: List[Dict[str, Any]] = field(default_factory=list)
    examples_truncated: bool = False


class _IndicatorSet:
    """Per-category line counts with capped, deduplicated stored examples."""

    def __init__(self) -> None:
        self.items: Dict[str, _Indicator] = {}
        self.seen: Dict[str, Set[str]] = {}
        self.distinct_capped: Set[str] = set()
        self.stored_examples = 0

    def hit(self, category: str, evidence: str, line: int, source: str) -> None:
        item = self.items.get(category)
        if item is None:
            item = _Indicator(category)
            self.items[category] = item
            self.seen[category] = set()
        item.count += 1
        safe = util.printable(evidence, PREVIEW_CHARS)
        seen = self.seen[category]
        if safe not in seen:
            if len(seen) < MAX_DISTINCT:
                seen.add(safe)
            else:
                self.distinct_capped.add(category)
        if len(item.examples) < MAX_EXAMPLES and self.stored_examples < MAX_FINDINGS:
            item.examples.append({"line": line, "source": source, "evidence": evidence})
            self.stored_examples += 1
        else:
            item.examples_truncated = True

    def payload(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in sorted(self.items.values(), key=lambda i: (-i.count, i.category)):
            seen = self.seen[item.category]
            out.append(
                {
                    "category": item.category,
                    "label": "indicator",
                    "count": item.count,
                    "distinct_evidence": len(seen),
                    "distinct_evidence_capped": item.category in self.distinct_capped,
                    "examples": [_example_payload(ex) for ex in item.examples],
                    "examples_truncated": item.examples_truncated,
                }
            )
        return out


@dataclass
class _FlagState:
    total: int = 0
    seen: Set[str] = field(default_factory=set)
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    truncated: bool = False

    def hit(self, value: str, line: int) -> None:
        self.total += 1
        if value in self.seen:
            return
        if len(self.seen) < MAX_FLAG_MATCHES:
            self.seen.add(value)
            self.candidates.append({"value": value, "line": line})
        else:
            self.truncated = True


def _example_payload(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "line": item.get("line"),
        "source": util.printable(str(item.get("source", "")), 160),
        "user": util.printable(str(item.get("user", "")), 160),
        "evidence": util.printable(str(item.get("evidence", "")), PREVIEW_CHARS),
    }


# --------------------------------------------------------------------------
# Format parsing
# --------------------------------------------------------------------------
def _parse_access(text: str) -> Optional[Dict[str, str]]:
    match = _ACCESS_RE.match(text)
    if match is None:
        return None
    request = match.group("request")
    request_body = request[1:-1] if len(request) >= 2 else request
    quoted = _ACCESS_QUOTED.findall(match.group("rest"))
    ua = quoted[-1] if quoted else ""
    return {
        "ip": match.group("ip"),
        "request": request_body,
        "status": match.group("status"),
        "ua": ua,
        "raw": text,
    }


def _parse_ssh(text: str) -> Optional[Dict[str, Any]]:
    failed = _SSH_FAILED_RE.search(text)
    accepted = _SSH_ACCEPTED_RE.search(text)
    invalid = _SSH_INVALID_RE.search(text)
    if failed is None and accepted is None and invalid is None:
        return None
    user = ""
    ip = ""
    for match in (failed, accepted, invalid):
        if match is not None:
            user = match.group("user")
            ip = match.group("ip")
            break
    return {
        "user": user,
        "ip": ip,
        "failed": failed is not None,
        "accepted": accepted is not None,
        "invalid": invalid is not None
        or (failed is not None and "invalid user" in text),
        "raw": text,
    }


def _request_target(request: str) -> str:
    request = request.strip()
    if not request or request == "-":
        return "-"
    parts = request.split()
    if len(parts) >= 2 and _HTTP_METHOD_RE.match(parts[0]):
        return parts[1]
    return parts[0]


def _path_only(target: str) -> str:
    if not target or target == "-":
        return "-"
    if "://" in target:
        remainder = target.split("://", 1)[1]
        target = "/" + remainder.split("/", 1)[1] if "/" in remainder else "/"
    path = target.split("?", 1)[0]
    return path or "-"


def _indicator_subject(request: str) -> str:
    if not request or request == "-":
        return ""
    raw = request[:MAX_SUBJECT_CHARS]
    decoded = urllib.parse.unquote_plus(raw)
    if decoded != raw:
        return raw + " " + decoded
    return raw


def _access_evidence(request: str, ua: str) -> str:
    text = request
    if ua and ua != "-":
        text += ' ua="' + ua + '"'
    return util.printable(text, PREVIEW_CHARS)


# --------------------------------------------------------------------------
# Streaming scan
# --------------------------------------------------------------------------
@dataclass
class _State:
    flag_re: Pattern[str]
    brute_threshold: int
    complete: bool = False
    lines_read: int = 0
    bytes_read: int = 0
    lines_parsed: int = 0
    access_lines: int = 0
    ssh_lines: int = 0
    truncated_lines: int = 0
    limit_reasons: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    status_codes: Dict[str, int] = field(default_factory=dict)
    status_buckets: Dict[str, int] = field(
        default_factory=lambda: {
            "1xx": 0,
            "2xx": 0,
            "3xx": 0,
            "4xx": 0,
            "5xx": 0,
            "other": 0,
        }
    )
    sources: _CappedCounts = field(default_factory=_CappedCounts)
    paths: _CappedCounts = field(default_factory=_CappedCounts)
    agents: _CappedCounts = field(default_factory=_CappedCounts)
    ssh_failed: int = 0
    ssh_accepted: int = 0
    ssh_invalid: int = 0
    failed_source: _CappedCounts = field(default_factory=_CappedCounts)
    failed_user: _CappedCounts = field(default_factory=_CappedCounts)
    invalid_source: _CappedCounts = field(default_factory=_CappedCounts)
    invalid_users: _CappedCounts = field(default_factory=_CappedCounts)
    accepted_source: _CappedCounts = field(default_factory=_CappedCounts)
    failed_examples: List[Dict[str, Any]] = field(default_factory=list)
    accepted_examples: List[Dict[str, Any]] = field(default_factory=list)
    indicators: _IndicatorSet = field(default_factory=_IndicatorSet)
    flags: _FlagState = field(default_factory=_FlagState)

    def reason(self, name: str) -> None:
        if name not in self.limit_reasons:
            self.limit_reasons.append(name)


def _process_line(state: _State, text: str, line_no: int) -> None:
    for match in state.flag_re.finditer(text):
        state.flags.hit(util.printable(match.group(0), 160), line_no)
    parsed = _parse_access(text)
    if parsed is not None:
        state.access_lines += 1
        state.lines_parsed += 1
        _handle_access(state, parsed, line_no)
        return
    ssh = _parse_ssh(text)
    if ssh is not None:
        state.ssh_lines += 1
        state.lines_parsed += 1
        _handle_ssh(state, ssh, line_no)


def _handle_access(state: _State, parsed: Dict[str, str], line_no: int) -> None:
    ip = parsed["ip"]
    safe_ip = util.printable(ip, 160)
    state.sources.add(ip)
    request = parsed["request"]
    state.paths.add(_path_only(_request_target(request)))
    ua = parsed["ua"]
    if ua and ua != "-":
        state.agents.add(ua)
    status = parsed["status"]
    state.status_codes[status] = state.status_codes.get(status, 0) + 1
    bucket = status[0] + "xx" if status[0] in "12345" else "other"
    state.status_buckets[bucket] = state.status_buckets.get(bucket, 0) + 1
    subject = _indicator_subject(request)
    evidence = _access_evidence(request, ua)
    if subject:
        for category, pattern in _REQUEST_INDICATORS:
            if pattern.search(subject):
                state.indicators.hit(category, evidence, line_no, safe_ip)
    if ua and ua != "-" and _SCANNER_UA_RE.search(ua[:MAX_SUBJECT_CHARS]):
        state.indicators.hit("scanner", evidence, line_no, safe_ip)


def _handle_ssh(state: _State, parsed: Dict[str, Any], line_no: int) -> None:
    user = parsed["user"]
    ip = parsed["ip"]
    if parsed.get("failed"):
        state.ssh_failed += 1
        state.failed_source.add(ip)
        state.failed_user.add(user)
        if len(state.failed_examples) < MAX_EXAMPLES:
            state.failed_examples.append(
                {"line": line_no, "source": ip, "user": user, "evidence": parsed["raw"]}
            )
    if parsed.get("invalid"):
        state.ssh_invalid += 1
        state.invalid_source.add(ip)
        state.invalid_users.add(user)
    if parsed.get("accepted"):
        state.ssh_accepted += 1
        state.accepted_source.add(ip)
        if len(state.accepted_examples) < MAX_EXAMPLES:
            state.accepted_examples.append(
                {"line": line_no, "source": ip, "user": user, "evidence": parsed["raw"]}
            )


def _scan(
    state: _State,
    handle: Any,
    *,
    max_bytes: int,
    max_lines: int,
    deadline: float,
) -> None:
    while True:
        if time.monotonic() >= deadline:
            state.reason("max-seconds")
            break
        if state.lines_read >= max_lines:
            state.reason("max-lines")
            break
        raw = handle.readline()
        if not raw:
            state.complete = True
            break
        if state.bytes_read + len(raw) > max_bytes:
            state.reason("max-bytes")
            break
        state.bytes_read += len(raw)
        state.lines_read += 1
        if len(raw) > MAX_LINE_SCAN_BYTES:
            state.truncated_lines += 1
            state.reason("max-line-length")
            scan_bytes = raw[:MAX_LINE_SCAN_BYTES]
        else:
            scan_bytes = raw
        text = scan_bytes.decode("utf-8", "replace").rstrip("\r\n")
        _process_line(state, text, state.lines_read)


def _brute_force(state: _State) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    ranked = sorted(
        state.failed_source.counts.items(), key=lambda item: (-item[1], item[0])
    )
    for source, count in ranked:
        if count < state.brute_threshold:
            continue
        examples = [
            _example_payload(ex)
            for ex in state.failed_examples
            if ex["source"] == source
        ][:3]
        out.append(
            {
                "source": util.printable(source, 160),
                "failed": count,
                "threshold": state.brute_threshold,
                "label": "indicator",
                "examples": examples,
            }
        )
    return out


def _compile_flag_regex(flag_regex: str) -> Pattern[str]:
    if not isinstance(flag_regex, str):
        raise util.UsageError("--flag-regex must be a string")
    try:
        raw = flag_regex.encode("ascii")
    except UnicodeEncodeError as exc:
        raise util.UsageError("--flag-regex must be ASCII") from exc
    if not raw or len(raw) > MAX_FLAG_REGEX:
        raise util.UsageError(f"--flag-regex must be 1-{MAX_FLAG_REGEX} bytes")
    try:
        return re.compile(raw)
    except re.error as exc:
        raise util.UsageError(f"invalid --flag-regex: {exc}") from exc


def triage(
    path: str,
    *,
    flag_regex: str = DEFAULT_FLAG_REGEX,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    brute_threshold: int = DEFAULT_BRUTE_THRESHOLD,
    top: int = DEFAULT_TOP,
) -> Dict[str, Any]:
    """Triage one local log file and return the machine payload.

    Payload keys: ``schema``, ``path``, ``size``, ``format`` (access/ssh/
    unparsed line counts and the detected ``kind``), ``complete``,
    ``stopped_by_limit``, ``limits``, ``counts``, ``access`` (sources, paths,
    user agents, status buckets and top codes; null when no access line
    parsed), ``ssh`` (failure/accept/invalid counters, per-source and
    per-user maps, bounded examples and brute-force indicators; null when no
    SSH line parsed), ``indicators``, ``flags``, ``errors`` and ``note``.

    ``complete`` is true only when the whole file was read under the caps;
    ``stopped_by_limit`` names the cap that stopped the scan, and a stop is
    never implied to be complete. Raises ``LogTriageError`` (exit 1) for a
    missing, unreadable or non-regular input and ``util.UsageError`` (exit 2)
    for invalid limits or a bad flag regex.
    """
    if not path:
        raise util.UsageError("a path is required")
    if "\x00" in path:
        raise util.UsageError("path must not contain NUL bytes")
    for name, value in (
        ("--max-bytes", max_bytes),
        ("--max-lines", max_lines),
        ("--max-seconds", max_seconds),
        ("--brute-threshold", brute_threshold),
        ("--top", top),
    ):
        if value < 0:
            raise util.UsageError(f"{name} must not be negative")
    if brute_threshold < 1:
        raise util.UsageError("--brute-threshold must be at least 1")
    if top < 1:
        raise util.UsageError("--top must be at least 1")
    flag_re = _compile_flag_regex(flag_regex)

    resolved = os.path.abspath(path)
    safe_path = util.printable(path, 300)
    if not os.path.exists(resolved):
        raise LogTriageError(f"input does not exist: {safe_path}")
    try:
        info = os.stat(resolved)
    except OSError as exc:
        raise LogTriageError(
            f"cannot stat {safe_path}: {util.printable(str(exc), 200)}"
        ) from exc
    if stat.S_ISDIR(info.st_mode):
        raise LogTriageError(f"input is a directory, not a log file: {safe_path}")
    if not stat.S_ISREG(info.st_mode):
        raise LogTriageError(f"input is not a regular file: {safe_path}")

    top = min(int(top), MAX_TOP)
    max_seconds = min(float(max_seconds), MAX_SECONDS_CAP)
    state = _State(flag_re=flag_re, brute_threshold=int(brute_threshold))
    deadline = time.monotonic() + max_seconds
    try:
        handle = open(resolved, "rb")
    except OSError as exc:
        raise LogTriageError(
            f"cannot read {safe_path}: {util.printable(str(exc), 200)}"
        ) from exc
    with handle:
        try:
            _scan(
                state,
                handle,
                max_bytes=int(max_bytes),
                max_lines=int(max_lines),
                deadline=deadline,
            )
        except OSError as exc:
            state.errors.append(
                "read error after line "
                + str(state.lines_read)
                + ": "
                + util.printable(str(exc), 160)
            )
    return _payload(
        state,
        safe_path,
        int(info.st_size),
        max_bytes=int(max_bytes),
        max_lines=int(max_lines),
        max_seconds=max_seconds,
        top=top,
    )


def _payload(
    state: _State,
    safe_path: str,
    size: int,
    *,
    max_bytes: int,
    max_lines: int,
    max_seconds: float,
    top: int,
) -> Dict[str, Any]:
    if state.access_lines and state.ssh_lines:
        kind = "mixed"
    elif state.access_lines:
        kind = "access"
    elif state.ssh_lines:
        kind = "ssh"
    else:
        kind = "unknown"
    stopped_by_limit = None
    for name in ("max-seconds", "max-lines", "max-bytes"):
        if name in state.limit_reasons:
            stopped_by_limit = name
            break

    access: Any = None
    if state.access_lines:
        status_ranked = sorted(
            state.status_codes.items(), key=lambda item: (-item[1], item[0])
        )
        access = {
            "sources": state.sources.payload(top, "ip"),
            "paths": state.paths.payload(top, "path"),
            "user_agents": state.agents.payload(top, "user_agent"),
            "status_buckets": dict(state.status_buckets),
            "status_codes": [
                {"code": code, "count": count} for code, count in status_ranked[:top]
            ],
            "status_codes_distinct": len(state.status_codes),
        }

    ssh: Any = None
    if state.ssh_lines:
        ssh = {
            "failed_total": state.ssh_failed,
            "accepted_total": state.ssh_accepted,
            "invalid_total": state.ssh_invalid,
            "failed_by_source": state.failed_source.payload(top, "ip"),
            "failed_by_user": state.failed_user.payload(top, "user"),
            "invalid_by_source": state.invalid_source.payload(top, "ip"),
            "invalid_users": state.invalid_users.payload(top, "user"),
            "accepted_by_source": state.accepted_source.payload(top, "ip"),
            "failed_examples": [_example_payload(ex) for ex in state.failed_examples],
            "accepted_examples": [
                _example_payload(ex) for ex in state.accepted_examples
            ],
            "brute_threshold": state.brute_threshold,
            "brute_force": _brute_force(state),
        }

    return {
        "schema": SCHEMA,
        "path": safe_path,
        "size": size,
        "format": {
            "kind": kind,
            "access_lines": state.access_lines,
            "ssh_lines": state.ssh_lines,
            "unparsed_lines": state.lines_read - state.lines_parsed,
        },
        "complete": state.complete and not state.limit_reasons and not state.errors,
        "stopped_by_limit": stopped_by_limit,
        "limits": {
            "hit": bool(state.limit_reasons),
            "reasons": list(state.limit_reasons),
            "max_bytes": max_bytes,
            "max_lines": max_lines,
            "max_seconds": max_seconds,
            "line_scan_bytes": MAX_LINE_SCAN_BYTES,
        },
        "counts": {
            "lines_read": state.lines_read,
            "bytes_read": state.bytes_read,
            "lines_parsed": state.lines_parsed,
            "lines_unparsed": state.lines_read - state.lines_parsed,
            "truncated_lines": state.truncated_lines,
            "flag_matches": state.flags.total,
            "stored_examples": state.indicators.stored_examples,
        },
        "access": access,
        "ssh": ssh,
        "indicators": state.indicators.payload(),
        "flags": {
            "label": "candidate",
            "total_matches": state.flags.total,
            "distinct": len(state.flags.seen),
            "candidates": state.flags.candidates,
            "truncated": state.flags.truncated,
            "note": "flag-regex matches are candidates, not proof",
        },
        "errors": state.errors,
        "note": NOTE,
    }


# --------------------------------------------------------------------------
# Human rendering
# --------------------------------------------------------------------------
def _values_text(block: Dict[str, Any], key_name: str) -> str:
    values = block.get("values", [])
    if not values:
        return "none"
    text = " ".join(
        f"{item.get(key_name, '')}={item.get('count', 0)}" for item in values
    )
    distinct = int(block.get("distinct", 0))
    stored = int(block.get("stored", len(values)))
    other = int(block.get("other_hits", 0))
    suffix = f"  (distinct={distinct}"
    if other:
        suffix += (
            f", +{other} hit(s) from {max(0, distinct - stored)} untracked value(s)"
        )
    suffix += ")"
    return text + suffix


def render_triage(payload: Dict[str, Any]) -> str:
    """Human summary; the JSON payload stays the machine interface."""
    counts = payload.get("counts", {})
    size = payload.get("size")
    size_text = util.human_bytes(size) if isinstance(size, int) else "unknown"
    lines: List[str] = [
        f"logs triage: {payload.get('path', '')}  "
        f"({size_text}, {counts.get('lines_read', 0)} line(s))"
    ]
    fmt = payload.get("format", {})
    lines.append(
        f"  format    access={fmt.get('access_lines', 0)} "
        f"ssh={fmt.get('ssh_lines', 0)} unparsed={fmt.get('unparsed_lines', 0)}"
    )
    access = payload.get("access")
    if access:
        buckets = access.get("status_buckets", {})
        bucket_text = " ".join(f"{k}={v}" for k, v in buckets.items() if v)
        lines.append(f"  status    {bucket_text or 'none'}")
        codes = " ".join(
            f"{item.get('code')}={item.get('count')}"
            for item in access.get("status_codes", [])
        )
        lines.append(f"  codes     {codes or 'none'}")
        lines.append(f"  sources   {_values_text(access.get('sources', {}), 'ip')}")
        lines.append(f"  paths     {_values_text(access.get('paths', {}), 'path')}")
        agents = access.get("user_agents", {})
        if agents.get("values"):
            lines.append(f"  agents    {_values_text(agents, 'user_agent')}")
    ssh = payload.get("ssh")
    if ssh:
        lines.append(
            f"  ssh       failed={ssh.get('failed_total', 0)} "
            f"accepted={ssh.get('accepted_total', 0)} "
            f"invalid={ssh.get('invalid_total', 0)}"
        )
        lines.append(
            f"  ssh fail  {_values_text(ssh.get('failed_by_source', {}), 'ip')}"
        )
        lines.append(
            f"  ssh user  {_values_text(ssh.get('failed_by_user', {}), 'user')}"
        )
        lines.append(
            f"  ssh inv   {_values_text(ssh.get('invalid_by_source', {}), 'ip')}"
        )
        for brute in ssh.get("brute_force", []):
            lines.append(
                f"  BRUTE?    {brute.get('source')} failed={brute.get('failed')} "
                f">= threshold {brute.get('threshold')} (indicator, not proof)"
            )
    indicators = payload.get("indicators", [])
    if indicators:
        lines.append("  indicators (signature matches, not proof):")
        for item in indicators:
            cap = " [examples capped]" if item.get("examples_truncated") else ""
            lines.append(
                f"    {item.get('category')}: count={item.get('count')} "
                f"distinct_evidence={item.get('distinct_evidence', 0)}{cap}"
            )
            for example in item.get("examples", []):
                lines.append(
                    f"      L{example.get('line')} {example.get('source', '')} "
                    f"{example.get('evidence', '')}"
                )
    flags = payload.get("flags", {})
    lines.append(
        f"  flags     total={flags.get('total_matches', 0)} "
        f"distinct={flags.get('distinct', 0)} (candidates, not proof)"
    )
    for item in flags.get("candidates", []):
        lines.append(f"      L{item.get('line')} {item.get('value', '')}")
    if flags.get("truncated"):
        lines.append("  ! flag candidate list capped: further matches were not stored")
    limits = payload.get("limits", {})
    if payload.get("stopped_by_limit"):
        lines.append(
            f"  limits    stopped by {payload['stopped_by_limit']}: "
            "the remaining input was NOT scanned"
        )
    elif limits.get("reasons"):
        lines.append("  limits    incomplete: " + ", ".join(limits["reasons"]))
    elif payload.get("complete"):
        lines.append("  limits    whole input scanned within the configured caps")
    for error in payload.get("errors", [])[:5]:
        lines.append(f"  ! {error}")
    lines.append("")
    lines.append(
        "triage, not proof: indicators and flag matches are candidates; "
        "a truncated scan says nothing about the lines it did not read."
    )
    return "\n".join(lines)
