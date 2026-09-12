"""Bounded IO, hashing, redaction and structured subprocess helpers.

Design rules enforced here:
  * no shell=True anywhere in the codebase;
  * every subprocess call has an explicit argv list, timeout and output cap;
  * every filesystem read that can touch untrusted input is size-bounded;
  * secrets are redacted before anything is written to state or stdout JSON.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Exit codes (documented in AGENTS.md)
# --------------------------------------------------------------------------
EXIT_OK = 0
EXIT_NEGATIVE = 1  # expected negative result: refused, stale, not detected
EXIT_USAGE = 2
EXIT_INTERNAL = 3

MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_SUBPROCESS_OUTPUT = 256 * 1024
DEFAULT_TIMEOUT = 20.0


class CtfError(Exception):
    """An expected, user-facing failure."""

    exit_code = EXIT_NEGATIVE

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


class UsageError(CtfError):
    exit_code = EXIT_USAGE


class InternalError(CtfError):
    exit_code = EXIT_INTERNAL


# --------------------------------------------------------------------------
# Repo layout
# --------------------------------------------------------------------------
def repo_root(start: Optional[str] = None) -> str:
    """Locate the repository root by walking up for AGENTS.md."""
    here = os.path.abspath(start or os.getcwd())
    cur = here
    for _ in range(12):
        if os.path.isfile(os.path.join(cur, "AGENTS.md")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    # Fallback: tools/ctfctl/__file__ -> repo root is two levels up.
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def repo_path(*parts: str) -> str:
    return os.path.join(repo_root(), *parts)


STATE_DIRNAME = "state"
CAPTURES_DIRNAME = "captures"
BACKUPS_DIRNAME = "backups"
INDEX_DIRNAME = "index"


def state_dir(create: bool = True, root: Optional[str] = None) -> str:
    """Runtime state directory for `root` (defaults to this checkout).

    `root` exists so tests and drills can use a throwaway repository without ever
    writing runtime state into the real checkout.
    """
    path = os.path.join(root or repo_root(), STATE_DIRNAME)
    if create:
        os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def captures_dir(create: bool = True, root: Optional[str] = None) -> str:
    path = os.path.join(root or repo_root(), CAPTURES_DIRNAME)
    if create:
        os.makedirs(path, mode=0o700, exist_ok=True)
    return path


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "surrogatepass"))


def sha256_file(path: str, limit: Optional[int] = None) -> str:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 256)
            if not chunk:
                break
            total += len(chunk)
            if limit is not None and total > limit:
                raise CtfError(f"file exceeds hash limit: {path}")
            h.update(chunk)
    return h.hexdigest()


def normalized_text_hash(text: str) -> str:
    """Duplicate-detection hash: stable across CRLF and trailing whitespace."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    out: List[str] = []
    blank_run = 0
    for line in lines:
        if line == "":
            blank_run += 1
            if blank_run > 2:
                continue
        else:
            blank_run = 0
        out.append(line)
    return sha256_text("\n".join(out).rstrip("\n") + "\n")


def short_id(prefix: str, *parts: str, length: int = 8) -> str:
    digest = sha256_text("\x00".join(parts))[:length]
    return f"{prefix}-{digest}"


# --------------------------------------------------------------------------
# Bounded text and JSON IO
# --------------------------------------------------------------------------
def read_text(path: str, limit: int = MAX_TEXT_BYTES, errors: str = "replace") -> str:
    size = os.path.getsize(path)
    if size > limit:
        raise CtfError(
            f"refusing to read {path}: {size} bytes exceeds limit {limit}",
            hint="raise the limit deliberately or trim the file",
        )
    with open(path, "r", encoding="utf-8", errors=errors) as fh:
        return fh.read(limit + 1)


def detect_newline(raw: bytes) -> str:
    """Detect the dominant line ending so a patch cannot rewrite every line."""
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n") - crlf
    return "\r\n" if crlf > lf else "\n"


def read_text_preserving(path: str, limit: int = MAX_TEXT_BYTES,
                         errors: str = "replace") -> Tuple[str, str]:
    """Read a text file, returning (text with \\n endings, detected newline).

    Editing text requires normalized newlines, but writing it back must restore
    the original convention: silently converting CRLF to LF would rewrite every
    line of the file and produce an unreviewable diff.
    """
    raw = read_bytes(path, limit)
    return raw.decode("utf-8", errors), detect_newline(raw)


def encode_with_newline(text: str, newline: str) -> bytes:
    if newline and newline != "\n":
        text = text.replace("\n", newline)
    return text.encode("utf-8")


def read_bytes(path: str, limit: int = MAX_TEXT_BYTES) -> bytes:
    size = os.path.getsize(path)
    if size > limit:
        raise CtfError(f"refusing to read {path}: {size} bytes exceeds limit {limit}")
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def write_text_atomic(path: str, text: str, mode: Optional[int] = None) -> None:
    """Write via same-directory temp file + os.replace, fsync both."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode or 0o644)
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_dir(directory)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def load_json(path: str, default: Any = None) -> Any:
    if not os.path.isfile(path):
        return default
    raw = read_text(path, MAX_JSON_BYTES)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CtfError(f"invalid JSON in {path}: {exc}") from exc


def load_jsonl(path: str, limit: int = MAX_JSON_BYTES) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        consumed = 0
        for lineno, line in enumerate(fh, 1):
            consumed += len(line)
            if consumed > limit:
                raise CtfError(f"{path}: exceeded {limit} bytes at line {lineno}")
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CtfError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise CtfError(f"{path}:{lineno}: expected a JSON object")
            out.append(record)
    return out


def dump_json(obj: Any, *, indent: int = 2) -> str:
    return json.dumps(obj, indent=indent, sort_keys=False, ensure_ascii=False)


def dump_jsonl(records: Iterable[Dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in records)


# --------------------------------------------------------------------------
# Redaction — applied before anything reaches state/ or stdout
# --------------------------------------------------------------------------
_SECRET_KEYS = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|"
    r"session|bearer|cookie|dsn|connection[_-]?string|pw)",
    re.IGNORECASE,
)
_URL_CREDS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<user>[^:/@\s]+):(?P<pw>[^@/\s]+)@")
_ASSIGN_SECRET = re.compile(
    r"(?P<key>[A-Za-z0-9_.\-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|auth|"
    r"credential|private[_-]?key|session|cookie|dsn)[A-Za-z0-9_.\-]*)"
    r"(?P<sep>\s*[:=]\s*)"
    # An unquoted value runs to the end of the line: a partial replacement would
    # otherwise leave the interesting half of "Bearer <token>" in the output.
    r"(?P<val>\"[^\"]{1,400}\"|'[^']{1,400}'|[^\n,;]{1,400})",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}")
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_FLAGLIKE = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_!@#$%^&*\-+.]{3,200}\}")

REDACTED = "<REDACTED>"


def redact(text: str, *, redact_flags: bool = True) -> str:
    """Best-effort secret scrubbing for logs, plans and state files."""
    if not isinstance(text, str):
        return text
    out = _PEM.sub("<REDACTED PRIVATE KEY>", text)
    out = _URL_CREDS.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@", out)
    # Bearer/Basic first: otherwise an assignment rule consumes the scheme and
    # leaves the token itself behind.
    out = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _ASSIGN_SECRET.sub(lambda m: f"{m.group('key')}{m.group('sep')}{REDACTED}", out)
    if redact_flags:
        out = _FLAGLIKE.sub(REDACTED, out)
    return out


def is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEYS.search(key or ""))


def redact_env(env: Dict[str, str], *, keep: Sequence[str] = ()) -> Dict[str, str]:
    keep_upper = {k.upper() for k in keep}
    out: Dict[str, str] = {}
    for key, value in env.items():
        if key.upper() in keep_upper:
            out[key] = value
        elif is_secret_key(key):
            out[key] = REDACTED if value else ""
        else:
            out[key] = redact(value, redact_flags=False)
    return out


# --------------------------------------------------------------------------
# Terminal-safe rendering of untrusted text
# --------------------------------------------------------------------------
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def printable(text: str, limit: int = 400) -> str:
    """Make untrusted text inert for terminal/log display."""
    cleaned = _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    cleaned = cleaned.replace("\x1b", "\\x1b")
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 3] + "..."
    return cleaned


def bounded(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 20] + f"\n...[{len(text) - limit + 20} bytes omitted]"


# --------------------------------------------------------------------------
# Structured subprocess (never shell=True)
# --------------------------------------------------------------------------
@dataclass
class ProcResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    truncated: bool = False
    unavailable: bool = False
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.unavailable

    def as_dict(self) -> Dict[str, Any]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "ok": self.ok,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "unavailable": self.unavailable,
            "reason": self.reason,
            # Output is capped and redacted by construction.
            "stderr_tail": bounded(redact(self.stderr.strip()), 600),
        }


def run(
    argv: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = MAX_SUBPROCESS_OUTPUT,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    input_text: Optional[str] = None,
    allow_missing: bool = True,
) -> ProcResult:
    """Run argv without a shell, with a hard timeout and capped output."""
    argv = [str(a) for a in argv]
    started = time.time()
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        if not allow_missing:
            raise CtfError(f"required command not found: {argv[0]}")
        return ProcResult(argv, 127, "", f"command not found: {argv[0]}", 0.0,
                          unavailable=True, reason="not-installed")
    except OSError as exc:
        if exc.errno == errno.EPERM:
            return ProcResult(argv, 126, "", str(exc), 0.0, unavailable=True,
                              reason="permission-denied")
        if not allow_missing:
            raise CtfError(f"cannot execute {argv[0]}: {exc}") from exc
        return ProcResult(argv, 126, "", str(exc), 0.0, unavailable=True,
                          reason=f"oserror-{exc.errno}")

    truncated = False
    try:
        out, err = proc.communicate(
            input=(input_text or "").encode("utf-8") if input_text is not None else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:  # pragma: no cover - defensive
            out, err = b"", b""
        return ProcResult(argv, -9, "", "", time.time() - started, timed_out=True,
                          reason=f"timeout after {timeout}s")

    if len(out) > max_output:
        out = out[:max_output]
        truncated = True
    if len(err) > max_output:
        err = err[:max_output]
        truncated = True

    return ProcResult(
        argv,
        proc.returncode if proc.returncode is not None else -1,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
        time.time() - started,
        truncated=truncated,
    )


def which(name: str) -> Optional[str]:
    from shutil import which as _which

    return _which(name)


def have(name: str) -> bool:
    return which(name) is not None


def pid_alive(pid: int) -> bool:
    """Non-destructive process liveness check.

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


# --------------------------------------------------------------------------
# File metadata (used by the mutation engine)
# --------------------------------------------------------------------------
@dataclass
class FileState:
    path: str
    exists: bool
    sha256: str = ""
    size: int = 0
    mode: int = 0
    uid: int = -1
    gid: int = -1
    mtime_ns: int = 0
    inode: int = 0
    is_symlink: bool = False
    symlink_target: str = ""
    xattrs: Dict[str, str] = field(default_factory=dict)
    acl: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "mtime_ns": self.mtime_ns,
            "inode": self.inode,
            "is_symlink": self.is_symlink,
            "symlink_target": self.symlink_target,
            "xattrs": self.xattrs,
            "acl": self.acl,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "FileState":
        fields = {f for f in FileState.__dataclass_fields__}  # type: ignore[attr-defined]
        return FileState(**{k: v for k, v in data.items() if k in fields})


def capture_file_state(path: str, *, with_xattrs: bool = True) -> FileState:
    """Record identity + metadata of a file, without reading secret content."""
    state = FileState(path=path, exists=False)
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return state
    except OSError as exc:
        raise CtfError(f"cannot stat {path}: {exc}") from exc

    state.exists = True
    state.is_symlink = stat.S_ISLNK(lst.st_mode)
    state.inode = int(lst.st_ino)
    state.size = int(lst.st_size)
    state.mtime_ns = int(lst.st_mtime_ns)
    # Ownership is only meaningful where it can be restored; reporting a fake 0
    # on Windows would make the plan look more authoritative than it is.
    if hasattr(os, "chown"):
        state.uid = int(getattr(lst, "st_uid", -1))
        state.gid = int(getattr(lst, "st_gid", -1))
    else:
        state.uid = -1
        state.gid = -1
    state.mode = stat.S_IMODE(lst.st_mode)
    if state.is_symlink:
        try:
            state.symlink_target = os.readlink(path)
        except OSError:
            state.symlink_target = ""
        return state
    if stat.S_ISREG(lst.st_mode):
        state.sha256 = sha256_file(path)
        if with_xattrs:
            state.xattrs = _read_xattrs(path)
            state.acl = _read_acl(path)
    return state


def _read_xattrs(path: str) -> Dict[str, str]:
    if not hasattr(os, "listxattr"):
        return {}
    out: Dict[str, str] = {}
    try:
        for name in os.listxattr(path):
            try:
                value = os.getxattr(path, name)
            except OSError:
                continue
            # Values may be binary; store a hash-ish preview only.
            if isinstance(value, bytes) and len(value) <= 256:
                out[name] = value.hex()
            else:
                out[name] = "<opaque>"
    except OSError:
        return {}
    return out


def _read_acl(path: str) -> str:
    """Best-effort POSIX ACL read via getfacl; empty when unavailable."""
    if not have("getfacl"):
        return ""
    res = run(["getfacl", "-p", "--absolute-names", path], timeout=5, max_output=8192)
    if not res.ok:
        return ""
    return res.stdout.strip()


def apply_file_metadata(path: str, state: FileState, *, strict: bool = False) -> List[str]:
    """Restore ownership/mode/xattrs/ACL. Returns a list of warnings."""
    warnings: List[str] = []
    if not state.exists:
        return warnings
    if state.is_symlink:
        return warnings
    if hasattr(os, "chown") and state.uid >= 0 and state.gid >= 0:
        try:
            os.chown(path, state.uid, state.gid)
        except PermissionError:
            warnings.append("could not restore ownership (requires privilege)")
        except OSError as exc:
            warnings.append(f"could not restore ownership: {exc}")
    else:
        if state.uid >= 0:
            warnings.append("ownership restoration unavailable on this platform")
    try:
        os.chmod(path, state.mode)
    except OSError as exc:
        warnings.append(f"could not restore mode: {exc}")
    if state.xattrs and hasattr(os, "setxattr"):
        for name, hexval in state.xattrs.items():
            try:
                os.setxattr(path, name, bytes.fromhex(hexval))
            except (OSError, ValueError) as exc:
                warnings.append(f"could not restore xattr {name}: {exc}")
    elif state.xattrs:
        warnings.append("xattrs present but setxattr unavailable; restoration incomplete")
    if state.acl and have("setfacl"):
        res = run(["setfacl", "--restore=-", "-"], timeout=5, input_text=state.acl)
        if not res.ok:
            warnings.append("could not restore ACL via setfacl")
    elif state.acl:
        warnings.append("ACL present but setfacl unavailable; restoration incomplete")
    if strict and warnings:
        raise CtfError("strict metadata restoration failed: " + "; ".join(warnings))
    return warnings


def os_replace(src: str, dst: str) -> None:
    """Atomic replace of one pathname, with parent-directory fsync."""
    os.replace(src, dst)
    _fsync_dir(os.path.dirname(os.path.abspath(dst)) or ".")


def disk_free(path: str) -> Dict[str, int]:
    st = os.statvfs(path) if hasattr(os, "statvfs") else None
    if st is None:
        usage = _shutil_disk_usage(path)
        return {"free_bytes": usage[2], "total_bytes": usage[0], "free_inodes": -1}
    return {
        "free_bytes": st.f_bavail * st.f_frsize,
        "total_bytes": st.f_blocks * st.f_frsize,
        "free_inodes": st.f_favail,
    }


def _shutil_disk_usage(path: str) -> Tuple[int, int, int]:
    import shutil

    usage = shutil.disk_usage(path)
    return (usage.total, usage.used, usage.free)


def human_bytes(value: int) -> str:
    if value < 0:
        return "unknown"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{value}B"


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def emit_json(obj: Any, stream: Any = None) -> None:
    stream = stream or sys.stdout
    stream.write(dump_json(obj) + "\n")


def iter_files(root: str, *, extensions: Sequence[str] = (), max_files: int = 20000,
               follow_symlinks: bool = False) -> Iterator[str]:
    """Deterministic, bounded, symlink-averse file walk."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in
                             {"node_modules", "__pycache__", ".git"})
        for name in sorted(filenames):
            if extensions and not name.lower().endswith(tuple(extensions)):
                continue
            count += 1
            if count > max_files:
                return
            yield os.path.join(dirpath, name)


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
