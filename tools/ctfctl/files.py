"""Bounded, read-only filesystem exploration.

This module is deliberately boring: it lists, finds and reads files with hard
caps, never follows a directory symlink during a walk, refuses to print
secret-looking files, and redacts secret-looking values in anything it does
print. It runs both on the operator laptop (`ctfctl files ...`) and on a remote
host after `ctfctl remote install` pushes the toolkit.

Nothing here mutates the filesystem.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
from typing import Any, Dict, List

from . import util

MAX_DEPTH = 4
DEFAULT_LIMIT = 200
MAX_LIMIT = 2000
DEFAULT_READ_BYTES = 64 * 1024
MAX_READ_BYTES = 1024 * 1024
MAX_PATH = 4096

# Names that are reported as metadata only. A file called id_rsa is exactly the
# file an explorer should not print, regardless of where it sits.
_SECRET_NAME = re.compile(
    r"(^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"
    r"|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$"
    r"|^\.env(\..+)?$|^\.netrc$|^kubeconfig$"
    r"|shadow$|gshadow$|passwd$|sudoers$"
    r"|credentials?(\.(json|ya?ml|txt|ini|cfg))?$"
    r"|secrets?(\.(json|ya?ml|txt|ini|cfg))?$"
    r"|_history$|\.bash_history$|\.zsh_history$"
    r"|\.mysql_history$|\.psql_history$|\.pgpass$"
    r"|\.htpasswd$|\.npmrc$|\.pypirc$|\.dockercfg$)",
    re.IGNORECASE,
)


class FilesError(util.CtfError):
    """Expected, user-facing files-exploration failure."""


def validate_path(path: str) -> str:
    """Refuse anything that is not a clean absolute path.

    Absolute-only is what makes a path safe to send to a remote host: a relative
    path would silently resolve against a cwd the operator cannot see. POSIX
    paths (/var/www) are absolute on every platform, including Windows, where
    `os.path.isabs` alone would wrongly reject them; native absolute paths
    (E:\\www) are accepted for local exploration.
    """
    if not path:
        raise FilesError(
            "a path is required", hint="use an absolute path, e.g. /var/www"
        )
    if "\x00" in path:
        raise FilesError("path contains a NUL byte")
    if len(path) > MAX_PATH:
        raise FilesError(f"path is longer than {MAX_PATH} characters")
    posix_absolute = path.startswith("/")
    if not posix_absolute and not os.path.isabs(path):
        raise FilesError(
            f"only absolute paths are accepted, got {path!r}",
            hint="start at / on the target (e.g. /var/www); relative paths would "
            "depend on a working directory you cannot see",
        )
    if any(part == ".." for part in re.split(r"[\\/]", path)):
        raise FilesError(f"path must not contain '..': {path!r}")
    if posix_absolute:
        # Keep POSIX paths verbatim: os.path.normpath on Windows would rewrite
        # the separators and hand the remote host a path it cannot use.
        return path
    return os.path.normpath(path)


def resolve_local_path(path: str) -> str:
    """Absolute-path form for local exploration: relative input is allowed."""
    if not path or "\x00" in path or len(path) > MAX_PATH:
        raise FilesError("a valid path is required")
    return validate_path(os.path.abspath(path))


def _mode_string(mode: int) -> str:
    return stat.filemode(mode)


def _entry_type(entry: os.DirEntry) -> str:
    try:
        if entry.is_symlink():
            return "symlink"
        if entry.is_dir(follow_symlinks=False):
            return "dir"
        if entry.is_file(follow_symlinks=False):
            return "file"
    except OSError:
        return "unknown"
    return "other"


def describe(path: str) -> Dict[str, Any]:
    """Metadata for one path, without opening it."""
    info: Dict[str, Any] = {"path": path, "exists": os.path.lexists(path)}
    try:
        lst = os.lstat(path)
    except OSError as exc:
        info["error"] = util.printable(str(exc), 200)
        return info
    info.update(
        {
            "type": "symlink"
            if stat.S_ISLNK(lst.st_mode)
            else (
                "dir"
                if stat.S_ISDIR(lst.st_mode)
                else ("file" if stat.S_ISREG(lst.st_mode) else "other")
            ),
            "mode": _mode_string(lst.st_mode),
            "size": int(lst.st_size),
            "mtime": int(lst.st_mtime),
            "uid": int(getattr(lst, "st_uid", -1)),
            "gid": int(getattr(lst, "st_gid", -1)),
        }
    )
    if stat.S_ISLNK(lst.st_mode):
        try:
            info["link_target"] = util.printable(os.readlink(path), 300)
        except OSError:
            info["link_target"] = "?"
    return info


def list_dir(
    path: str,
    *,
    depth: int = 1,
    limit: int = DEFAULT_LIMIT,
    include_hidden: bool = True,
) -> Dict[str, Any]:
    """Bounded directory listing. `depth` is clamped to [0, MAX_DEPTH]."""
    root = validate_path(path)
    if not os.path.isdir(root):
        raise FilesError(f"not a directory: {root}")
    depth = max(0, min(int(depth), MAX_DEPTH))
    limit = max(1, min(int(limit), MAX_LIMIT))
    entries: List[Dict[str, Any]] = []
    skipped: List[str] = []
    truncated = False

    def walk(directory: str, remaining: int) -> None:
        nonlocal truncated
        if truncated:
            return
        try:
            with os.scandir(directory) as it:
                items = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            skipped.append(f"{directory}: {util.printable(str(exc), 160)}")
            return
        for entry in items:
            if truncated:
                return
            if len(entries) >= limit:
                truncated = True
                return
            if not include_hidden and entry.name.startswith("."):
                continue
            try:
                lst = entry.stat(follow_symlinks=False)
                kind = _entry_type(entry)
                item: Dict[str, Any] = {
                    "name": util.printable(entry.name, 200),
                    "path": util.printable(
                        os.path.join(directory, entry.name), MAX_PATH
                    ),
                    "type": kind,
                    "size": int(lst.st_size),
                    "mode": _mode_string(lst.st_mode),
                    "mtime": int(lst.st_mtime),
                }
                if kind == "symlink":
                    try:
                        item["link_target"] = util.printable(
                            os.readlink(entry.path), 300
                        )
                    except OSError:
                        item["link_target"] = "?"
                entries.append(item)
            except OSError as exc:
                skipped.append(f"{entry.path}: {util.printable(str(exc), 160)}")
                continue
            if remaining > 1 and _entry_type(entry) == "dir":
                walk(entry.path, remaining - 1)

    walk(root, depth)
    return {
        "path": root,
        "depth": depth,
        "entries": entries,
        "count": len(entries),
        "limit": limit,
        "truncated": truncated,
        "skipped": skipped[:50],
    }


def find_files(
    path: str, *, name: str, limit: int = DEFAULT_LIMIT, max_depth: int = MAX_DEPTH
) -> Dict[str, Any]:
    """Bounded filename search below `path`. Never follows directory symlinks."""
    root = validate_path(path)
    if not name:
        raise FilesError("--name is required", hint="example: --name '*.py'")
    if not os.path.isdir(root):
        raise FilesError(f"not a directory: {root}")
    limit = max(1, min(int(limit), MAX_LIMIT))
    max_depth = max(1, min(int(max_depth), MAX_DEPTH))
    matches: List[Dict[str, Any]] = []
    skipped: List[str] = []
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        relative = os.path.relpath(dirpath, root)
        depth = 0 if relative == "." else relative.count(os.sep) + 1
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))
        )
        for filename in sorted(filenames):
            if not fnmatch.fnmatch(filename, name):
                continue
            if len(matches) >= limit:
                truncated = True
                break
            full = os.path.join(dirpath, filename)
            try:
                lst = os.lstat(full)
            except OSError as exc:
                skipped.append(f"{full}: {util.printable(str(exc), 160)}")
                continue
            matches.append(
                {
                    "path": util.printable(full, MAX_PATH),
                    "name": util.printable(filename, 200),
                    "type": "symlink" if stat.S_ISLNK(lst.st_mode) else "file",
                    "size": int(lst.st_size),
                }
            )
        if truncated:
            break
    return {
        "path": root,
        "name": name,
        "matches": matches,
        "count": len(matches),
        "limit": limit,
        "truncated": truncated,
        "skipped": skipped[:50],
    }


def _is_secret_name(path: str) -> bool:
    base = os.path.basename(os.path.realpath(path))
    given = os.path.basename(path)
    return bool(_SECRET_NAME.search(given) or _SECRET_NAME.search(base))


def _looks_binary(raw: bytes) -> bool:
    if b"\x00" in raw[:8192]:
        return True
    sample = raw[:8192]
    if not sample:
        return False
    text_chars = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b"
    nontext = sum(1 for byte in sample if byte not in text_chars)
    return nontext / len(sample) > 0.30


def read_file(
    path: str, *, max_bytes: int = DEFAULT_READ_BYTES, redact: bool = True
) -> Dict[str, Any]:
    """Read a bounded head of one file, refusing secret-looking names.

    The caller gets metadata plus, for text files, a redacted excerpt. Binary
    files are reported as binary and never decoded into the output.
    """
    if not path:
        raise FilesError("a path is required")
    if "\x00" in path or len(path) > MAX_PATH:
        raise FilesError("invalid path")
    max_bytes = max(1, min(int(max_bytes), MAX_READ_BYTES))

    result: Dict[str, Any] = {"path": path}
    if _is_secret_name(path):
        result.update(
            {
                "readable": False,
                "reason": "secret-looking filename: metadata only",
                "content": None,
            }
        )
        result.update(describe(path))
        return result

    # The secret-name refusal above runs first so the message is honest about
    # *why* nothing was printed; then the path itself must be clean.
    path = validate_path(path)
    result["path"] = path

    try:
        lst = os.lstat(path)
    except OSError as exc:
        raise FilesError(
            f"cannot stat {path}: {util.printable(str(exc), 200)}"
        ) from exc
    result.update(
        {
            "type": "symlink"
            if stat.S_ISLNK(lst.st_mode)
            else (
                "dir"
                if stat.S_ISDIR(lst.st_mode)
                else ("file" if stat.S_ISREG(lst.st_mode) else "other")
            ),
            "size": int(lst.st_size),
            "mode": _mode_string(lst.st_mode),
            "mtime": int(lst.st_mtime),
        }
    )
    if stat.S_ISDIR(lst.st_mode):
        result.update(
            {"readable": False, "reason": "path is a directory", "content": None}
        )
        return result
    if not stat.S_ISREG(lst.st_mode):
        result.update(
            {"readable": False, "reason": "not a regular file", "content": None}
        )
        return result

    with open(path, "rb") as fh:
        raw = fh.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    result["truncated"] = truncated
    if _looks_binary(raw):
        result.update(
            {
                "readable": False,
                "reason": "binary file: metadata only (no bytes are printed)",
                "content": None,
            }
        )
        return result
    text = raw.decode("utf-8", "replace")
    if redact:
        text = util.redact(text)
    result.update(
        {
            "readable": True,
            "encoding": "utf-8",
            "content": text,
            "redacted": redact,
        }
    )
    return result


# --------------------------------------------------------------------------
# Human rendering
# --------------------------------------------------------------------------
def render_listing(payload: Dict[str, Any]) -> str:
    lines = [
        f"{payload['path']}  ({payload['count']} entries"
        + (", truncated" if payload.get("truncated") else "")
        + ")"
    ]
    for item in payload.get("entries", []):
        size = str(item.get("size", ""))
        name = item.get("name", "")
        if item.get("type") == "dir":
            name += "/"
        if item.get("type") == "symlink":
            name += " -> " + str(item.get("link_target", "?"))
        lines.append(f"  {item.get('mode', '')}  {size:>10}  {name}")
    for skipped in payload.get("skipped", []):
        lines.append(f"  ! {skipped}")
    return "\n".join(lines)


def render_matches(payload: Dict[str, Any]) -> str:
    lines = [
        f"{payload['path']}  name={payload['name']}  ({payload['count']} matches"
        + (", truncated" if payload.get("truncated") else "")
        + ")"
    ]
    for item in payload.get("matches", []):
        lines.append(f"  {item.get('size', ''):>10}  {item['path']}")
    for skipped in payload.get("skipped", []):
        lines.append(f"  ! {skipped}")
    return "\n".join(lines)


def render_read(payload: Dict[str, Any]) -> str:
    header = (
        f"{payload['path']}  type={payload.get('type')} size={payload.get('size')}"
        f" mode={payload.get('mode')}"
        + ("  truncated" if payload.get("truncated") else "")
    )
    if not payload.get("readable"):
        return header + f"\n  not shown: {payload.get('reason')}"
    body = payload.get("content") or ""
    return header + "\n" + body
