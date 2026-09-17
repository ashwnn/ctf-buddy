"""Bounded decode chains over a value or a file: strict codecs first, plus
ASCII-whitespace-collapsed variants labelled heuristic.

This is triage, not proof. ``proven`` means the codec consumed its whole step
input exactly (no bytes discarded, no trailing data, under the per-step size
cap); it says nothing about whether the output is meaningful. ``heuristic``
means ASCII whitespace had to be removed first (for example a wrapped base64
blob), so bytes were discarded. A flag-regex match only sets ``flag_like``; it
is never proof that the expected flag was recovered and must be checked against
the challenge.

Decoders, applied in deterministic name order:
  * base64  standard alphabet; canonical padded or unpadded form only;
  * base32  RFC 4648 alphabet, case-folded; canonical padding only;
  * hex     even-length [0-9A-Fa-f] only;
  * binary  0/1 digits only, 8-bit aligned;
  * url     ASCII only, every % must introduce two hex digits;
  * rot13   ASCII letters only, whole input must be ASCII;
  * gzip    only with the 1f 8b magic; the stream must end exactly;
  * zlib    only with a valid zlib header; the stream must end exactly.

Chains are breadth-first from the input, depth-capped (default 4, hard cap 8),
candidate-capped (200 decoder applications) and cycle-guarded by seen value, so
the first (shallowest, then name-ordered) chain that reaches a value wins.
Results are unique by value and sorted by (depth, chain text); identical
output is never repeated. gzip and zlib therefore surface as chained steps
after hex, base64 or base32 when the decoded bytes carry their magic.

Limits: argument input 64 KiB (a longer argument is a usage error), file input
1 MiB read with truncation reported, 1 MiB per decoded step (a larger or
unfinished decompression is skipped, never truncated), 200 candidates total,
200-character escaped previews. Nothing is executed, nothing is written, no
network is used.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import urllib.parse
import zlib
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Pattern, Tuple

from . import util

SCHEMA = "ctfctl.decode/1"

DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_]{2,32}\{[^\s{}]{3,200}\}"
MAX_FLAG_REGEX = 512
MAX_FLAG_MATCHES = 20

DEFAULT_MAX_DEPTH = 4
MAX_DEPTH_CAP = 8
MAX_CANDIDATES = 200
MAX_STEP_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024
MAX_FILE_BYTES = 1024 * 1024
PREVIEW_CHARS = 200

NOTE = (
    "decode chains are triage, not proof: 'proven' means the codec consumed "
    "its step input exactly, not that the output is meaningful; a flag-regex "
    "match is a lead to verify against the challenge."
)

_ASCII_WS = re.compile(rb"\s+")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]*={0,2}\Z")
_B32_RE = re.compile(rb"[A-Za-z2-7]*={0,6}\Z")
_HEX_RE = re.compile(rb"[0-9A-Fa-f]*\Z")
_BINARY_RE = re.compile(rb"[01]*\Z")
_BAD_PCT = re.compile(rb"%(?![0-9A-Fa-f]{2})")
_GZIP_MAGIC = b"\x1f\x8b"

_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

_Decoder = Callable[[bytes], Optional[Tuple[bytes, bool]]]


class DecodeError(util.CtfError):
    """Expected negative result: the input is missing or unreadable (exit 1)."""


@dataclass
class _Node:
    depth: int
    chain: Tuple[str, ...]
    data: bytes
    strict: bool


# --------------------------------------------------------------------------
# Strict decoders: return (output, strict) or None when the input does not
# apply or does not consume exactly.
# --------------------------------------------------------------------------
def _dec_base64(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data or len(data) % 4 == 1 or not _B64_RE.fullmatch(data):
        return None
    if b"=" in data and len(data) % 4 != 0:
        return None
    try:
        out = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not out:
        return None
    # Canonical round-trip: rejects non-zero trailing bits and stray padding.
    if base64.b64encode(out).rstrip(b"=") != data.rstrip(b"="):
        return None
    return out, True


def _dec_base32(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data or not _B32_RE.fullmatch(data):
        return None
    body = data.rstrip(b"=")
    if len(body) % 8 not in (0, 2, 4, 5, 7):
        return None
    pad_len = (8 - len(body) % 8) % 8
    if pad_len > 6:
        return None
    pads = len(data) - len(body)
    if pads not in (0, pad_len):
        return None
    try:
        out = base64.b32decode(body + b"=" * pad_len, casefold=True)
    except (binascii.Error, ValueError):
        return None
    if not out:
        return None
    if base64.b32encode(out).rstrip(b"=") != body.upper():
        return None
    return out, True


def _dec_hex(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data or len(data) % 2 or not _HEX_RE.fullmatch(data):
        return None
    try:
        out = bytes.fromhex(data.decode("ascii"))
    except ValueError:
        return None
    return out, True


def _dec_binary(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data or len(data) % 8 or not _BINARY_RE.fullmatch(data):
        return None
    out = bytearray()
    for i in range(0, len(data), 8):
        out.append(int(data[i : i + 8], 2))
    return bytes(out), True


def _dec_url(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data or not data.isascii() or b"%" not in data:
        return None
    if _BAD_PCT.search(data):
        return None
    out = urllib.parse.unquote_to_bytes(data)
    if not out:
        return None
    return out, True


def _dec_rot13(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data or not data.isascii():
        return None
    text = data.decode("ascii")
    if not any("a" <= ch <= "z" or "A" <= ch <= "Z" for ch in text):
        return None
    return text.translate(_ROT13).encode("ascii"), True


def _inflate(data: bytes, wbits: int) -> Optional[Tuple[bytes, bool]]:
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data, MAX_STEP_BYTES + 1)
    except zlib.error:
        return None
    if len(out) > MAX_STEP_BYTES or obj.unconsumed_tail:
        return None  # over the step cap: skipped, never truncated
    if not obj.eof or obj.unused_data:
        return None  # truncated stream or trailing bytes: not exact
    try:
        out += obj.flush()
    except zlib.error:
        return None
    if len(out) > MAX_STEP_BYTES:
        return None
    return out, True


def _dec_gzip(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not data.startswith(_GZIP_MAGIC):
        return None
    return _inflate(data, 31)


def _zlib_header_ok(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    if (cmf & 0x0F) != 8 or (cmf >> 4) > 7:
        return False
    return ((cmf << 8) | flg) % 31 == 0


def _dec_zlib(data: bytes) -> Optional[Tuple[bytes, bool]]:
    if not _zlib_header_ok(data):
        return None
    return _inflate(data, 15)


#: Fixed, alphabetical decoder order: deterministic exploration and sort keys.
_DECODERS: Tuple[Tuple[str, _Decoder], ...] = (
    ("base32", _dec_base32),
    ("base64", _dec_base64),
    ("binary", _dec_binary),
    ("gzip", _dec_gzip),
    ("hex", _dec_hex),
    ("rot13", _dec_rot13),
    ("url", _dec_url),
    ("zlib", _dec_zlib),
)


def _apply(func: _Decoder, data: bytes) -> Optional[Tuple[bytes, bool]]:
    """Run one decoder strictly, then once with ASCII whitespace collapsed.

    The collapsed retry discards bytes, so its result is heuristic by
    definition even when the codec itself consumed the collapsed input exactly.
    """
    step = func(data)
    if step is not None:
        return step
    collapsed = _ASCII_WS.sub(b"", data)
    if collapsed and collapsed != data:
        step = func(collapsed)
        if step is not None:
            out, _ = step
            return out, False
    return None


# --------------------------------------------------------------------------
# Flag matching and previews
# --------------------------------------------------------------------------
def _compile_flag_regex(flag_regex: str) -> Pattern[bytes]:
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


def _flag_matches(pattern: Pattern[bytes], data: bytes) -> List[str]:
    found: List[str] = []
    for match in pattern.findall(data):
        if len(found) >= MAX_FLAG_MATCHES:
            break
        text = match.decode("ascii", "replace")
        if text not in found:
            found.append(util.printable(text, 160))
    return found


def _preview(data: bytes) -> str:
    return util.printable(data.decode("utf-8", "replace"), PREVIEW_CHARS)


# --------------------------------------------------------------------------
# Input loading
# --------------------------------------------------------------------------
def _load_input(
    value: Optional[str], file_path: Optional[str]
) -> Tuple[bytes, str, Optional[str], bool]:
    if value is not None and file_path is not None:
        raise util.UsageError("provide either VALUE or --file, not both")
    if value is None and file_path is None:
        raise util.UsageError(
            "provide a VALUE to decode or --file PATH",
            hint="example: ctfctl decode ZmxhZ3t4fQ==",
        )
    if file_path is not None:
        path = str(file_path)
        if "\x00" in path:
            raise util.UsageError("path must not contain NUL bytes")
        shown = util.printable(path, 300)
        if not os.path.exists(path):
            raise DecodeError(f"file does not exist: {shown}")
        if os.path.isdir(path):
            raise DecodeError(f"not a regular file: {shown}")
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise DecodeError(f"cannot read {shown}: {exc.strerror or exc}") from exc
        truncated = len(data) > MAX_FILE_BYTES
        if truncated:
            data = data[:MAX_FILE_BYTES]
        return data, "file", shown, truncated
    data = str(value).encode("utf-8")
    if len(data) > MAX_INPUT_BYTES:
        raise util.UsageError(
            f"input is {len(data)} bytes; the argument cap is "
            f"{MAX_INPUT_BYTES} bytes (use --file for more)"
        )
    return data, "argument", None, False


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def decode(
    value: Optional[str] = None,
    file_path: Optional[str] = None,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    flag_regex: str = DEFAULT_FLAG_REGEX,
) -> Dict[str, Any]:
    """Iterate bounded decode chains and return a machine payload.

    Payload keys: ``schema``, ``input`` (source, path, bytes, sha256,
    truncated), ``limits``, ``candidates_tried``, ``limit_hit`` (candidate cap
    reached, so deeper values were not explored), ``results`` (depth, chain,
    chain_text, classification proven/heuristic, bytes, sha256, escaped
    preview, flag_like, flag_matches) and ``note``.

    Raises ``DecodeError`` (exit 1) for a missing or unreadable file and
    ``util.UsageError`` (exit 2) for a bad argument, depth or regex.
    """
    try:
        depth = int(max_depth)
    except (TypeError, ValueError):
        raise util.UsageError("--max-depth must be an integer") from None
    if depth < 1:
        raise util.UsageError("--max-depth must be at least 1")
    depth = min(depth, MAX_DEPTH_CAP)
    pattern = _compile_flag_regex(flag_regex)
    data, source, shown_path, truncated = _load_input(value, file_path)

    seen = {data}
    queue: Deque[_Node] = deque([_Node(0, (), data, True)])
    results: List[_Node] = []
    tried = 0
    limit_hit = False
    while queue:
        node = queue.popleft()
        if node.depth >= depth:
            continue
        stop = False
        for name, func in _DECODERS:
            if tried >= MAX_CANDIDATES:
                limit_hit = True
                stop = True
                break
            tried += 1
            step = _apply(func, node.data)
            if step is None:
                continue
            out, strict = step
            if not out or out in seen:
                continue
            seen.add(out)
            child = _Node(
                node.depth + 1, node.chain + (name,), out, node.strict and strict
            )
            results.append(child)
            queue.append(child)
        if stop:
            break

    best: Dict[bytes, _Node] = {}
    for node in results:
        previous = best.get(node.data)
        if previous is None or (node.depth, node.chain) < (
            previous.depth,
            previous.chain,
        ):
            best[node.data] = node
    ordered = sorted(best.values(), key=lambda n: (n.depth, " -> ".join(n.chain)))

    entries: List[Dict[str, Any]] = []
    for node in ordered:
        matches = _flag_matches(pattern, node.data)
        entries.append(
            {
                "depth": node.depth,
                "chain": list(node.chain),
                "chain_text": " -> ".join(node.chain),
                "classification": "proven" if node.strict else "heuristic",
                "bytes": len(node.data),
                "sha256": hashlib.sha256(node.data).hexdigest(),
                "preview": _preview(node.data),
                "flag_like": bool(matches),
                "flag_matches": matches,
            }
        )

    return {
        "schema": SCHEMA,
        "input": {
            "source": source,
            "path": shown_path,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "truncated": truncated,
        },
        "limits": {
            "max_depth": depth,
            "max_candidates": MAX_CANDIDATES,
            "max_step_bytes": MAX_STEP_BYTES,
            "argument_cap_bytes": MAX_INPUT_BYTES,
            "file_cap_bytes": MAX_FILE_BYTES,
        },
        "candidates_tried": tried,
        "limit_hit": limit_hit,
        "results": entries,
        "note": NOTE,
    }


def render_decode(payload: Dict[str, Any]) -> str:
    """Human summary; the JSON payload stays the machine interface."""
    info = payload.get("input", {})
    if info.get("source") == "file":
        head = f"decode: {info.get('path', '')}"
    else:
        head = "decode: argument"
    head += f" ({info.get('bytes', 0)} bytes"
    if info.get("truncated"):
        head += ", truncated to the file cap"
    head += ")"
    lines = [head]
    results = payload.get("results", [])
    if not results:
        lines.append("  no decode applied within the depth and candidate caps")
    for index, item in enumerate(results, 1):
        marker = "  flag-like: yes" if item.get("flag_like") else ""
        lines.append(
            f"  {index}. depth={item.get('depth')} {item.get('chain_text')} "
            f"[{item.get('classification')}] bytes={item.get('bytes')}{marker}"
        )
        lines.append(f"     {item.get('preview', '')}")
    if payload.get("limit_hit"):
        lines.append("  ! candidate cap reached: deeper chains were not explored")
    lines.append("")
    lines.append("triage, not proof: verify any flag-like match against the challenge.")
    return "\n".join(lines)
