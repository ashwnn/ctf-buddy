"""Bounded, read-only artifact triage: hashes, strings, flags, one decode pass
and in-memory ZIP/TAR member inspection.

This is triage, not proof. Every bound is enforced while data is streamed, and
every category that was not fully analyzed is reported. ``complete`` is true
only when the whole input was analyzed within the configured limits. It is
false whenever any of the following happened, and the ``incomplete`` list
names each category that applies:

  * ``limits``: at least one entry in ``limits.reasons`` (a cap or the
    deadline stopped work);
  * ``errors``: any read or open failure, including failed member reads,
    directory entries that could not be stat'ed, and a plain file whose size
    changed between ``fstat`` and the streaming read (``size-mismatch``);
  * ``archive-errors``: archive bytes that could not be detected or parsed (a
    ``.tar.gz`` cut inside its first member, a ``.zip`` that is not a zip);
  * ``files-skipped``, ``links-skipped``, ``special-skipped``,
    ``depth-skipped``: a walk entry that was not scanned, a symlink or reparse
    point that was never followed, a non-regular entry, or a subtree beyond
    the depth limit;
  * ``members-skipped``: a member refused by name validation, a duplicate, an
    encrypted member or one over the ratio guard;
  * ``members-unparsed``: a member cut short, refused for its declared size or
    otherwise not fully read.

A normal archive that contains a symlink therefore reports ``complete=false``,
with ``counts.links_skipped`` (and the ``incomplete`` category) explaining why.
A truncated scan proves nothing about the bytes it did not read.

Nothing is written to disk and nothing is executed: archive members are read
through ``ZipFile.open``/``TarFile.extractfile`` into bounded buffers, member
names and filesystem entry paths are validated for containment before any read
(C0/C1 controls, Unicode format characters and lone surrogates are escaped into
visible form once at intake, before any output), and decoded layers are never
recursed into (that is the decode command's job).

Default limits:
  * streaming SHA-256 in 256 KiB chunks; directory walk depth 3 and 2000
    entries (streamed with ``os.scandir``, never fully materialized),
    symlinked directories and files are never followed and are counted as
    skipped;
  * printable-ASCII runs of 4+ characters, 64 KiB of strings per file and
    4 MiB of strings in total;
  * flag regex ``[A-Za-z0-9_]{2,32}\\{[^\\s{}]{3,200}\\}`` over raw chunks
    (with overlap) and decoded text, at most 200 findings;
  * one base64/hex decode pass: runs of 16+ characters, 200 candidates, 64 KiB
    per run, 4 MiB decoded in total, no recursion;
  * ZIP/TAR: nesting depth 3 (the input archive is level 1), 2000 members,
    50 MiB per member and 250 MiB expanded in total, counted from bytes
    actually streamed (declared sizes are never trusted for caps, only for
    early refusal), 200:1 declared zip compression ratio, 60 s time budget.
    A zip is refused before ``zipfile`` opens it when the last
    end-of-central-directory signature in the bounded tail (the record
    ``zipfile`` itself honors) is not aligned to the file end, declares more
    members than the budget, uses a zip64 sentinel or locator, or declares a
    central-directory size over
    ``max(4 MiB, min(input size, max_members * 4096))``; a tar member
    that declares more than the per-member cap is refused unread; tarfile
    parses a decompressed stream through a counting wrapper (member budget
    plus 16 MiB of metadata slack), so PAX/GNU longname records cannot force
    unbounded reads, and once a cap or the deadline stops the wrapper or a
    member mid-read the tar loop aborts immediately instead of seeking over
    the remaining declared bytes.

The input file's ``sha256`` is computed in the same deadline-aware streaming
pass that scans it, from the same open handle used for its size, so it covers
exactly the bytes counted in the file summary ``bytes_read`` (all of the file
when ``complete`` is true).

The machine payload is documented in :func:`scan`.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import io
import lzma
import os
import re
import stat
import struct
import tarfile
import time
import unicodedata
import zipfile
from typing import Any, BinaryIO, Dict, List, Optional, Pattern, Set, Tuple

from . import util

MIB = 1024 * 1024

DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_]{2,32}\{[^\s{}]{3,200}\}"

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_ENTRIES = 2000
DEFAULT_MAX_MEMBERS = 2000
DEFAULT_MAX_MEMBER_MIB = 50
DEFAULT_MAX_TOTAL_MIB = 250
DEFAULT_MAX_SECONDS = 60.0

READ_CHUNK = 256 * 1024
FLAG_CARRY = 4096

MIN_STRING = 4
MAX_STRINGS_PER_FILE = 64 * 1024
MAX_STRINGS_TOTAL = 4 * 1024 * 1024
MAX_STRINGS_ENTRIES = 20000
MAX_STRING_RUN = 1024 * 1024

MIN_DECODE_RUN = 16
MAX_DECODE_RUN = 64 * 1024
MAX_DECODE_CANDIDATES = 200
MAX_DECODED_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 200

MAX_NESTED_BYTES = 8 * MIB
MAX_COMPRESSION_RATIO = 200.0
MAX_MEMBER_PATH = 1024
MAX_FLAG_REGEX = 512
MAX_DEPTH_CAP = 16
TOP_FINDINGS = 20

#: Decompressed bytes the tar metadata limiter may deliver over the member
#: total budget before it stops the archive (PAX/GNU longname records, record
#: padding and headers all count as metadata).
TAR_METADATA_SLACK = 16 * MIB
#: Floor for the zip preflight central-directory size cap, so a small archive
#: is never refused for a member budget smaller than its directory.
MIN_ZIP_CD_CAP = 4 * MIB
#: Zip64 end-of-central-directory locator magic, never openable under a bound.
_ZIP64_LOCATOR_MAGIC = b"PK\x06\x07"

_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING)
_TOKEN = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_DECODE_RUN)
_TOKEN_STOP = re.compile(rb"[^A-Za-z0-9+/=]")
_HEX_ONLY = re.compile(rb"[0-9A-Fa-f]+\Z")

_ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")

_LINK_REPARSE_TAGS = frozenset(
    tag
    for tag in (
        getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0),
        getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0),
    )
    if tag
)


class ArtifactError(util.CtfError):
    """Expected negative result: the input is missing or unreadable (exit 1)."""


def _is_linklike_stat(info: os.stat_result) -> bool:
    """True for a symlink, and for a Windows junction or mount point."""
    if stat.S_ISLNK(info.st_mode):
        return True
    tag = getattr(info, "st_reparse_tag", 0)
    if tag and tag in _LINK_REPARSE_TAGS:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _path_is_link(path: str) -> bool:
    try:
        return _is_linklike_stat(os.lstat(path))
    except OSError:
        return False


# --------------------------------------------------------------------------
# Member names
# --------------------------------------------------------------------------
def validate_member_name(name: str, *, is_dir: bool = False) -> Optional[str]:
    """Return a safe, POSIX-normalized member path, or None when refused.

    Refused: empty names, absolute paths, drive letters, UNC prefixes, NUL and
    control characters, ``.`` or ``..`` components, empty components after
    backslash normalization, over-long names and trailing separators on
    non-directory entries. Directory entries (``is_dir=True``) may carry the
    trailing slash that zip and tar writers normally emit.
    """
    if not name or len(name) > MAX_MEMBER_PATH:
        return None
    for char in name:
        code = ord(char)
        if code < 0x20 or code == 0x7F:
            return None
    normalized = name.replace("\\", "/")
    if normalized.endswith("/"):
        if not is_dir:
            return None
        normalized = normalized.rstrip("/")
    if not normalized or normalized.startswith("/"):
        return None
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        return None
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    return "/".join(parts)


def _sanitize_member_name(name: str) -> str:
    """Escape C0/C1 controls, Unicode format characters and lone surrogates.

    Member names and filesystem entry paths (a directory walker decodes names
    with ``surrogateescape`` on non-UTF-8 filesystems) reach human and JSON
    output, where C1 controls, Cf characters (bidi overrides, zero-width
    joiners) and unpaired surrogates can reorder text, hide it, or make
    ``json.dumps(..., ensure_ascii=False)`` raise on encode. Sanitize at
    intake, after :func:`validate_member_name` has seen the original for
    traversal checks, and use the escaped form everywhere.
    """
    if not name:
        return name
    escaped: List[str] = []
    for char in name:
        code = ord(char)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            escaped.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF or unicodedata.category(char) == "Cf":
            escaped.append("\\u%04x" % code)
        else:
            escaped.append(char)
    return "".join(escaped)


def _safe_note(text: str, limit: int = 200) -> str:
    """Printable, symbol-escaped text for one error or refusal note.

    Control bytes first (tab, CR, LF and C0/C1), then the C1/Cf/Cs code points
    ``util.printable`` does not cover, so no emitted error can carry a raw
    control, format or lone-surrogate character into JSON or a terminal.
    """
    return _sanitize_member_name(util.printable(text, limit))


def _rewind(source: Any) -> None:
    """Best-effort ``seek(0)`` so a probe or parse never starts mid-stream."""
    seek = getattr(source, "seek", None)
    if seek is None:
        return
    try:
        seek(0)
    except (OSError, ValueError):
        return


class _TarStreamLimit(Exception):
    """Controlled stop raised by :class:`_LimitedTarStream`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _LimitedTarStream:
    """Count every decompressed byte handed to tarfile, and bound them.

    ``tarfile`` parses attacker-declared PAX/GNU longname and longlink records
    with unbounded ``read(size)`` calls inside ``next()``; wrapping the
    decompressed stream means those reads pass through this counter. There is
    deliberately no ``seek``: streaming mode never seeks, and a seek would
    move bytes around the count. Reads raise :class:`_TarStreamLimit` once the
    delivered bytes pass ``limit`` or the shared deadline has expired.
    """

    def __init__(self, stream: BinaryIO, state: _ScanState, limit: int) -> None:
        self._stream = stream
        self._state = state
        self.limit = limit
        self.delivered = 0

    def read(self, size: int = -1) -> bytes:
        if self._state.expired():
            raise _TarStreamLimit("max-seconds")
        if size is None or size < 0:
            size = READ_CHUNK
        chunk = self._stream.read(size)
        self.delivered += len(chunk)
        if self.delivered > self.limit:
            raise _TarStreamLimit("tar-metadata-cap")
        return chunk

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False


# --------------------------------------------------------------------------
# Scan state
# --------------------------------------------------------------------------
class _ScanState:
    """Budgets, counters and findings shared by every pass of one scan."""

    def __init__(
        self,
        *,
        flag_pattern: bytes,
        max_depth: int,
        max_entries: int,
        max_members: int,
        max_member_bytes: int,
        max_total_bytes: int,
        max_seconds: float,
    ) -> None:
        self.flag_re: Pattern[bytes] = re.compile(flag_pattern)
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.max_members = max_members
        self.max_member_bytes = max_member_bytes
        self.max_total_bytes = max_total_bytes
        self.deadline = time.monotonic() + max_seconds
        self.reasons: List[str] = []
        self.errors: List[str] = []
        self.archive_errors: List[Dict[str, str]] = []
        self.findings: List[Dict[str, Any]] = []
        self.strings: List[Dict[str, Any]] = []
        self.files: List[Dict[str, Any]] = []
        self.members: List[Dict[str, Any]] = []
        self.entries = 0
        self.files_scanned = 0
        self.files_skipped = 0
        self.links_skipped = 0
        self.special_skipped = 0
        self.depth_skipped = 0
        self.collisions = 0
        self.invalid_members = 0
        self.encrypted_skipped = 0
        self.members_seen = 0
        self.members_parsed = 0
        self.members_skipped = 0
        self.members_unparsed = 0
        self.bytes_read = 0
        self.bytes_expanded = 0
        self.metadata_bytes = 0
        self.strings_bytes = 0
        self.decoded_bytes = 0
        self.decode_candidates = 0
        self.decode_ok = 0
        self.decode_failed = 0
        self.discovered_bytes = 0
        self.stopped = False
        self.strings_closed = False
        self.finding_index: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        self.finding_values: Set[Tuple[str, str, str]] = set()
        self.member_seen: Set[Tuple[str, str]] = set()
        self.candidate_seen: Set[Tuple[str, str, bytes]] = set()

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def hit(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)

    def stop(self, reason: str) -> None:
        self.hit(reason)
        self.stopped = True

    def fail_archive(self, label: str, reason: str) -> None:
        """Record archive bytes that could not be detected or parsed.

        The input is still triaged as a plain file, but it was attempted as an
        archive: the unread bytes are named in ``archive_errors``/``errors`` and
        the scan is no longer complete. Labels and reasons are sanitized here
        so exception text built from attacker names cannot carry controls,
        format characters or lone surrogates into the payload.
        """
        safe_label = _sanitize_member_name(label)
        safe_reason = _safe_note(reason, 200)
        entry = {"path": safe_label, "reason": safe_reason}
        if entry not in self.archive_errors:
            self.archive_errors.append(entry)
            self.errors.append(f"{safe_label}: archive unparsed: {safe_reason}")
        self.hit("archive-unparsed")

    def check_time(self) -> bool:
        if not self.stopped and self.expired():
            self.stop("max-seconds")
        return self.stopped

    def add_finding(
        self,
        path: str,
        offset: int,
        value: str,
        source: str = "raw",
        inner_offset: Optional[int] = None,
    ) -> None:
        """Record one flag match, deduplicated per (path, source, value)."""
        if not value:
            return
        key = (path, source, offset)
        previous = self.finding_index.get(key)
        if previous is not None:
            if len(value) > len(previous["value"]):
                previous["value"] = value
                previous["inner_offset"] = inner_offset
            return
        value_key = (path, source, value)
        if value_key in self.finding_values:
            return
        if len(self.findings) >= MAX_FINDINGS:
            self.hit("max-findings")
            return
        item = {
            "path": path,
            "offset": offset,
            "value": value,
            "source": source,
            "inner_offset": inner_offset,
        }
        self.finding_index[key] = item
        self.finding_values.add(value_key)
        self.findings.append(item)

    def add_string(
        self,
        path: str,
        source: str,
        offset: int,
        value: str,
        inner_offset: Optional[int] = None,
    ) -> bool:
        """Store one printable run if the global string budget allows it."""
        if self.strings_closed:
            return False
        if len(self.strings) >= MAX_STRINGS_ENTRIES:
            self.hit("max-strings-entries")
            self.strings_closed = True
            return False
        if self.strings_bytes + len(value) > MAX_STRINGS_TOTAL:
            self.hit("max-strings-total")
            self.strings_closed = True
            return False
        self.strings_bytes += len(value)
        self.strings.append(
            {
                "path": path,
                "offset": offset,
                "value": value,
                "source": source,
                "inner_offset": inner_offset,
            }
        )
        return True

    def claim_member(self, parent: str, normalized: str) -> bool:
        """Collision check on one member path within its parent archive."""
        key = (parent, os.path.normcase(normalized))
        if key in self.member_seen:
            self.collisions += 1
            self.members_skipped += 1
            return False
        self.member_seen.add(key)
        return True


# --------------------------------------------------------------------------
# Streaming string and decode-candidate collectors
# --------------------------------------------------------------------------
class _StringRun:
    """Printable-ASCII run collector that survives chunk boundaries.

    A run that touches the end of a chunk is held and re-examined with the next
    chunk, so a run spanning two reads is emitted exactly once.
    """

    def __init__(
        self,
        state: _ScanState,
        path: str,
        source: str,
        outer_offset: Optional[int] = None,
    ) -> None:
        self.state = state
        self.path = path
        self.source = source
        self.outer_offset = outer_offset
        self.pending = b""
        self.pending_offset = 0
        self.bytes_used = 0
        self.emitted = 0
        self.stopped = False

    def feed(self, data: bytes, base: int, eof: bool = False) -> None:
        if self.stopped or self.state.stopped:
            return
        if self.pending:
            buf = self.pending + data
            buf_base = self.pending_offset
        else:
            buf = data
            buf_base = base
        self.pending = b""
        for match in _PRINTABLE.finditer(buf):
            if not eof and match.end() == len(buf):
                self.pending = bytes(match.group())
                self.pending_offset = buf_base + match.start()
                break
            self._emit(bytes(match.group()), buf_base + match.start())
        if len(self.pending) > MAX_STRING_RUN:
            self.state.hit("max-string-run")
            self._emit(self.pending[:MAX_STRING_RUN], self.pending_offset)
            self.pending = b""

    def _emit(self, value: bytes, position: int) -> None:
        if self.stopped:
            return
        text = value.decode("ascii", "replace")
        if self.bytes_used + len(text) > MAX_STRINGS_PER_FILE:
            self.stopped = True
            self.state.hit("max-strings-per-file")
            return
        if self.outer_offset is None:
            offset = position
            inner = None
        else:
            offset = self.outer_offset
            inner = position
        if self.state.add_string(self.path, self.source, offset, text, inner):
            self.bytes_used += len(text)
            self.emitted += 1


class _TokenFeed:
    """Base64/hex candidate runs, with a pending tail across chunk boundaries."""

    def __init__(self, state: _ScanState, path: str) -> None:
        self.state = state
        self.path = path
        self.pending = b""
        self.pending_offset = 0
        self.skipping = False

    def feed(self, data: bytes, base: int, eof: bool = False) -> None:
        if self.state.stopped:
            return
        if self.skipping:
            stop = _TOKEN_STOP.search(data)
            if stop is None:
                return
            data = data[stop.end() :]
            base += stop.end()
            self.skipping = False
        if self.pending:
            buf = self.pending + data
            buf_base = self.pending_offset
        else:
            buf = data
            buf_base = base
        self.pending = b""
        for match in _TOKEN.finditer(buf):
            token = bytes(match.group())
            if not eof and match.end() == len(buf):
                self.pending = token
                self.pending_offset = buf_base + match.start()
                if len(token) > MAX_DECODE_RUN:
                    self.state.hit("max-decode-run")
                    self._decode(token[:MAX_DECODE_RUN], self.pending_offset)
                    self.pending = b""
                    self.skipping = True
                break
            self._decode(token, buf_base + match.start())

    def _decode(self, token: bytes, offset: int) -> None:
        if len(token) < MIN_DECODE_RUN or self.state.stopped:
            return
        encodings: List[str] = []
        if b"=" not in token and _HEX_ONLY.match(token):
            encodings.append("hex")
        encodings.append("base64")
        for encoding in encodings:
            self._attempt(encoding, token, offset)

    def _attempt(self, encoding: str, token: bytes, offset: int) -> None:
        state = self.state
        key = (self.path, encoding, token)
        if key in state.candidate_seen:
            return
        state.candidate_seen.add(key)
        if state.decode_candidates >= MAX_DECODE_CANDIDATES:
            state.hit("max-decode-candidates")
            return
        state.decode_candidates += 1
        raw = _decode_token(encoding, token)
        if not raw:
            state.decode_failed += 1
            return
        if state.decoded_bytes + len(raw) > MAX_DECODED_BYTES:
            state.hit("max-decoded-bytes")
            return
        state.decoded_bytes += len(raw)
        state.decode_ok += 1
        _scan_decoded(state, self.path, encoding, raw, offset)


def _decode_token(encoding: str, token: bytes) -> Optional[bytes]:
    """Strict one-shot decode; None when the run is not valid input."""
    try:
        if encoding == "hex":
            if len(token) % 2:
                token = token[:-1]
            return binascii.unhexlify(token)
        text = token.decode("ascii")
        text += "=" * (-len(text) % 4)
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _scan_decoded(
    state: _ScanState, path: str, source: str, raw: bytes, offset: int
) -> None:
    """Rescan one decoded buffer for the flag regex and printable runs.

    Offsets point at the encoded run in the original stream; ``inner_offset``
    carries the position inside the decoded buffer. There is deliberately no
    recursion: a decoded buffer is never fed back into the decode pass.
    """
    for match in state.flag_re.finditer(raw):
        state.add_finding(
            path,
            offset,
            match.group().decode("ascii", "replace"),
            source,
            match.start(),
        )
    run = _StringRun(state, path, source, outer_offset=offset)
    run.feed(raw, 0, eof=True)


# --------------------------------------------------------------------------
# Stream scanning
# --------------------------------------------------------------------------
def _scan_chunk_flags(
    state: _ScanState, path: str, carry: bytes, chunk: bytes, base: int
) -> None:
    buf = carry + chunk
    buf_base = base - len(carry)
    for match in state.flag_re.finditer(buf):
        if match.end() <= len(carry):
            # Already examined in the previous window; this is the overlap.
            continue
        state.add_finding(
            path, buf_base + match.start(), match.group().decode("ascii", "replace")
        )


def _scan_stream(
    state: _ScanState,
    path: str,
    stream: BinaryIO,
    *,
    declared_size: Optional[int] = None,
    member_of: Optional[str] = None,
    member_cap: Optional[int] = None,
) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Stream one file or archive member through every content pass.

    Returns the file summary and, for archive members, a bounded capture of the
    raw bytes used to detect a nested archive (None when capture is incomplete).
    """
    digest = hashlib.sha256()
    total = 0
    strings_before = len(state.strings)
    findings_before = len(state.findings)
    expanded_before = state.bytes_expanded
    strings_run = _StringRun(state, path, "raw")
    tokens = _TokenFeed(state, path)
    flag_carry = b""
    offset = 0
    # A stream opened after the scan was already stopped cannot be fully read,
    # so its summary must say truncated too (an expired deadline included).
    truncated = state.stopped
    eof_reached = False
    capture: Optional[bytearray] = bytearray() if member_of is not None else None
    capture_complete = True

    while not state.stopped:
        if state.check_time():
            truncated = True
            break
        try:
            chunk = stream.read(READ_CHUNK)
        except _TarStreamLimit:
            # A metadata cap or the deadline tripped inside the tar stream
            # wrapper; let the tar reader turn it into a limit reason.
            raise
        except Exception as exc:  # untrusted stream: record, never crash the scan
            state.errors.append(f"{path}: read failed: {_safe_note(str(exc), 160)}")
            truncated = True
            break
        if not chunk:
            eof_reached = True
            break
        total += len(chunk)
        state.bytes_read += len(chunk)
        if member_of is not None:
            state.bytes_expanded += len(chunk)
            if member_cap is not None and total > member_cap:
                state.hit("max-member-bytes")
                truncated = True
                break
            if state.bytes_expanded > state.max_total_bytes:
                state.stop("max-total-bytes")
                truncated = True
                break
        digest.update(chunk)
        if capture is not None:
            room = MAX_NESTED_BYTES - len(capture)
            if room >= len(chunk):
                capture.extend(chunk)
            elif room > 0:
                capture.extend(chunk[:room])
                capture_complete = False
            else:
                capture_complete = False
        _scan_chunk_flags(state, path, flag_carry, chunk, offset)
        flag_carry = (flag_carry + chunk)[-FLAG_CARRY:]
        strings_run.feed(chunk, offset)
        tokens.feed(chunk, offset)
        offset += len(chunk)

    if eof_reached and not state.stopped:
        strings_run.feed(b"", offset, eof=True)
        tokens.feed(b"", offset, eof=True)

    captured = bytes(capture) if capture else None
    if capture is not None and not capture_complete and captured:
        if _sniff_archive_magic(captured):
            state.hit("max-nested-bytes")
    if capture is not None and not capture_complete:
        captured = None

    summary: Dict[str, Any] = {
        "path": path,
        "sha256": digest.hexdigest(),
        "bytes_read": total,
        "strings": len(state.strings) - strings_before,
        "findings": len(state.findings) - findings_before,
        "truncated": truncated,
        "strings_truncated": strings_run.stopped,
    }
    if member_of is not None:
        summary["size"] = total
        summary["declared_size"] = declared_size
        summary["bytes_expanded"] = state.bytes_expanded - expanded_before
    else:
        summary["size"] = int(declared_size) if declared_size is not None else total
    return summary, captured


def _sniff_archive_magic(data: bytes) -> bool:
    if data[:4] in _ARCHIVE_MAGIC:
        return True
    return len(data) >= 262 and data[257:262] == b"ustar"


#: Name suffixes whose garbage content is reported as a failed archive attempt.
_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tbz",
    ".tar.xz",
    ".txz",
)


def _archive_name_hint(path: str) -> bool:
    """True when the file name claims to be an archive."""
    return path.lower().endswith(_ARCHIVE_SUFFIXES)


#: End-of-central-directory record: 4-byte signature plus 18 fixed bytes.
_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_MIN_SIZE = 22
#: Match ``zipfile._EndRecData``'s window (64 KiB plus one record) exactly, so
#: the last signature this preflight finds is the one zipfile will use.
_EOCD_MAX_TAIL = (1 << 16) + _EOCD_MIN_SIZE


def _zip_eocd_preflight(
    source: Any, max_members: int
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Read the zip end-of-central-directory record cheaply, before opening.

    Returns ``(declared_total_entries, parse_note, refusal_reason,
    refusal_detail)``; exactly one of ``parse_note`` and ``refusal_reason`` is
    set when ``declared_total_entries`` is None. The declared count is never
    trusted for a cap, only used to refuse an archive that already exceeds the
    member budget before ``zipfile`` materializes its central directory.

    A classic record cannot bound a zip64 archive (``zipfile`` follows the
    ``PK\\x06\\x07`` locator and then reads a 64-bit central-directory size and
    one ``ZipInfo`` per record), so a zip64 locator, a ``0xFFFF`` count or a
    ``0xFFFFFFFF`` size is refused outright. A classic directory whose declared
    size exceeds ``max(4 MiB, min(input size, max_members * 4096))`` is
    refused too: ``zipfile`` would read exactly that many bytes and build one
    ``ZipInfo`` per entry before any member cap applies.

    ``zipfile._EndRecData`` honors the LAST ``PK\\x05\\x06`` signature in its
    tail window even when that record is not aligned to the file end, so an
    earlier aligned record must not be validated in its place. When the last
    signature is truncated or its comment length does not reach the file end,
    the preflight refuses (``eocd-misaligned``) instead of guessing which
    record zipfile will read.
    """
    try:
        if isinstance(source, str):
            with open(source, "rb") as handle:
                return _read_eocd(handle, max_members)
        return _read_eocd(source, max_members)
    except (OSError, ValueError, struct.error) as exc:
        return None, f"end-of-central-directory read failed: {exc}", None, None


def _read_eocd(
    handle: Any, max_members: int
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    tail_size = min(size, _EOCD_MAX_TAIL)
    if tail_size < _EOCD_MIN_SIZE:
        return None, "smaller than an end-of-central-directory record", None, None
    handle.seek(size - tail_size)
    tail = handle.read(tail_size)
    # ``zipfile._EndRecData`` uses ``data.rfind(signature)`` over this same
    # window and ignores alignment, so the preflight must validate that exact
    # record: an earlier aligned record is not what zipfile will read.
    index = tail.rfind(_EOCD_SIGNATURE)
    if index < 0:
        return None, "no end-of-central-directory record found", None, None
    if index + _EOCD_MIN_SIZE > len(tail):
        return (
            None,
            None,
            "eocd-misaligned",
            "the last end-of-central-directory signature is truncated",
        )
    comment_size = struct.unpack_from("<H", tail, index + 20)[0]
    if index + _EOCD_MIN_SIZE + comment_size != len(tail):
        # Signature bytes inside a comment or trailing junk: zipfile still
        # honors this record, so its declared fields cannot be preflighted.
        return (
            None,
            None,
            "eocd-misaligned",
            "the last end-of-central-directory record does not end at the file end",
        )
    count = struct.unpack_from("<H", tail, index + 10)[0]
    cd_size = struct.unpack_from("<I", tail, index + 12)[0]
    if count == 0xFFFF:
        return (
            None,
            None,
            "zip64-unsupported",
            "member count 0xFFFF is the zip64 sentinel",
        )
    if cd_size == 0xFFFFFFFF:
        return (
            None,
            None,
            "zip64-unsupported",
            "central-directory size 0xFFFFFFFF is the zip64 sentinel",
        )
    if _ZIP64_LOCATOR_MAGIC in tail:
        # Conservative: any locator signature in the bounded tail window
        # refuses, even one that zipfile would not follow.
        return (
            None,
            None,
            "zip64-unsupported",
            "zip64 end-of-central-directory locator present",
        )
    cap = max(MIN_ZIP_CD_CAP, min(size, max_members * 4096))
    if cd_size > cap:
        return (
            None,
            None,
            "cd-size-cap",
            f"central directory declares {cd_size} bytes, over the {cap} byte cap",
        )
    return count, None, None, None


def _stop_tar(state: _ScanState, label: str, reason: str) -> None:
    """Record a tar stream limit stop; no tarfile.next() may follow it."""
    state.stop(reason)
    state.errors.append(f"{label}: {reason}: tar archive not fully parsed")


def _stop_tar_member(
    state: _ScanState, label: str, member_label: str, reason: str
) -> None:
    """Stop a tar scan with one member in flight, counted as unparsed.

    The stream limit tripped while this member was being read, so no summary
    exists for it. Count it as unparsed and name it in the error list before
    the shared stop record, or the member vanishes from the summaries.
    """
    state.members_unparsed += 1
    state.hit("member-unparsed")
    state.errors.append(f"{member_label}: {reason}: member not fully read")
    _stop_tar(state, label, reason)


def _limited_tar_stream(
    raw: Any, state: _ScanState
) -> Tuple[Optional[Any], _LimitedTarStream]:
    """Wrap raw in the decompressor it declares, then in the byte limiter.

    Compression is detected here (gzip, bzip2, xz from their magic) and
    tarfile parses the DECOMPRESSED stream, so the limiter counts exactly the
    bytes tarfile reads, metadata included.
    """
    _rewind(raw)
    try:
        head = raw.read(6)
    finally:
        _rewind(raw)
    decomp: Optional[Any] = None
    if head.startswith(b"\x1f\x8b"):
        decomp = gzip.GzipFile(fileobj=raw)
    elif head.startswith(b"BZh"):
        decomp = bz2.BZ2File(raw)
    elif head.startswith(b"\xfd7zXZ\x00"):
        decomp = lzma.LZMAFile(raw)
    stream = decomp if decomp is not None else raw
    limiter = _LimitedTarStream(
        stream, state, state.max_total_bytes + TAR_METADATA_SLACK
    )
    return decomp, limiter


def _close_tar_stream(decomp: Optional[Any], raw: Any, close_raw: bool) -> None:
    """Close the decompressor and, when this module opened it, the raw source."""
    if decomp is not None:
        try:
            decomp.close()
        except OSError:
            pass
    if close_raw:
        try:
            raw.close()
        except OSError:
            pass


def _probe_zip(state: _ScanState, source: Any) -> bool:
    """Zip detection; ``is_zipfile`` only reads a bounded tail window."""
    return bool(zipfile.is_zipfile(source))


def _probe_tar(state: _ScanState, source: Any) -> bool:
    """Bounded replacement for ``tarfile.is_tarfile``.

    Opens the decompressed stream through the limiter and parses one header;
    tar parse errors mean "not a tar", while a metadata cap or the deadline
    raises :class:`_TarStreamLimit` for the caller to record. A tripped probe
    adds what it delivered to ``metadata_bytes``: no member was read, so every
    delivered byte was metadata.
    """
    raw = source
    close_raw = False
    if isinstance(source, str):
        raw = open(source, "rb")
        close_raw = True
    decomp: Optional[Any] = None
    limiter: Optional[_LimitedTarStream] = None
    try:
        try:
            decomp, limiter = _limited_tar_stream(raw, state)
            archive = tarfile.open(fileobj=limiter, mode="r|")
            with archive:
                archive.next()
            return True
        except _TarStreamLimit:
            if limiter is not None:
                state.metadata_bytes += limiter.delivered
            raise
        except Exception:
            return False
    finally:
        _close_tar_stream(decomp, raw, close_raw)
        if not close_raw:
            _rewind(source)


def _probe_archive(
    state: _ScanState,
    label: str,
    source: Any,
    *,
    name_hint: Optional[str] = None,
) -> Optional[str]:
    """Return ``"zip"``/``"tar"`` when source parses as that archive, else None.

    Probes parse untrusted bytes, so parse-time exceptions (``EOFError`` from a
    gzip stream cut inside its first member, ``zlib.error``/``struct.error``
    from corrupt members, tar and zip errors) must never escape. Every failed
    probe is recorded through :meth:`_ScanState.fail_archive`, which also marks
    the scan incomplete; the source is still triaged as plain bytes. A path
    whose name claims an archive but carries no recognizable structure is
    recorded the same way. Both probes are bounded: zip detection reads a tail
    window, and tar detection parses one header through
    :class:`_LimitedTarStream`, whose cap or deadline stop is recorded as a
    limit instead of a parse failure.

    ``source`` is rewound before every probe and again before returning:
    ``zipfile.is_zipfile`` reads from the current position, so a stream left
    mid-way by an earlier probe could misclassify a nested member. ``name_hint``
    supplies the file name when ``source`` is not a path string.
    """
    failed = False
    try:
        for fmt, probe in (("zip", _probe_zip), ("tar", _probe_tar)):
            _rewind(source)
            try:
                if probe(state, source):
                    return fmt
            except _TarStreamLimit as exc:
                # A metadata bomb: stop the scan rather than keep parsing.
                _stop_tar(state, label, exc.reason)
                return None
            except Exception as exc:  # untrusted archive detection: record, go on
                failed = True
                state.fail_archive(
                    label, f"{fmt} detection failed: {_safe_note(str(exc), 160)}"
                )
    finally:
        _rewind(source)
    hint = (
        name_hint
        if name_hint is not None
        else (source if isinstance(source, str) else None)
    )
    if not failed and hint and _archive_name_hint(hint):
        state.fail_archive(
            label, "name suggests an archive but no zip/tar structure was found"
        )
    return None


# --------------------------------------------------------------------------
# Directory walk
# --------------------------------------------------------------------------
def _note_size_mismatch(
    state: _ScanState, label: str, size: int, summary: Dict[str, Any]
) -> None:
    """Report a plain file that changed size between fstat and the read.

    A truncated stream already carries the cap or deadline that stopped it;
    only a completed read that covers a different byte count than the stat
    reported is a mismatch, and its digest does not describe ``size`` bytes.
    """
    if summary["truncated"] or state.stopped or summary["bytes_read"] == size:
        return
    state.hit("size-mismatch")
    state.errors.append(
        f"{label}: size-mismatch: stat reported {size} bytes, read "
        f"{summary['bytes_read']}"
    )


def _scan_path_file(state: _ScanState, label: str, resolved: str) -> None:
    try:
        handle = open(resolved, "rb")
    except OSError as exc:
        state.files_skipped += 1
        state.errors.append(f"{label}: {_safe_note(str(exc), 160)}")
        return
    with handle:
        try:
            size = int(os.fstat(handle.fileno()).st_size)
        except OSError as exc:
            state.files_skipped += 1
            state.errors.append(f"{label}: {_safe_note(str(exc), 160)}")
            return
        summary, _ = _scan_stream(state, label, handle, declared_size=size)
        _note_size_mismatch(state, label, size, summary)
        state.files_scanned += 1
        state.discovered_bytes += size
        state.files.append(summary)
        # An archive found during a directory walk is inspected like a
        # top-level one: raw bytes first, then bounded member reads, all from
        # the same already-open handle so size and digest cannot drift.
        if not state.stopped:
            _rewind(handle)
            if _probe_archive(state, label, handle, name_hint=label) is not None:
                _inspect_archive(state, label, handle, 1)


def _walk_directory(state: _ScanState, root: str) -> None:
    stack: List[Tuple[str, int]] = [(root, 0)]
    while stack:
        if state.stopped:
            return
        if state.check_time():
            return
        directory, depth = stack.pop()
        remaining = state.max_entries - state.entries
        if remaining < 0:
            state.stop("max-entries")
            return
        entries: List[Any] = []
        try:
            with os.scandir(directory) as iterator:
                # Stream and collect at most one entry past the remaining
                # budget; a hostile directory must never be materialized whole.
                for entry in iterator:
                    if len(entries) >= remaining + 1:
                        break
                    entries.append(entry)
        except OSError as exc:
            state.files_skipped += 1
            state.errors.append(
                f"{_sanitize_member_name(directory)}: {_safe_note(str(exc), 160)}"
            )
            continue
        entries.sort(key=lambda entry: entry.name)
        child_dirs: List[Tuple[str, int]] = []
        for entry in entries:
            if state.stopped:
                return
            if state.check_time():
                return
            state.entries += 1
            if state.entries > state.max_entries:
                state.stop("max-entries")
                return
            try:
                linklike = entry.is_symlink() or _is_linklike_stat(
                    entry.stat(follow_symlinks=False)
                )
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError as exc:
                state.files_skipped += 1
                state.errors.append(
                    f"{_sanitize_member_name(entry.path)}: {_safe_note(str(exc), 160)}"
                )
                continue
            if linklike:
                state.links_skipped += 1
                continue
            if is_dir:
                if depth < state.max_depth:
                    child_dirs.append((entry.path, depth + 1))
                else:
                    state.depth_skipped += 1
                    state.hit("max-depth")
                continue
            if not is_file:
                state.special_skipped += 1
                continue
            _scan_path_file(state, _sanitize_member_name(entry.path), entry.path)
        stack.extend(reversed(child_dirs))


# --------------------------------------------------------------------------
# Archive inspection (in memory only)
# --------------------------------------------------------------------------
def _scan_member(
    state: _ScanState,
    parent: str,
    normalized: str,
    stream: BinaryIO,
    declared_size: Optional[int],
    depth: int,
    ratio: Optional[float],
) -> Dict[str, Any]:
    label = f"{parent}!/{normalized}"
    summary, nested = _scan_stream(
        state,
        label,
        stream,
        declared_size=declared_size,
        member_of=parent,
        member_cap=state.max_member_bytes,
    )
    summary["name"] = normalized
    summary["parent"] = parent
    summary["ratio"] = ratio
    if summary["truncated"]:
        state.members_unparsed += 1
        state.hit("member-unparsed")
    else:
        state.members_parsed += 1
    state.members.append(summary)
    if nested is None:
        return summary
    if _probe_archive(state, label, io.BytesIO(nested)) is None:
        return summary
    if depth + 1 > state.max_depth:
        state.hit("max-depth")
        return summary
    _inspect_archive(state, label, io.BytesIO(nested), depth + 1)
    return summary


def _inspect_archive(state: _ScanState, label: str, source: Any, depth: int) -> None:
    """Dispatch one archive (path or seekable buffer) to its reader."""
    if depth > state.max_depth:
        state.hit("max-depth")
        return
    archive_format = _probe_archive(state, label, source)
    if archive_format == "zip":
        _inspect_zip(state, label, source, depth)
    elif archive_format == "tar":
        _inspect_tar(state, label, source, depth)


def _inspect_zip(state: _ScanState, label: str, source: Any, depth: int) -> None:
    declared, note, refusal, refusal_detail = _zip_eocd_preflight(
        source, state.max_members
    )
    if refusal is not None:
        # A zip64 archive or an over-cap central directory cannot be bounded
        # from the classic record, so it is refused before zipfile opens it.
        state.hit(refusal)
        state.errors.append(f"{label}: {refusal}: {refusal_detail}")
        return
    if declared is None:
        state.fail_archive(label, f"zip preflight refused: {_safe_note(note, 200)}")
        return
    if declared > state.max_members:
        # The declared count is only ever used to refuse opening an archive
        # that is already over budget; it is never trusted for a cap.
        state.hit("archive-over-member-cap")
        state.errors.append(
            f"{label}: archive-over-member-cap: end-of-central-directory "
            f"declares {declared} members, over the {state.max_members} budget"
        )
        return
    _rewind(source)
    try:
        archive = zipfile.ZipFile(source)
    except Exception as exc:  # untrusted archive: record, never crash
        state.fail_archive(label, f"zip open failed: {_safe_note(str(exc), 160)}")
        return
    with archive:
        try:
            infos = archive.infolist()
        except Exception as exc:  # untrusted archive: record, never crash
            state.fail_archive(
                label, f"zip listing failed: {_safe_note(str(exc), 160)}"
            )
            return
        # The preflight bounds what zipfile materializes; cap again before
        # sorting so a lying record still cannot grow the processed list, and
        # count the dropped entries so the member totals do not understate
        # what the archive declared.
        if len(infos) > state.max_members:
            dropped = len(infos) - state.max_members
            state.hit("max-members")
            state.members_unparsed += dropped
            infos = infos[: state.max_members]
        infos = sorted(infos, key=lambda info: info.filename)
        for info in infos:
            if state.stopped:
                return
            if state.check_time():
                return
            state.members_seen += 1
            if state.members_seen > state.max_members:
                state.members_unparsed += 1
                state.stop("max-members")
                return
            name = info.filename
            mode = (info.external_attr >> 16) & 0xFFFF
            # Some writers store permission bits without a file type; type 0
            # means "regular" and must not be mistaken for a special entry.
            file_type = stat.S_IFMT(mode) if mode else 0
            is_dir = name.endswith("/") or file_type == stat.S_IFDIR
            if file_type == stat.S_IFLNK:
                state.links_skipped += 1
                continue
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                state.special_skipped += 1
                continue
            normalized = validate_member_name(name, is_dir=is_dir)
            if normalized is None:
                state.invalid_members += 1
                state.members_skipped += 1
                continue
            normalized = _sanitize_member_name(normalized)
            if not state.claim_member(label, normalized):
                continue
            if is_dir:
                continue
            if info.flag_bits & 0x1:
                state.encrypted_skipped += 1
                state.members_skipped += 1
                continue
            ratio: Optional[float] = None
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size if info.file_size else 0.0
                if ratio > MAX_COMPRESSION_RATIO:
                    state.hit("max-ratio")
                    state.members_skipped += 1
                    continue
            try:
                with archive.open(info) as member:
                    _scan_member(
                        state, label, normalized, member, info.file_size, depth, ratio
                    )
            except Exception as exc:  # corrupt member stream: record and go on
                state.members_skipped += 1
                state.hit("member-unparsed")
                state.errors.append(
                    f"{label}!/{normalized}: {_safe_note(str(exc), 160)}"
                )


def _inspect_tar(state: _ScanState, label: str, source: Any, depth: int) -> None:
    raw = source
    close_raw = False
    if isinstance(source, str):
        try:
            raw = open(source, "rb")
        except OSError as exc:
            state.fail_archive(label, f"tar open failed: {_safe_note(str(exc), 160)}")
            return
        close_raw = True
    decomp: Optional[Any] = None
    limiter: Optional[_LimitedTarStream] = None
    member_bytes = 0
    try:
        try:
            decomp, limiter = _limited_tar_stream(raw, state)
            archive = tarfile.open(fileobj=limiter, mode="r|")
        except _TarStreamLimit as exc:
            _stop_tar(state, label, exc.reason)
            return
        except Exception as exc:  # untrusted archive: record, never crash
            state.fail_archive(label, f"tar open failed: {_safe_note(str(exc), 160)}")
            return
        with archive:
            while True:
                if state.stopped:
                    return
                if state.check_time():
                    return
                try:
                    member = archive.next()
                except _TarStreamLimit as exc:
                    _stop_tar(state, label, exc.reason)
                    return
                except Exception as exc:  # untrusted archive: record, never crash
                    state.fail_archive(
                        label, f"tar read failed: {_safe_note(str(exc), 160)}"
                    )
                    return
                if member is None:
                    return
                state.members_seen += 1
                if state.members_seen > state.max_members:
                    state.members_unparsed += 1
                    state.stop("max-members")
                    return
                name = member.name
                if member.isdir():
                    normalized = validate_member_name(name, is_dir=True)
                    if normalized is None:
                        state.invalid_members += 1
                        state.members_skipped += 1
                        continue
                    state.claim_member(label, _sanitize_member_name(normalized))
                    continue
                if member.islnk() or member.issym():
                    state.links_skipped += 1
                    continue
                if not member.isreg():
                    state.special_skipped += 1
                    continue
                normalized = validate_member_name(name, is_dir=False)
                if normalized is None:
                    state.invalid_members += 1
                    state.members_skipped += 1
                    continue
                normalized = _sanitize_member_name(normalized)
                if not state.claim_member(label, normalized):
                    continue
                if member.size > state.max_member_bytes:
                    # Never call next() after refusing a member: the stream
                    # skip would decompress and discard attacker-declared
                    # bytes outside every counter, so refuse the member and
                    # abort the loop.
                    state.hit("member-declared-over-cap")
                    state.members_unparsed += 1
                    state.errors.append(
                        f"{label}!/{normalized}: member-declared-over-cap: declared "
                        f"{member.size} bytes, over the {state.max_member_bytes} byte budget"
                    )
                    return
                try:
                    handle = archive.extractfile(member)
                except _TarStreamLimit as exc:
                    _stop_tar_member(state, label, f"{label}!/{normalized}", exc.reason)
                    return
                except Exception as exc:  # untrusted archive: record, never crash
                    state.members_skipped += 1
                    state.hit("member-unparsed")
                    state.errors.append(
                        f"{label}!/{normalized}: {_safe_note(str(exc), 160)}"
                    )
                    return
                if handle is None:
                    state.members_skipped += 1
                    state.hit("member-unparsed")
                    return
                try:
                    before = limiter.delivered
                    summary = _scan_member(
                        state, label, normalized, handle, member.size, depth, None
                    )
                except _TarStreamLimit as exc:
                    _stop_tar_member(state, label, f"{label}!/{normalized}", exc.reason)
                    return
                except Exception as exc:  # corrupt member stream: record, never crash
                    state.members_skipped += 1
                    state.hit("member-unparsed")
                    state.errors.append(
                        f"{label}!/{normalized}: {_safe_note(str(exc), 160)}"
                    )
                    return
                finally:
                    # Bytes tarfile delivered while this member was read are
                    # member bytes; everything else the limiter counted
                    # (headers, longname records, padding) is metadata.
                    member_bytes += limiter.delivered - before
                    handle.close()
                if state.stopped or summary["truncated"]:
                    # A cap or the deadline cut this member short. Aborting now
                    # is what keeps declared sizes from becoming a seek target
                    # for the next header; the archive is reported incomplete
                    # instead.
                    return
    finally:
        if limiter is not None:
            state.metadata_bytes += max(0, limiter.delivered - member_bytes)
        _close_tar_stream(decomp, raw, close_raw)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def scan(
    path: str,
    *,
    flag_regex: str = DEFAULT_FLAG_REGEX,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_MIB * MIB,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_MIB * MIB,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> Dict[str, Any]:
    """Triage one file, directory or archive and return a machine payload.

    Payload keys: ``schema``, ``path``, ``resolved_path``, ``input_was_link``,
    ``kind`` (file/dir/archive), ``archive_format``, ``size``, ``sha256``,
    ``complete``, ``incomplete`` (category names that made ``complete`` false,
    see the module docstring), ``limits`` (``hit`` plus ``reasons``),
    ``counts`` (entries, files, members, archive_errors, bytes, metadata and
    decode totals), ``files``, ``members``, ``findings`` and ``strings``
    (sorted by path, offset, value), ``errors`` and ``archive_errors`` (one
    ``path``/``reason`` per archive that could not be detected or parsed).
    Every emitted path and error is sanitized at intake; ``metadata_bytes``
    counts the tar stream bytes that were not member data (headers, longname
    records, padding).

    ``sha256`` is computed in the streaming pass over the same handle that
    reported ``size``: it covers exactly the bytes in the file summary
    ``bytes_read``, which is the whole file only when ``complete`` is true.

    Raises ``ArtifactError`` (exit 1) for a missing or unreadable input and
    ``util.UsageError`` (exit 2) for an invalid regex or negative limit.
    """
    if not path:
        raise util.UsageError("a path is required")
    if "\x00" in path:
        raise util.UsageError("path must not contain NUL bytes")
    for name, value in (
        ("max-depth", max_depth),
        ("max-entries", max_entries),
        ("max-members", max_members),
        ("max-member-bytes", max_member_bytes),
        ("max-total-bytes", max_total_bytes),
        ("max-seconds", max_seconds),
    ):
        if value < 0:
            raise util.UsageError(f"{name} must not be negative")
    max_depth = min(int(max_depth), MAX_DEPTH_CAP)
    try:
        flag_pattern = flag_regex.encode("ascii")
    except UnicodeEncodeError as exc:
        raise util.UsageError("--flag-regex must be ASCII") from exc
    if not flag_pattern or len(flag_pattern) > MAX_FLAG_REGEX:
        raise util.UsageError(f"--flag-regex must be 1-{MAX_FLAG_REGEX} bytes")
    try:
        re.compile(flag_pattern)
    except re.error as exc:
        raise util.UsageError(f"invalid --flag-regex: {exc}") from exc

    input_was_link = _path_is_link(path)
    resolved = os.path.realpath(path) if input_was_link else os.path.abspath(path)
    if not os.path.exists(resolved):
        raise ArtifactError(f"input does not exist: {_sanitize_member_name(path)}")
    # Reporter copies only: filesystem calls keep the raw path, while every
    # emitted path is escaped once here so C1/Cf/lone-surrogate code points
    # cannot reach human output or make ensure_ascii=False JSON raise.
    safe_path = _sanitize_member_name(path)
    safe_resolved = _sanitize_member_name(resolved)

    state = _ScanState(
        flag_pattern=flag_pattern,
        max_depth=max_depth,
        max_entries=int(max_entries),
        max_members=int(max_members),
        max_member_bytes=int(max_member_bytes),
        max_total_bytes=int(max_total_bytes),
        max_seconds=float(max_seconds),
    )

    payload: Dict[str, Any] = {
        "schema": "ctfctl.artifact/1",
        "path": safe_path,
        "resolved_path": safe_resolved,
        "input_was_link": input_was_link,
        "kind": None,
        "archive_format": None,
        "size": None,
        "sha256": None,
    }

    if os.path.isdir(resolved):
        payload["kind"] = "dir"
        try:
            with os.scandir(resolved):
                pass
        except OSError as exc:
            raise ArtifactError(
                f"cannot read directory {safe_path}: {_safe_note(str(exc), 200)}"
            ) from exc
        _walk_directory(state, resolved)
        payload["size"] = state.discovered_bytes
    else:
        try:
            st = os.lstat(resolved)
        except OSError as exc:
            raise ArtifactError(
                f"cannot stat {safe_path}: {_safe_note(str(exc), 200)}"
            ) from exc
        if not stat.S_ISREG(st.st_mode):
            raise ArtifactError(
                f"not a regular file or directory: {safe_path} "
                "(special files are refused)"
            )
        try:
            handle = open(resolved, "rb")
        except OSError as exc:
            raise ArtifactError(
                f"cannot read {safe_path}: {_safe_note(str(exc), 200)}"
            ) from exc
        with handle:
            try:
                info = os.fstat(handle.fileno())
            except OSError as exc:
                raise ArtifactError(
                    f"cannot stat {safe_path}: {_safe_note(str(exc), 200)}"
                ) from exc
            if not stat.S_ISREG(info.st_mode):
                raise ArtifactError(
                    f"not a regular file or directory: {safe_path} "
                    "(special files are refused)"
                )
            size = int(info.st_size)
            archive_format = _probe_archive(
                state, safe_path, handle, name_hint=safe_resolved
            )
            kind = "archive" if archive_format else "file"
            payload["kind"] = kind
            payload["archive_format"] = archive_format
            payload["size"] = size
            # One handle for stat, hash and scan: the digest covers exactly
            # the bytes this same stream reported.
            summary, _ = _scan_stream(state, safe_path, handle, declared_size=size)
            _note_size_mismatch(state, safe_path, size, summary)
            state.files_scanned += 1
            state.discovered_bytes += size
            state.files.append(summary)
            payload["sha256"] = summary["sha256"]
            if kind == "archive" and not state.stopped:
                _rewind(handle)
                _inspect_archive(state, safe_path, handle, 1)

    incomplete = _incomplete_categories(state)
    payload["complete"] = not incomplete
    payload["incomplete"] = incomplete
    payload["limits"] = {"hit": bool(state.reasons), "reasons": list(state.reasons)}
    payload["counts"] = _counts(state)
    payload["files"] = state.files
    payload["members"] = state.members
    payload["findings"] = sorted(
        state.findings, key=lambda item: (item["path"], item["offset"], item["value"])
    )
    payload["strings"] = sorted(
        state.strings, key=lambda item: (item["path"], item["offset"], item["value"])
    )
    payload["errors"] = state.errors
    payload["archive_errors"] = state.archive_errors
    return payload


def _incomplete_categories(state: _ScanState) -> List[str]:
    """Every category that means part of the input was not fully analyzed."""
    categories: List[str] = []
    if state.reasons:
        categories.append("limits")
    if state.errors:
        categories.append("errors")
    if state.archive_errors:
        categories.append("archive-errors")
    if state.files_skipped:
        categories.append("files-skipped")
    if state.links_skipped:
        categories.append("links-skipped")
    if state.special_skipped:
        categories.append("special-skipped")
    if state.depth_skipped:
        categories.append("depth-skipped")
    if state.members_skipped:
        categories.append("members-skipped")
    if state.members_unparsed:
        categories.append("members-unparsed")
    return categories


def _counts(state: _ScanState) -> Dict[str, int]:
    return {
        "entries": state.entries,
        "files_scanned": state.files_scanned,
        "files_skipped": state.files_skipped,
        "links_skipped": state.links_skipped,
        "special_skipped": state.special_skipped,
        "depth_skipped": state.depth_skipped,
        "archive_errors": len(state.archive_errors),
        "members_seen": state.members_seen,
        "members_parsed": state.members_parsed,
        "members_skipped": state.members_skipped,
        "members_unparsed": state.members_unparsed,
        "collisions": state.collisions,
        "invalid_members": state.invalid_members,
        "encrypted_skipped": state.encrypted_skipped,
        "bytes_read": state.bytes_read,
        "bytes_expanded": state.bytes_expanded,
        "metadata_bytes": state.metadata_bytes,
        "strings": len(state.strings),
        "strings_bytes": state.strings_bytes,
        "findings": len(state.findings),
        "decode_candidates": state.decode_candidates,
        "decode_ok": state.decode_ok,
        "decode_failed": state.decode_failed,
        "decoded_bytes": state.decoded_bytes,
    }


# --------------------------------------------------------------------------
# Human rendering
# --------------------------------------------------------------------------
def render_scan(payload: Dict[str, Any]) -> str:
    """Human summary; the JSON payload stays the machine interface.

    Paths are already sanitized at intake; they are escaped again here so a
    hand-built payload cannot print controls either (the escape is idempotent).
    """
    lines: List[str] = []
    kind = payload.get("kind", "?")
    fmt = payload.get("archive_format")
    path_text = _sanitize_member_name(str(payload.get("path", "")))
    head = f"artifact scan: {path_text}  kind={kind}"
    if fmt:
        head += f" ({fmt})"
    lines.append(head)
    if payload.get("input_was_link"):
        resolved_text = _sanitize_member_name(str(payload.get("resolved_path", "")))
        lines.append(f"  input was a link, scanned: {resolved_text}")
    if payload.get("size") is not None:
        size = int(payload["size"])
        lines.append(f"  size={size} ({util.human_bytes(size)})")
    if payload.get("sha256"):
        lines.append(f"  sha256={payload['sha256']}")
    counts = payload.get("counts", {})
    if kind == "dir":
        lines.append(
            "  entries={entries} files={files} skipped={skipped} "
            "links={links} special={special} depth_skipped={depth}".format(
                entries=counts.get("entries", 0),
                files=counts.get("files_scanned", 0),
                skipped=counts.get("files_skipped", 0),
                links=counts.get("links_skipped", 0),
                special=counts.get("special_skipped", 0),
                depth=counts.get("depth_skipped", 0),
            )
        )
    if counts.get("members_seen"):
        lines.append(
            "  members seen={seen} parsed={parsed} skipped={skipped} "
            "unparsed={unparsed} expanded={expanded}".format(
                seen=counts.get("members_seen", 0),
                parsed=counts.get("members_parsed", 0),
                skipped=counts.get("members_skipped", 0),
                unparsed=counts.get("members_unparsed", 0),
                expanded=util.human_bytes(counts.get("bytes_expanded", 0)),
            )
        )
        lines.append(
            "  collisions={collisions} invalid_names={invalid} encrypted={encrypted}".format(
                collisions=counts.get("collisions", 0),
                invalid=counts.get("invalid_members", 0),
                encrypted=counts.get("encrypted_skipped", 0),
            )
        )
    lines.append(
        "  strings={strings} ({size}) findings={findings} "
        "decoded={ok}/{tried} candidates".format(
            strings=counts.get("strings", 0),
            size=util.human_bytes(counts.get("strings_bytes", 0)),
            findings=counts.get("findings", 0),
            ok=counts.get("decode_ok", 0),
            tried=counts.get("decode_candidates", 0),
        )
    )
    limits = payload.get("limits", {})
    if payload.get("complete"):
        lines.append("  complete: yes (within the configured limits)")
    else:
        reasons = ", ".join(limits.get("reasons", [])) or "see incomplete categories"
        lines.append("  complete: no - stopped by: " + reasons)
        incomplete = payload.get("incomplete", [])
        if incomplete:
            lines.append("  incomplete: " + ", ".join(incomplete))
    for error in payload.get("errors", [])[:5]:
        lines.append(f"  ! {error}")
    findings = payload.get("findings", [])
    if findings:
        shown = min(len(findings), TOP_FINDINGS)
        lines.append(f"  findings (top {shown} of {len(findings)}):")
        for item in findings[:TOP_FINDINGS]:
            lines.append(
                "    [{source}] {path} @{offset}  {preview}".format(
                    source=item.get("source", "raw"),
                    path=_sanitize_member_name(str(item["path"])),
                    offset=item["offset"],
                    preview=util.printable(item["value"], 160),
                )
            )
    lines.append("")
    lines.append("triage, not proof: unscanned or truncated bytes are not cleared.")
    return "\n".join(lines)
