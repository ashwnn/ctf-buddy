"""`ctfctl artifact scan`: bounded, read-only triage of files, dirs and archives.

Every fixture is generated at test time in a throwaway temp dir with the
standard library only (`zipfile`, `tarfile`) and scanned in-process through
`ctfctl.cli.main`, matching the rest of the suite. Each scan runs with a tree
snapshot before and after, so a scan that extracts or writes anything fails
loudly instead of passing quietly.

Limits are shrunk through the command's own flags (`--max-members`,
`--max-member-mib`, `--max-total-mib`, `--max-seconds`, `--max-depth`) so no
fixture has to be large. Link cases (a symlinked or junction subdirectory, and
a link pointing outside the scanned tree) skip individually with a printed
reason when the host permits neither `os.symlink` nor `mklink /J`.

A `.tar.gz` truncated inside its first member is reported, not skipped:
`test_truncated_targz_is_reported_not_a_crash` asserts exit 0,
`complete=false` and the `archive-unparsed` reason, and that a directory walk
survives the same file.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import tarfile
import warnings
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, List, Optional, Tuple

from helpers import check, check_eq, check_in, temp_dir

from ctfctl import artifact as artifact_mod
from ctfctl import cli, util


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
def _run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _scan_cli(
    *argv: str,
) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """Run `artifact scan ... --json`; payload is None on a non-zero exit."""
    code, out, err = _run_cli(["artifact", "scan", *argv, "--json"])
    payload = json.loads(out) if code == util.EXIT_OK else None
    return code, payload, err


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def _values(payload: Dict[str, Any]) -> List[str]:
    return [item["value"] for item in payload["findings"]]


def _triples(payload: Dict[str, Any]) -> set:
    return {
        (item["source"], item["path"], item["value"]) for item in payload["findings"]
    }


def _member_names(payload: Dict[str, Any]) -> List[str]:
    return [item["name"] for item in payload["members"]]


def _skip(reason: str) -> None:
    """Record a per-case skip in the runner output (the suite has no skip API)."""
    print(f"  SKIP  {reason}")


# --------------------------------------------------------------------------
# Links: symlink when permitted, otherwise a Windows junction
# --------------------------------------------------------------------------
def _remove_link(link: str) -> None:
    for remover in (os.unlink, os.rmdir):
        try:
            remover(link)
            return
        except OSError:
            continue


def _make_dir_link(target: str, link: str) -> Optional[str]:
    """Create a directory symlink or junction. None on success, else a reason."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return None
    except (OSError, NotImplementedError) as exc:
        symlink_error = f"{type(exc).__name__}: {exc}"
    if os.name != "nt":
        return f"cannot create a directory symlink: {symlink_error}"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", link, target], capture_output=True, text=True
    )
    if created.returncode == 0:
        return None
    detail = (created.stderr or created.stdout).strip() or f"exit {created.returncode}"
    return (
        f"cannot create a symlink ({symlink_error}) or junction ({detail}); "
        "the host forbids both"
    )


def _link_support_reason() -> Optional[str]:
    with temp_dir("ctfctl-artifact-linkprobe-") as probe:
        target = os.path.join(probe, "target")
        link = os.path.join(probe, "link")
        os.makedirs(target)
        try:
            return _make_dir_link(target, link)
        finally:
            _remove_link(link)


_LINK_REASON = _link_support_reason()


# --------------------------------------------------------------------------
# Write detection: a full recursive snapshot of the temp tree
# --------------------------------------------------------------------------
def _is_linklike(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _snapshot(root: str) -> List[Tuple[str, str, int, str]]:
    """Every entry under root as (relpath, kind, size, sha256), sorted."""
    items: List[Tuple[str, str, int, str]] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            relative = os.path.relpath(entry.path, root)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                items.append((relative, "error", 0, ""))
                continue
            if _is_linklike(info):
                items.append((relative, "link", 0, ""))
                continue
            if entry.is_dir(follow_symlinks=False):
                items.append((relative, "dir", 0, ""))
                stack.append(entry.path)
                continue
            with open(entry.path, "rb") as handle:
                data = handle.read()
            items.append(
                (relative, "file", len(data), hashlib.sha256(data).hexdigest())
            )
    return sorted(items)


# --------------------------------------------------------------------------
# Archive builders
# --------------------------------------------------------------------------
def _zip_bytes(members: List[Tuple[str, bytes]], *, stored: bool = False) -> bytes:
    buffer = io.BytesIO()
    compress = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with warnings.catch_warnings():
        # Hostile fixtures deliberately repeat names; the warning is expected.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", compress) as archive:
            for name, data in members:
                archive.writestr(name, data)
    return buffer.getvalue()


def _tar_bytes(members: List[Tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _gz_tar_bytes(members: List[Tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _dir_tar_bytes() -> bytes:
    """A tar with an explicit directory entry and one regular member."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        directory = tarfile.TarInfo("empty/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        data = b"FLAG{dir_tar}"
        regular = tarfile.TarInfo("file.txt")
        regular.size = len(data)
        archive.addfile(regular, io.BytesIO(data))
    return buffer.getvalue()


def _disposition_zip_bytes() -> bytes:
    """A zip with a symlink-mode entry, a fifo entry and one regular member."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("real.txt", b"FLAG{disp_zip}")
        symlink = zipfile.ZipInfo("sym.txt")
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(symlink, b"../../outside-secret")
        fifo = zipfile.ZipInfo("pipe.txt")
        fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
        archive.writestr(fifo, b"special data")
    return buffer.getvalue()


def _patch_tar_member_size(data: bytes, block_index: int, declared: int) -> bytes:
    """Rewrite the size field and checksum of the block_index-th 512B tar header.

    ``tarfile`` refuses to write fewer payload bytes than a member declares, so
    a hostile "declared far beyond the stream" tar is built by patching a real
    header. The checksum is recomputed so the header stays parseable.
    """
    buf = bytearray(data)
    offset = block_index * 512
    buf[offset + 124 : offset + 136] = ("%011o" % declared).encode("ascii") + b"\x00"
    checksum = (
        256 + sum(buf[offset : offset + 148]) + sum(buf[offset + 156 : offset + 512])
    )
    buf[offset + 148 : offset + 156] = ("%06o" % checksum).encode("ascii") + b"\x00 "
    return bytes(buf)


def _tar_header(name: bytes, size: int, typeflag: bytes = b"0") -> bytes:
    """One 512-byte ustar header with a correct checksum.

    ``tarfile`` refuses to write a GNU longname record whose declared size is
    not backed by that many payload bytes, so metadata-cap fixtures are
    hand-built from these headers.
    """
    header = bytearray(512)
    header[0 : len(name)] = name
    header[100:108] = b"0000644\x00"
    header[108:116] = b"0001750\x00"
    header[116:124] = b"0001750\x00"
    header[124:136] = ("%011o" % size).encode("ascii") + b"\x00"
    header[136:148] = b"00000000000\x00"
    header[148:156] = b" " * 8
    header[156:157] = typeflag
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    header[148:156] = ("%06o" % sum(header)).encode("ascii") + b"\x00 "
    return bytes(header)


def _gnu_longname_targz(declared: int, fill: bytes = b"A") -> bytes:
    """A .tar.gz whose first record declares a GNU longname of ``declared`` bytes.

    The payload is a repeated byte, so the compressed fixture stays tiny while
    the decompressed stream is large enough to cross ``TAR_METADATA_SLACK``
    when the caller zeroes the total-byte budget.
    """
    payload = fill * declared
    raw = b"".join(
        (
            _tar_header(b"././@LongLink", declared, b"L"),
            payload + b"\0" * ((-len(payload)) % 512),
            _tar_header(b"real.txt", 3),
            b"ok\n" + b"\0" * 509,
            b"\0" * 1024,
        )
    )
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as archive:
        archive.write(raw)
    return buffer.getvalue()


def _pax_record(key: bytes, value: bytes) -> bytes:
    """One PAX extended-header record, prefix included in its own length."""
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while True:
        prefix = str(size).encode("ascii") + b" "
        if len(prefix) + len(body) == size:
            return prefix + body
        size = len(prefix) + len(body)


def _pax_metadata_targz(metadata_bytes: int, member_bytes: int) -> bytes:
    """A .tar.gz whose PAX payload alone decompresses to ``metadata_bytes``.

    ``tarfile`` reads the whole PAX record during ``next()``, so the named
    member is seen only after that metadata has been delivered. With a small
    ``--max-total-mib`` the stream limiter then trips while the member itself is
    being read: the member is seen but never fully parsed. The payload fill is
    non-printable, so the stop cannot be mistaken for a string or decode limit,
    and gzip keeps the fixture tiny.
    """
    value = b"A" * (metadata_bytes - len(b"comment=") - 8)
    payload = _pax_record(b"comment", value)
    raw = b"".join(
        (
            _tar_header(b"PaxHeaders/seen.bin", len(payload), b"x"),
            payload + b"\0" * ((-len(payload)) % 512),
            _tar_header(b"seen.bin", member_bytes),
            b"\xff" * member_bytes + b"\0" * ((-member_bytes) % 512),
            b"\0" * 1024,
        )
    )
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as archive:
        archive.write(raw)
    return buffer.getvalue()


def _patch_zip_eocd(
    data: bytes, *, count: Optional[int] = None, cd_size: Optional[int] = None
) -> bytes:
    """Rewrite the member-count or central-directory-size field of the EOCD."""
    buf = bytearray(data)
    offset = bytes(buf).rfind(b"PK\x05\x06")
    check(offset >= 0, "fixture must carry an end-of-central-directory record")
    if count is not None:
        struct.pack_into("<H", buf, offset + 10, count)
    if cd_size is not None:
        struct.pack_into("<I", buf, offset + 12, cd_size)
    return bytes(buf)


def _zip_with_zip64_locator(members: List[Tuple[str, bytes]]) -> bytes:
    """A zip ``zipfile`` opens that still carries a zip64 locator in its tail.

    The classic records stay valid; a well-formed zip64 end-of-central-
    directory record and its locator (``PK\\x06\\x07``) are inserted before
    them, so ``zipfile`` follows the locator and opens the archive while the
    bounded tail read sees the locator signature.
    """
    base = _zip_bytes(members, stored=True)
    eocd = base.rfind(b"PK\x05\x06")
    check(eocd >= 0, "fixture must carry a classic end-of-central-directory record")
    count = struct.unpack_from("<H", base, eocd + 10)[0]
    cd_size = struct.unpack_from("<I", base, eocd + 12)[0]
    cd_offset = struct.unpack_from("<I", base, eocd + 16)[0]
    zip64 = struct.pack(
        "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, count, count, cd_size, cd_offset
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, eocd, 1)
    return base[:eocd] + zip64 + locator + base[eocd:]


def _decoy_eocd_zip() -> bytes:
    """A zip whose EOCD comment embeds a second, inconsistent EOCD record.

    EOCD1 is a real record and its comment reaches the file end, but the comment
    starts with a full 22-byte decoy record whose declared comment length
    (0xFFFF) does not reach the file end. ``zipfile._EndRecData`` honors the LAST
    ``PK\\x05\\x06`` signature in its tail window, so it reads the decoy, not
    EOCD1; the preflight must refuse that shape instead of validating a record
    zipfile will not use. The decoy's declared central-directory size is chosen
    so that a zipfile which also checks the directory after the last signature
    still recognizes the file as a zip (the check seeks to record start minus
    declared directory size, which this fixture lands on the real directory).
    """
    base = _zip_bytes([("inside.txt", b"FLAG{decoy_inside}\n")])
    eocd = base.rfind(b"PK\x05\x06")
    check(eocd >= 0, "fixture must carry an end-of-central-directory record")
    record = base[eocd : eocd + 22]
    cd_offset = struct.unpack_from("<I", record, 16)[0]
    decoy_at = eocd + len(record)
    decoy = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, decoy_at - cd_offset, cd_offset, 0xFFFF
    )
    comment = decoy + b"decoy-tail"
    eocd1 = bytearray(record)
    struct.pack_into("<H", eocd1, 20, len(comment))
    return base[:eocd] + bytes(eocd1) + comment


def _set_encrypted_bits(path: str, member: str) -> None:
    """Set the zip encryption GP bit on one member's local and central headers."""
    data = bytearray(open(path, "rb").read())
    needle = member.encode("ascii")
    for magic, flag_offset, name_offset in (
        (b"PK\x03\x04", 6, 30),
        (b"PK\x01\x02", 8, 46),
    ):
        position = 0
        while True:
            position = bytes(data).find(magic, position)
            if position < 0:
                break
            start = position + name_offset
            if bytes(data[start : start + len(needle)]) == needle:
                bits = struct.unpack_from("<H", data, position + flag_offset)[0] | 0x1
                struct.pack_into("<H", data, position + flag_offset, bits)
            position += 4
    with open(path, "wb") as handle:
        handle.write(bytes(data))


# --------------------------------------------------------------------------
# Plain files and directories
# --------------------------------------------------------------------------
def test_plain_text_file_hash_flag_and_json_shape() -> None:
    data = b"hello\nFLAG{plain_text_flag}\nworld\n"
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "note.txt")
        _write(path, data)
        code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"plain file must scan cleanly: {err}")
        check_eq(err, "", "a clean scan must not write to stderr")
        check_eq(payload["schema"], "ctfctl.artifact/1", "schema id must be pinned")
        check_eq(payload["kind"], "file", "a plain file is kind=file")
        check_eq(payload["archive_format"], None, "a plain file has no archive format")
        check_eq(payload["complete"], True, "a small file must scan completely")
        check_eq(payload["limits"], {"hit": False, "reasons": []}, "limits shape")
        check_eq(payload["size"], len(data), "size must be the exact byte count")
        check_eq(
            payload["sha256"],
            hashlib.sha256(data).hexdigest(),
            "payload sha256 must be the real digest",
        )
        check_eq(len(payload["files"]), 1, "one input file means one summary")
        summary = payload["files"][0]
        for key in (
            "path",
            "sha256",
            "bytes_read",
            "strings",
            "findings",
            "truncated",
            "strings_truncated",
            "size",
        ):
            check_in(key, summary, "file summary must carry the documented keys")
        check_eq(summary["sha256"], payload["sha256"], "summary and payload agree")
        check_eq(summary["bytes_read"], len(data), "stream must read every byte")
        check_eq(summary["truncated"], False, "an unbounded read is not truncated")
        flag = "FLAG{plain_text_flag}"
        check_eq(_values(payload), [flag], "exactly the one flag must be found")
        finding = payload["findings"][0]
        check_eq(finding["source"], "raw", "raw-stream finding source")
        check_eq(finding["offset"], data.index(flag.encode()), "exact byte offset")
        check_eq(finding["inner_offset"], None, "raw findings have no inner offset")
        check_eq(payload["counts"]["findings"], 1, "counts must agree with findings")
        check_eq(payload["counts"]["files_scanned"], 1, "one file scanned")


def test_directory_walk_is_bounded_and_finds_nested_flags() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        _write(os.path.join(root, "top.txt"), b"FLAG{dir_top}\n")
        _write(os.path.join(root, "sub", "one.txt"), b"FLAG{dir_nested}\n")
        _write(os.path.join(root, "sub", "deep", "two.txt"), b"FLAG{dir_deep}\n")

        code, payload, err = _scan_cli(root, "--max-depth", "1")
        check_eq(code, util.EXIT_OK, f"directory scan must exit 0: {err}")
        check_eq(payload["kind"], "dir", "directory input is kind=dir")
        values = _values(payload)
        check_in("FLAG{dir_top}", values, "root file must be found")
        check_in("FLAG{dir_nested}", values, "depth-1 file must be found")
        check(
            "FLAG{dir_deep}" not in values,
            "a directory below --max-depth must not be scanned",
        )
        check_eq(
            payload["counts"]["depth_skipped"],
            1,
            "the skipped directory must be counted",
        )
        check_eq(payload["counts"]["files_scanned"], 2, "only depth 1 is walked")

        code, payload, err = _scan_cli(root)
        check_eq(code, util.EXIT_OK, f"default-depth directory scan: {err}")
        check_in("FLAG{dir_deep}", _values(payload), "the default depth reaches it")
        check_eq(payload["counts"]["files_scanned"], 3, "all three files scanned")
        check_eq(payload["counts"]["depth_skipped"], 0, "nothing skipped by depth")


def test_directory_symlink_is_skipped_and_counted() -> None:
    if _LINK_REASON is not None:
        _skip(f"symlinked directory case: {_LINK_REASON}")
        return
    with temp_dir("ctfctl-artifact-") as root:
        outside = os.path.join(root, "outside")
        scanned = os.path.join(root, "scanned")
        _write(os.path.join(outside, "secret.txt"), b"FLAG{behind_the_link}\n")
        _write(os.path.join(scanned, "real.txt"), b"FLAG{in_front}\n")
        link = os.path.join(scanned, "jump")
        reason = _make_dir_link(outside, link)
        if reason is not None:
            _skip(f"symlinked directory case: {reason}")
            return
        try:
            code, payload, err = _scan_cli(scanned)
            check_eq(code, util.EXIT_OK, f"linked-directory scan must exit 0: {err}")
            check_eq(
                payload["counts"]["links_skipped"],
                1,
                "the linked directory must be counted as skipped",
            )
            check_eq(
                payload["counts"]["files_scanned"],
                1,
                "only the real file must be read",
            )
            values = _values(payload)
            check_in("FLAG{in_front}", values, "the real file is scanned")
            check(
                "FLAG{behind_the_link}" not in values,
                "content behind the link must never be scanned",
            )
        finally:
            _remove_link(link)


def test_directory_link_to_outside_content_is_not_followed() -> None:
    if _LINK_REASON is not None:
        _skip(f"link-outside-directory case: {_LINK_REASON}")
        return
    with temp_dir("ctfctl-artifact-") as root:
        outside = os.path.join(root, "outside")
        scanned = os.path.join(root, "scanned")
        _write(os.path.join(outside, "secret.txt"), b"FLAG{outside_only}\n")
        _write(os.path.join(scanned, "inside.txt"), b"FLAG{inside_only}\n")
        link = os.path.join(scanned, "escape")
        reason = _make_dir_link(outside, link)
        if reason is not None:
            _skip(f"link-outside-directory case: {reason}")
            return
        try:
            before = _snapshot(root)
            code, payload, err = _scan_cli(scanned)
            check_eq(code, util.EXIT_OK, f"outside-link scan must exit 0: {err}")
            check(
                payload["counts"]["links_skipped"] >= 1,
                "the escape link must be counted",
            )
            values = _values(payload)
            check_in("FLAG{inside_only}", values, "the scanned tree is covered")
            check(
                "FLAG{outside_only}" not in values,
                "the outside target must not be scanned through the link",
            )
            check_eq(
                sorted(os.listdir(outside)),
                ["secret.txt"],
                "the outside directory must be untouched",
            )
            check_eq(_snapshot(root), before, "the scan must not write anything")
        finally:
            _remove_link(link)


def test_directory_entry_cap_stops_and_reports() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        for index in range(4):
            _write(os.path.join(root, f"f{index}.txt"), b"data\n")
        code, payload, err = _scan_cli(root, "--max-entries", "2")
        check_eq(code, util.EXIT_OK, f"entry-capped scan must exit 0: {err}")
        check_eq(payload["complete"], False, "a capped walk is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["max-entries"]},
            "the entry cap must be reported as the reason",
        )
        check_eq(payload["counts"]["entries"], 3, "the third entry trips the cap")
        check_eq(payload["counts"]["files_scanned"], 2, "only two files were read")


# --------------------------------------------------------------------------
# ZIP
# --------------------------------------------------------------------------
def test_zip_members_flags_encodings_and_nested_archives() -> None:
    b64_flag = base64.b64encode(b"FLAG{b64_member}")
    hex_flag = b"FLAG{hex_member}".hex().encode()
    inner_zip = _zip_bytes([("inner.txt", b"FLAG{zip_inner}\n")])
    level1 = _zip_bytes(
        [("level2.txt", b"FLAG{zip_level2}\n"), ("inner.zip", inner_zip)]
    )
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "bundle.zip")
        _write(
            path,
            _zip_bytes(
                [
                    ("hello.txt", b"hi FLAG{zip_plain} there\n"),
                    ("b64.txt", b"encoded " + b64_flag + b"\n"),
                    ("hex.txt", b"encoded " + hex_flag + b"\n"),
                    ("level1.zip", level1),
                ]
            ),
        )
        code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"zip scan must exit 0: {err}")
        check_eq(payload["kind"], "archive", "a zip is an archive")
        check_eq(payload["archive_format"], "zip", "zip format must be named")
        check_eq(payload["complete"], True, "this small zip must scan completely")
        parent = payload["path"]
        expected = {
            ("raw", parent + "!/hello.txt", "FLAG{zip_plain}"),
            ("base64", parent + "!/b64.txt", "FLAG{b64_member}"),
            ("hex", parent + "!/hex.txt", "FLAG{hex_member}"),
            ("raw", parent + "!/level1.zip!/level2.txt", "FLAG{zip_level2}"),
            ("raw", parent + "!/level1.zip!/inner.zip!/inner.txt", "FLAG{zip_inner}"),
        }
        found = _triples(payload)
        missing = expected - found
        check_eq(missing, set(), "every encoded and nested flag must be found")
        check(
            payload["counts"]["decode_ok"] >= 2,
            "the base64 and hex runs must each decode successfully",
        )
        members = _member_names(payload)
        for name in ("hello.txt", "b64.txt", "hex.txt", "level1.zip"):
            check_in(name, members, "top-level member must be listed")
        check_in("inner.zip", members, "nested zip member must be listed")


def test_zip_nesting_beyond_max_depth_is_reported() -> None:
    level1 = _zip_bytes([("level2.txt", b"FLAG{too_deep}\n")])
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "nested.zip")
        _write(path, _zip_bytes([("level1.zip", level1)]))
        code, payload, err = _scan_cli(path, "--max-depth", "1")
        check_eq(code, util.EXIT_OK, f"depth-capped zip scan: {err}")
        check_eq(payload["complete"], False, "an unscanned layer is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["max-depth"]},
            "the depth cap must be reported as the reason",
        )
        check(
            "FLAG{too_deep}" not in _values(payload),
            "the nested layer must not be silently ignored or silently scanned",
        )
        check_eq(
            _member_names(payload), ["level1.zip"], "only depth-1 members are listed"
        )

        code, payload, err = _scan_cli(path, "--max-depth", "2")
        check_eq(code, util.EXIT_OK, f"depth-2 zip scan: {err}")
        check_eq(payload["complete"], True, "depth 2 has no further nesting")
        check_in(
            "FLAG{too_deep}",
            _values(payload),
            "the nested layer is scanned when within the configured depth",
        )


# --------------------------------------------------------------------------
# TAR
# --------------------------------------------------------------------------
def test_tar_and_targz_members_and_nested_tar() -> None:
    nested = _tar_bytes([("inner.txt", b"FLAG{tar_inner}\n")])
    with temp_dir("ctfctl-artifact-") as root:
        tar_path = os.path.join(root, "bundle.tar")
        _write(
            tar_path,
            _tar_bytes([("one.txt", b"FLAG{tar_plain}\n"), ("nested.tar", nested)]),
        )
        code, payload, err = _scan_cli(tar_path)
        check_eq(code, util.EXIT_OK, f"tar scan must exit 0: {err}")
        check_eq(payload["archive_format"], "tar", "tar format must be named")
        check_eq(payload["complete"], True, "this small tar must scan completely")
        expected = {
            ("raw", tar_path + "!/one.txt", "FLAG{tar_plain}"),
            ("raw", tar_path + "!/nested.tar!/inner.txt", "FLAG{tar_inner}"),
        }
        check_eq(expected - _triples(payload), set(), "tar members must be scanned")

        code, payload, err = _scan_cli(tar_path, "--max-depth", "1")
        check_eq(code, util.EXIT_OK, f"depth-capped tar scan: {err}")
        check_eq(payload["complete"], False, "the nested tar is beyond depth 1")
        check_in("max-depth", payload["limits"]["reasons"], "depth cap must be named")

        gz_path = os.path.join(root, "bundle.tar.gz")
        _write(gz_path, _gz_tar_bytes([("gz.txt", b"FLAG{targz_plain}\n")]))
        code, payload, err = _scan_cli(gz_path)
        check_eq(code, util.EXIT_OK, f"tar.gz scan must exit 0: {err}")
        check_eq(payload["archive_format"], "tar", "gzipped tar reports tar format")
        check_eq(
            {("raw", gz_path + "!/gz.txt", "FLAG{targz_plain}")} - _triples(payload),
            set(),
            "a member of a tar.gz must be read through the gzip layer",
        )


# --------------------------------------------------------------------------
# Malformed inputs
# --------------------------------------------------------------------------
def test_malformed_inputs_exit_zero_without_a_crash() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        garbage_zip = os.path.join(root, "garbage.zip")
        _write(garbage_zip, b"this is definitely not a zip archive\n" * 4)
        garbage_tgz = os.path.join(root, "garbage.tar.gz")
        _write(garbage_tgz, b"this is not gzip either\n")

        good_zip = _zip_bytes(
            [("a.txt", b"FLAG{cut_a}"), ("b.txt", b"FLAG{cut_b}")], stored=True
        )
        truncated_zip = os.path.join(root, "truncated.zip")
        _write(truncated_zip, good_zip[:-40])  # removes the end-of-central-directory

        corrupt = bytearray(good_zip)
        marker = bytes(corrupt).find(b"FLAG{cut_a}")
        corrupt[marker + 2] ^= 0x20  # still opens, CRC check fails on read
        corrupt_zip = os.path.join(root, "corrupt.zip")
        _write(corrupt_zip, bytes(corrupt))

        for path in (garbage_zip, garbage_tgz, truncated_zip):
            code, payload, err = _scan_cli(path)
            check_eq(code, util.EXIT_OK, f"{os.path.basename(path)} must exit 0: {err}")
            check(
                "Traceback" not in err and "internal error" not in err,
                f"{os.path.basename(path)} must not crash the CLI: {err}",
            )
            check_eq(
                payload["kind"],
                "file",
                "an archive that does not parse is triaged as raw bytes",
            )
            check_eq(payload["archive_format"], None, "no archive format is claimed")
            check_eq(
                payload["sha256"],
                hashlib.sha256(open(path, "rb").read()).hexdigest(),
                "the bytes are still hashed",
            )
        code, payload, err = _scan_cli(corrupt_zip)
        check_eq(code, util.EXIT_OK, f"corrupt zip member must exit 0: {err}")
        check_eq(payload["kind"], "archive", "a readable zip is still an archive")
        check(
            payload["errors"],
            "a corrupt member read must be reported as an error",
        )
        check_in("CRC", payload["errors"][0], "the CRC failure must be named")
        check_eq(
            payload["counts"]["members_unparsed"],
            1,
            "the truncated member must be counted as unparsed",
        )


def test_truncated_targz_is_reported_not_a_crash() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        full = _gz_tar_bytes([("f.txt", b"FLAG{cut_tgz}")])
        cut = os.path.join(root, "cut.tar.gz")
        _write(cut, full[: len(full) // 2])
        code, payload, err = _scan_cli(cut)
        check_eq(code, util.EXIT_OK, f"a truncated .tar.gz must exit 0: {err}")
        check("Traceback" not in err, f"a malformed input must never traceback: {err}")
        check_eq(payload["complete"], False, "a truncated archive is not complete")
        check_eq(
            payload["kind"],
            "file",
            "an archive whose bytes cannot be parsed is triaged as raw bytes",
        )
        check_in(
            "archive-unparsed",
            payload["limits"]["reasons"],
            "the unread archive bytes must be named as the reason",
        )
        check_in(
            "archive-errors",
            payload["incomplete"],
            "the failed parse must be an incomplete category",
        )
        check(payload["errors"], "the truncation must be reported in errors")
        check_eq(
            len(payload["archive_errors"]),
            1,
            "the failed archive attempt must be recorded once",
        )
        check_eq(
            payload["archive_errors"][0]["path"],
            cut,
            "the failed archive must be the cut file itself",
        )
        check_eq(payload["members"], [], "nothing may be read from a cut archive")

        directory = os.path.join(root, "dir")
        os.makedirs(directory)
        os.replace(cut, os.path.join(directory, "cut.tar.gz"))
        _write(os.path.join(directory, "ok.txt"), b"FLAG{still_scanning}")
        code, payload, err = _scan_cli(directory)
        check_eq(
            code, util.EXIT_OK, f"one truncated file must not kill the walk: {err}"
        )
        check_in(
            "FLAG{still_scanning}",
            _values(payload),
            "the healthy sibling must still be scanned",
        )
        check_eq(
            payload["complete"],
            False,
            "a walk containing a cut archive is not complete",
        )


# --------------------------------------------------------------------------
# Member name attacks
# --------------------------------------------------------------------------
#: Names that must be refused without ever being read.
_INVALID_NAMES = (
    "../x.txt",
    "..\\x.txt",
    "/abs.txt",
    "C:\\x.txt",
    "\\\\server\\share.txt",
    "a//b.txt",
    "a/./b.txt",
    "ctl\x01name.txt",
    "bad\tname.txt",
    "del\x7fname.txt",
)

#: Unique flag marker per refused member; none may surface as a finding.
_INVALID_FLAGS = [
    f"FLAG{{zip_invalid_{index}}}" for index in range(len(_INVALID_NAMES))
]


def test_zip_member_name_attacks_are_refused_and_not_read() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "hostile.zip")
        members = [
            (name, flag.encode()) for name, flag in zip(_INVALID_NAMES, _INVALID_FLAGS)
        ]
        members += [
            ("dir/", b"padding"),
            ("sneaky.txt/", b"trailing separator is not a file"),
            ("dup.txt", b"FLAG{zip_dup_first}"),
            ("dup.txt", b"FLAG{zip_dup_second}"),
            ("Case.txt", b"FLAG{zip_case_upper}"),
            ("case.txt", b"FLAG{zip_case_lower}"),
        ]
        _write(path, _zip_bytes(members))
        before = _snapshot(root)
        code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"hostile zip names must not crash: {err}")
        counts = payload["counts"]
        check_eq(
            counts["invalid_members"],
            len(_INVALID_NAMES),
            "every invalid member name must be counted",
        )
        case_collides = os.name == "nt"
        check_eq(
            counts["collisions"],
            2 if case_collides else 1,
            "case variants collide only where the filesystem is case-insensitive",
        )
        check_eq(
            counts["directory_members_skipped"],
            2,
            "both directory members must be counted as skipped directories",
        )
        check_eq(
            counts["members_skipped"],
            counts["invalid_members"] + counts["collisions"] + 2,
            "refused, colliding and directory members must all be counted as skipped",
        )
        values = _values(payload)
        for flag in _INVALID_FLAGS:
            check(
                flag not in values,
                "a member with an invalid name must never be read",
            )
        check_in("FLAG{zip_dup_first}", values, "the first duplicate is read")
        check(
            "FLAG{zip_dup_second}" not in values,
            "the second duplicate must not be read",
        )
        upper_read = "FLAG{zip_case_upper}" in values
        lower_read = "FLAG{zip_case_lower}" in values
        if case_collides:
            check_eq(
                upper_read + lower_read,
                1,
                "on a case-insensitive host exactly one case variant is read",
            )
        else:
            check(upper_read and lower_read, "both case variants are distinct files")
        check(
            "sneaky.txt" not in _member_names(payload),
            "a trailing separator is treated as a directory, not a file member",
        )
        for finding in payload["findings"]:
            tail = finding["path"].split("!/", 1)[1] if "!/" in finding["path"] else ""
            check(
                not tail.startswith("/")
                and ".." not in tail
                and "\\" not in tail
                and "\x01" not in tail,
                f"no finding may come from a refused member path: {tail!r}",
            )
        check_eq(_snapshot(root), before, "no member may be extracted to disk")


def test_tar_member_name_attacks_are_refused_and_not_read() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "hostile.tar")
        members = [
            (name, flag.encode()) for name, flag in zip(_INVALID_NAMES, _INVALID_FLAGS)
        ]
        members += [
            ("dup.txt", b"FLAG{tar_dup_first}"),
            ("dup.txt", b"FLAG{tar_dup_second}"),
        ]
        _write(path, _tar_bytes(members))
        before = _snapshot(root)
        code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"hostile tar names must not crash: {err}")
        counts = payload["counts"]
        check_eq(
            counts["invalid_members"],
            len(_INVALID_NAMES),
            "every invalid tar member must be counted",
        )
        check_eq(counts["collisions"], 1, "the duplicate tar member must collide")
        check_eq(
            _member_names(payload), ["dup.txt"], "only the first duplicate is read"
        )
        for finding in payload["findings"]:
            check(
                finding["path"] in (path, path + "!/dup.txt"),
                f"no finding may come from a refused tar member: {finding['path']!r}",
            )
        check_eq(_snapshot(root), before, "no member may be extracted to disk")


# --------------------------------------------------------------------------
# Links and special member types
# --------------------------------------------------------------------------
def test_tar_links_and_special_entries_and_zip_specials_are_skipped() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        tar_path = os.path.join(root, "links.tar")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            flag_data = b"FLAG{tar_regular}"
            regular = tarfile.TarInfo("real.txt")
            regular.size = len(flag_data)
            archive.addfile(regular, io.BytesIO(flag_data))
            symlink = tarfile.TarInfo("sym.txt")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "../../outside-secret"
            archive.addfile(symlink)
            hardlink = tarfile.TarInfo("hard.txt")
            hardlink.type = tarfile.LNKTYPE
            hardlink.linkname = "real.txt"
            archive.addfile(hardlink)
            for name, kind in (
                ("pipe.txt", tarfile.FIFOTYPE),
                ("char.txt", tarfile.CHRTYPE),
                ("block.txt", tarfile.BLKTYPE),
            ):
                special = tarfile.TarInfo(name)
                special.type = kind
                archive.addfile(special)
        _write(tar_path, buffer.getvalue())
        code, payload, err = _scan_cli(tar_path)
        check_eq(code, util.EXIT_OK, f"tar links must not crash: {err}")
        check_eq(payload["counts"]["links_skipped"], 2, "symlink and hardlink skipped")
        check_eq(payload["counts"]["special_skipped"], 3, "fifo and devices skipped")
        check_eq(_member_names(payload), ["real.txt"], "only the regular file is read")
        for finding in payload["findings"]:
            check(
                "sym.txt" not in finding["path"]
                and "hard.txt" not in finding["path"]
                and "pipe.txt" not in finding["path"],
                "no finding may come from a skipped entry",
            )
        check(
            not os.path.lexists(os.path.join(root, "outside-secret")),
            "link targets must never be materialised",
        )

        zip_path = os.path.join(root, "links.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("real.txt", "FLAG{zip_regular}")
            symlink = zipfile.ZipInfo("sym.txt")
            symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(symlink, "../../outside-secret")
            fifo = zipfile.ZipInfo("pipe.txt")
            fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
            archive.writestr(fifo, "special data")
            encrypted = zipfile.ZipInfo("secret.txt")
            encrypted.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(encrypted, "FLAG{zip_encrypted}")
        _set_encrypted_bits(zip_path, "secret.txt")
        code, payload, err = _scan_cli(zip_path)
        check_eq(code, util.EXIT_OK, f"zip specials must not crash: {err}")
        counts = payload["counts"]
        check_eq(counts["links_skipped"], 1, "the zip symlink mode is skipped")
        check_eq(counts["special_skipped"], 1, "the fifo mode is skipped")
        check_eq(counts["encrypted_skipped"], 1, "the encrypted member is skipped")
        check_eq(_member_names(payload), ["real.txt"], "only the regular file is read")
        for finding in payload["findings"]:
            check(
                not finding["path"].endswith(("/sym.txt", "/pipe.txt", "/secret.txt")),
                "no skipped zip member may be read",
            )


def test_symlink_member_marks_zip_incomplete_and_clean_zip_stays_complete() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "links.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("real.txt", "FLAG{zip_regular}")
            symlink = zipfile.ZipInfo("sym.txt")
            symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(symlink, "../../outside-secret")

        code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"symlink zip must scan: {err}")
        check_eq(
            payload["complete"],
            False,
            "a skipped symlink member means the archive was not fully analyzed",
        )
        check_in(
            "links-skipped",
            payload["incomplete"],
            "the incomplete list must name the links category",
        )
        check_eq(payload["counts"]["links_skipped"], 1, "the symlink is counted")
        check_eq(_member_names(payload), ["real.txt"], "only the regular file is read")
        check_eq(
            payload["limits"],
            {"hit": False, "reasons": []},
            "the incompleteness is not a limit",
        )

        clean = os.path.join(root, "clean.zip")
        _write(clean, _zip_bytes([("only.txt", b"nothing special")]))
        code, payload, err = _scan_cli(clean)
        check_eq(code, util.EXIT_OK, f"clean zip must scan: {err}")
        check_eq(payload["complete"], True, "a clean zip stays complete")
        check_eq(payload["incomplete"], [], "no incomplete category may be listed")


# --------------------------------------------------------------------------
# Streaming limits
# --------------------------------------------------------------------------
def _stored_zero_zip(path: str, size: int) -> None:
    _write(path, _zip_bytes([("zeros.bin", b"\x00" * size)], stored=True))


def test_member_count_cap_reports_max_members() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "many.zip")
        _write(
            path,
            _zip_bytes([(f"m{index:02d}.txt", b"data") for index in range(5)]),
        )
        code, payload, err = _scan_cli(path, "--max-members", "2")
        check_eq(code, util.EXIT_OK, f"member-capped scan must exit 0: {err}")
        check_eq(payload["kind"], "archive", "the zip is recognized, then refused")
        check_eq(payload["complete"], False, "a refused archive is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["archive-over-member-cap"]},
            "the end-of-central-directory preflight must name the refusal",
        )
        check_in("limits", payload["incomplete"], "the cap marks the scan limited")
        check_in("errors", payload["incomplete"], "the refusal is reported as an error")
        check_eq(
            payload["archive_errors"],
            [],
            "the archive parses; only its declared member count is over the cap",
        )
        check_eq(payload["counts"]["members_seen"], 0, "no member may even be listed")
        check_eq(payload["counts"]["bytes_expanded"], 0, "no member may be read")
        check_eq(payload["members"], [], "the member list must stay empty")
        check(
            any("archive-over-member-cap" in item for item in payload["errors"]),
            "the refusal must be named in the error list",
        )


def test_zip_preflight_accepts_within_cap_count_with_trailing_junk() -> None:
    """The preflight refuses on the declared count, not on a strict EOCD shape."""
    with temp_dir("ctfctl-artifact-") as root:
        members = [("one.txt", b"FLAG{preflight_ok}"), ("two.txt", b"data")]
        data = _zip_bytes(members, stored=True)
        eocd = data.rfind(b"PK\x05\x06")
        junk = b"\xff\xfe bad bytes after the central directory"
        # The junk is carried as the EOCD comment, so zipfile still opens it and
        # a preflight that only reads the declared count must not refuse it.
        mutated = data[: eocd + 20] + struct.pack("<H", len(junk)) + junk
        path = os.path.join(root, "trailing-junk.zip")
        _write(path, mutated)

        code, payload, err = _scan_cli(path, "--max-members", "2")
        check_eq(code, util.EXIT_OK, f"within-cap junk tail must scan: {err}")
        check_eq(
            payload["complete"], True, "a within-cap declared count must not be refused"
        )
        check_eq(payload["limits"], {"hit": False, "reasons": []}, "no cap may be hit")
        check(
            "archive-over-member-cap" not in payload["limits"]["reasons"],
            "trailing bytes must not be misread as an over-cap count",
        )
        check_eq(payload["counts"]["members_seen"], 2, "both declared members are seen")
        check_eq(
            _member_names(payload), ["one.txt", "two.txt"], "both members are read"
        )
        check_in("FLAG{preflight_ok}", _values(payload), "member content is scanned")


def test_member_byte_cap_reports_max_member_bytes() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "big.zip")
        _stored_zero_zip(path, artifact_mod.MIB + 230 * 1024)
        code, payload, err = _scan_cli(path, "--max-member-mib", "1")
        check_eq(code, util.EXIT_OK, f"member-capped scan must exit 0: {err}")
        check_eq(payload["complete"], False, "a capped member is not complete")
        check_in(
            "max-member-bytes", payload["limits"]["reasons"], "the member cap is named"
        )
        check_eq(
            payload["counts"]["members_unparsed"],
            1,
            "the capped member must be counted as unparsed",
        )
        check(
            payload["members"][0]["truncated"],
            "the member summary must say it was cut short",
        )


def test_total_byte_cap_reports_max_total_bytes() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "big.zip")
        _stored_zero_zip(path, artifact_mod.MIB + 230 * 1024)
        code, payload, err = _scan_cli(path, "--max-total-mib", "1")
        check_eq(code, util.EXIT_OK, f"total-capped scan must exit 0: {err}")
        check_eq(payload["complete"], False, "a capped expansion is not complete")
        check_in(
            "max-total-bytes", payload["limits"]["reasons"], "the total cap is named"
        )
        check(
            payload["counts"]["bytes_expanded"]
            <= artifact_mod.MIB + artifact_mod.READ_CHUNK,
            "expansion must stop on the first chunk past the cap",
        )


def test_tar_declared_size_beyond_stream_aborts_before_later_members() -> None:
    """A lying declared size must not become a skip target for later bytes."""
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "declared.tar")
        raw = _tar_bytes(
            [
                ("a.bin", b"\x00" * (2 * artifact_mod.MIB)),
                ("later.txt", b"FLAG{later_a}"),
            ]
        )
        _write(path, _patch_tar_member_size(raw, 0, 8 * artifact_mod.MIB))

        code, payload, err = _scan_cli(
            path, "--max-member-mib", "8", "--max-total-mib", "1"
        )
        check_eq(code, util.EXIT_OK, f"lying declared size must not crash: {err}")
        check_eq(payload["complete"], False, "the cut read is not complete")
        check_in(
            "max-total-bytes",
            payload["limits"]["reasons"],
            "the expansion cap that stopped the member must be named",
        )
        check_eq(payload["counts"]["members_seen"], 1, "only the first member is seen")
        check_eq(_member_names(payload), ["a.bin"], "the later member must not be read")
        summary = payload["members"][0]
        check_eq(
            summary["declared_size"],
            8 * artifact_mod.MIB,
            "the summary keeps the declared size",
        )
        check(summary["truncated"], "the cut member must be marked truncated")
        check(
            payload["counts"]["bytes_expanded"]
            <= artifact_mod.MIB + artifact_mod.READ_CHUNK,
            "expansion must stop on the first chunk past the cap",
        )
        check(
            not any(
                item["path"].endswith("!/later.txt") for item in payload["findings"]
            ),
            "no finding may come from an unread later member",
        )


def test_tar_member_declared_over_cap_is_refused_unread() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "huge-declared.tar")
        raw = _tar_bytes([("huge.bin", b"A" * 1024), ("later.txt", b"FLAG{later_b}")])
        _write(path, _patch_tar_member_size(raw, 0, 2 * artifact_mod.MIB))

        code, payload, err = _scan_cli(path, "--max-member-mib", "1")
        check_eq(code, util.EXIT_OK, f"declared-over-cap tar must exit 0: {err}")
        check_eq(payload["complete"], False, "the refused member is not complete")
        check_in(
            "member-declared-over-cap",
            payload["limits"]["reasons"],
            "the declared size must be the refusal reason",
        )
        check_eq(
            payload["counts"]["members_seen"], 1, "the member is seen, then refused"
        )
        check_eq(payload["members"], [], "the refused member must never be read")
        check_eq(
            payload["counts"]["bytes_expanded"],
            0,
            "refusal happens before any member byte is expanded",
        )
        check(
            any("member-declared-over-cap" in item for item in payload["errors"]),
            "the refusal must name the declared-over-cap reason",
        )
        check(
            not any(
                item["path"].endswith("!/later.txt") for item in payload["findings"]
            ),
            "the later member must stay unscanned",
        )


def test_tar_total_cap_mid_archive_leaves_later_members_unscanned() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "mid.tar")
        _write(
            path,
            _tar_bytes(
                [
                    ("a.bin", b"\x00" * (artifact_mod.MIB + 230 * 1024)),
                    ("later.txt", b"FLAG{later_c}"),
                ]
            ),
        )
        code, payload, err = _scan_cli(path, "--max-total-mib", "1")
        check_eq(code, util.EXIT_OK, f"total-capped tar must exit 0: {err}")
        check_eq(payload["complete"], False, "the cut archive is not complete")
        check_in(
            "max-total-bytes",
            payload["limits"]["reasons"],
            "the total cap that stopped the member must be named",
        )
        check_eq(payload["counts"]["members_seen"], 1, "only the first member is seen")
        check_eq(_member_names(payload), ["a.bin"], "the later member must not be read")
        check(payload["members"][0]["truncated"], "the capped member must be truncated")
        check_eq(
            payload["counts"]["members_unparsed"],
            1,
            "the unread remainder must be counted as unparsed",
        )
        check(
            payload["counts"]["bytes_expanded"]
            <= artifact_mod.MIB + artifact_mod.READ_CHUNK,
            "expansion must stop on the first chunk past the cap",
        )
        check(
            not any(
                item["path"].endswith("!/later.txt") for item in payload["findings"]
            ),
            "no finding may come from an unread later member",
        )


def test_zero_seconds_reports_max_seconds() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "plain.txt")
        _write(path, b"hello FLAG{seconds_zero}\n")
        code, payload, err = _scan_cli(path, "--max-seconds", "0")
        check_eq(code, util.EXIT_OK, f"time-capped scan must exit 0: {err}")
        check_eq(payload["complete"], False, "a time-stopped scan is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["max-seconds"]},
            "the time budget must be named as the reason",
        )
        check_eq(payload["counts"]["bytes_read"], 0, "no bytes are read at zero budget")
        check(payload["files"][0]["truncated"], "the file summary must be truncated")


def test_compression_ratio_guard_skips_the_member() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "ratio.zip")
        _write(
            path,
            _zip_bytes(
                [
                    ("zeros.bin", b"\x00" * artifact_mod.MIB),
                    ("after.txt", b"FLAG{after_ratio}"),
                ]
            ),
        )
        code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"ratio-guard scan must exit 0: {err}")
        check_eq(payload["complete"], False, "a ratio-refused member is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["max-ratio"]},
            "the 200:1 ratio guard must be reported",
        )
        check_eq(payload["counts"]["members_skipped"], 1, "the bomb member is skipped")
        check_in(
            "FLAG{after_ratio}",
            _values(payload),
            "members within the ratio must still be scanned",
        )


# --------------------------------------------------------------------------
# Read-only guarantee
# --------------------------------------------------------------------------
def test_scan_never_writes_or_extracts_anything() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        plain = os.path.join(root, "plain.txt")
        _write(plain, b"FLAG{plain}\n")
        hostile_zip = os.path.join(root, "hostile.zip")
        _write(
            hostile_zip,
            _zip_bytes(
                [
                    ("../ctfctl-escape-marker.txt", b"FLAG{zip_escape}"),
                    ("/abs.txt", b"FLAG{zip_abs}"),
                    ("nested.tar", _tar_bytes([("../inner-escape.txt", b"x")])),
                ]
            ),
        )
        hostile_tar = os.path.join(root, "hostile.tar")
        _write(
            hostile_tar,
            _tar_bytes([("../ctfctl-escape-marker.txt", b"FLAG{tar_escape}")]),
        )
        directory = os.path.join(root, "tree")
        _write(os.path.join(directory, "sibling.txt"), b"FLAG{tree}\n")

        before = _snapshot(root)
        for target in (plain, hostile_zip, hostile_tar, directory):
            code, _payload, err = _scan_cli(target)
            check_eq(code, util.EXIT_OK, f"scan of {os.path.basename(target)}: {err}")
        check_eq(_snapshot(root), before, "the scanned tree must be byte-identical")
        check(
            not os.path.lexists(os.path.join(root, "ctfctl-escape-marker.txt")),
            "no traversal member may be written into the temp root",
        )
        check(
            not os.path.lexists(os.path.join(root, "abs.txt")),
            "no absolute member may be written into the temp root",
        )
        check(
            not os.path.lexists(
                os.path.join(os.path.dirname(root), "ctfctl-escape-marker.txt")
            ),
            "no traversal member may be written next to the temp root",
        )


# --------------------------------------------------------------------------
# CLI surface and output safety
# --------------------------------------------------------------------------
def test_cli_custom_regex_usage_errors_and_missing_input() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "custom.txt")
        _write(path, b"AAA{xyz} 7{12345}\n")

        code, _out, err = _run_cli(
            ["artifact", "scan", path, "--flag-regex", r"7\{[0-9]+\}", "--json"]
        )
        check_eq(code, util.EXIT_OK, f"custom regex must be accepted: {err}")
        payload = json.loads(_out)
        check_eq(
            _values(payload),
            ["7{12345}"],
            "the custom pattern, not the default, defines the findings",
        )

        code, out, err = _run_cli(["artifact", "scan", path, "--json"])
        check_eq(code, util.EXIT_OK, f"default regex scan: {err}")
        check_eq(
            _values(json.loads(out)),
            ["AAA{xyz}"],
            "the default pattern must still apply when no override is given",
        )

        code, _out, err = _run_cli(["artifact", "scan", path, "--flag-regex", "["])
        check_eq(code, util.EXIT_USAGE, "a bad regex is a usage error")
        check_in("invalid --flag-regex", err, "the bad regex must be named")

        code, _out, err = _run_cli(["artifact", "scan", path, "--flag-regex", ""])
        check_eq(code, util.EXIT_USAGE, "an empty regex is a usage error")

        missing = os.path.join(root, "missing.bin")
        code, _out, err = _run_cli(["artifact", "scan", missing, "--json"])
        check_eq(code, util.EXIT_NEGATIVE, "a missing input is an expected negative")
        check_in("does not exist", err, "the missing path must be named")


def test_findings_and_strings_order_is_deterministic() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "ordered.zip")
        _write(
            path,
            _zip_bytes(
                [
                    ("zz.txt", b"flag FLAG{order_zz}"),
                    ("aa.txt", b"flag FLAG{order_aa}"),
                    ("mm.txt", b"flag FLAG{order_mm}"),
                ]
            ),
        )
        code, first, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"first ordering run: {err}")
        code, second, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"second ordering run: {err}")
        check_eq(first["findings"], second["findings"], "two runs must agree exactly")
        check_eq(
            first["findings"],
            sorted(
                first["findings"],
                key=lambda item: (item["path"], item["offset"], item["value"]),
            ),
            "findings must be sorted by path, offset and value",
        )
        check_eq(
            first["strings"],
            sorted(
                first["strings"],
                key=lambda item: (item["path"], item["offset"], item["value"]),
            ),
            "strings must be sorted the same way",
        )


def test_control_characters_are_escaped_in_human_and_json_output() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "ansi.zip")
        _write(
            path,
            _zip_bytes([("ansi.txt", b"pre FLAG{esc\x1b[31mred} post")]),
        )
        code, out, err = _run_cli(["artifact", "scan", path])
        check_eq(code, util.EXIT_OK, f"human scan must exit 0: {err}")
        check("\x1b" not in out, "human output must not emit a raw ESC byte")
        check_in("\\x1b", out, "the ESC byte must be shown as an escape")
        for char in out:
            check(
                char == "\n" or ord(char) >= 0x20,
                f"human output must be printable, found {ord(char):#x}",
            )

        code, out, err = _run_cli(["artifact", "scan", path, "--json"])
        check_eq(code, util.EXIT_OK, f"json scan must exit 0: {err}")
        check("\x1b" not in out, "JSON text must not contain a raw ESC byte")
        payload = json.loads(out)
        check(
            any("\x1b" in value for value in _values(payload)),
            "the finding value itself keeps the original escape byte",
        )


def test_c1_and_bidi_member_names_are_escaped_in_human_and_json_output() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "names.zip")
        c1_name = "c1\x9bname.txt"
        bidi_name = "bidi\u202eexe.txt"
        _write(
            path,
            _zip_bytes([(c1_name, b"FLAG{c1_name}"), (bidi_name, b"FLAG{bidi_name}")]),
        )

        code, out, err = _run_cli(["artifact", "scan", path])
        check_eq(code, util.EXIT_OK, f"hostile member names must not crash: {err}")
        check("\x9b" not in out, "human output must not emit a raw C1 byte")
        check("\u202e" not in out, "human output must not emit a raw bidi control")
        check_in("\\x9b", out, "the C1 byte must be shown as an escape")
        check_in("\\u202e", out, "the bidi control must be shown as an escape")
        for char in out:
            check(
                char == "\n" or ord(char) >= 0x20,
                f"human output must be printable, found {ord(char):#x}",
            )

        code, out, err = _run_cli(["artifact", "scan", path, "--json"])
        check_eq(code, util.EXIT_OK, f"json scan must exit 0: {err}")
        check("\x9b" not in out, "JSON text must not contain a raw C1 byte")
        check("\u202e" not in out, "JSON text must not contain a raw bidi control")
        payload = json.loads(out)
        check_in(
            "c1\\x9bname.txt",
            _member_names(payload),
            "the C1 name must be escaped in the member list",
        )
        check_in(
            "bidi\\u202eexe.txt",
            _member_names(payload),
            "the bidi name must be escaped in the member list",
        )
        finding_paths = [item["path"] for item in payload["findings"]]
        check_in(
            path + "!/c1\\x9bname.txt",
            finding_paths,
            "the escaped C1 name must be used in finding paths",
        )
        check_in(
            path + "!/bidi\\u202eexe.txt",
            finding_paths,
            "the escaped bidi name must be used in finding paths",
        )
        check_eq(payload["complete"], True, "escaped names are still scanned")


# --------------------------------------------------------------------------
# Round-2 hardening: preflight refusals, caps and entry escaping
# --------------------------------------------------------------------------
class _ZipOpenRecorder:
    """Record any ``zipfile.ZipFile`` construction while a scan runs.

    The preflight refusals exist so ``zipfile`` never materializes a central
    directory for a hostile record. Recording the constructor turns "refused
    before opening" into an observable assertion instead of an inference from
    counters.
    """

    def __init__(self) -> None:
        self.opened: List[str] = []
        self._real: Any = None

    def __enter__(self) -> "_ZipOpenRecorder":
        self._real = zipfile.ZipFile
        recorder = self
        base = self._real

        class RecordingZipFile(base):  # type: ignore[misc, valid-type]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                recorder.opened.append(repr(args[0])[:80] if args else "<no argument>")
                super().__init__(*args, **kwargs)

        zipfile.ZipFile = RecordingZipFile
        return self

    def __exit__(self, *exc: Any) -> bool:
        if self._real is not None:
            zipfile.ZipFile = self._real
        return False


class _StatFailEntry:
    """Delegating DirEntry whose ``stat`` always reports an OSError.

    ``DirEntry.stat`` is implemented in C and does not route through the
    Python-level ``os.stat``, so a stat failure is injected by wrapping the
    scandir result instead of patching ``os.stat``.
    """

    def __init__(self, entry: Any) -> None:
        self._entry = entry

    def __getattr__(self, name: str) -> Any:
        return getattr(self._entry, name)

    def stat(self, *, follow_symlinks: bool = True) -> Any:
        raise OSError("synthetic stat failure")


class _ScandirProxy:
    """An ``os.scandir`` result with one entry replaced by a stat-failing proxy."""

    def __init__(self, real: Any, bad_name: str) -> None:
        self._real = real
        self._bad_name = bad_name

    def __iter__(self) -> Any:
        for entry in self._real:
            if entry.name == self._bad_name:
                yield _StatFailEntry(entry)
            else:
                yield entry

    def __enter__(self) -> "_ScandirProxy":
        self._real.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return self._real.__exit__(*exc)

    def close(self) -> None:
        self._real.close()


def test_zip64_locator_is_refused_before_opening() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "zip64.zip")
        _write(path, _zip_with_zip64_locator([("inside.txt", b"FLAG{zip64_inside}\n")]))
        with zipfile.ZipFile(path) as archive:
            check_eq(
                archive.namelist(),
                ["inside.txt"],
                "the fixture must be a zip that zipfile itself opens",
            )
        with _ZipOpenRecorder() as recorder:
            code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"a zip64 zip must not crash the scan: {err}")
        check_eq(payload["archive_format"], "zip", "detection happened before refusal")
        check_eq(payload["complete"], False, "a refused archive is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["zip64-unsupported"]},
            "the locator must be the reported limit",
        )
        check_eq(
            payload["counts"]["members_seen"], 0, "no member may be claimed or read"
        )
        check_eq(payload["counts"]["bytes_expanded"], 0, "no member may be read")
        check_eq(payload["members"], [], "no member summary may be produced")
        check_eq(recorder.opened, [], "zipfile.ZipFile must not be constructed at all")
        check("zip64-unsupported" in payload["errors"][0], "the error must name it")
        check("locator" in payload["errors"][0], "the locator must be named")


def test_zip_central_directory_size_cap_is_refused_before_opening() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        # A huge classic cd_size can only reach the preflight when zipfile
        # still recognizes the file as a zip. `zipfile.is_zipfile` locates the
        # central directory at size-22-cd_size, so the fixture plants a
        # central-directory signature where that check looks and pads the file
        # above the 4 MiB floor cap with a stored member.
        filler = 5 * artifact_mod.MIB
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("payload.bin", b"\x00" * filler)
        base = buffer.getvalue()
        declared_cd = artifact_mod.MIN_ZIP_CD_CAP + 1024
        marker = len(base) - 22 - declared_cd
        check(0 <= marker < len(base) - 22, "the marker must land inside the file")
        patched = bytearray(base)
        patched[marker : marker + 4] = b"PK\x01\x02"
        path = os.path.join(root, "cd-cap.zip")
        _write(
            path,
            _patch_zip_eocd(bytes(patched), count=1, cd_size=declared_cd),
        )
        check(zipfile.is_zipfile(path), "the fixture must still look like a zip")

        with _ZipOpenRecorder() as recorder:
            code, payload, err = _scan_cli(path, "--max-members", "2")
        check_eq(code, util.EXIT_OK, f"an over-cap central directory: {err}")
        check_eq(payload["complete"], False, "a refused archive is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["cd-size-cap"]},
            "the central-directory cap must be the reported limit",
        )
        check_eq(payload["counts"]["members_seen"], 0, "no member may be read")
        check_eq(payload["counts"]["bytes_expanded"], 0, "no member may be read")
        check_eq(recorder.opened, [], "zipfile.ZipFile must not be constructed at all")
        check("cd-size-cap" in payload["errors"][0], "the error must name the cap")

        # The naive shape (a tiny zip whose cd_size alone is huge) never
        # reaches the preflight through the CLI: zipfile's own is_zipfile check
        # fails first and the scan reports archive-unparsed. The preflight
        # itself still refuses it, which is asserted directly here.
        naive = _patch_zip_eocd(
            _zip_bytes([("a.txt", b"x")], stored=True), count=1, cd_size=0x7FFFFFFF
        )
        declared, note, refusal, detail = artifact_mod._zip_eocd_preflight(
            io.BytesIO(naive), 2000
        )
        check_eq(declared, None, "a refused preflight declares no member count")
        check_eq(note, None, "a refusal is not a parse note")
        check_eq(
            refusal, "cd-size-cap", "the preflight must refuse the naive shape too"
        )
        check(detail is not None and "cap" in detail, "the refusal must name the cap")


def test_tar_longname_metadata_cap_stops_with_bounded_metadata_bytes() -> None:
    declared = artifact_mod.TAR_METADATA_SLACK + artifact_mod.MIB
    blob = _gnu_longname_targz(declared)
    check(
        declared > artifact_mod.TAR_METADATA_SLACK,
        "fixture premise: the longname must exceed the internal slack",
    )
    check(len(blob) < artifact_mod.MIB, "the metadata bomb fixture must stay tiny")
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "longname.tar.gz")
        _write(path, blob)
        code, payload, err = _scan_cli(path, "--max-total-mib", "0")
        check_eq(code, util.EXIT_OK, f"a metadata bomb must not crash the scan: {err}")
        check("Traceback" not in err, "no parse failure may escape as a traceback")
        check_eq(payload["complete"], False, "a stopped tar is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["tar-metadata-cap"]},
            "the metadata cap must be the reported limit",
        )
        check_in("limits", payload["incomplete"], "the limit must make it incomplete")
        check(
            payload["errors"] and "tar-metadata-cap" in payload["errors"][0],
            "the stop must be named in errors",
        )
        check(
            "archive-errors" not in payload["incomplete"],
            "a cap stop is not an unparsed archive",
        )
        metadata = payload["counts"]["metadata_bytes"]
        check(
            metadata > artifact_mod.TAR_METADATA_SLACK,
            "the delivered metadata must have crossed the slack bound",
        )
        check(
            metadata <= declared + 64 * 1024,
            "metadata_bytes must stay bounded near the declared size",
        )
        check_eq(payload["counts"]["members_seen"], 0, "no member may be claimed")
        check_eq(payload["counts"]["bytes_expanded"], 0, "no member may be read")
        check_eq(payload["members"], [], "no member summary may be produced")


def test_metadata_bytes_is_counted_for_tar_and_zero_for_plain_files() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        tar_path = os.path.join(root, "one.tar")
        _write(tar_path, _tar_bytes([("a.txt", b"FLAG{meta_tar}\n")]))
        code, payload, err = _scan_cli(tar_path)
        check_eq(code, util.EXIT_OK, f"tar scan must exit 0: {err}")
        check_in("metadata_bytes", payload["counts"], "the count must be in the JSON")
        check(
            payload["counts"]["metadata_bytes"] > 0,
            "tar headers and padding must be counted as metadata",
        )

        tgz_path = os.path.join(root, "one.tar.gz")
        _write(tgz_path, _gz_tar_bytes([("a.txt", b"FLAG{meta_tgz}\n")]))
        code, payload, err = _scan_cli(tgz_path)
        check_eq(code, util.EXIT_OK, f"tar.gz scan must exit 0: {err}")
        check(
            payload["counts"]["metadata_bytes"] > 0,
            "a tar.gz keeps the same metadata accounting",
        )

        plain_path = os.path.join(root, "plain.txt")
        _write(plain_path, b"FLAG{meta_plain}\n")
        code, payload, err = _scan_cli(plain_path)
        check_eq(code, util.EXIT_OK, f"plain scan must exit 0: {err}")
        check_in("metadata_bytes", payload["counts"], "the key must always be present")
        check_eq(
            payload["counts"]["metadata_bytes"],
            0,
            "a plain file has no tar metadata",
        )


def test_zip_eocd_count_below_real_entries_counts_dropped_members() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        members = [(f"m{index}.txt", b"x") for index in range(4)]
        path = os.path.join(root, "overflow.zip")
        _write(
            path,
            _patch_zip_eocd(_zip_bytes(members, stored=True), count=1),
        )
        code, payload, err = _scan_cli(path, "--max-members", "2")
        check_eq(code, util.EXIT_OK, f"a lying EOCD count must not crash: {err}")
        check_eq(payload["archive_format"], "zip", "the archive still opens")
        check_eq(payload["complete"], False, "the truncated member list is partial")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["max-members"]},
            "the member cap must be the reported limit",
        )
        counts = payload["counts"]
        check_eq(
            counts["members_unparsed"],
            2,
            "the dropped entries must be counted, not silently discarded",
        )
        check_eq(
            counts["members_seen"],
            4,
            "the dropped entries must also be counted as seen: 2 kept + 2 dropped",
        )
        check_eq(counts["members_parsed"], 2, "the kept entries were read")
        check_eq(
            counts["members_seen"],
            counts["members_parsed"]
            + counts["members_skipped"]
            + counts["members_unparsed"],
            "seen members must equal parsed + skipped + unparsed",
        )
        check_eq(
            sorted(_member_names(payload)),
            ["m0.txt", "m1.txt"],
            "the kept entries are the first two by sorted name",
        )
        check_in("limits", payload["incomplete"], "the cap makes it incomplete")
        check_in(
            "members-unparsed",
            payload["incomplete"],
            "the dropped entries make it incomplete",
        )


def test_plain_file_size_mismatch_marks_the_scan_incomplete() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "mismatch.bin")
        data = b"FLAG{size_mismatch}\n" * 8
        _write(path, data)
        target = os.stat(path)
        if target.st_ino == 0:
            _skip(
                "size-mismatch case: the host filesystem reports st_ino 0, so the "
                "fstat call cannot be matched"
            )
            return
        real_fstat = os.fstat

        def patched_fstat(fd: int) -> os.stat_result:
            info = real_fstat(fd)
            if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
                values = list(info)
                values[6] = info.st_size + 3  # st_size
                return os.stat_result(values)
            return info

        os.fstat = patched_fstat
        try:
            code, payload, err = _scan_cli(path)
        finally:
            os.fstat = real_fstat
        check_eq(code, util.EXIT_OK, f"a changing file must not crash: {err}")
        check_eq(payload["complete"], False, "a mismatched digest is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["size-mismatch"]},
            "the mismatch must be the reported limit",
        )
        check_in("limits", payload["incomplete"], "the mismatch is a limit reason")
        check_in("errors", payload["incomplete"], "the mismatch is also an error")
        check_eq(len(payload["errors"]), 1, "exactly one mismatch is reported")
        check(
            "size-mismatch" in payload["errors"][0],
            "the error entry must name the mismatch",
        )
        check_eq(
            payload["sha256"],
            hashlib.sha256(data).hexdigest(),
            "the digest must still cover the bytes actually read",
        )
        check_eq(
            payload["files"][0]["bytes_read"],
            len(data),
            "the summary must report the bytes actually streamed",
        )


def test_filesystem_control_char_names_are_escaped_in_output() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        scanned = os.path.join(root, "scanned")
        outside = os.path.join(root, "outside")
        _write(os.path.join(scanned, "plain.txt"), b"FLAG{fs_plain}\n")
        _write(os.path.join(outside, "secret.txt"), b"FLAG{fs_outside}\n")
        # Windows refuses ESC in file names; C1 is accepted there. Whichever
        # the host stores is asserted escaped, and when it stores neither the
        # case is skipped with a reason.
        control_names = {
            "esc\x1bname.txt": "esc\\x1bname.txt",
            "c1\x9bname.txt": "c1\\x9bname.txt",
        }
        accepted: List[Tuple[str, str]] = []
        for raw_name, escaped in control_names.items():
            try:
                with open(os.path.join(scanned, raw_name), "wb") as handle:
                    handle.write(b"FLAG{fs_control}\n")
            except (OSError, ValueError):
                continue
            accepted.append((raw_name, escaped))
        if not accepted:
            _skip(
                "filesystem control-character case: the host filesystem refused "
                "both ESC and C1 entry names"
            )
            return

        link = os.path.join(scanned, "jump")
        have_link = False
        if _LINK_REASON is None:
            have_link = _make_dir_link(outside, link) is None
        try:
            code, text, err = _run_cli(["artifact", "scan", scanned, "--json"])
            check_eq(code, util.EXIT_OK, f"control-char walk must exit 0: {err}")
            payload = json.loads(text)
            human_code, human_text, human_err = _run_cli(["artifact", "scan", scanned])
            check_eq(human_code, util.EXIT_OK, f"human scan must exit 0: {human_err}")
        finally:
            if have_link:
                _remove_link(link)

        values = _values(payload)
        check_in("FLAG{fs_plain}", values, "a normal file is still scanned")
        check_in("FLAG{fs_control}", values, "the control-named file is scanned")
        for raw_name, escaped in accepted:
            check(
                raw_name not in text,
                f"JSON must not carry the raw control bytes of {raw_name!r}",
            )
            check_in(
                json.dumps(escaped)[1:-1],
                text,
                f"JSON must carry {escaped!r} in encoded form",
            )
            check(
                raw_name not in human_text,
                f"human output must not carry the raw bytes of {raw_name!r}",
            )
            check_in(escaped, human_text, f"human output must show {escaped!r}")
            check(
                any(escaped in item["path"] for item in payload["files"]),
                f"the file summary path must use the escaped form {escaped!r}",
            )
        for char in human_text:
            check(
                char == "\n" or ord(char) >= 0x20,
                f"human output must be printable, found {ord(char):#x}",
            )

        if have_link:
            check(
                payload["counts"]["links_skipped"] >= 1,
                "the directory link must still be counted as skipped",
            )
            check_eq(
                payload["complete"],
                False,
                "a skipped link keeps the scan incomplete",
            )
            check(
                "FLAG{fs_outside}" not in values,
                "content behind the link must never be scanned",
            )
        else:
            _skip(
                "control-char directory case: link semantics not asserted "
                "(no symlink or junction on this host)"
            )
            check_eq(
                payload["counts"]["links_skipped"], 0, "nothing was treated as a link"
            )
            check_eq(payload["complete"], True, "the escaped entries still scan fully")


def test_directory_entry_stat_failure_is_recorded_not_crashed() -> None:
    with temp_dir("ctfctl-artifact-") as root:
        _write(os.path.join(root, "good.txt"), b"FLAG{stat_good}\n")
        _write(os.path.join(root, "badstat.txt"), b"FLAG{stat_bad}\n")
        real_scandir = os.scandir

        def patched_scandir(path: Any, *args: Any, **kwargs: Any) -> Any:
            result = real_scandir(path, *args, **kwargs)
            if os.path.abspath(os.fspath(path)) == os.path.abspath(root):
                return _ScandirProxy(result, "badstat.txt")
            return result

        os.scandir = patched_scandir
        try:
            code, payload, err = _scan_cli(root)
        finally:
            os.scandir = real_scandir
        check_eq(code, util.EXIT_OK, f"a stat failure must not crash the walk: {err}")
        check_eq(payload["complete"], False, "a skipped entry is not complete")
        check_eq(payload["counts"]["files_skipped"], 1, "the entry must be skipped")
        check_eq(payload["counts"]["files_scanned"], 1, "the good file is still read")
        check_in("files-skipped", payload["incomplete"], "the skip category applies")
        check_in("errors", payload["incomplete"], "the failure is an error")
        check_in("FLAG{stat_good}", _values(payload), "the good file is scanned")
        check(
            "FLAG{stat_bad}" not in _values(payload),
            "the stat-failed entry must never be read",
        )
        check_eq(len(payload["errors"]), 1, "exactly one entry failure is reported")
        check(
            "badstat.txt" in payload["errors"][0],
            "the failing entry must be named in errors",
        )
        check(
            "synthetic stat failure" in payload["errors"][0],
            "the failure reason must be kept in errors",
        )


# --------------------------------------------------------------------------
# Round-3 pinning: last-signature EOCD decoys and tar member accounting
# --------------------------------------------------------------------------
def test_zip_eocd_decoy_in_comment_is_refused_before_opening() -> None:
    """The preflight must validate the last EOCD signature, not an aligned one."""
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "decoy.zip")
        _write(path, _decoy_eocd_zip())
        check(
            zipfile.is_zipfile(path),
            "fixture premise: the decoy shape must still be detected as a zip",
        )
        declared, note, refusal, detail = artifact_mod._zip_eocd_preflight(path, 2000)
        check_eq(declared, None, "a refused preflight declares no member count")
        check_eq(note, None, "a refusal is not a parse note")
        check_eq(refusal, "eocd-misaligned", "the embedded decoy must be refused")
        check(
            detail is not None and "file end" in detail,
            "the refusal must name the misalignment, not a zip64 or cap shape",
        )

        with _ZipOpenRecorder() as recorder:
            code, payload, err = _scan_cli(path)
        check_eq(code, util.EXIT_OK, f"a decoy EOCD must not crash the scan: {err}")
        check_eq(payload["kind"], "archive", "the zip is recognized, then refused")
        check_eq(payload["archive_format"], "zip", "detection happened before refusal")
        check_eq(payload["complete"], False, "a refused archive is not complete")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["eocd-misaligned"]},
            "the deceptive record must be the reported limit",
        )
        check_in("limits", payload["incomplete"], "the refusal marks the scan limited")
        check_in("errors", payload["incomplete"], "the refusal is reported as an error")
        check_eq(payload["counts"]["members_seen"], 0, "no member may even be listed")
        check_eq(payload["counts"]["bytes_expanded"], 0, "no member may be read")
        check_eq(payload["members"], [], "no member summary may be produced")
        check_eq(
            recorder.opened,
            [],
            "zipfile.ZipFile must not be constructed for a refused record",
        )
        check_eq(
            payload["archive_errors"],
            [],
            "a refusal is a limit, not an unparsed archive",
        )
        check(
            any(
                "eocd-misaligned" in item and "does not end" in item
                for item in payload["errors"]
            ),
            "the error must name the misaligned decoy record",
        )

        # Negative control: a legitimate comment whose length reaches the file
        # end must preflight clean, open and scan like any other zip.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("inside.txt", b"FLAG{comment_ok}\n")
            archive.comment = b"benign comment"
        clean_path = os.path.join(root, "comment.zip")
        _write(clean_path, buffer.getvalue())
        declared, note, refusal, detail = artifact_mod._zip_eocd_preflight(
            clean_path, 2000
        )
        check_eq(
            (declared, note, refusal, detail),
            (1, None, None, None),
            "a correctly sized EOCD comment must preflight clean",
        )
        check(
            zipfile.is_zipfile(clean_path),
            "fixture premise: the commented control must be a zip",
        )
        with _ZipOpenRecorder() as recorder:
            code, payload, err = _scan_cli(clean_path)
        check_eq(code, util.EXIT_OK, f"a commented zip must scan: {err}")
        check_eq(payload["complete"], True, "the commented control must scan fully")
        check_eq(
            payload["limits"], {"hit": False, "reasons": []}, "no limit may be hit"
        )
        check_eq(payload["counts"]["members_seen"], 1, "the member is seen")
        check_eq(_member_names(payload), ["inside.txt"], "the member is read")
        check_in("FLAG{comment_ok}", _values(payload), "member content is scanned")
        check_eq(
            len(recorder.opened),
            1,
            "an accepted preflight must open the archive exactly once",
        )


def _check_member_accounting(payload: Dict[str, Any], label: str) -> None:
    """Every seen member must land in exactly one disposition counter.

    Skipped members are refused unread: a directory, link or special entry, an
    invalid name, a duplicate, an encrypted member or one over the ratio guard;
    unparsed members are cut short or refused for their declared size. The
    identity therefore holds for every archive shape, not just file members.
    """
    counts = payload["counts"]
    check_eq(
        counts["members_seen"],
        counts["members_parsed"]
        + counts["members_skipped"]
        + counts["members_unparsed"],
        f"{label}: seen members must equal parsed + skipped + unparsed",
    )
    truncated = sum(1 for member in payload["members"] if member["truncated"])
    check_eq(
        len(payload["members"]),
        counts["members_parsed"] + truncated,
        f"{label}: every member summary must be a parsed or truncated member",
    )


def test_tar_member_seen_then_cut_mid_read_is_counted_unparsed() -> None:
    """A limiter trip inside a member must leave it visible in the accounting."""
    blob = _pax_metadata_targz(
        artifact_mod.TAR_METADATA_SLACK + 256 * 1024, 2 * artifact_mod.MIB
    )
    check(len(blob) < artifact_mod.MIB, "the metadata fixture must stay tiny")
    with temp_dir("ctfctl-artifact-") as root:
        path = os.path.join(root, "pax-mid.tar.gz")
        _write(path, blob)
        code, payload, err = _scan_cli(path, "--max-total-mib", "1")
        check_eq(code, util.EXIT_OK, f"a mid-member stop must exit 0: {err}")
        check("Traceback" not in err, "no parse failure may escape as a traceback")
        check_eq(payload["complete"], False, "a stopped tar is not complete")
        check_in("limits", payload["incomplete"], "the stop is a limit")
        check_in("errors", payload["incomplete"], "the stop is named in errors")
        check_in("members-unparsed", payload["incomplete"], "the member is unparsed")
        check_eq(
            payload["limits"],
            {"hit": True, "reasons": ["member-unparsed", "tar-metadata-cap"]},
            "the member-level stop must be reported before the archive-level stop",
        )
        counts = payload["counts"]
        check_eq(counts["members_seen"], 1, "the PAX-named member was seen")
        check_eq(counts["members_parsed"], 0, "the member was cut before it parsed")
        check_eq(counts["members_unparsed"], 1, "the cut member is unparsed")
        _check_member_accounting(payload, "pax-mid.tar.gz")
        check(
            0 < counts["bytes_expanded"] <= artifact_mod.MIB,
            "the trip must happen after member bytes were counted, under the cap",
        )
        check(
            counts["metadata_bytes"] > artifact_mod.TAR_METADATA_SLACK + 128 * 1024,
            "the PAX metadata alone must have spent the slack budget",
        )
        check_eq(payload["members"], [], "a member cut mid-read has no summary")
        check(
            any(
                "!/seen.bin" in item
                and "tar-metadata-cap" in item
                and "member not fully read" in item
                for item in payload["errors"]
            ),
            "the affected member must be named in the unparsed error",
        )

        # General invariant: the same identity must hold for the cheap,
        # regular-member archive shapes this suite already builds elsewhere,
        # and for directory, link and special members, which are now counted
        # as skipped members rather than sitting outside the identity.
        regulars = {
            "normal.zip": _zip_bytes([("a.txt", b"FLAG{a}"), ("b.txt", b"B")]),
            "collision.zip": _zip_bytes([("dup.txt", b"1"), ("dup.txt", b"2")]),
            "nested.zip": _zip_bytes(
                [
                    ("outer.txt", b"FLAG{o}"),
                    ("inner.zip", _zip_bytes([("deep.txt", b"FLAG{d}")])),
                ]
            ),
            "ratio.zip": _zip_bytes([("zeros.bin", b"\x00" * artifact_mod.MIB)]),
            "normal.tar": _tar_bytes([("a.txt", b"AAA"), ("b.txt", b"B")]),
            "dirs.zip": _zip_bytes([("empty/", b""), ("file.txt", b"FLAG{dir_zip}")]),
            "dirs.tar": _dir_tar_bytes(),
            "dispositions.zip": _disposition_zip_bytes(),
        }
        for name, data in regulars.items():
            fixture = os.path.join(root, name)
            _write(fixture, data)
            code, payload, err = _scan_cli(fixture)
            check_eq(code, util.EXIT_OK, f"{name} must scan: {err}")
            check(
                payload["counts"]["members_seen"] > 0,
                f"{name}: the invariant must not be vacuous",
            )
            _check_member_accounting(payload, name)
