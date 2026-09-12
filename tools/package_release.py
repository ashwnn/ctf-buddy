#!/usr/bin/env python3
"""Package a documented, offline release of this repository.

The archive contains only source, docs, corpus cards, profiles, fixtures, drills
and tests. It deliberately excludes runtime state, captures, generated indexes,
local source snapshots and anything secret-looking. No binaries are bundled.

    python tools/package_release.py                 # build into dist/
    python tools/package_release.py --json          # machine summary
    python tools/package_release.py --check dist/ctf-buddy-0.1.0.tar.gz
    python tools/package_release.py --rehearse      # build, extract, run tests

Outputs, next to the archive:

    ctf-buddy-<version>.tar.gz      the release
    MANIFEST.sha256                 sha256 of every archived file
    SOURCE-LICENSES.jsonl           source/licence/reuse manifest
    CHECKSUMS.sha256                sha256 of the archive and manifests
    RELEASE-NOTES.md                what this is and how to verify it
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from ctfctl import __version__ as toolkit_version  # noqa: E402
from ctfctl import util  # noqa: E402

ROOT = os.path.dirname(TOOLS_DIR)

INCLUDE_TOP = [
    "README.md",
    "AGENTS.md",
    "ctfctl",
    "docs",
    "kb",
    "sources",
    "profiles",
    "fixtures",
    "drills",
    "templates",
    "tests",
    "tools",
]
EXCLUDE_DIR_NAMES = {
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".venv",
    "venv",
    "dist",
    "build",
    "state",
    "captures",
    "backups",
    "index",
    "loot",
    "runtime",
}
EXCLUDE_REL_PREFIXES = (
    "sources/raw/",
    "sources/text/private/",
    "sources/local/",
)
EXCLUDE_FILE_NAMES = {".env", "targets.json", "targets.local.json"}
EXCLUDE_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".pcap",
    ".pcapng",
    ".cap",
    ".sqlite3",
    ".sqlite3-journal",
)
MAX_FILE_BYTES = 8 * 1024 * 1024

#: Files that carry the provenance instead of appearing in MANIFEST.sha256.
META_FILES = (
    "MANIFEST.sha256",
    "SOURCE-LICENSES.jsonl",
    "RELEASE-NOTES.md",
    "CHECKSUMS.sha256",
)


class ReleaseError(Exception):
    pass


def _iter_files(root: str = ROOT) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Return (sorted (relative posix path, absolute path), skipped notes)."""
    found: List[Tuple[str, str]] = []
    skipped: List[str] = []
    for name in INCLUDE_TOP:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            found.append((name.replace(os.sep, "/"), path))
            continue
        if not os.path.isdir(path):
            continue
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIR_NAMES)
            for filename in sorted(filenames):
                absolute = os.path.join(dirpath, filename)
                relative = os.path.relpath(absolute, root).replace(os.sep, "/")
                if filename in EXCLUDE_FILE_NAMES:
                    skipped.append(relative)
                    continue
                if relative.startswith(EXCLUDE_REL_PREFIXES):
                    skipped.append(relative)
                    continue
                if filename.endswith(EXCLUDE_SUFFIXES):
                    skipped.append(relative)
                    continue
                if os.path.islink(absolute):
                    skipped.append(relative + " (symlink)")
                    continue
                if os.path.getsize(absolute) > MAX_FILE_BYTES:
                    skipped.append(f"{relative} (>{MAX_FILE_BYTES} bytes)")
                    continue
                found.append((relative, absolute))
    found.sort(key=lambda pair: pair[0])
    return found, skipped


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(256 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(files: List[Tuple[str, str]]) -> str:
    lines = [f"{_sha256_file(path)}  {relative}" for relative, path in files]
    return "\n".join(lines) + "\n"


def build_source_licenses(root: str) -> str:
    records = util.load_jsonl(os.path.join(root, "sources", "manifest.jsonl"))
    out = []
    for record in records:
        out.append(
            {
                "source_id": record.get("source_id"),
                "title": record.get("title"),
                "author": record.get("author"),
                "team": record.get("team"),
                "canonical_url": record.get("canonical_url"),
                "event": record.get("event"),
                "retrieved_at": record.get("retrieved_at"),
                "license_expression": record.get("license_expression"),
                "redistribution": record.get("redistribution"),
                "primary": bool(record.get("primary")),
            }
        )
    return "".join(
        json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n" for record in out
    )


def _source_counts(root: str) -> Dict[str, Any]:
    records = util.load_jsonl(os.path.join(root, "sources", "manifest.jsonl"))
    redistribution: Dict[str, int] = {}
    primary = 0
    for record in records:
        key = str(record.get("redistribution") or "unknown")
        redistribution[key] = redistribution.get(key, 0) + 1
        if record.get("primary"):
            primary += 1
    return {
        "total": len(records),
        "primary": primary,
        "redistribution": dict(sorted(redistribution.items())),
    }


def _generated_at(root: str) -> str:
    """A stable timestamp for reproducible archives.

    Honors SOURCE_DATE_EPOCH, then the HEAD commit date, then the epoch. A
    release must not change bytes just because it was built a second later.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if epoch.isdigit():
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))
    try:
        proc = subprocess.run(
            ["git", "-C", root, "log", "-1", "--format=%cI"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        stamp = proc.stdout.strip()
        if proc.returncode == 0 and stamp:
            return stamp
    except (OSError, subprocess.SubprocessError):
        pass
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(0))


def build_release_notes(
    root: str, archive_name: str, files: List[Tuple[str, str]], skipped: List[str]
) -> str:
    cards = 0
    manifest_path = os.path.join(root, "kb", "manifest.jsonl")
    if os.path.isfile(manifest_path):
        cards = len(util.load_jsonl(manifest_path))
    profiles = []
    profile_dir = os.path.join(root, "profiles")
    if os.path.isdir(profile_dir):
        profiles = sorted(
            name for name in os.listdir(profile_dir) if name.endswith(".json")
        )
    counts = _source_counts(root)
    lines = [
        f"# ctf-buddy release {toolkit_version}",
        "",
        f"Generated: {_generated_at(root)}",
        f"Archive: {archive_name}",
        f"Files: {len(files)}",
        f"Cards: {cards}",
        f"Profiles: {', '.join(profiles) or 'none'}",
        f"Source records: {counts['total']} ({counts['primary']} primary)",
        "",
        "## What this is",
        "",
        "Portable, offline-first preparation tooling for a first-time CTF team:",
        "a source-linked knowledge base with local search, read-only discovery, a",
        "transactional patch engine with rollback, bounded observation, an optional",
        "decoy, drills, and ssh remote mode for a declared team-owned host.",
        "",
        "## Requirements",
        "",
        "Python 3.9+ standard library only. An OpenSSH client for remote mode.",
        "No Internet, no API keys and no cloud service are required for ordinary use.",
        "",
        "## Verify this archive",
        "",
        "```bash",
        "sha256sum -c CHECKSUMS.sha256",
        "python tools/package_release.py --check " + archive_name,
        "```",
        "",
        "## Offline rehearsal",
        "",
        "```bash",
        "tar -xzf " + archive_name,
        "cd ctf-buddy-" + toolkit_version,
        "python tests/run_tests.py",
        "```",
        "",
        "## Redistribution and provenance",
        "",
        "SOURCE-LICENSES.jsonl lists every source with its licence and reuse",
        "status. Cards are original, source-linked summaries; no third-party",
        "article text is redistributed. The distribution counts are: "
        + json.dumps(counts["redistribution"], sort_keys=True)
        + ".",
        "No binaries are bundled.",
        "",
        "## Excluded on purpose",
        "",
        "Runtime state, captures, backups, generated search index, local source",
        "snapshots, secrets and binaries are never packaged. Skipped entries:",
        "",
    ]
    if skipped:
        lines += [f"- {item}" for item in sorted(set(skipped))[:40]]
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def build_release(out_dir: str, *, root: str = ROOT) -> Dict[str, Any]:
    files, skipped = _iter_files(root)
    if not files:
        raise ReleaseError("no files collected; refusing to build an empty release")
    forbidden = [
        relative
        for relative, _ in files
        if relative.startswith(("state/", "captures/", "index/", "backups/"))
        or relative.startswith(EXCLUDE_REL_PREFIXES)
    ]
    if forbidden:
        raise ReleaseError(f"refusing to package excluded paths: {forbidden[:5]}")

    manifest = build_manifest(files)
    source_licenses = build_source_licenses(root)
    archive_name = f"ctf-buddy-{toolkit_version}.tar.gz"
    notes = build_release_notes(root, archive_name, files, skipped)

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        base = f"ctf-buddy-{toolkit_version}"
        for relative, path in files:
            info = tar.gettarinfo(path, arcname=f"{base}/{relative}")
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            with open(path, "rb") as fh:
                tar.addfile(info, fh)
        _add_bytes(tar, f"{base}/MANIFEST.sha256", manifest.encode("utf-8"))
        _add_bytes(
            tar, f"{base}/SOURCE-LICENSES.jsonl", source_licenses.encode("utf-8")
        )
        _add_bytes(tar, f"{base}/RELEASE-NOTES.md", notes.encode("utf-8"))
    archive_bytes = gzip.compress(tar_buffer.getvalue(), compresslevel=9, mtime=0)

    os.makedirs(out_dir, exist_ok=True)
    archive_path = os.path.join(out_dir, archive_name)
    with open(archive_path, "wb") as fh:
        fh.write(archive_bytes)
    checksum = hashlib.sha256(archive_bytes).hexdigest()
    manifest_path = os.path.join(out_dir, "MANIFEST.sha256")
    licenses_path = os.path.join(out_dir, "SOURCE-LICENSES.jsonl")
    notes_path = os.path.join(out_dir, "RELEASE-NOTES.md")
    checksums_path = os.path.join(out_dir, "CHECKSUMS.sha256")
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(manifest)
    with open(licenses_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(source_licenses)
    with open(notes_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(notes)
    with open(checksums_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{checksum}  {archive_name}\n")
        fh.write(f"{_sha256_file(manifest_path)}  MANIFEST.sha256\n")
        fh.write(f"{_sha256_file(licenses_path)}  SOURCE-LICENSES.jsonl\n")

    return {
        "archive": archive_path,
        "archive_sha256": checksum,
        "archive_bytes": len(archive_bytes),
        "files": len(files),
        "skipped": sorted(set(skipped)),
        "manifest": manifest_path,
        "licenses": licenses_path,
        "notes": notes_path,
        "checksums": checksums_path,
        "version": toolkit_version,
    }


def verify_archive(archive_path: str) -> Dict[str, Any]:
    """Verify every MANIFEST.sha256 entry against the archive contents."""
    result: Dict[str, Any] = {
        "archive": archive_path,
        "ok": True,
        "checked": 0,
        "problems": [],
    }
    with tarfile.open(archive_path, "r:gz") as tar:
        members = {member.name: member for member in tar.getmembers()}
        manifest_name = next(
            (name for name in members if name.endswith("/MANIFEST.sha256")), None
        )
        if not manifest_name:
            result["ok"] = False
            result["problems"].append("archive has no MANIFEST.sha256")
            return result
        base = manifest_name[: -len("MANIFEST.sha256")]
        manifest = tar.extractfile(members[manifest_name]).read().decode("utf-8")
        listed = set()
        for line in manifest.splitlines():
            if not line.strip():
                continue
            expected, _, relative = line.partition("  ")
            listed.add(f"{base}{relative}")
            member = members.get(f"{base}{relative}")
            if member is None:
                result["problems"].append(f"missing from archive: {relative}")
                continue
            data = tar.extractfile(member).read()
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                result["problems"].append(f"hash mismatch: {relative}")
            result["checked"] += 1
        for name, member in members.items():
            if member.isdir() or name in listed:
                continue
            if name.rsplit("/", 1)[-1] in META_FILES:
                continue
            result["problems"].append(f"unlisted content file: {name}")
        if result["problems"]:
            result["ok"] = False
    return result


def rehearse(archive_path: str) -> Dict[str, Any]:
    """Extract the archive to a temp dir and run the test suite there."""
    with tempfile.TemporaryDirectory(prefix="ctf-buddy-rehearse-") as work:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(work)
        roots = [
            name for name in os.listdir(work) if os.path.isdir(os.path.join(work, name))
        ]
        if len(roots) != 1:
            return {"ok": False, "reason": f"unexpected archive layout: {roots}"}
        root = os.path.join(work, roots[0])
        started = time.time()
        proc = subprocess.run(
            [sys.executable, "-u", os.path.join("tests", "run_tests.py")],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        tail = "\n".join(proc.stdout.strip().splitlines()[-20:])
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "seconds": round(time.time() - started, 1),
            "tail": util.redact(tail),
        }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"))
    parser.add_argument("--check", metavar="ARCHIVE")
    parser.add_argument("--rehearse", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.check:
        result = verify_archive(args.check)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"verify {'OK' if result['ok'] else 'PROBLEMS'} "
                f"({result['checked']} files checked)"
            )
            for problem in result["problems"][:20]:
                print(f"  ! {problem}")
        return 0 if result["ok"] else 1

    summary = build_release(args.out)
    if args.rehearse:
        summary["rehearsal"] = rehearse(summary["archive"])
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"archive   {summary['archive']}")
        print(f"sha256    {summary['archive_sha256']}")
        print(f"files     {summary['files']}")
        print(f"checksums {summary['checksums']}")
        print(f"licenses  {summary['licenses']}")
        if summary.get("rehearsal"):
            rehearsal = summary["rehearsal"]
            print(
                f"rehearsal {'PASS' if rehearsal['ok'] else 'FAIL'} "
                f"in {rehearsal.get('seconds', '?')}s"
            )
            if not rehearsal["ok"]:
                print(rehearsal.get("tail", ""))
    if summary.get("rehearsal") and not summary["rehearsal"]["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ReleaseError as exc:
        print(f"release: {exc}", file=sys.stderr)
        raise SystemExit(3)
