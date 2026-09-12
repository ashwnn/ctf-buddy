"""Release packaging: contents, manifest integrity, determinism, exclusions."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile

import package_release

from helpers import REPO_ROOT, check, check_eq, check_in, temp_dir


def _members(archive: str):
    with tarfile.open(archive, "r:gz") as tar:
        return {m.name: m for m in tar.getmembers() if not m.isdir()}


def _read(archive: str, name: str) -> bytes:
    with tarfile.open(archive, "r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("/" + name))
        return tar.extractfile(member).read()


def test_release_contains_core_paths_and_verifies() -> None:
    with temp_dir() as out:
        summary = package_release.build_release(out, root=REPO_ROOT)
        check(os.path.isfile(summary["archive"]), "archive must exist")
        names = set(_members(summary["archive"]))
        for expected in (
            "README.md",
            "tools/ctfctl/cli.py",
            "tools/ctfctl/remote.py",
            "kb/manifest.jsonl",
            "sources/manifest.jsonl",
            "drills/01-web-diagnosis-and-patch.md",
            "profiles/web-nginx-flask-compose.json",
            "MANIFEST.sha256",
            "SOURCE-LICENSES.jsonl",
            "RELEASE-NOTES.md",
        ):
            check(
                any(name.endswith(expected) for name in names),
                f"release must contain {expected}: {sorted(names)[:5]}",
            )
        check(
            summary["files"] >= 100,
            f"expected a substantial file list, got {summary['files']}",
        )
        result = package_release.verify_archive(summary["archive"])
        check_eq(result["ok"], True, f"archive must verify: {result['problems'][:5]}")
        check_eq(
            result["checked"], summary["files"], "every manifest entry must be checked"
        )


def test_release_excludes_state_captures_index_and_snapshots() -> None:
    with temp_dir() as out:
        summary = package_release.build_release(out, root=REPO_ROOT)
        names = list(_members(summary["archive"]))
        forbidden = [
            name
            for name in names
            if "__pycache__" in name
            or name.endswith(".pyc")
            or "/state/" in name
            or "/captures/" in name
            or "/index/" in name
            or "/sources/raw/" in name
            or "sources/text/private" in name
            or name.endswith((".pcap", ".pcapng", ".key", ".pem", ".sqlite3"))
        ]
        check_eq(forbidden, [], "release must not contain runtime or secret material")


def test_release_refuses_a_seeded_secret_file() -> None:
    from package_release import build_release

    with temp_dir() as root:
        os.makedirs(os.path.join(root, "sources", "raw"))
        os.makedirs(os.path.join(root, "sources", "local"))
        os.makedirs(os.path.join(root, "state"))
        with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as fh:
            fh.write("mini root\n")
        with open(os.path.join(root, "AGENTS.md"), "w", encoding="utf-8") as fh:
            fh.write("mini root\n")
        with open(os.path.join(root, "sources", "raw", "capture.pcap"), "wb") as fh:
            fh.write(b"\x00\x01")
        with open(
            os.path.join(root, "sources", "local", "my-note.md"), "w", encoding="utf-8"
        ) as fh:
            fh.write("private operator note\n")
        with open(
            os.path.join(root, "state", "targets.json"), "w", encoding="utf-8"
        ) as fh:
            fh.write("{}")
        with temp_dir() as out:
            summary = build_release(out, root=root)
            names = list(_members(summary["archive"]))
            check_eq(
                [n for n in names if "raw" in n or "state" in n or "local" in n],
                [],
                "seeded runtime files must never be packaged",
            )
            check(
                any("capture.pcap" in note for note in summary["skipped"]),
                "the skipped capture must be recorded in the release notes",
            )
            notes = _read(summary["archive"], "RELEASE-NOTES.md").decode("utf-8")
        check("capture.pcap" in notes, "release notes must list skipped material")
        check("my-note.md" in notes, "operator-local notes must be listed as skipped")


def test_release_is_deterministic() -> None:
    with temp_dir() as first, temp_dir() as second:
        one = package_release.build_release(first, root=REPO_ROOT)
        two = package_release.build_release(second, root=REPO_ROOT)
        check_eq(
            one["archive_sha256"],
            two["archive_sha256"],
            "same inputs must produce the same archive bytes",
        )
        check_eq(one["archive_bytes"], two["archive_bytes"], "same archive size")


def test_tampered_archive_is_detected() -> None:
    with temp_dir() as out:
        summary = package_release.build_release(out, root=REPO_ROOT)
        good = summary["archive"]
        with tarfile.open(good, "r:gz") as tar:
            members = [
                (m, tar.extractfile(m).read() if m.isfile() else b"")
                for m in tar.getmembers()
            ]
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for member, data in members:
                if member.isfile() and member.name.endswith("README.md"):
                    data = data + b"\ntampered\n"
                if member.isfile():
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
                elif member.isdir():
                    tar.addfile(member)
        tampered = os.path.join(out, "tampered.tar.gz")
        with open(tampered, "wb") as fh:
            fh.write(gzip.compress(buffer.getvalue(), mtime=0))
        result = package_release.verify_archive(tampered)
        check_eq(result["ok"], False, "a tampered archive must not verify")
        check(
            any("hash mismatch" in problem for problem in result["problems"]),
            f"the mismatch must be named: {result['problems'][:3]}",
        )


def test_source_licenses_mirror_the_manifest() -> None:
    with temp_dir() as out:
        summary = package_release.build_release(out, root=REPO_ROOT)
        records = [
            json.loads(line)
            for line in open(summary["licenses"], encoding="utf-8").read().splitlines()
            if line
        ]
        manifest = [
            json.loads(line)
            for line in open(
                os.path.join(REPO_ROOT, "sources", "manifest.jsonl"), encoding="utf-8"
            )
            .read()
            .splitlines()
            if line
        ]
        check_eq(
            len(records), len(manifest), "one licence record per source manifest record"
        )
        sample = records[0]
        for field in (
            "source_id",
            "canonical_url",
            "license_expression",
            "redistribution",
        ):
            check_in(field, sample, "licence records need the reuse fields")
