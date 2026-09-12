"""Bounded filesystem exploration: caps, refusals, redaction, determinism."""

from __future__ import annotations

import os

from helpers import Failure, check, check_eq, check_in, temp_dir

from ctfctl import files as files_mod


def _write(path: str, text: str = "x", binary: bool = False) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if binary:
        with open(path, "wb") as fh:
            fh.write(text.encode("latin-1"))
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def test_list_dir_bounds_and_sorts() -> None:
    with temp_dir() as root:
        for name in ("b.txt", "a.txt", "c.txt", "d.txt"):
            _write(os.path.join(root, name))
        payload = files_mod.list_dir(root, depth=1, limit=3)
        check_eq(payload["count"], 3, "the limit must bound the entry count")
        check(payload["truncated"], "the payload must say it was truncated")
        names = [e["name"] for e in payload["entries"]]
        check_eq(names, ["a.txt", "b.txt", "c.txt"], "entries must be sorted by name")
        check_eq(payload["depth"], 1, "depth must be echoed")


def test_list_dir_refuses_relative_path_and_traversal() -> None:
    for bad in ("kb", "kb/../etc", ".."):
        try:
            files_mod.list_dir(bad)
        except files_mod.FilesError:
            continue
        raise Failure(f"list_dir must refuse non-absolute path {bad!r}")


def test_validate_path_keeps_posix_paths_verbatim() -> None:
    # Windows reports os.path.isabs("/etc") as False; remote paths must still
    # pass, and must not be rewritten with backslashes.
    for path in ("/etc", "/var/www", "/opt/app/app.py"):
        check_eq(
            files_mod.validate_path(path),
            path,
            f"POSIX absolute path must pass verbatim: {path}",
        )
    resolved = files_mod.resolve_local_path("kb")
    check(
        os.path.isabs(resolved), "local relative path must resolve to an absolute path"
    )
    check_eq(
        files_mod.validate_path(resolved), resolved, "resolved local path must validate"
    )


def test_find_files_respects_glob_and_depth() -> None:
    with temp_dir() as root:
        _write(os.path.join(root, "a.py"))
        _write(os.path.join(root, "b.txt"))
        _write(os.path.join(root, "sub", "c.py"))
        _write(os.path.join(root, "sub", "deep", "d.py"))
        payload = files_mod.find_files(root, name="*.py", max_depth=2)
        found = sorted(m["name"] for m in payload["matches"])
        check_eq(found, ["a.py", "c.py"], "max_depth must stop before sub/deep")
        payload = files_mod.find_files(root, name="*.py", max_depth=4)
        found = sorted(m["name"] for m in payload["matches"])
        check_eq(found, ["a.py", "c.py", "d.py"], "a deeper search should find d.py")


def test_read_refuses_secret_looking_names() -> None:
    with temp_dir() as root:
        secret = os.path.join(root, "id_rsa")
        _write(secret, "-----BEGIN OPENSSH PRIVATE KEY-----\nsecrets\n")
        payload = files_mod.read_file(secret)
        check_eq(payload["readable"], False, "a private key must never be printed")
        check_in("secret", payload["reason"].lower(), "the reason must say why")
        check_eq(payload["content"], None, "no content may be returned")


def test_read_reports_binary_without_printing_bytes() -> None:
    with temp_dir() as root:
        blob = os.path.join(root, "blob.bin")
        _write(blob, "\x00\x01\x02binary", binary=True)
        payload = files_mod.read_file(blob)
        check_eq(payload["readable"], False, "binary files are metadata only")
        check_in("binary", payload["reason"].lower(), "the reason must say binary")
        check_eq(payload["content"], None, "no content may be returned")


def test_read_redacts_secret_assignments() -> None:
    with temp_dir() as root:
        cfg = os.path.join(root, "app.conf")
        _write(cfg, "user = admin\npassword = hunter2\nport = 8080\n")
        payload = files_mod.read_file(cfg)
        check_eq(payload["readable"], True, "a text config should be readable")
        text = payload["content"]
        check("hunter2" not in text, "the secret value must not survive redaction")
        check("<REDACTED>" in text, "the redaction marker must be present")
        check_in("port = 8080", text, "non-secret values must be preserved")


def test_read_truncates_to_the_requested_cap() -> None:
    with temp_dir() as root:
        big = os.path.join(root, "big.txt")
        _write(big, "A" * 5000)
        payload = files_mod.read_file(big, max_bytes=1000)
        check(payload["truncated"], "the payload must report truncation")
        check(len(payload["content"]) <= 1000, "content must respect max_bytes")
        check_eq(payload["size"], 5000, "the real size must still be reported")


def test_read_refuses_a_directory() -> None:
    with temp_dir() as root:
        _write(os.path.join(root, "sub", "a.txt"))
        payload = files_mod.read_file(os.path.join(root, "sub"))
        check_eq(payload["readable"], False, "a directory is not a readable file")
        check_in("directory", payload["reason"].lower(), payload["reason"])


def test_read_does_not_follow_secret_symlink_target() -> None:
    with temp_dir() as root:
        secret = os.path.join(root, "real_secret.pem")
        _write(secret, "PRIVATE MATERIAL\n")
        link = os.path.join(root, "innocent.txt")
        try:
            os.symlink(secret, link)
        except (OSError, NotImplementedError):
            return  # symlink creation is not always permitted; nothing to test
        payload = files_mod.read_file(link)
        check_eq(
            payload["readable"], False, "the resolved secret name must refuse the read"
        )
        check_eq(
            payload["content"], None, "no content may be returned for a secret target"
        )
