"""`ctfctl challenge init`: workspace layout, id validation and containment.

The handler resolves the work root from `util.repo_root()`, which walks up from
the current working directory looking for `AGENTS.md`, so every test runs with
the process cwd inside a throwaway repository root and never touches the real
checkout.

Containment cases need a directory symlink or a Windows junction. At import the
module probes both mechanisms; if neither works on this host the whole module
records `SKIP`/`SKIP_REASON` so the runner counts the skip instead of reporting
a pass with zero containment coverage. A case-level probe still prints a
`SKIP` line and returns if a link cannot be created at that specific path.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from typing import Iterator, List, Optional, Tuple

from helpers import check, check_eq, check_in, temp_dir

from ctfctl import challenge as challenge_mod
from ctfctl import cli, util

#: The complete workspace tree, sorted, exactly as `challenge init` builds it.
EXPECTED_TREE = ["evidence", "files", "flags.txt", "notes.md", "prompt.md", "solve.py"]

#: Files that must exist directly under the workspace root.
WORKSPACE_FILES = ("prompt.md", "notes.md", "solve.py", "flags.txt")

#: Every id shape the CLI must refuse with a usage error (exit 2).
INVALID_IDS = (
    "",
    "..",
    "a/b",
    "a\\b",
    "C:x",
    "con",
    "nul.txt",
    "com7",
    "lpt9.bin",
    "caf\u00e9",  # non-ASCII letters must be refused: the id regex is ASCII-only
    "UPPER",
    "-x",
    ".",
    "a.",
    "a ",
)


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
@contextlib.contextmanager
def _cwd(path: str) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


@contextlib.contextmanager
def _repo() -> Iterator[str]:
    """A minimal throwaway repository root (AGENTS.md only), cwd inside it."""
    with temp_dir("ctfctl-challenge-") as root:
        with open(os.path.join(root, "AGENTS.md"), "w", encoding="utf-8") as handle:
            handle.write("test root\n")
        with _cwd(root):
            yield root


def _run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def _without_debug_escape() -> Iterator[None]:
    """Keep unexpected exceptions on the exit 3 path, not the re-raise path."""
    previous = os.environ.pop("CTFCTL_DEBUG", None)
    try:
        yield
    finally:
        if previous is not None:
            os.environ["CTFCTL_DEBUG"] = previous


def _skip(reason: str) -> None:
    """Record a per-case skip in the runner output (the suite has no skip API)."""
    print(f"  SKIP  {reason}")


# --------------------------------------------------------------------------
# Directory links: symlink when permitted, otherwise a Windows junction
# --------------------------------------------------------------------------
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
        ["cmd", "/c", "mklink", "/J", link, target],
        capture_output=True,
        text=True,
    )
    if created.returncode == 0:
        return None
    detail = (created.stderr or created.stdout).strip() or f"exit {created.returncode}"
    return (
        f"cannot create a symlink ({symlink_error}) or junction ({detail}); "
        "the host forbids both"
    )


def _make_dangling_link(link: str) -> Optional[str]:
    """Create a directory link and remove its target so the link dangles."""
    target = link + "-removed-target"
    os.makedirs(target)
    reason = _make_dir_link(target, link)
    try:
        os.rmdir(target)
    except OSError as exc:
        if reason is None:
            return f"cannot remove the link target to make the link dangle: {exc}"
    return reason


def _remove_link(link: str) -> None:
    """Remove a symlink or junction without following it into the target.

    POSIX removes a symlink with unlink (rmdir fails with ENOTDIR), while
    Windows removes a directory symlink or junction with rmdir. Try unlink
    first, then rmdir, so cleanup is honest on both platforms.
    """
    for remover in (os.unlink, os.rmdir):
        try:
            remover(link)
            return
        except OSError:
            continue


def _link_support_reason() -> Optional[str]:
    """None when a directory symlink or junction can be created, else why not."""
    with temp_dir("ctfctl-linkprobe-") as probe:
        target = os.path.join(probe, "target")
        link = os.path.join(probe, "link")
        os.makedirs(target)
        try:
            return _make_dir_link(target, link)
        finally:
            _remove_link(link)


#: Set when neither `os.symlink` nor `mklink /J` works on this host. Without a
#: single working link mechanism every containment case below would skip and the
#: module would still report PASS with zero containment coverage, so the whole
#: module is skipped with an explicit recorded reason instead.
SKIP = False
SKIP_REASON = ""

_LINK_FAILURE = _link_support_reason()
if _LINK_FAILURE is not None:
    SKIP = True
    SKIP_REASON = (
        "no directory symlink or junction can be created on this host "
        f"({_LINK_FAILURE}); the containment cases would have zero coverage"
    )


@contextlib.contextmanager
def _fail_writes_after(successful_writes: int) -> Iterator[None]:
    """Let the first N stub writes succeed, then raise like a full disk."""
    original = challenge_mod._write_new_file
    calls = {"done": 0}

    def flaky(path: str, text: str) -> None:
        calls["done"] += 1
        if calls["done"] > successful_writes:
            raise OSError("simulated write failure")
        original(path, text)

    challenge_mod._write_new_file = flaky  # type: ignore[method-assign]
    try:
        yield
    finally:
        challenge_mod._write_new_file = original  # type: ignore[method-assign]


# --------------------------------------------------------------------------
# Valid creation
# --------------------------------------------------------------------------
def test_init_creates_the_exact_workspace_tree() -> None:
    with _repo() as root:
        code, out, err = _run_cli(["challenge", "init", "sample-web"])
        check_eq(code, util.EXIT_OK, f"a valid id must exit 0: {err}")
        check_eq(err, "", "a successful init prints nothing to stderr")
        workspace = os.path.join(root, "work", "sample-web")
        check_eq(
            sorted(os.listdir(workspace)),
            EXPECTED_TREE,
            "the workspace tree must be exactly the fixed layout",
        )
        for name in WORKSPACE_FILES:
            path = os.path.join(workspace, name)
            check(os.path.isfile(path), f"{name} must be a regular file")
            check(os.path.getsize(path) > 0, f"{name} must not be empty")
        for name in ("files", "evidence"):
            check(
                os.path.isdir(os.path.join(workspace, name)),
                f"{name}/ must be a directory",
            )
        prompt = util.read_text(os.path.join(workspace, "prompt.md"))
        check_in("# Challenge: sample-web", prompt, "the prompt stub names the id")
        check_in(
            "created workspace work/sample-web",
            out,
            "human output must name the workspace",
        )
        check_in(workspace, out, "human output must print the workspace path")


def test_init_json_reports_the_workspace_layout() -> None:
    with _repo() as root:
        code, out, err = _run_cli(["challenge", "init", "js-01", "--json"])
        check_eq(code, util.EXIT_OK, f"a json init must exit 0: {err}")
        check_eq(err, "", "a json success writes nothing to stderr")
        check(out.lstrip().startswith("{"), "stdout must hold only the JSON document")
        payload = json.loads(out)
        work_root = os.path.join(root, "work")
        workspace = os.path.join(work_root, "js-01")
        check_eq(payload["id"], "js-01", "id must round-trip")
        check_eq(payload["created"], True, "created must be true")
        check_eq(payload["work_root"], work_root, "work_root must be the repo work/")
        check_eq(payload["workspace"], workspace, "workspace must sit under work/")
        check_eq(
            sorted(payload["paths"]),
            ["evidence", "files", "flags", "notes", "prompt", "solve"],
            "paths must name the whole layout",
        )
        for key, path in payload["paths"].items():
            check(os.path.exists(path), f"paths[{key}] must exist: {path}")
        check_eq(
            payload["paths"]["prompt"],
            os.path.join(workspace, "prompt.md"),
            "the prompt path must be exact",
        )


# --------------------------------------------------------------------------
# Refusals: existing destinations
# --------------------------------------------------------------------------
def test_duplicate_init_refuses_and_preserves_sentinel() -> None:
    with _repo() as root:
        code, _out, err = _run_cli(["challenge", "init", "dup-01"])
        check_eq(code, util.EXIT_OK, f"the first init must succeed: {err}")
        workspace = os.path.join(root, "work", "dup-01")
        sentinel = "SENTINEL: do not clobber\n"
        notes = os.path.join(workspace, "notes.md")
        util.write_text_atomic(notes, sentinel)
        code, out, err = _run_cli(["challenge", "init", "dup-01", "--json"])
        check_eq(code, util.EXIT_NEGATIVE, f"a duplicate id must exit 1: {err}")
        payload = json.loads(out)
        check_eq(payload["created"], False, "a refusal must report created:false")
        check_eq(payload["reason"], "exists", "a duplicate must report reason 'exists'")
        check_in("error", payload, "a refusal must carry an error message")
        check_eq(
            util.read_text(notes), sentinel, "the sentinel must not be overwritten"
        )
        check_eq(
            sorted(os.listdir(workspace)),
            EXPECTED_TREE,
            "a refused init must not add or remove entries",
        )


def test_existing_file_at_the_destination_is_refused() -> None:
    with _repo() as root:
        work = os.path.join(root, "work")
        os.makedirs(work)
        target = os.path.join(work, "occupied")
        util.write_text_atomic(target, "keep me\n")
        code, out, err = _run_cli(["challenge", "init", "occupied", "--json"])
        check_eq(code, util.EXIT_NEGATIVE, f"an existing file must exit 1: {err}")
        payload = json.loads(out)
        check_eq(payload["created"], False, "created must be false")
        check_eq(payload["reason"], "exists", "reason must be 'exists'")
        check_eq(
            util.read_text(target), "keep me\n", "the file must not be overwritten"
        )
        check_eq(sorted(os.listdir(work)), ["occupied"], "no extra entries may appear")


def test_dangling_link_at_the_destination_is_refused() -> None:
    with _repo() as root:
        work = os.path.join(root, "work")
        os.makedirs(work)
        link = os.path.join(work, "ghost")
        reason = _make_dangling_link(link)
        if reason is not None:
            _skip(f"dangling destination link: {reason}")
            return
        try:
            check(os.path.lexists(link), "the dangling link must still exist")
            code, out, err = _run_cli(["challenge", "init", "ghost", "--json"])
            check_eq(code, util.EXIT_NEGATIVE, f"a dangling link must exit 1: {err}")
            payload = json.loads(out)
            check_eq(payload["created"], False, "created must be false")
            check_in("error", payload, "the refusal must carry an error message")
            check(not os.path.isdir(link), "no directory may be created over the link")
            check(
                not os.path.lexists(link + "-removed-target"),
                "nothing may be created at the removed link target",
            )
        finally:
            _remove_link(link)


# --------------------------------------------------------------------------
# Invalid ids
# --------------------------------------------------------------------------
def test_invalid_ids_are_usage_errors_and_create_nothing() -> None:
    with _repo() as root:
        work = os.path.join(root, "work")
        for challenge_id in INVALID_IDS:
            code, out, err = _run_cli(["challenge", "init", challenge_id])
            check_eq(
                code, util.EXIT_USAGE, f"{challenge_id!r} must be a usage error: {err}"
            )
            check_eq(out, "", f"{challenge_id!r} must not print a success payload")
            check(err.strip(), f"{challenge_id!r} must explain the refusal")
            check(not os.path.lexists(work), f"{challenge_id!r} must not create work/")


def test_id_length_and_punctuation_boundaries() -> None:
    with _repo() as root:
        longest = "a" * 64
        code, _out, err = _run_cli(["challenge", "init", longest])
        check_eq(code, util.EXIT_OK, f"64 characters must be accepted: {err}")
        code, out, err = _run_cli(["challenge", "init", "a" * 65])
        check_eq(code, util.EXIT_USAGE, "65 characters must be refused")
        check_eq(out, "", "a refused id must not print a success payload")
        code, _out, err = _run_cli(["challenge", "init", "a.b_c-9"])
        check_eq(code, util.EXIT_OK, f"dot, underscore and dash are allowed: {err}")
        code, _out, err = _run_cli(["challenge", "init", "nulx"])
        check_eq(code, util.EXIT_OK, f"a device-name prefix is not reserved: {err}")
        check_eq(
            sorted(os.listdir(os.path.join(root, "work"))),
            sorted([longest, "a.b_c-9", "nulx"]),
            "only the accepted ids may exist",
        )


# --------------------------------------------------------------------------
# Containment: links may not redirect a write outside work/
# --------------------------------------------------------------------------
def test_link_at_the_destination_cannot_escape_work() -> None:
    with temp_dir("ctfctl-outside-") as outside:
        with _repo() as root:
            sentinel = os.path.join(outside, "keep.txt")
            util.write_text_atomic(sentinel, "outside sentinel\n")
            work = os.path.join(root, "work")
            os.makedirs(work)
            link = os.path.join(work, "esc")
            reason = _make_dir_link(outside, link)
            if reason is not None:
                _skip(f"destination escape link: {reason}")
                return
            try:
                check(
                    challenge_mod._is_linklike(os.lstat(link)),
                    "the fixture link must be detected as linklike, or this case "
                    "can pass on the generic containment refusal alone",
                )
                code, out, err = _run_cli(["challenge", "init", "esc", "--json"])
                check_eq(code, util.EXIT_NEGATIVE, f"an escape link must exit 1: {err}")
                payload = json.loads(out)
                check_eq(payload["created"], False, "created must be false")
                check_eq(
                    payload["workspace"],
                    link,
                    "the refusal must name the link as the workspace",
                )
                check_in(
                    "refusing to follow a symlink or junction component",
                    payload["error"],
                    "the refusal must be link-aware, not generic containment",
                )
                check_in(link, payload["error"], "the refusal must name the link")
                check_eq(
                    sorted(os.listdir(outside)),
                    ["keep.txt"],
                    "the link target must gain no entries",
                )
                check_eq(
                    util.read_text(sentinel),
                    "outside sentinel\n",
                    "the link target sentinel must be untouched",
                )
            finally:
                _remove_link(link)


def test_link_as_work_root_is_refused() -> None:
    with temp_dir("ctfctl-outside-") as outside:
        with _repo() as root:
            sentinel = os.path.join(outside, "keep.txt")
            util.write_text_atomic(sentinel, "outside sentinel\n")
            work = os.path.join(root, "work")
            reason = _make_dir_link(outside, work)
            if reason is not None:
                _skip(f"work root link: {reason}")
                return
            try:
                check(
                    challenge_mod._is_linklike(os.lstat(work)),
                    "the linked work root must be detected as linklike",
                )
                code, out, err = _run_cli(["challenge", "init", "probe", "--json"])
                check_eq(code, util.EXIT_NEGATIVE, f"a linked work/ must exit 1: {err}")
                payload = json.loads(out)
                check_eq(payload["created"], False, "created must be false")
                check_in(
                    "refusing to follow a symlink or junction component",
                    payload["error"],
                    "the refusal must be link-aware, not the work-root shape check",
                )
                check_eq(
                    sorted(os.listdir(outside)),
                    ["keep.txt"],
                    "the linked work root target must gain no entries",
                )
                check_eq(
                    util.read_text(sentinel),
                    "outside sentinel\n",
                    "the linked work root sentinel must be untouched",
                )
            finally:
                _remove_link(work)


# --------------------------------------------------------------------------
# Rollback
# --------------------------------------------------------------------------
def test_failed_init_rolls_back_everything_it_created() -> None:
    with _repo() as root:
        with _without_debug_escape():
            with _fail_writes_after(1):
                code, _out, err = _run_cli(["challenge", "init", "rolled-back"])
        check_eq(code, util.EXIT_INTERNAL, f"a write failure must exit 3: {err}")
        check_in("internal error", err, "the failure must be reported")
        check(
            not os.path.lexists(os.path.join(root, "work")),
            "work/ must be removed when this init created it",
        )


def test_failed_init_preserves_pre_existing_work_content() -> None:
    with _repo() as root:
        work = os.path.join(root, "work")
        os.makedirs(work)
        sentinel = os.path.join(work, "keep.txt")
        util.write_text_atomic(sentinel, "keep me\n")
        with _without_debug_escape():
            with _fail_writes_after(2):
                code, _out, err = _run_cli(["challenge", "init", "partial"])
        check_eq(code, util.EXIT_INTERNAL, f"a write failure must exit 3: {err}")
        check_eq(
            sorted(os.listdir(work)),
            ["keep.txt"],
            "only pre-existing content may remain",
        )
        check_eq(util.read_text(sentinel), "keep me\n", "the sentinel must survive")
        check(
            not os.path.lexists(os.path.join(work, "partial")),
            "the partial workspace directory must be gone",
        )
