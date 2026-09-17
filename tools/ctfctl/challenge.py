"""Isolated per-challenge workspaces under `work/<challenge-id>/`.

`ctfctl challenge init <id>` creates one fixed layout - prompt.md, files/,
notes.md, solve.py, evidence/ and flags.txt - and refuses to reuse an id that
already exists. The destination is always a direct child of the repository
`work/` root and no component between that root and the destination is ever
followed through a symlink or Windows junction, so a hostile id or a planted
link cannot redirect a write outside `work/`.

Nothing here touches the network, executes ingested input, or stores secrets.
The workspace is runtime state: `work/` is git-ignored and excluded from
release packaging.
"""

from __future__ import annotations

import os
import re
import stat
from typing import Any, Dict, List, Optional, Tuple

from . import util

WORK_DIRNAME = "work"
PROMPT_NAME = "prompt.md"
NOTES_NAME = "notes.md"
SOLVE_NAME = "solve.py"
FLAGS_NAME = "flags.txt"
FILES_DIRNAME = "files"
EVIDENCE_DIRNAME = "evidence"

#: Directories created directly below the workspace root, in creation order.
SUBDIR_NAMES: Tuple[str, ...] = (FILES_DIRNAME, EVIDENCE_DIRNAME)

#: Files created directly below the workspace root, in creation order.
WORKSPACE_FILES: Tuple[str, ...] = (PROMPT_NAME, NOTES_NAME, SOLVE_NAME, FLAGS_NAME)

#: Evidence vocabulary shared with the knowledge-base card template.
EVIDENCE_LABELS: Tuple[str, ...] = (
    "reproduced locally",
    "source-supported but untested",
    "version-sensitive",
    "unresolved",
)

#: Conservative id shape: one lowercase path component, 1-64 characters.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

#: Windows reserves these device names in every directory, extension or not.
_RESERVED_WINDOWS_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)

#: Windows reparse tags that redirect one directory to another. Junctions are
#: not reported by S_ISLNK, so they are refused by tag as well.
_LINK_REPARSE_TAGS = frozenset(
    tag
    for tag in (
        getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0),
        getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0),
    )
    if tag
)


class ChallengeError(util.CtfError):
    """Expected negative result: the workspace was refused (exit 1)."""

    def __init__(
        self,
        message: str,
        *,
        hint: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, hint=hint)
        self.payload: Dict[str, Any] = dict(payload or {})


class ChallengeIdError(util.UsageError):
    """Unsafe or malformed challenge id (exit 2)."""


class WorkspaceExistsError(ChallengeError):
    """The destination already exists as a file, directory or symlink."""


def validate_id(challenge_id: str) -> str:
    """Return a safe workspace id, or raise ChallengeIdError (exit 2).

    An id is a single lowercase path component. Everything that could be
    ambiguous to a shell, a Windows API or a path resolver is refused rather
    than repaired: separators, drive or UNC forms, traversal, control bytes,
    leading dashes, trailing dot or space, and reserved device names.
    """
    if not challenge_id:
        raise ChallengeIdError(
            "a challenge id is required",
            hint="example: ctfctl challenge init sample-web",
        )
    if any(char in challenge_id for char in ("\x00", "\n", "\r")):
        raise ChallengeIdError("challenge id must not contain control characters")
    if ".." in challenge_id:
        raise ChallengeIdError(f"challenge id must not contain '..': {challenge_id!r}")
    if challenge_id.startswith("-"):
        raise ChallengeIdError(
            f"challenge id must not start with a dash: {challenge_id!r}"
        )
    if "/" in challenge_id or "\\" in challenge_id:
        raise ChallengeIdError(
            f"challenge id must not contain a path separator: {challenge_id!r}"
        )
    if ":" in challenge_id:
        raise ChallengeIdError(
            "challenge id must not contain a drive or device separator: "
            f"{challenge_id!r}"
        )
    if challenge_id != challenge_id.rstrip(". "):
        raise ChallengeIdError(
            f"challenge id must not end with a dot or space: {challenge_id!r}"
        )
    if not _ID_RE.match(challenge_id):
        raise ChallengeIdError(
            f"unsafe challenge id {challenge_id!r}: use 1-64 characters from "
            "a-z, 0-9, dot, underscore or dash, starting with a letter or digit"
        )
    if challenge_id.split(".", 1)[0] in _RESERVED_WINDOWS_NAMES:
        raise ChallengeIdError(
            f"challenge id {challenge_id!r} is a reserved Windows device name"
        )
    return challenge_id


def init_workspace(challenge_id: str, root: Optional[str] = None) -> Dict[str, Any]:
    """Create one isolated workspace and return its machine-readable summary.

    Raises ChallengeIdError (exit 2) for an unsafe id, and ChallengeError
    (exit 1) when the destination exists, a path component is a symlink, or
    creation fails and is rolled back. `root` defaults to the repository root
    and exists so tests and drills can use a throwaway tree.
    """
    validate_id(challenge_id)
    repo, work_root, destination = _resolve_paths(challenge_id, root)
    payload = _payload(challenge_id, work_root, destination)
    _reject_symlinked_component(repo, destination, payload)
    real_work_root = _assert_contained(work_root, destination, payload)
    if os.path.lexists(destination):
        raise _exists_error(destination, payload)

    created_root = False
    destination_identity: Optional[Tuple[int, int]] = None
    created_dirs: List[str] = []
    created_files: List[str] = []
    try:
        created_root = _ensure_work_root(work_root, payload)
        try:
            os.mkdir(destination, 0o700)
        except FileExistsError:
            raise _exists_error(destination, payload) from None
        # Capture the fresh directory's identity before anything can replace
        # it; rollback refuses to act without a matching lstat.
        destination_identity = _destination_identity(destination, payload)
        # TOCTOU: the checks above ran before mkdir. Re-resolve the path now,
        # before the first write, and refuse if a component was swapped.
        _recheck_containment(destination, real_work_root, payload)
        for name in SUBDIR_NAMES:
            path = os.path.join(destination, name)
            os.mkdir(path, 0o700)
            created_dirs.append(path)
        for name, text in _stub_contents(challenge_id).items():
            path = os.path.join(destination, name)
            _write_new_file(path, text)
            created_files.append(path)
    except BaseException:
        _rollback(
            destination,
            work_root,
            created_root=created_root,
            destination_identity=destination_identity,
            created_dirs=created_dirs,
            created_files=created_files,
        )
        raise
    return {**payload, "created": True}


#: Short alias for the `challenge init` handler and drill snippets.
init = init_workspace


def _resolve_paths(challenge_id: str, root: Optional[str]) -> Tuple[str, str, str]:
    repo = os.path.abspath(root or util.repo_root())
    work_root = os.path.join(repo, WORK_DIRNAME)
    destination = os.path.join(work_root, challenge_id)
    # Lexical containment: the validated id is a single component, so the
    # destination can only ever be a direct child of work/.
    if (
        os.path.dirname(destination) != work_root
        or os.path.basename(destination) != challenge_id
    ):
        raise ChallengeIdError(
            f"challenge id must be a single path component: {challenge_id!r}"
        )
    return repo, work_root, destination


def _payload(challenge_id: str, work_root: str, destination: str) -> Dict[str, Any]:
    return {
        "id": challenge_id,
        "workspace": destination,
        "work_root": work_root,
        "paths": {
            "prompt": os.path.join(destination, PROMPT_NAME),
            "files": os.path.join(destination, FILES_DIRNAME),
            "notes": os.path.join(destination, NOTES_NAME),
            "solve": os.path.join(destination, SOLVE_NAME),
            "evidence": os.path.join(destination, EVIDENCE_DIRNAME),
            "flags": os.path.join(destination, FLAGS_NAME),
        },
    }


def _is_linklike(info: os.stat_result) -> bool:
    """True for a symlink, and for a Windows junction or mount point."""
    if stat.S_ISLNK(info.st_mode):
        return True
    tag = getattr(info, "st_reparse_tag", 0)
    return bool(tag) and tag in _LINK_REPARSE_TAGS


def _refuse(message: str, payload: Dict[str, Any], *, hint: str = "") -> None:
    raise ChallengeError(message, hint=hint, payload={**payload, "created": False})


def _exists_error(destination: str, payload: Dict[str, Any]) -> WorkspaceExistsError:
    return WorkspaceExistsError(
        f"workspace already exists: {destination}",
        hint="pick a new challenge id, or move the existing workspace first",
        payload={
            **payload,
            "created": False,
            "reason": "exists",
        },
    )


def _reject_symlinked_component(
    repo: str, destination: str, payload: Dict[str, Any]
) -> None:
    """Refuse a symlink anywhere between the repo root and the destination.

    Every component is inspected with lstat and never followed, so even a link
    that resolves back inside the repository is refused instead of trusted.
    The repository root itself is the caller-provided starting point.
    """
    relative = os.path.relpath(destination, repo)
    current = repo
    for part in relative.split(os.sep):
        if not part or part in (".", os.pardir):
            _refuse(
                f"refusing an unsafe path below the repository root: {destination}",
                payload,
            )
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _refuse(f"cannot inspect {current}: {exc}", payload)
        if _is_linklike(info):
            _refuse(
                f"refusing to follow a symlink or junction component: {current}",
                payload,
                hint="work/ and every component below it must be real directories",
            )


def _assert_contained(work_root: str, destination: str, payload: Dict[str, Any]) -> str:
    """Second containment check on fully resolved paths (defense in depth).

    Returns the resolved work root so the post-mkdir recheck can compare the
    destination against the exact root validated here.
    """
    real_work = os.path.realpath(work_root)
    real_destination = os.path.realpath(destination)
    if not _is_strictly_inside(real_work, real_destination):
        _refuse(
            f"workspace path is not strictly inside {work_root}: {destination}",
            payload,
        )
    return real_work


def _is_strictly_inside(parent: str, child: str) -> bool:
    """True when child is below parent, with both already resolved."""
    try:
        common = os.path.commonpath([parent, child])
    except ValueError:
        return False
    return common == parent and child != parent


def _destination_identity(destination: str, payload: Dict[str, Any]) -> Tuple[int, int]:
    """Capture (st_dev, st_ino) of the directory this run just created.

    The leaf is inspected with lstat only. Rollback acts on this directory
    only while a fresh lstat still matches, so a concurrent swap for a link or
    another directory leaves the replacement untouched.
    """
    try:
        info = os.lstat(destination)
    except OSError as exc:
        _refuse(f"cannot inspect the new workspace {destination}: {exc}", payload)
    if _is_linklike(info) or not stat.S_ISDIR(info.st_mode):
        _refuse(
            f"the new workspace is not a real directory: {destination}",
            payload,
            hint="another process may have replaced it; inspect work/ manually",
        )
    return (info.st_dev, info.st_ino)


def _recheck_containment(
    destination: str, real_work_root: str, payload: Dict[str, Any]
) -> None:
    """Re-resolve the destination after mkdir and before the first write.

    The pre-flight checks ran before mkdir; a swap in between could redirect
    the writes. The leaf is inspected with lstat and never followed, then the
    path is re-resolved and required to stay strictly inside the real work
    root that the earlier check validated.
    """
    try:
        info = os.lstat(destination)
    except OSError as exc:
        _refuse(f"cannot inspect the new workspace {destination}: {exc}", payload)
    if _is_linklike(info) or not stat.S_ISDIR(info.st_mode):
        _refuse(
            "workspace changed after creation and is no longer a real "
            f"directory: {destination}",
            payload,
            hint="refusing to write through a replaced work/ component",
        )
    real_destination = os.path.realpath(destination)
    if not _is_strictly_inside(real_work_root, real_destination):
        _refuse(
            "workspace resolves outside the validated work root: "
            f"{destination} -> {real_destination}",
            payload,
        )


def _ensure_work_root(work_root: str, payload: Dict[str, Any]) -> bool:
    """Create work/ if needed; return True only if this call created it."""
    try:
        os.mkdir(work_root, 0o700)
        return True
    except FileExistsError:
        pass
    try:
        info = os.lstat(work_root)
    except OSError as exc:
        _refuse(f"cannot inspect work root {work_root}: {exc}", payload)
    if _is_linklike(info) or not stat.S_ISDIR(info.st_mode):
        _refuse(
            f"refusing a work root that is not a real directory: {work_root}",
            payload,
            hint="replace work/ with a real directory inside the repository",
        )
    return False


def _write_new_file(path: str, text: str) -> None:
    """Create a file exclusively (O_EXCL semantics); never overwrite."""
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def _rollback(
    destination: str,
    work_root: str,
    *,
    created_root: bool,
    destination_identity: Optional[Tuple[int, int]],
    created_dirs: List[str],
    created_files: List[str],
) -> None:
    """Remove only what this invocation created, and only while it is ours.

    The destination is re-inspected with lstat and must still be the same
    (st_dev, st_ino) real directory captured right after mkdir; anything else
    is left in place and reported. Then only tracked files are unlinked, only
    tracked directories are removed (deepest first, via rmdir, which refuses a
    non-empty directory), and work/ is removed only when this run created it
    and it is empty. Untracked entries are never touched.
    """
    if destination_identity is not None:
        if _owns_destination(destination, destination_identity):
            for path in created_files:
                _quiet_unlink(path)
            for path in sorted(created_dirs, key=_path_depth, reverse=True):
                _quiet_rmdir(path)
            _quiet_rmdir(destination)
        else:
            util.eprint(
                f"challenge: {destination} is no longer the directory this run "
                "created; leaving it and its contents in place for inspection"
            )
    if created_root:
        _quiet_rmdir(work_root)


def _owns_destination(destination: str, identity: Tuple[int, int]) -> bool:
    """True when a fresh lstat shows the same real directory as after mkdir."""
    try:
        info = os.lstat(destination)
    except OSError:
        return False
    if _is_linklike(info) or not stat.S_ISDIR(info.st_mode):
        return False
    return (info.st_dev, info.st_ino) == identity


def _path_depth(path: str) -> int:
    """Component count, for removing tracked directories deepest first."""
    return len(os.path.normpath(path).split(os.sep))


def _quiet_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _quiet_rmdir(path: str) -> None:
    try:
        os.rmdir(path)
    except OSError:
        pass


def _stub_contents(challenge_id: str) -> Dict[str, str]:
    return {
        PROMPT_NAME: _prompt_stub(challenge_id),
        NOTES_NAME: _notes_stub(challenge_id),
        SOLVE_NAME: _solve_stub(challenge_id),
        FLAGS_NAME: _flags_stub(),
    }


def _prompt_stub(challenge_id: str) -> str:
    return (
        f"# Challenge: {challenge_id}\n"
        "\n"
        "## Prompt\n"
        "\n"
        "Paste the challenge prompt verbatim, plus where it came from.\n"
        "\n"
        "## Provided material\n"
        "\n"
        "Distributed files live in files/ unchanged. Record their sha256 in\n"
        "notes.md before opening them.\n"
        "\n"
        "## Access\n"
        "\n"
        "URLs, ports and placeholders the challenge provides. Never paste real\n"
        "team credentials here.\n"
    )


def _notes_stub(challenge_id: str) -> str:
    return (
        f"# Notes: {challenge_id}\n"
        "\n"
        "One entry per observation: the command, the raw result, and what it\n"
        "means. Label every entry with one of: " + " | ".join(EVIDENCE_LABELS) + ".\n"
        "\n"
        "## Observations\n"
        "\n"
        "- [reproduced locally] `<command>` -> `<observed result>`\n"
        "\n"
        "## Hypotheses\n"
        "\n"
        "- (add the next testable guess here)\n"
        "\n"
        "## Next actions\n"
        "\n"
        "- (add the next command here)\n"
    )


def _solve_stub(challenge_id: str) -> str:
    return (
        f'"""Solver stub for challenge {challenge_id}.\n'
        "\n"
        "Local files only: no network, no execution of ingested input, no\n"
        "secrets in this file. Write derived artifacts under evidence/ and keep\n"
        "the commands that produced them in notes.md.\n"
        '"""\n'
        "\n"
        "from __future__ import annotations\n"
        "\n"
        "\n"
        "def main() -> int:\n"
        '    """Run the solver. Replace this stub with the real workflow."""\n'
        f'    print("challenge {challenge_id}: no solver implemented yet")\n'
        "    return 0\n"
        "\n"
        "\n"
        'if __name__ == "__main__":\n'
        "    raise SystemExit(main())\n"
    )


def _flags_stub() -> str:
    return (
        "# One candidate flag per line. work/ is git-ignored; never commit a\n"
        "# live flag.\n"
    )
