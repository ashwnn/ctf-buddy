"""`kb show`, `kb open` and `kb export` at the CLI boundary.

These commands read the manifest and the card files directly, so every test
runs against `repo_copy()` with the working directory moved inside the copy:
nothing here writes to the real checkout.

`kb open` is specified as "print the local path of a search hit (for $EDITOR)".
The tests pin the printed path and record every browser/editor/process hook so
an unconditional launch would fail loudly instead of opening a real window.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import webbrowser
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, Iterator, List, Tuple

from helpers import check, check_eq, check_in, repo_copy, temp_dir

from ctfctl import cli, util


@contextlib.contextmanager
def _cwd(path: str) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


@contextlib.contextmanager
def _kb_repo() -> Iterator[str]:
    """A throwaway copy of kb/, sources/ and profiles/, with cwd inside it."""
    with repo_copy() as root:
        with _cwd(root):
            yield root


@contextlib.contextmanager
def _wide_help() -> Iterator[None]:
    """Force a wide formatter so help flags cannot be wrapped onto two lines."""
    previous = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "200"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = previous


@contextlib.contextmanager
def _launch_recorder() -> Iterator[List[str]]:
    """Record any browser, editor or external process launch attempt."""
    calls: List[str] = []

    def _record(name: str, *_args: Any, **_kwargs: Any) -> bool:
        calls.append(name)
        return True

    originals = {
        "webbrowser.open": webbrowser.open,
        "subprocess.Popen": subprocess.Popen,
        "os.system": os.system,
    }
    had_startfile = hasattr(os, "startfile")
    if had_startfile:
        originals["os.startfile"] = os.startfile
    webbrowser.open = lambda *a, **k: _record("webbrowser.open")  # type: ignore[assignment]
    subprocess.Popen = lambda *a, **k: _record("subprocess.Popen")  # type: ignore[assignment]
    os.system = lambda *a, **k: _record("os.system")  # type: ignore[assignment]
    if had_startfile:
        os.startfile = lambda *a, **k: _record("os.startfile")  # type: ignore[attr-defined]
    try:
        yield calls
    finally:
        webbrowser.open = originals["webbrowser.open"]  # type: ignore[assignment]
        subprocess.Popen = originals["subprocess.Popen"]  # type: ignore[assignment]
        os.system = originals["os.system"]  # type: ignore[assignment]
        if had_startfile:
            os.startfile = originals["os.startfile"]  # type: ignore[attr-defined]


def _run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _first_card(root: str) -> Dict[str, Any]:
    records = util.load_jsonl(os.path.join(root, "kb", "manifest.jsonl"))
    check(records, "the copied knowledge base must have at least one card")
    return records[0]


# --------------------------------------------------------------------------
# Parser and help wiring
# --------------------------------------------------------------------------
def test_parser_wires_show_open_and_export() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["kb", "show", "card-x"])
    check_eq(args.command, "kb", "kb must stay the top-level command")
    check_eq(args.kb_command, "show", "kb show must parse")
    check_eq(args.identifier, "card-x", "the identifier must be positional")
    check_eq(args.path_only, False, "--path-only must default off")
    args = parser.parse_args(["kb", "show", "card-x", "--path-only"])
    check_eq(args.path_only, True, "--path-only must parse")
    args = parser.parse_args(["kb", "open", "src-x"])
    check_eq(args.kb_command, "open", "kb open must parse")
    check_eq(args.identifier, "src-x", "kb open takes the identifier positionally")
    args = parser.parse_args(["kb", "export", "out"])
    check_eq(args.kb_command, "export", "kb export must parse")
    check_eq(args.directory, "out", "the destination must be positional")
    check_eq(args.shareable, False, "--shareable must default off")
    check_eq(args.json, False, "--json must default off")
    args = parser.parse_args(["kb", "export", "out", "--shareable", "--json"])
    check_eq(args.shareable, True, "--shareable must parse")
    check_eq(args.json, True, "--json must parse")


def test_show_open_and_export_help_document_their_arguments() -> None:
    for argv, needles in (
        (["kb", "show", "--help"], ["identifier", "--path-only"]),
        (["kb", "open", "--help"], ["identifier"]),
        (["kb", "export", "--help"], ["directory", "--shareable", "--json"]),
    ):
        with _wide_help():
            code, out, _err = _run_cli(argv)
        check_eq(code, 0, f"{argv} must exit 0")
        for needle in needles:
            check_in(needle, out, f"{argv} must document {needle}")


# --------------------------------------------------------------------------
# kb show / kb open
# --------------------------------------------------------------------------
def test_show_prints_the_full_card_for_a_manifest_id() -> None:
    with _kb_repo() as root:
        record = _first_card(root)
        card_id = str(record["card_id"])
        path = os.path.join(root, str(record["path"]))
        text = util.read_text(path)
        code, out, err = _run_cli(["kb", "show", card_id])
        check_eq(code, util.EXIT_OK, f"a known card must exit 0: {err}")
        check_eq(err, "", "a successful show prints nothing to stderr")
        check_eq(out.rstrip("\n"), text.rstrip("\n"), "show must print the whole card")


def test_show_path_only_and_open_print_the_resolved_path() -> None:
    with _kb_repo() as root:
        record = _first_card(root)
        card_id = str(record["card_id"])
        expected = os.path.join(root, str(record["path"]))
        code, out, err = _run_cli(["kb", "show", card_id, "--path-only"])
        check_eq(code, util.EXIT_OK, f"show --path-only must exit 0: {err}")
        check_eq(out, expected + "\n", "show --path-only prints the card path")
        code, out, err = _run_cli(["kb", "open", card_id])
        check_eq(code, util.EXIT_OK, f"kb open must exit 0: {err}")
        check_eq(out, expected + "\n", "kb open prints the same resolved path")
        check(os.path.isfile(expected), "the printed path must exist")


def test_show_accepts_a_direct_file_path() -> None:
    with _kb_repo():
        with temp_dir() as outside:
            path = os.path.join(outside, "note.md")
            util.write_text_atomic(path, "# outside card\n")
            code, out, err = _run_cli(["kb", "show", path])
            check_eq(code, util.EXIT_OK, f"an absolute path must print: {err}")
            check_in("# outside card", out, "show must print the file at that path")


def test_show_and_open_report_an_unknown_identifier() -> None:
    with _kb_repo():
        code, out, err = _run_cli(["kb", "show", "card-does-not-exist"])
        check_eq(code, util.EXIT_NEGATIVE, "an unknown card id must exit 1")
        check_eq(out, "", "a missing card prints nothing to stdout")
        check_in("no such card or path", err, "the error must name the failure")
        check_in("card-does-not-exist", err, "the error must name the identifier")
        code, _out, err = _run_cli(["kb", "open", "card-does-not-exist"])
        check_eq(code, util.EXIT_NEGATIVE, "kb open must fail the same way")
        check_in("no such card or path", err, "kb open must explain the failure")


def test_show_resolves_a_source_id_to_its_record() -> None:
    with _kb_repo() as root:
        records = util.load_jsonl(os.path.join(root, "sources", "manifest.jsonl"))
        check(records, "the copied sources manifest must not be empty")
        source_id = str(records[0]["source_id"])
        code, out, err = _run_cli(["kb", "show", source_id])
        check_eq(code, util.EXIT_OK, f"a source id must resolve: {err}")
        payload = json.loads(out)
        check_eq(payload["source_id"], source_id, "the full record must be printed")


def test_open_never_launches_a_browser_or_editor() -> None:
    with _launch_recorder() as launched:
        with _kb_repo() as root:
            record = _first_card(root)
            expected = os.path.join(root, str(record["path"]))
            code, out, err = _run_cli(["kb", "open", str(record["card_id"])])
    check_eq(code, util.EXIT_OK, f"kb open must succeed: {err}")
    check_eq(out, expected + "\n", "kb open must print exactly the card path")
    check_eq(err, "", "kb open must not warn")
    check_eq(launched, [], "kb open must never launch a browser, editor or process")


# --------------------------------------------------------------------------
# kb export
# --------------------------------------------------------------------------
def test_export_writes_the_destination_tree_and_manifest() -> None:
    with _kb_repo() as root:
        with temp_dir() as dest:
            target = os.path.join(dest, "archive")
            code, out, err = _run_cli(["kb", "export", target])
            check_eq(code, util.EXIT_OK, f"a fresh directory must export: {err}")
            check_in("exported to", out, "human output must name the destination")
            manifest = os.path.join(target, "EXPORT.json")
            check(os.path.isfile(manifest), "EXPORT.json must be written")
            payload = json.loads(util.read_text(manifest))
            check_eq(
                payload["destination"],
                os.path.abspath(target),
                "the destination must be recorded",
            )
            check_eq(payload["shareable"], False, "a plain export is not shareable")
            check_in("AGENTS.md", payload["copied"], "top-level docs are copied")
            check_in("kb/", payload["copied"], "the knowledge base tree is copied")
            check_in("profiles/", payload["copied"], "profiles travel with the corpus")
            check_eq(
                payload["excluded_snapshots"],
                [],
                "nothing is excluded by a plain export",
            )
            check(payload["note"], "the payload must explain the shareable rule")
            record = _first_card(root)
            check(
                os.path.isfile(os.path.join(target, str(record["path"]))),
                "the exported tree must contain the cards",
            )
            check(
                not os.path.exists(os.path.join(target, "state")),
                "runtime state must never be exported",
            )
            check(
                not os.path.exists(os.path.join(target, "index")),
                "the search index must never be exported",
            )


def test_export_json_matches_the_written_manifest() -> None:
    with _kb_repo():
        with temp_dir() as dest:
            target = os.path.join(dest, "archive")
            code, out, err = _run_cli(["kb", "export", target, "--json"])
            check_eq(code, util.EXIT_OK, f"--json export must succeed: {err}")
            check_eq(err, "", "machine mode must not write to stderr")
            payload = json.loads(out)
            on_disk = json.loads(util.read_text(os.path.join(target, "EXPORT.json")))
            check_eq(
                payload, on_disk, "--json must print exactly what EXPORT.json holds"
            )


def test_export_refuses_a_non_empty_destination() -> None:
    with _kb_repo():
        with temp_dir() as dest:
            occupied = os.path.join(dest, "occupied.txt")
            util.write_text_atomic(occupied, "do not clobber\n")
            code, out, err = _run_cli(["kb", "export", dest])
            check_eq(code, util.EXIT_NEGATIVE, "a non-empty directory must be refused")
            check_eq(out, "", "a refusal prints nothing to stdout")
            check_in(
                "refusing to export into a non-empty directory",
                err,
                "the reason must be explicit",
            )
            check_in(
                "choose a new directory", err, "the hint must suggest a new directory"
            )
            check_eq(
                util.read_text(occupied),
                "do not clobber\n",
                "the refusal must not touch existing files",
            )
            check(
                not os.path.exists(os.path.join(dest, "EXPORT.json")),
                "no partial export may be left behind",
            )


def test_export_refuses_an_existing_file_destination() -> None:
    with _kb_repo():
        with temp_dir() as dest:
            occupied = os.path.join(dest, "occupied.txt")
            util.write_text_atomic(occupied, "do not clobber\n")
            code, out, err = _run_cli(["kb", "export", occupied])
            check_eq(code, util.EXIT_NEGATIVE, "an existing file must be refused")
            check_eq(out, "", "a refusal prints nothing to stdout")
            check_in(
                "refusing to export into an existing file",
                err,
                "the reason must name the file destination",
            )
            check_in(occupied, err, "the refusal must name the absolute path")
            check_in(
                "choose a new directory", err, "the hint must suggest a new directory"
            )
            check_eq(
                util.read_text(occupied),
                "do not clobber\n",
                "the refusal must leave the file untouched",
            )


def test_export_json_refuses_an_existing_file_destination() -> None:
    with _kb_repo():
        with temp_dir() as dest:
            occupied = os.path.join(dest, "occupied.txt")
            util.write_text_atomic(occupied, "do not clobber\n")
            code, out, err = _run_cli(["kb", "export", occupied, "--json"])
            check_eq(code, util.EXIT_NEGATIVE, "json mode must refuse with exit 1")
            check_eq(out, "", "json mode must not print a payload on refusal")
            check_in(
                "refusing to export into an existing file",
                err,
                "json mode must keep the refusal on stderr",
            )
            check_eq(
                util.read_text(occupied),
                "do not clobber\n",
                "json mode must leave the file untouched",
            )


def test_export_accepts_an_existing_empty_destination() -> None:
    with _kb_repo():
        with temp_dir() as dest:
            empty = os.path.join(dest, "empty")
            os.makedirs(empty)
            code, out, err = _run_cli(["kb", "export", empty])
            check_eq(code, util.EXIT_OK, f"an empty existing directory is fine: {err}")
            check(
                os.path.isfile(os.path.join(empty, "EXPORT.json")),
                "EXPORT.json must be written into the empty directory",
            )


def test_export_shareable_excludes_non_redistributable_snapshots() -> None:
    with _kb_repo() as root:
        # Snapshots only appear when the sources manifest points at them, so the
        # throwaway copy gets one allowed and one denied record.
        text_dir = os.path.join(root, "sources", "text")
        os.makedirs(text_dir, exist_ok=True)
        util.write_text_atomic(os.path.join(text_dir, "allowed.txt"), "public\n")
        util.write_text_atomic(os.path.join(text_dir, "denied.txt"), "private\n")
        manifest = os.path.join(root, "sources", "manifest.jsonl")
        with open(manifest, "a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "source_id": "src-test-allowed",
                        "local_path": "sources/text/allowed.txt",
                        "redistribution": "allowed-with-attribution",
                    }
                )
                + "\n"
            )
            fh.write(
                json.dumps(
                    {
                        "source_id": "src-test-denied",
                        "local_path": "sources/text/denied.txt",
                        "redistribution": "denied",
                    }
                )
                + "\n"
            )
        with temp_dir() as dest:
            plain = os.path.join(dest, "plain")
            code, _out, err = _run_cli(["kb", "export", plain])
            check_eq(code, util.EXIT_OK, f"a plain export copies every snapshot: {err}")
            check(
                os.path.isfile(os.path.join(plain, "sources", "text", "denied.txt")),
                "a plain export keeps the denied snapshot",
            )
            shareable = os.path.join(dest, "shareable")
            code, out, err = _run_cli(
                ["kb", "export", shareable, "--shareable", "--json"]
            )
            check_eq(code, util.EXIT_OK, f"a shareable export must succeed: {err}")
            payload = json.loads(out)
            check_eq(payload["shareable"], True, "the flag must be recorded")
            check_eq(
                payload["excluded_snapshots"],
                [{"path": "sources/text/denied.txt", "redistribution": "denied"}],
                "the denied snapshot must be the only exclusion",
            )
            check(
                os.path.isfile(
                    os.path.join(shareable, "sources", "text", "allowed.txt")
                ),
                "allowed snapshots still travel",
            )
            check(
                not os.path.exists(
                    os.path.join(shareable, "sources", "text", "denied.txt")
                ),
                "denied snapshots must not be written to a shareable export",
            )
            check_in(
                "sources/text/allowed.txt",
                payload["copied"],
                "the allowed snapshot must be listed as copied",
            )
