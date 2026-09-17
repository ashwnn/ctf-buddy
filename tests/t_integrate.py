"""Corpus integration: card merge skips, conflicts, problems, idempotence, dry runs."""

from __future__ import annotations

import io
import os
from contextlib import contextmanager, redirect_stdout
from typing import Any, Dict, Iterator, List, Optional, Sequence

from helpers import REPO_ROOT, check, check_eq, check_in, temp_dir

from ctfctl import integrate, util

WORKER = "manifest.worker.jsonl"


# --------------------------------------------------------------------------
# Fixture helpers
# --------------------------------------------------------------------------
def _card(card_id: str, **fields: Any) -> Dict[str, Any]:
    """A minimal card manifest record, shaped like a real kb/ entry."""
    record: Dict[str, Any] = {
        "card_id": card_id,
        "path": f"kb/topic/{card_id}.md",
        "title": card_id,
        "summary": f"summary for {card_id}",
        "source_ids": [],
    }
    record.update(fields)
    return record


def _fixture(
    root: str,
    baseline: Sequence[Dict[str, Any]],
    staged: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    cards: Sequence[str] = (),
) -> None:
    """Lay out kb/manifest.jsonl, an optional staged manifest, and card .md files."""
    kb_dir = os.path.join(root, "kb")
    os.makedirs(kb_dir, exist_ok=True)
    util.write_text_atomic(
        os.path.join(kb_dir, "manifest.jsonl"), util.dump_jsonl(baseline)
    )
    if staged is not None:
        util.write_text_atomic(os.path.join(kb_dir, WORKER), util.dump_jsonl(staged))
    for card_id in cards:
        card_path = os.path.join(kb_dir, "topic", f"{card_id}.md")
        util.write_text_atomic(card_path, f"# {card_id}\n")
    # main() resolves the repo root by walking up for AGENTS.md.
    util.write_text_atomic(os.path.join(root, "AGENTS.md"), "test root\n")


def _live_manifest(root: str) -> str:
    return os.path.join(root, "kb", "manifest.jsonl")


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _snapshot(root: str) -> Dict[str, bytes]:
    files: Dict[str, bytes] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            files[rel] = _read_bytes(path)
    return files


@contextmanager
def _cwd(path: str) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


# --------------------------------------------------------------------------
# merge_cards
# --------------------------------------------------------------------------
def test_merge_cards_skips_identical_records() -> None:
    with temp_dir() as root:
        _fixture(root, [_card("card-a")], [_card("card-a")], cards=["card-a"])
        records, report = integrate.merge_cards(root)
        check_eq(report["skipped"], ["card-a"], "an identical staged card is skipped")
        check_eq(report["conflicts"], [], "identical cards are never conflicts")
        check_eq(report["added"], [], "an identical staged card adds nothing")
        check_eq(report["problems"], [], "a complete fixture has no problems")
        check_eq(report["merged"], 1, "one merged card")
        check_eq(
            [r["card_id"] for r in records], ["card-a"], "the baseline record survives"
        )


def test_merge_cards_normalises_defaults_before_comparing() -> None:
    with temp_dir() as root:
        staged = [
            _card(
                "card-a",
                content_origin="original-summary",
                evidence_status="source-supported but untested",
            )
        ]
        _fixture(root, [_card("card-a")], staged, cards=["card-a"])
        _records, report = integrate.merge_cards(root)
        check_eq(
            report["skipped"], ["card-a"], "implicit defaults must not read as a change"
        )
        check_eq(report["conflicts"], [], "default-filled records are identical")


def test_merge_cards_reports_field_level_conflict_and_keeps_baseline() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a")],
            [_card("card-a", title="renamed")],
            cards=["card-a"],
        )
        records, report = integrate.merge_cards(root)
        check_eq(len(report["conflicts"]), 1, "one differing field is one conflict")
        conflict = report["conflicts"][0]
        check_eq(conflict["card_id"], "card-a", "the conflict names the card")
        check_eq(conflict["fragment"], WORKER, "the conflict names the staged file")
        check_eq(
            conflict["existing_source"],
            "manifest.jsonl",
            "the conflict names the baseline file",
        )
        check_eq(
            set(conflict["fields"]), {"title"}, "only the changed field is reported"
        )
        check_eq(conflict["fields"]["title"]["existing"], "card-a", "baseline value")
        check_eq(conflict["fields"]["title"]["fragment"], "renamed", "fragment value")
        check_eq(report["skipped"], [], "a conflict is not a skip")
        check_eq(report["added"], [], "a conflict is not an add")
        check_eq(records[0]["title"], "card-a", "the baseline record wins")


def test_merge_cards_adds_new_cards() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a")],
            [_card("card-a"), _card("card-b")],
            cards=["card-a", "card-b"],
        )
        records, report = integrate.merge_cards(root)
        check_eq(
            report["added"],
            ["card-b"],
            "a staged card absent from the baseline is added",
        )
        check_eq(report["merged"], 2, "baseline plus one addition")
        check_eq(
            [r["card_id"] for r in records],
            ["card-a", "card-b"],
            "baseline order is kept, additions appended",
        )


def test_merge_cards_reports_missing_markdown() -> None:
    with temp_dir() as root:
        _fixture(root, [_card("card-live")], [_card("card-ghost")])
        records, report = integrate.merge_cards(root)
        check_eq(len(report["problems"]), 2, "both missing files are problems")
        check(
            any("card-live: file missing" in p for p in report["problems"]),
            f"the live card problem must name the file: {report['problems']}",
        )
        check(
            any("card-ghost: file missing" in p for p in report["problems"]),
            f"the staged card problem must name the file: {report['problems']}",
        )
        check_eq(report["added"], [], "a card without a file is never added")
        check_eq(report["conflicts"], [], "a missing file is a problem, not a conflict")
        check_eq(
            [r["card_id"] for r in records],
            ["card-live"],
            "an existing baseline record stays in the merged view",
        )


def test_merge_cards_reports_duplicate_and_unidentified_records() -> None:
    with temp_dir() as root:
        staged = [
            {"title": "no id", "path": "kb/topic/none.md"},
            _card("card-dup"),
            _card("card-dup"),
        ]
        _fixture(root, [], staged, cards=["card-dup"])
        records, report = integrate.merge_cards(root)
        check_eq(report["added"], ["card-dup"], "the first occurrence is added once")
        check_eq(len(report["problems"]), 2, "one problem per bad record")
        check(
            any("without card_id" in p for p in report["problems"]),
            f"a record without card_id must be reported: {report['problems']}",
        )
        check(
            any("duplicate card_id card-dup" in p for p in report["problems"]),
            f"a duplicated card_id must be reported: {report['problems']}",
        )
        check_eq([r["card_id"] for r in records], ["card-dup"], "only one copy merges")


def test_merge_cards_never_writes_any_file() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a"), _card("card-conflict")],
            [_card("card-a"), _card("card-b"), _card("card-conflict", summary="other")],
            cards=["card-a", "card-b", "card-conflict"],
        )
        before = _snapshot(root)
        _records, report = integrate.merge_cards(root)
        check(report["added"], "the fixture must exercise the add path")
        check(report["conflicts"], "the fixture must exercise the conflict path")
        check_eq(_snapshot(root), before, "merge_cards must be read-only")


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------
def test_run_write_is_idempotent() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a")],
            [_card("card-a"), _card("card-b")],
            cards=["card-a", "card-b"],
        )
        live = _live_manifest(root)
        first = integrate.run(root, online=False, check_cards=False, write=True)
        check_eq(
            first["cards"]["added"], ["card-b"], "the first write adds the staged card"
        )
        written = _read_bytes(live)
        ids = sorted(record["card_id"] for record in util.load_jsonl(live))
        check_eq(ids, ["card-a", "card-b"], "the written manifest holds both cards")

        second = integrate.run(root, online=False, check_cards=False, write=True)
        check_eq(second["cards"]["added"], [], "the second write adds nothing")
        check_eq(second["cards"]["conflicts"], [], "the second write has no conflicts")
        check_eq(second["cards"]["problems"], [], "the second write has no problems")
        check_eq(
            second["cards"]["skipped"],
            ["card-a", "card-b"],
            "both cards are unchanged on the second pass",
        )
        check_eq(_read_bytes(live), written, "the second write must be byte-identical")


def test_run_is_a_dry_run_without_write() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a")],
            [_card("card-a"), _card("card-b")],
            cards=["card-a", "card-b"],
        )
        before = _snapshot(root)
        report = integrate.run(root, online=False, check_cards=False)
        check_eq(report["write"], False, "run must default to a dry run")
        check_eq(
            report["cards"]["added"],
            ["card-b"],
            "the dry run still reports the pending addition",
        )
        check_eq(_snapshot(root), before, "a dry run must not touch any file")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def test_main_is_dry_run_by_default_then_writes_with_opt_in() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a")],
            [_card("card-a"), _card("card-b")],
            cards=["card-a", "card-b"],
        )
        live = _live_manifest(root)
        before = _read_bytes(live)
        out = io.StringIO()
        with _cwd(root), redirect_stdout(out):
            code = integrate.main(["--offline"])
        check_eq(code, util.EXIT_OK, "a clean merge exits zero")
        check_eq(_read_bytes(live), before, "main without --write must not write")
        check_in(
            "dry run", out.getvalue(), "the human report must say it was a dry run"
        )

        with _cwd(root), redirect_stdout(io.StringIO()):
            code = integrate.main(["--offline", "--write"])
        check_eq(code, util.EXIT_OK, "the writing run exits zero")
        written = _read_bytes(live)
        check(written != before, "the --write run must replace the manifest")
        ids = sorted(record["card_id"] for record in util.load_jsonl(live))
        check_eq(ids, ["card-a", "card-b"], "the written manifest holds both cards")

        with _cwd(root), redirect_stdout(io.StringIO()):
            code = integrate.main(["--offline", "--write"])
        check_eq(code, util.EXIT_OK, "the repeated writing run exits zero")
        check_eq(_read_bytes(live), written, "a repeated --write must change nothing")


def test_main_exits_one_on_conflicts_and_stays_read_only() -> None:
    with temp_dir() as root:
        _fixture(
            root,
            [_card("card-a")],
            [_card("card-a", title="renamed")],
            cards=["card-a"],
        )
        live = _live_manifest(root)
        before = _read_bytes(live)
        out = io.StringIO()
        with _cwd(root), redirect_stdout(out):
            code = integrate.main(["--offline"])
        check_eq(code, util.EXIT_NEGATIVE, "a conflict must exit 1")
        check_eq(_read_bytes(live), before, "the conflict dry run must not write")
        check_in(
            "CONFLICT card-a",
            out.getvalue(),
            "the report must name the conflicting card",
        )


# --------------------------------------------------------------------------
# Shipped corpus regression (read-only)
# --------------------------------------------------------------------------
def test_shipped_corpus_merges_cleanly_and_read_only() -> None:
    live = os.path.join(REPO_ROOT, "kb", "manifest.jsonl")
    before = _read_bytes(live)
    _records, report = integrate.merge_cards(REPO_ROOT)
    check_eq(
        report["conflicts"],
        [],
        "the shipped corpus must not have pending staged conflicts",
    )
    check_eq(
        report["problems"], [], "the shipped corpus must not have missing card files"
    )
    check_eq(
        _read_bytes(live), before, "merge_cards must never touch the real manifest"
    )
