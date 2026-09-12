"""Knowledge-base index: punctuation, deletion, missing FTS5, determinism."""

from __future__ import annotations

import os
import sqlite3

from helpers import Failure, check, check_eq, check_in, repo_copy

from ctfctl import kbindex, util

PUNCTUATION_QUERIES = [
    "../",
    "$_GET",
    "403",
    "ss -lntup",
    "python3 -m http.server 8000",
    "CVE-2024-1234",
    "Accept: */*",
    "s3cr3t{flag}",
    "a && b || c",
    "$$",
    "((((",
    'bare "quote',
    "col:on",
    "back\\slash",
    "100%",
    "^caret$",
    "NEAR(",
    "AND OR NOT",
]


def test_fts_query_construction_never_produces_invalid_syntax() -> None:
    for raw in PUNCTUATION_QUERIES:
        expression = kbindex.build_safe_match(raw, "auto")
        check(expression.startswith('"'), f"{raw!r} should be quoted: {expression!r}")
        check_eq(expression.count('"') % 2, 0, f"{raw!r} produced unbalanced quotes")


def test_quote_doubles_embedded_quotes() -> None:
    check_eq(kbindex.quote_fts5('say "hi"'), '"say ""hi"""', "quote escaping")


def test_search_survives_punctuation_queries() -> None:
    with repo_copy() as root:
        kbindex.build(root=root, rebuild=True)
        for raw in PUNCTUATION_QUERIES:
            hits = kbindex.search(raw, limit=3, root=root)
            check(isinstance(hits, list), f"{raw!r} did not return a list")


def test_literal_search_finds_code_strings() -> None:
    with repo_copy() as root:
        cards = os.path.join(root, "kb")
        target = None
        for dirpath, _dirnames, filenames in os.walk(cards):
            for name in filenames:
                if name.endswith(".md"):
                    target = os.path.join(dirpath, name)
                    break
            if target:
                break
        check(target is not None, "expected at least one card")
        with open(target, "a", encoding="utf-8") as fh:
            fh.write("\nMARKER_UNIQUE_STRING ss -lntup $_GET ../etc/passwd\n")
        hits = kbindex.literal("MARKER_UNIQUE_STRING", root=root)
        check(hits, "literal search found nothing for an inserted marker")
        check_eq(
            os.path.relpath(target, root).replace(os.sep, "/"),
            hits[0].path,
            "literal search returned the wrong path",
        )


def test_operator_local_text_is_indexed_without_a_manifest_record() -> None:
    with repo_copy() as root:
        local = os.path.join(root, "sources", "local")
        os.makedirs(local, exist_ok=True)
        with open(os.path.join(local, "my-note.md"), "w", encoding="utf-8") as fh:
            fh.write("# Operator note\n\nLOCALTERM_ONLY_HERE says hello.\n")
        kbindex.build(root=root, rebuild=True)
        hits = kbindex.search("LOCALTERM_ONLY_HERE", root=root)
        check(hits, "sources/local must be searchable without a manifest record")
        check_eq(hits[0].path, "sources/local/my-note.md", "local hit path")
        check_eq(hits[0].kind, "source", "local text is indexed as a source")
        check(hits[0].stable_id.startswith("file:"), "local docs use a file: id")
        report = kbindex.verify(root)
        check(report["ok"], f"local text must not break verify: {report['checks']}")


def test_deleted_document_is_removed_from_the_index() -> None:
    with repo_copy() as root:
        kbindex.build(root=root, rebuild=True)
        stats = kbindex.build(root=root)
        base = stats.total
        victim = None
        for dirpath, _dirnames, filenames in os.walk(os.path.join(root, "kb")):
            for name in filenames:
                if name.endswith(".md"):
                    victim = os.path.join(dirpath, name)
                    break
            if victim:
                break
        check(victim is not None, "need a card to delete")
        os.unlink(victim)
        stats = kbindex.build(root=root)
        check_eq(stats.deleted, 1, "exactly one document should be reported deleted")
        check_eq(stats.total, base - 1, "document count should drop by one")
        report = kbindex.verify(root)
        # Deleting a file that is still listed in the manifest is exactly the kind
        # of divergence verify exists to catch, so it must be reported.
        check(
            not report["ok"], "verify should flag a manifest entry whose file is gone"
        )
        check(
            any("manifest-files-exist" in err for err in report["errors"]),
            f"expected a manifest-files-exist error, got {report['errors']}",
        )
        names = [row["path"] for row in _indexed_rows(root)]
        check(
            os.path.relpath(victim, root).replace(os.sep, "/") not in names,
            "deleted file is still indexed",
        )


def _indexed_rows(root: str):
    conn = sqlite3.connect(kbindex.index_path(root))
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute("SELECT path FROM docs"))
    finally:
        conn.close()


def test_missing_fts5_still_serves_literal_results() -> None:
    from ctfctl import apply as _apply  # noqa: F401  (import cost only)

    original = kbindex._fts5_available

    def no_fts(_conn):
        return False

    kbindex._fts5_available = no_fts  # type: ignore[assignment]
    try:
        with repo_copy() as root:
            stats = kbindex.build(root=root, rebuild=True)
            check(not stats.fts5, "build should report fts5 unavailable")
            check(stats.warnings, "a warning must explain the degradation")
            hits = kbindex.search("traversal", limit=3, root=root)
            check(hits, "literal fallback should still find matches")
            check_eq(hits[0].match_kind, "literal", "fallback hits are literal matches")
    finally:
        kbindex._fts5_available = original  # type: ignore[assignment]


def test_malformed_advanced_fts_is_reported_not_raised() -> None:
    with repo_copy() as root:
        kbindex.build(root=root, rebuild=True)
        try:
            kbindex.search("NEAR(((", mode="raw", root=root)
        except util.CtfError as exc:
            check(
                "literal" in (exc.hint or ""),
                "the error should point at literal search",
            )
        except Exception as exc:  # any other exception type is a bug
            raise Failure(f"expected CtfError, got {type(exc).__name__}: {exc}")


def test_filters_narrow_results() -> None:
    with repo_copy() as root:
        kbindex.build(root=root, rebuild=True)
        stats = kbindex.stats(root)
        tag = next(iter(stats["tags"]), None)
        check(tag is not None, "corpus should have at least one tag")
        hits = kbindex.search("the", tag=tag, limit=5, root=root)
        for hit in hits:
            check(hit.kind == "card", "only cards carry tags")
        filtered = kbindex.literal("e", tag=tag, limit=5, root=root)
        check(len(filtered) <= 5, "literal limit respected")


def test_rebuild_is_deterministic() -> None:
    with repo_copy() as root:
        first = kbindex.build(root=root, rebuild=True)
        rows_one = _document_fingerprint(root)
        second = kbindex.build(root=root, rebuild=True)
        rows_two = _document_fingerprint(root)
        check_eq(
            first.total,
            second.total,
            "rebuild should index the same number of documents",
        )
        check_eq(rows_one, rows_two, "rebuild must produce identical document rows")


def _document_fingerprint(root: str):
    conn = sqlite3.connect(kbindex.index_path(root))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT rowid, stable_id, path, content_sha256 FROM docs ORDER BY rowid"
        ).fetchall()
        return [
            (r["rowid"], r["stable_id"], r["path"], r["content_sha256"]) for r in rows
        ]
    finally:
        conn.close()


def test_index_verify_detects_row_parity() -> None:
    with repo_copy() as root:
        kbindex.build(root=root, rebuild=True)
        report = kbindex.verify(root)
        check(report["ok"], f"fresh index should verify: {report['errors']}")
        conn = sqlite3.connect(kbindex.index_path(root))
        try:
            conn.execute(
                "DELETE FROM docs_fts WHERE rowid = (SELECT MIN(rowid) FROM docs_fts)"
            )
            conn.commit()
        finally:
            conn.close()
        report = kbindex.verify(root)
        check(not report["ok"], "verify must notice a docs/fts row mismatch")


def test_no_index_is_a_clear_error_with_a_hint() -> None:
    with repo_copy() as root:
        try:
            kbindex.search("anything", root=root)
        except util.CtfError as exc:
            check("index" in str(exc), "error should mention the index")
            check("kb index" in (exc.hint or ""), "hint should give the exact command")
        else:
            raise Failure("search without an index should raise CtfError")
