"""Knowledge-base index: SQLite FTS5 search with a literal ripgrep fallback.

Guarantees this module is responsible for:

  * punctuation-heavy queries never become malformed FTS5 expressions;
  * a literal/code search path that is exact and always available;
  * deterministic rebuilds (same inputs -> same index bytes);
  * detection of added, changed and deleted documents;
  * useful snippets plus the local file path for every hit;
  * the corpus stays readable as Markdown when no index exists at all.

Schema follows docs/architecture notes: a plain FTS5 table plus relational
metadata, with docs_fts.rowid == docs.rowid. The index is a pure cache of
files plus manifests and can always be rebuilt from scratch.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import util

SCHEMA_VERSION = 2
INDEX_REL = os.path.join("index", "kb.sqlite3")
CARD_ROOT_REL = "kb"
SOURCE_TEXT_ROOT_REL = os.path.join("sources", "text")
#: Operator-provided text, indexed locally and never packaged (git-ignored).
LOCAL_TEXT_ROOT_REL = os.path.join("sources", "local")
DEFAULT_EXTENSIONS = (".md", ".markdown", ".txt", ".rst")

# Minimum query length before we bother with a search.
MIN_QUERY_LEN = 1
MAX_QUERY_LEN = 400
DEFAULT_LIMIT = 10
MAX_LIMIT = 200


# --------------------------------------------------------------------------
# FTS query construction
# --------------------------------------------------------------------------
def quote_fts5(value: str) -> str:
    """Wrap arbitrary text as one FTS5 string literal (safe punctuation)."""
    return '"' + value.replace('"', '""') + '"'


def query_terms(raw: str) -> List[str]:
    """Split user input into search terms, preserving code-ish tokens."""
    terms = [t for t in re.split(r"\s+", raw.strip()) if t]
    return terms


def build_safe_match(raw: str, mode: str = "auto") -> str:
    """Convert arbitrary user input into a *valid* FTS5 MATCH expression.

    auto     -- each term quoted and AND-ed; a term keeps internal punctuation
                as one phrase, which is the least surprising behaviour for
                strings like '../etc/passwd', '$_GET' and 'ss -lntup'.
    phrase   -- the whole input as one phrase.
    any      -- OR of the quoted terms, for recall.
    """
    raw = raw.strip()
    if not raw:
        raise util.UsageError("empty query")
    if len(raw) > MAX_QUERY_LEN:
        raise util.UsageError(
            f"query too long ({len(raw)} > {MAX_QUERY_LEN} characters)"
        )
    if mode == "phrase":
        return quote_fts5(raw)
    terms = query_terms(raw)
    if not terms:
        raise util.UsageError("empty query")
    if mode == "any":
        return " OR ".join(quote_fts5(t) for t in terms)
    return " AND ".join(quote_fts5(t) for t in terms)


def is_literalish(raw: str) -> bool:
    """Heuristic: queries that are really code/error strings, not prose."""
    if re.search(r"[\\/{}<>$;|&()`\"'\[\]*~^]", raw):
        return True
    if re.search(r"\b\d{3}\b", raw) and len(raw.split()) <= 3:
        return True
    return len(raw.split()) == 1 and not raw.isalpha()


# --------------------------------------------------------------------------
# Document discovery
# --------------------------------------------------------------------------
@dataclass
class Doc:
    stable_id: str
    kind: str  # 'card' | 'source'
    path: str  # repo-relative, forward slashes
    title: str
    body: str
    aliases: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    stacks: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)

    @property
    def fts_text(self) -> str:
        return self.body


def _rel(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def title_from_markdown(text: str, fallback: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
        if line.startswith("## "):
            return line[3:].strip()
    return fallback


def load_cards(
    root: str, manifest_path: str, *, max_bytes: int = 512 * 1024
) -> List[Doc]:
    """Load card files. Manifest metadata is optional enrichment, not a gate."""
    manifest: Dict[str, Dict[str, Any]] = {}
    for record in util.load_jsonl(manifest_path):
        path = record.get("path")
        if path:
            manifest[str(path).replace(os.sep, "/")] = record
    docs: List[Doc] = []
    card_root = os.path.join(root, CARD_ROOT_REL)
    for path in util.iter_files(card_root, extensions=DEFAULT_EXTENSIONS):
        rel = _rel(path, root)
        try:
            body = util.read_text(path, max_bytes)
        except util.CtfError:
            continue
        record = manifest.get(rel, {})
        title = str(
            record.get("title") or title_from_markdown(body, os.path.basename(path))
        )
        docs.append(
            Doc(
                stable_id=str(record.get("card_id") or f"file:{rel}"),
                kind="card",
                path=rel,
                title=title,
                body=body,
                aliases=[str(a) for a in record.get("aliases", []) or []],
                tags=[str(t).lower() for t in record.get("tags", []) or []],
                stacks=[str(s).lower() for s in record.get("stacks", []) or []],
                source_ids=[str(s) for s in record.get("source_ids", []) or []],
            )
        )
    return docs


def load_sources(
    root: str, manifest_path: str, *, max_bytes: int = 2 * 1024 * 1024
) -> List[Doc]:
    """Load locally stored snapshots and operator notes (opt-in, licence-gated).

    Two roots are indexed, both git-ignored and both excluded from release
    archives:

    * `sources/text/` — licence-gated snapshots, matched to a manifest record by
      `local_path`;
    * `sources/local/` — the operator's own text, indexed with no manifest
      requirement so a note can be dropped in and searched immediately.

    Neither root is ever packaged: unknown licence is not permission to
    redistribute, and local notes are not part of the distributed corpus.
    """
    docs: List[Doc] = []
    records = {
        r.get("source_id"): r
        for r in util.load_jsonl(manifest_path)
        if r.get("source_id")
    }
    roots = (
        (SOURCE_TEXT_ROOT_REL, False),
        (LOCAL_TEXT_ROOT_REL, True),
    )
    for root_rel, operator_local in roots:
        text_root = os.path.join(root, root_rel)
        if not os.path.isdir(text_root):
            continue
        for path in util.iter_files(text_root, extensions=DEFAULT_EXTENSIONS):
            rel = _rel(path, root)
            record = None
            if not operator_local:
                for rec in records.values():
                    if (
                        rec.get("local_path")
                        and str(rec["local_path"]).replace(os.sep, "/") == rel
                    ):
                        record = rec
                        break
            try:
                body = util.read_text(path, max_bytes)
            except util.CtfError:
                continue
            title = str(
                (record or {}).get("title")
                or title_from_markdown(body, os.path.basename(path))
            )
            tags = [str((record or {}).get("source_type") or "").lower()]
            tags = [tag for tag in tags if tag]
            if operator_local:
                tags.append("local")
            source_id = str((record or {}).get("source_id") or "")
            docs.append(
                Doc(
                    stable_id=source_id or f"file:{rel}",
                    kind="source",
                    path=rel,
                    title=title,
                    body=body,
                    aliases=[str((record or {}).get("author") or "")],
                    tags=tags,
                    stacks=[],
                    source_ids=[source_id] if source_id else [],
                )
            )
    return docs


def collect_docs(root: Optional[str] = None) -> List[Doc]:
    root = root or util.repo_root()
    docs = load_cards(root, os.path.join(root, "kb", "manifest.jsonl"))
    docs += load_sources(root, os.path.join(root, "sources", "manifest.jsonl"))
    docs.sort(key=lambda d: (d.kind, d.stable_id))
    return docs


# --------------------------------------------------------------------------
# Index build
# --------------------------------------------------------------------------
DDL = """
PRAGMA foreign_keys = ON;
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE docs (
    rowid INTEGER PRIMARY KEY,
    stable_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('card','source')),
    path TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    indexed_at TEXT NOT NULL
);
CREATE TABLE doc_tags (
    doc_rowid INTEGER NOT NULL REFERENCES docs(rowid) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (doc_rowid, tag)
);
CREATE TABLE doc_stacks (
    doc_rowid INTEGER NOT NULL REFERENCES docs(rowid) ON DELETE CASCADE,
    stack TEXT NOT NULL,
    PRIMARY KEY (doc_rowid, stack)
);
CREATE VIRTUAL TABLE docs_fts USING fts5(
    title, aliases, body, tokenize='unicode61 remove_diacritics 2'
);
CREATE INDEX idx_docs_stable ON docs(stable_id);
"""


@dataclass
class IndexStats:
    added: int = 0
    updated: int = 0
    deleted: int = 0
    unchanged: int = 0
    total: int = 0
    mode: str = "incremental"
    fts5: bool = True
    warnings: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "added": self.added,
            "updated": self.updated,
            "deleted": self.deleted,
            "unchanged": self.unchanged,
            "total": self.total,
            "fts5": self.fts5,
            "warnings": self.warnings,
        }


def index_path(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), INDEX_REL)


def _connect(path: str, *, create: bool = False) -> sqlite3.Connection:
    if create:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Take manual control of transactions: the index build needs an explicit
    # BEGIN IMMEDIATE and must never rely on the driver's implicit transactions.
    conn.isolation_level = None
    return conn


def _fts5_available(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE temp.fts_probe USING fts5(x)")
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        try:
            conn.execute("DROP TABLE IF EXISTS temp.fts_probe")
        except sqlite3.Error:
            pass


def _insert_doc(
    conn: sqlite3.Connection,
    doc: Doc,
    sha: str,
    mtime_ns: int,
    size: int,
    use_fts: bool,
) -> int:
    cur = conn.execute(
        "INSERT INTO docs (stable_id, kind, path, title, content_sha256, mtime_ns,"
        " size_bytes, indexed_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            doc.stable_id,
            doc.kind,
            doc.path,
            doc.title,
            sha,
            mtime_ns,
            size,
            util.iso_now(),
        ),
    )
    rowid = int(cur.lastrowid)
    if use_fts:
        conn.execute(
            "INSERT INTO docs_fts (rowid, title, aliases, body) VALUES (?,?,?,?)",
            (rowid, doc.title, " ".join(doc.aliases), doc.fts_text),
        )
    for tag in sorted(set(doc.tags)):
        conn.execute(
            "INSERT OR IGNORE INTO doc_tags (doc_rowid, tag) VALUES (?,?)", (rowid, tag)
        )
    for stack in sorted(set(doc.stacks)):
        conn.execute(
            "INSERT OR IGNORE INTO doc_stacks (doc_rowid, stack) VALUES (?,?)",
            (rowid, stack),
        )
    return rowid


def _update_doc(
    conn: sqlite3.Connection,
    rowid: int,
    doc: Doc,
    sha: str,
    mtime_ns: int,
    size: int,
    use_fts: bool,
) -> None:
    conn.execute(
        "UPDATE docs SET stable_id=?, kind=?, path=?, title=?, content_sha256=?, mtime_ns=?,"
        " size_bytes=?, indexed_at=? WHERE rowid=?",
        (
            doc.stable_id,
            doc.kind,
            doc.path,
            doc.title,
            sha,
            mtime_ns,
            size,
            util.iso_now(),
            rowid,
        ),
    )
    if use_fts:
        conn.execute("DELETE FROM docs_fts WHERE rowid = ?", (rowid,))
        conn.execute(
            "INSERT INTO docs_fts (rowid, title, aliases, body) VALUES (?,?,?,?)",
            (rowid, doc.title, " ".join(doc.aliases), doc.fts_text),
        )
    conn.execute("DELETE FROM doc_tags WHERE doc_rowid = ?", (rowid,))
    conn.execute("DELETE FROM doc_stacks WHERE doc_rowid = ?", (rowid,))
    for tag in sorted(set(doc.tags)):
        conn.execute(
            "INSERT OR IGNORE INTO doc_tags (doc_rowid, tag) VALUES (?,?)", (rowid, tag)
        )
    for stack in sorted(set(doc.stacks)):
        conn.execute(
            "INSERT OR IGNORE INTO doc_stacks (doc_rowid, stack) VALUES (?,?)",
            (rowid, stack),
        )


def build(
    root: Optional[str] = None,
    *,
    rebuild: bool = False,
    docs: Optional[List[Doc]] = None,
    target: Optional[str] = None,
) -> IndexStats:
    """Incrementally (or fully) rebuild the index. Deterministic when rebuilding."""
    root = root or util.repo_root()
    path = target or index_path(root)
    docs = docs if docs is not None else collect_docs(root)
    stats = IndexStats(mode="rebuild" if rebuild else "incremental")

    if rebuild and os.path.exists(path):
        os.unlink(path)
    replacing = rebuild or not os.path.exists(path)
    work_path = path + ".new" if replacing else path
    if replacing and os.path.exists(work_path):
        # Stale temp file from an interrupted rebuild.
        os.unlink(work_path)

    conn = _connect(work_path, create=True)
    try:
        if replacing:
            conn.executescript(DDL)
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        else:
            # Existing index: verify schema before mutating.
            try:
                version = conn.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()
                if not version or int(version[0]) != SCHEMA_VERSION:
                    raise sqlite3.DatabaseError("schema version mismatch")
            except sqlite3.DatabaseError:
                util.eprint("index schema mismatch: performing a full rebuild")
                conn.close()
                if os.path.exists(work_path):
                    os.unlink(work_path)
                return build(root, rebuild=True, docs=docs, target=target)

        use_fts = _fts5_available(conn)
        stats.fts5 = use_fts
        if not use_fts:
            stats.warnings.append(
                "SQLite FTS5 is unavailable: ranked search is disabled and every query "
                "falls back to literal substring matching. Rebuild-safe, but slower."
            )
        conn.execute("BEGIN IMMEDIATE")

        existing: Dict[str, Tuple[int, str, int, int]] = {}
        for row in conn.execute(
            "SELECT rowid, stable_id, content_sha256, mtime_ns, size_bytes FROM docs"
        ):
            existing[row["stable_id"]] = (
                row["rowid"],
                row["content_sha256"],
                row["mtime_ns"],
                row["size_bytes"],
            )

        seen: set = set()
        for doc in docs:
            abs_path = os.path.join(root, doc.path)
            try:
                st = os.stat(abs_path)
            except OSError:
                continue
            seen.add(doc.stable_id)
            prior = existing.get(doc.stable_id)
            if prior and prior[2] == st.st_mtime_ns and prior[3] == st.st_size:
                stats.unchanged += 1
                continue
            sha = util.sha256_text(
                doc.title
                + "\x00"
                + doc.body
                + "\x00"
                + "\x00".join(doc.aliases)
                + "\x00"
                + "\x00".join(sorted(doc.tags))
            )
            if prior and prior[1] == sha and prior[2] == st.st_mtime_ns:
                stats.unchanged += 1
                continue
            if prior:
                _update_doc(
                    conn, prior[0], doc, sha, st.st_mtime_ns, st.st_size, use_fts
                )
                stats.updated += 1
            else:
                _insert_doc(conn, doc, sha, st.st_mtime_ns, st.st_size, use_fts)
                stats.added += 1

        for stable_id, (rowid, _sha, _mtime, _size) in existing.items():
            if stable_id not in seen:
                if use_fts:
                    conn.execute("DELETE FROM docs_fts WHERE rowid = ?", (rowid,))
                conn.execute("DELETE FROM docs WHERE rowid = ?", (rowid,))
                stats.deleted += 1

        count = conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('doc_count', ?)",
            (str(count),),
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('built_at', ?)",
            (util.iso_now(),),
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('fts5', ?)",
            ("1" if use_fts else "0"),
        )
        conn.commit()
        stats.total = int(count)
    except Exception:
        conn.rollback()
        conn.close()
        if replacing and os.path.exists(work_path):
            os.unlink(work_path)
        raise
    else:
        conn.close()
        if replacing:
            os.replace(work_path, path)
    return stats


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------
@dataclass
class Hit:
    stable_id: str
    kind: str
    path: str
    title: str
    score: float
    snippet: str
    line: Optional[int] = None
    column: Optional[int] = None
    match_kind: str = "ranked"

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "id": self.stable_id,
            "kind": self.kind,
            "path": self.path,
            "title": self.title,
            "score": round(self.score, 4),
            "snippet": self.snippet,
            "match": self.match_kind,
        }
        if self.line is not None:
            out["line"] = self.line
        return out


def _fts_filter_sql(tag: Optional[str], stack: Optional[str]) -> Tuple[str, List[Any]]:
    sql = ""
    params: List[Any] = []
    if tag:
        sql += " AND EXISTS (SELECT 1 FROM doc_tags t WHERE t.doc_rowid = d.rowid AND t.tag = ?)"
        params.append(tag.lower())
    if stack:
        sql += (
            " AND EXISTS (SELECT 1 FROM doc_stacks s WHERE s.doc_rowid = d.rowid"
            " AND s.stack = ?)"
        )
        params.append(stack.lower())
    return sql, params


def search(
    raw: str,
    *,
    mode: str = "auto",
    tag: Optional[str] = None,
    stack: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    kind: Optional[str] = None,
    root: Optional[str] = None,
) -> List[Hit]:
    """Ranked FTS5 search, degrading to literal search when FTS5 is missing."""
    limit = max(1, min(int(limit), MAX_LIMIT))
    root = root or util.repo_root()
    path = index_path(root)
    if not os.path.exists(path):
        raise util.CtfError(
            "no search index yet",
            hint="run: ctfctl kb index   (or use: ctfctl kb literal <text>)",
        )
    conn = _connect(path)
    try:
        use_fts = bool(
            conn.execute("SELECT value FROM meta WHERE key='fts5'").fetchone()
        )
        use_fts = use_fts and _fts5_available(conn)
        if not use_fts:
            return _py_literal_search(
                raw, tag=tag, stack=stack, limit=limit, kind=kind, root=root
            )
        match = build_safe_match(raw, mode)
        sql = (
            "SELECT d.stable_id, d.kind, d.path, d.title,"
            " bm25(docs_fts, 8.0, 5.0, 1.0) AS score,"
            " snippet(docs_fts, 2, '[[', ']]', ' ... ', 22) AS snippet"
            " FROM docs_fts JOIN docs d ON d.rowid = docs_fts.rowid"
            " WHERE docs_fts MATCH ?"
        )
        params: List[Any] = [match]
        if kind:
            sql += " AND d.kind = ?"
            params.append(kind)
        extra, extra_params = _fts_filter_sql(tag, stack)
        sql += extra
        params.extend(extra_params)
        sql += " ORDER BY score ASC, d.stable_id ASC LIMIT ?"
        params.append(limit)
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            raise util.CtfError(
                f"FTS5 rejected the query: {exc}",
                hint=f"try: ctfctl kb literal {json.dumps(raw)}",
            ) from exc
        hits = [
            Hit(
                stable_id=row["stable_id"],
                kind=row["kind"],
                path=row["path"],
                title=row["title"],
                score=float(row["score"]),
                snippet=_clean_snippet(row["snippet"] or ""),
            )
            for row in rows
        ]
        if not hits:
            hits = _py_literal_search(
                raw, tag=tag, stack=stack, limit=limit, kind=kind, root=root
            )
        return hits
    finally:
        conn.close()


def by_tag(tag: str, *, limit: int = 20, kind: Optional[str] = None,
           root: Optional[str] = None) -> List[Hit]:
    """List every indexed document carrying a tag, best-ranked first by title.

    Used by `ctfctl kb cheat` to enumerate quick-reference cards without a query.
    """
    limit = max(1, min(int(limit), MAX_LIMIT))
    root = root or util.repo_root()
    path = index_path(root)
    if not os.path.exists(path):
        raise util.CtfError(
            "no search index yet",
            hint="run: ctfctl kb index",
        )
    conn = _connect(path)
    try:
        sql = (
            "SELECT d.stable_id, d.kind, d.path, d.title"
            " FROM docs d JOIN doc_tags t ON t.doc_rowid = d.rowid"
            " WHERE t.tag = ?"
        )
        params: List[Any] = [tag.lower()]
        if kind:
            sql += " AND d.kind = ?"
            params.append(kind)
        sql += " ORDER BY d.title ASC, d.stable_id ASC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [
            Hit(stable_id=row["stable_id"], kind=row["kind"], path=row["path"],
                title=row["title"], score=0.0, snippet="")
            for row in rows
        ]
    finally:
        conn.close()


def _clean_snippet(text: str) -> str:
    text = re.sub(r"\s+", " ", text)
    return util.printable(text.strip(), 400)


def _resolve_missed_paths(
    root: str, tag: Optional[str], stack: Optional[str], kind: Optional[str]
) -> List[str]:
    """When FTS misses, allow literal search to find paths/tags/aliases."""
    if not tag and not stack and not kind:
        return []
    cards = load_cards(root, os.path.join(root, "kb", "manifest.jsonl"))
    out: List[str] = []
    for doc in cards:
        if kind and doc.kind != kind:
            continue
        if tag and tag.lower() not in doc.tags:
            continue
        if stack and stack.lower() not in doc.stacks:
            continue
        out.append(doc.path)
    return out


def literal(
    pattern: str,
    *,
    tag: Optional[str] = None,
    stack: Optional[str] = None,
    limit: int = 40,
    kind: Optional[str] = None,
    root: Optional[str] = None,
    fixed: bool = True,
) -> List[Hit]:
    """Exact substring (or regex) search over card text. Always available."""
    root = root or util.repo_root()
    if not pattern:
        raise util.UsageError("empty literal pattern")
    if len(pattern) > MAX_QUERY_LEN:
        raise util.UsageError("literal pattern too long")
    limit = max(1, min(int(limit), MAX_LIMIT))
    allowed: Optional[set] = None
    if tag or stack or kind:
        allowed = set(_resolve_missed_paths(root, tag, stack, kind))
    rg = util.which("rg")
    if rg:
        hits = _rg_literal(rg, pattern, root=root, limit=limit, fixed=fixed)
    else:
        hits = _py_literal_search(
            pattern,
            tag=tag,
            stack=stack,
            limit=limit,
            kind=kind,
            root=root,
            fixed=fixed,
        )
    if allowed is not None:
        hits = [h for h in hits if h.path in allowed]
    return hits[:limit]


def _rg_literal(
    rg: str, pattern: str, *, root: str, limit: int, fixed: bool
) -> List[Hit]:
    roots = [
        os.path.join(root, CARD_ROOT_REL),
        os.path.join(root, SOURCE_TEXT_ROOT_REL),
    ]
    roots = [r for r in roots if os.path.isdir(r)]
    if not roots:
        return []
    argv = [
        rg,
        "--no-config",
        "--json",
        "--sort",
        "path",
        "--line-number",
        "--max-count",
        "5",
        "--max-filesize",
        "4M",
    ]
    if not fixed:
        argv.append("--")
    if fixed:
        argv += ["-F"]
    argv += ["--", pattern] + roots
    res = util.run(argv, timeout=30, max_output=8 * 1024 * 1024)
    hits: List[Hit] = []
    if res.unavailable:
        return _py_literal_search(
            pattern, tag=None, stack=None, limit=limit, root=root, fixed=fixed
        )
    for line in res.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("type") != "match":
            continue
        data = record.get("data", {})
        rel_path = _rel(data.get("path", {}).get("text", ""), root)
        line_no = data.get("line_number")
        text = data.get("lines", {}).get("text", "")
        hits.append(
            Hit(
                stable_id=f"file:{rel_path}",
                kind="card" if rel_path.startswith("kb/") else "source",
                path=rel_path,
                title="",
                score=0.0,
                snippet=util.printable(text.strip(), 300),
                line=line_no,
                match_kind="literal",
            )
        )
        if len(hits) >= limit:
            break
    return hits


def _py_literal_search(
    pattern: str,
    *,
    tag: Optional[str],
    stack: Optional[str],
    limit: int,
    kind: Optional[str],
    root: str,
    fixed: bool = True,
) -> List[Hit]:
    """Pure-Python fallback: used when ripgrep is absent or FTS5 is missing."""
    docs = load_cards(root, os.path.join(root, "kb", "manifest.jsonl"))
    docs += load_sources(root, os.path.join(root, "sources", "manifest.jsonl"))
    matcher = None
    if not fixed:
        try:
            matcher = re.compile(pattern)
        except re.error as exc:
            raise util.UsageError(f"invalid regex: {exc}") from exc
    needle = pattern if fixed else None
    hits: List[Hit] = []
    for doc in docs:
        if kind and doc.kind != kind:
            continue
        if tag and tag.lower() not in doc.tags:
            continue
        if stack and stack.lower() not in doc.stacks:
            continue
        for line_no, line in enumerate(doc.body.splitlines(), 1):
            found = (
                (needle in line) if fixed else bool(matcher and matcher.search(line))
            )
            if not found:
                continue
            hits.append(
                Hit(
                    stable_id=doc.stable_id,
                    kind=doc.kind,
                    path=doc.path,
                    title=doc.title,
                    score=0.0,
                    snippet=util.printable(line.strip(), 300),
                    line=line_no,
                    match_kind="literal",
                )
            )
            break
        if len(hits) >= limit * 4:
            break
    hits.sort(key=lambda h: (h.path, h.line or 0, h.snippet))
    return hits[:limit]


# --------------------------------------------------------------------------
# Verification and stats
# --------------------------------------------------------------------------
def verify(root: Optional[str] = None) -> Dict[str, Any]:
    """Structural integrity checks. Never mutates anything."""
    root = root or util.repo_root()
    report: Dict[str, Any] = {"ok": True, "checks": [], "warnings": [], "errors": []}

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            report["ok"] = False
            report["errors"].append(f"{name}: {detail}")

    index_file = index_path(root)
    check("index-exists", os.path.exists(index_file), index_file)
    if os.path.exists(index_file):
        conn = _connect(index_file)
        try:
            integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
            check("sqlite-quick-check", integrity == "ok", str(integrity))
            try:
                conn.execute("INSERT INTO docs_fts(docs_fts) VALUES('integrity-check')")
                check("fts5-integrity", True)
            except sqlite3.Error as exc:
                check("fts5-integrity", False, str(exc))
            doc_count = conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
            use_fts = conn.execute("SELECT value FROM meta WHERE key='fts5'").fetchone()
            if use_fts and use_fts[0] == "1":
                fts_count = conn.execute("SELECT COUNT(*) FROM docs_fts").fetchone()[0]
                check(
                    "docs-fts-row-parity",
                    doc_count == fts_count,
                    f"docs={doc_count} fts={fts_count}",
                )
            orphans = conn.execute(
                "SELECT COUNT(*) FROM doc_tags t LEFT JOIN docs d ON d.rowid=t.doc_rowid"
                " WHERE d.rowid IS NULL"
            ).fetchone()[0]
            check("no-orphan-tags", orphans == 0, f"{orphans} orphan rows")
            stale = []
            for row in conn.execute("SELECT stable_id, path FROM docs"):
                if not os.path.exists(os.path.join(root, row["path"])):
                    stale.append(row["path"])
            check("indexed-paths-exist", not stale, ", ".join(stale[:5]))
            docs_on_disk = {d.path for d in collect_docs(root)}
            missing = sorted(
                docs_on_disk
                - {row["path"] for row in conn.execute("SELECT path FROM docs")}
            )
            if missing:
                report["warnings"].append(
                    f"{len(missing)} file(s) are not indexed yet; run `ctfctl kb index`"
                )
        finally:
            conn.close()

    manifest_path = os.path.join(root, "kb", "manifest.jsonl")
    cards = util.load_jsonl(manifest_path)
    ids = [c.get("card_id") for c in cards]
    dupes = {i for i in ids if ids.count(i) > 1}
    check("unique-card-ids", not dupes, ", ".join(sorted(d for d in dupes if d)))
    paths = [c.get("path") for c in cards]
    dup_paths = {p for p in paths if paths.count(p) > 1}
    check(
        "unique-card-paths", not dup_paths, ", ".join(sorted(p for p in dup_paths if p))
    )
    known_sources = {r.get("source_id") for r in _all_source_records(root)}
    unresolved = []
    for card in cards:
        for sid in card.get("source_ids", []) or []:
            if sid not in known_sources:
                unresolved.append(f"{card.get('card_id')}->{sid}")
    check("card-sources-resolve", not unresolved, ", ".join(unresolved[:5]))
    missing_files = [
        c.get("path")
        for c in cards
        if c.get("path") and not os.path.exists(os.path.join(root, c["path"]))
    ]
    check("manifest-files-exist", not missing_files, ", ".join(missing_files[:5]))
    return report


def _all_source_records(root: str) -> List[Dict[str, Any]]:
    records = []
    for name in ("manifest.jsonl", "verified-index.jsonl"):
        path = os.path.join(root, "sources", name)
        if os.path.isfile(path):
            records.extend(util.load_jsonl(path))
    frag = os.path.join(root, "sources", "fragments")
    if os.path.isdir(frag):
        for entry in sorted(os.listdir(frag)):
            if entry.endswith(".jsonl"):
                records.extend(util.load_jsonl(os.path.join(frag, entry)))
    return records


def stats(root: Optional[str] = None) -> Dict[str, Any]:
    root = root or util.repo_root()
    cards = util.load_jsonl(os.path.join(root, "kb", "manifest.jsonl"))
    sources = _all_source_records(root)
    primary = [s for s in sources if s.get("primary") is True]
    teams = {s.get("team") for s in primary if s.get("team")}
    tags: Dict[str, int] = {}
    stacks: Dict[str, int] = {}
    for card in cards:
        for tag in card.get("tags", []) or []:
            tags[str(tag)] = tags.get(str(tag), 0) + 1
        for stack in card.get("stacks", []) or []:
            stacks[str(stack)] = stacks.get(str(stack), 0) + 1
    files = [d for d in collect_docs(root) if d.kind == "card"]
    return {
        "cards_manifest": len(cards),
        "cards_on_disk": len(files),
        "sources_total": len(sources),
        "sources_primary": len(primary),
        "teams_organizers": len(teams),
        "teams": sorted(t for t in teams if t),
        "tags": dict(sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))),
        "stacks": dict(sorted(stacks.items(), key=lambda kv: (-kv[1], kv[0]))),
        "index": {
            "path": os.path.relpath(index_path(root), root).replace(os.sep, "/"),
            "exists": os.path.exists(index_path(root)),
        },
    }
