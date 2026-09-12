# Research 05 - Search and Offline Packaging

**Scope:** smallest practical offline Markdown CTF knowledge base for a small team, with at least 100 curated cards and room for thousands of source documents.

**Research date:** 2026-09-11

## Executive recommendation

Use a file-first design:

1. Plain Markdown files are the durable source of truth for curated cards.
2. Plain UTF-8 Markdown or text snapshots are the only source material eligible for full-text indexing.
3. Two JSONL manifests hold machine-readable metadata: `cards/manifest.jsonl` and `sources/manifest.jsonl`.
4. A single Python standard-library CLI, `kb.py`, performs validation, incremental indexing, search, verification and export.
5. SQLite FTS5 is an optional acceleration and ranking layer, detected at runtime. It is a disposable cache, not the canonical store.
6. ripgrep is the exact-substring engine and the primary no-FTS5 fallback when installed.
7. A pure-Python streaming literal search is the final fallback if FTS5 and ripgrep are both unavailable.
8. No server, browser UI, LLM, vector database, container runtime or network service is required.

This architecture fits the event-prep brief well. The brief expects a hybrid mini-Jeopardy plus live attack/defend event, permits only one CTF-connected device per team member, and explicitly advises keeping tools, wordlists, documentation and references local because Internet access may be limited or unavailable. It also prioritizes web, PCAP/forensics and attack/defend work, where punctuation-heavy strings such as paths, ports, IOCs, commands and configuration fragments are common.

The important separation is:

- `kb search` uses FTS5 for ranked natural-language/token search when available.
- `kb literal` performs exact substring search over the actual locally stored text.
- The database never becomes the only copy of source text.
- The exporter never assumes that every locally available source may legally be redistributed.

For a 100-card starting corpus and a few thousand source documents, this is simpler and more robust than adding a local HTTP service, Elasticsearch, Tantivy, Meilisearch, a vector database or an embedding model.

---

## 1. Requirements derived from the brief

The design should optimize for:

- fast lookup under time pressure;
- no Internet dependency during the event;
- no additional network server or team device;
- ordinary Linux/macOS/Windows laptops;
- full-text lookup of real locally stored content, not just titles and URLs;
- low maintenance during an attack/defend round;
- exact lookup of punctuation-heavy technical strings;
- ranked lookup of human concepts and remembered phrases;
- safe import of untrusted writeups and snippets;
- reproducible packaging before the event;
- graceful degradation if the local Python/SQLite build lacks FTS5.

The KB is preparation infrastructure, not a runtime evidence store. It should not ingest live PCAPs, credentials, flags, shell history, attack outputs, service state or other volatile event artifacts. Those belong in separate working directories.

---

## 2. Options evaluated

### 2.1 Markdown plus ripgrep

**Strengths**

- Searches the canonical files directly.
- `-F/--fixed-strings` gives exact literal matching with no regex interpretation.
- Excellent for paths, hashes, protocol fragments, code snippets, CLI flags and CVE identifiers.
- No index to rebuild or corrupt.
- Recurses efficiently through thousands of text files.
- Cross-platform release binaries exist.
- Can emit stable JSON for machine parsing.
- `--sort path` makes result ordering deterministic, at the cost of parallel search.
- Easy to exclude unsafe or irrelevant trees by passing only approved roots.

**Weaknesses**

- No native relevance ranking across documents.
- Metadata filters such as tags and stacks require either path conventions, post-filtering, or a side manifest.
- Matching is line-oriented by default.
- Natural-language search is less forgiving than a token index.
- ripgrep is not guaranteed to be preinstalled.
- Its default filtering and configuration behavior is user-environment dependent unless the wrapper constrains it.

**Use in the recommended design**

Required only for the best `literal` experience. It is optional at runtime because a Python literal fallback is feasible.

For deterministic programmatic invocation, the wrapper should call ripgrep directly through `subprocess.run()` without a shell and include at least:

```text
rg
--no-config
--json
--sort
path
--fixed-strings
--line-number
--
<PATTERN>
<APPROVED_ROOT_1>
<APPROVED_ROOT_2>
```

Do not search the repository root by default. Pass `cards/` and `sources/text/` explicitly. This prevents accidental searching of captures, credentials, runtime state or vendor caches.

The `--` argument terminates option parsing, so a literal beginning with `-` is not interpreted as an option. `--no-config` prevents a teammate's `RIPGREP_CONFIG_PATH` or future config mechanisms from changing behavior.

### 2.2 Python `sqlite3` plus SQLite FTS5

**Strengths**

- No database server.
- Python's `sqlite3` is a standard-library interface when the distributor includes it.
- FTS5 provides tokenized full-text search, quoted phrases, boolean expressions, prefix queries, BM25 ranking and `snippet()`.
- Metadata joins and tag/stack filters are straightforward.
- Thousands of small text documents are trivial for SQLite in capacity terms.
- One database file is easy to rebuild and verify.

**Weaknesses**

- FTS5 is a build capability, not something to assume from the Python version alone.
- FTS query syntax is not literal substring syntax.
- The default `unicode61` tokenizer treats punctuation as separators.
- A malformed FTS expression can raise an SQLite operational error even when SQL parameters are bound safely.
- A generated index creates another artifact that must be kept in sync with the file corpus.
- An external-content FTS table adds synchronization pitfalls that are unnecessary at this scale.

**Use in the recommended design**

Preferred ranked search backend when a functional capability probe succeeds.

Do not make FTS5 mandatory. Do not load arbitrary SQLite extensions to obtain it during the event. If it is absent, print a clear capability result and fall back.

### 2.3 Combined result

The smallest useful combination is not "pick one." It is:

- SQLite FTS5 for ranked concept/phrase retrieval.
- ripgrep `-F` for exact substring retrieval.
- Markdown/text on disk as canonical content.
- Python as the single user-facing command surface.

These engines solve different search problems and avoid forcing punctuation-sensitive technical text through a natural-language tokenizer.

---

## 3. Verified runtime and query behavior

### 3.1 What must be detected at runtime

`kb doctor` should report:

```text
KB format version
Python version
Python implementation
OS and release
machine architecture
sqlite3 module present: yes/no
SQLite runtime version
FTS5 functional probe: yes/no
ENABLE_FTS5 compile option: present/absent/unknown
ripgrep path
ripgrep version
ripgrep feature line
corpus root
indexed document count
indexed card count
source snapshot count
last successful index generation
index schema version
```

Python exposes the SQLite runtime version as `sqlite3.sqlite_version`. SQLite also exposes compile-time options through `PRAGMA compile_options`.

However, the authoritative FTS5 test should be functional, not just string matching against compile options:

```python
def probe_fts5(con):
    try:
        con.execute("CREATE VIRTUAL TABLE temp.__kb_fts_probe USING fts5(x)")
        con.execute("INSERT INTO temp.__kb_fts_probe(x) VALUES (?)", ("probe text",))
        ok = con.execute(
            "SELECT 1 FROM temp.__kb_fts_probe WHERE __kb_fts_probe MATCH ?",
            ("probe",),
        ).fetchone() is not None
        con.execute("DROP TABLE temp.__kb_fts_probe")
        return ok
    except sqlite3.DatabaseError:
        return False
```

Why both checks:

- `PRAGMA compile_options` is useful diagnostic evidence.
- A real temporary FTS5 table proves the current `sqlite3` connection can actually use the module.
- The CLI should not attempt `enable_load_extension()` or download a missing extension.

If the Python distribution lacks the `sqlite3` module entirely, `doctor` reports that and the CLI continues with literal search.

### 3.2 Local verification performed for this research

This research environment reported:

```text
Python 3.13.5
SQLite 3.46.1
PRAGMA compile_options includes ENABLE_FTS5
functional FTS5 probe: success
ripgrep 14.1.1
```

This is a verification fixture only, not an event-device assumption. Official ripgrep releases have since reached 15.2.0, so the event package should record and verify whichever binary is actually bundled or installed.

### 3.3 FTS5 punctuation behavior

With the default `unicode61` tokenizer, punctuation is generally a separator. Therefore FTS5 phrase search operates on token sequences, not exact byte/character substrings.

The following behavior was verified locally against a small synthetic FTS5 table:

| User text | Raw FTS expression | Observed behavior |
|---|---|---|
| `CVE-2024-1234` | raw | error: parsed as FTS syntax, not a literal |
| `"CVE-2024-1234"` | quoted FTS string | matched both `CVE-2024-1234` and `CVE/2024/1234` because the token sequence is `cve 2024 1234` |
| `"/api/v1/login"` | quoted | matched the path token sequence |
| `"Authorization: Bearer"` | quoted | matched `authorization bearer` |
| `"../../etc/passwd"` | quoted | matched `etc passwd` |
| `"C:\Windows\System32"` | quoted | matched `c windows system32` |
| `"::1"` | quoted | matched the token `1`, which is far broader than literal IPv6 loopback matching |
| `"$2b$12$"` | quoted | matched tokens `2b 12`, not the exact dollar-delimited prefix |
| `"a=b&c=d"` | quoted | matched token sequence `a b c d` |
| `CVE/2024/1234` | raw | malformed FTS expression error |

This is the central reason to preserve a separate `literal` mode.

The default FTS tokenizer is still the right choice for the ranked index. Customizing punctuation into token characters makes other natural-language/code searches harder to predict, while the exact-literal path already exists.

Do not add a second trigram FTS index initially. FTS5's trigram tokenizer supports substring matching, but that increases index complexity and duplicates a job ripgrep already performs over canonical files.

### 3.4 Exact literal behavior

The same punctuation-heavy fixtures were searched with:

```text
rg -F --sort path --line-number --no-heading -- <literal> <fixture>
```

Exact matches were returned for all of these:

```text
CVE-2024-1234
/api/v1/login
../../etc/passwd
C:\Windows\System32
::1
$2b$12$
a=b&c=d
```

Therefore the user-facing rule should be simple:

> If punctuation itself matters, use `kb literal`. If the concept or phrase matters, use `kb search`.

---

## 4. Repository layout

Recommended minimum:

```text
ctf-kb/
├── README.md
├── kb.py
├── cards/
│   ├── manifest.jsonl
│   ├── web/
│   ├── forensics/
│   ├── attack-defend/
│   ├── reverse/
│   ├── crypto/
│   └── misc/
├── sources/
│   ├── manifest.jsonl
│   └── text/
│       └── <source-id>.md-or-txt
├── vendor/
│   ├── manifest.jsonl
│   └── licenses/
├── index/
│   └── kb.sqlite3
├── tests/
│   ├── fixtures/
│   └── queries.jsonl
├── dist/
└── .gitignore
```

The actual shareable export should omit `index/kb.sqlite3` if reproducibility matters more than startup time, or include it only as a cache plus an export checksum. Rebuilding a small index is cheap and avoids compatibility surprises.

### Hard separation of content classes

`cards/`:
- original team-authored summaries and techniques;
- concise, actionable;
- safe to display as text;
- expected to be at least 100 cards in the initial pack.

`sources/text/`:
- locally stored source text or normalized source snapshots;
- only present where local storage is allowed by the team's source policy;
- searchable in full;
- clearly attributed and licensed in the source manifest.

`sources/raw/` is intentionally absent from the minimum layout. If later added, it must remain outside search roots and exports by default.

`captures/`, `loot/`, `runtime/`, `.env`, credentials and event state should not live inside the KB repository at all.

---

## 5. Source manifest

Use JSONL to avoid YAML/TOML dependencies and to permit streaming updates.

One source per line:

```json
{
  "source_id": "src-ooo-web-2019-4f932a9c",
  "title": "Example attack-defend web retrospective",
  "author": "Original Team",
  "canonical_url": "https://example.invalid/writeup",
  "source_type": "article",
  "publisher": "Original Team",
  "retrieved_at": "2026-09-11T23:41:00Z",
  "retrieval_method": "manual-save",
  "upstream_revision": null,
  "etag": null,
  "last_modified": null,
  "license_expression": "CC-BY-4.0",
  "license_url": "https://creativecommons.org/licenses/by/4.0/",
  "redistribution": "allowed-with-attribution",
  "storage": "snapshot-text",
  "local_path": "sources/text/src-ooo-web-2019-4f932a9c.md",
  "content_sha256": "…",
  "normalized_sha256": "…",
  "notes": "HTML converted to plain text during online preparation."
}
```

Required fields:

- `source_id`
- `title`
- `canonical_url`
- `retrieved_at`
- `license_expression` or `"unknown"`
- `redistribution`
- `storage`
- `content_sha256` when a local snapshot exists

Recommended revision fields:

- Git repository: commit SHA and exact repository file path.
- Release artifact: release/tag/version plus artifact checksum.
- Web page: retrieval time plus ETag/Last-Modified if available.
- PDF/document: publication/revision date plus file SHA-256.

### Source ID rules

A source ID is assigned once and never regenerated just because metadata changes.

Recommended generation on first import:

```text
src-<short-human-slug>-<first-8-hex-of-sha256(canonical_url)>
```

Then freeze it in the manifest.

If the canonical URL later moves:

- keep `source_id`;
- update `canonical_url`;
- add `previous_urls`;
- do not generate a new identity unless it is genuinely a different source.

---

## 6. Normalized card format

Keep the Markdown body clean and human-readable. Put structured metadata in `cards/manifest.jsonl`, not YAML front matter.

Example file:

`cards/web/card-web-path-traversal-source-route.md`

```markdown
# Trace a web path back to its source route

Symptom: a request path appears in a capture or checker failure, but you do not know which application route owns it.

Fast path:

1. Identify the listening process and reverse proxy.
2. Find the proxy upstream or application port.
3. Search source/config for the literal path and route fragments.
4. Confirm middleware and authentication boundaries.
5. Patch only the vulnerable route.
6. Replay a known-good request before and after the change.

Search aliases: source route, endpoint owner, nginx upstream, flask route, express route

Failure modes:
- Editing only the reverse proxy while the vulnerable handler remains reachable.
- Grepping a generated/vendor tree before application source.
- Changing a scored route without recording a rollback.

Sources:
- src-example-1
- src-example-2
```

Matching manifest record:

```json
{
  "card_id": "card-web-path-traversal-source-route",
  "path": "cards/web/card-web-path-traversal-source-route.md",
  "title": "Trace a web path back to its source route",
  "tags": ["web", "source-review", "attack-defend"],
  "stacks": ["generic", "nginx", "flask", "express"],
  "aliases": [
    "source route",
    "endpoint owner",
    "nginx upstream",
    "flask route",
    "express route"
  ],
  "source_ids": ["src-example-1", "src-example-2"],
  "content_origin": "original-summary",
  "created_at": "2026-09-11T00:00:00Z",
  "updated_at": "2026-09-11T00:00:00Z",
  "content_sha256": "…"
}
```

### Card ID rules

- lowercase ASCII;
- `card-` prefix;
- descriptive slug;
- no version number in the stable ID;
- immutable after publication unless the card is split into a genuinely different concept.

Revisions belong in `updated_at`, Git history and content hashes.

---

## 7. Deduplication

Deduplication should be conservative.

### Sources

Check, in order:

1. exact `source_id`;
2. exact canonical URL after URL normalization;
3. exact `content_sha256`;
4. normalized-text SHA-256 as a warning only.

Recommended URL normalization:

- lowercase scheme and host;
- remove URL fragment;
- remove default port;
- normalize an empty path to `/`;
- preserve query parameters unless a source-specific rule explicitly identifies tracking parameters.

Do not globally delete arbitrary query parameters because some documentation URLs use them to select a revision or resource.

### Normalized text hash

For duplicate warnings only:

- convert CRLF/CR to LF;
- strip trailing whitespace;
- collapse runs of more than two blank lines;
- ensure one terminal newline.

Do not collapse internal whitespace in code lines. Whitespace can be semantically meaningful.

If two sources have the same normalized hash but different provenance, keep both manifest identities and mark one as `duplicate_of` only after human review.

### Cards

- exact `card_id` collision: hard error;
- exact path collision: hard error;
- exact content hash: warning;
- same title: warning;
- do not perform fuzzy auto-deletion.

At a few hundred cards, human curation is cheaper and safer than an automatic near-duplicate algorithm.

---

## 8. Copyright and license handling

The KB should distinguish three things:

1. original team-authored cards;
2. locally indexed source snapshots;
3. metadata-only references to sources not stored locally.

Do not copy an article into a card and call it a summary. Cards should be independently written, concise syntheses with source attribution.

For each source, record a policy value:

```text
allowed
allowed-with-attribution
private-only
metadata-only
unknown
```

`unknown` should behave like `metadata-only` for shareable exports.

This policy value is an operational packaging decision, not a legal conclusion.

### Export behavior

`kb export --shareable`:

- includes cards;
- includes source snapshots only when manifest policy permits redistribution;
- includes required license/attribution files;
- includes source metadata for all cited sources;
- excludes `private-only`, `metadata-only` and `unknown` snapshots;
- fails if a bundled vendor binary lacks recorded license metadata.

`kb export --local-event` may include team-local material only when the team has independently determined that local possession/use is allowed. The tool should not infer that merely because a URL was publicly accessible.

### Tool licenses

Current primary tool licensing verified during research:

- SQLite deliverable code/documentation is dedicated to the public domain.
- ripgrep is dual-licensed under MIT or the Unlicense.
- Python software/documentation is under the PSF License Version 2, with additional incorporated-software notices.

Keep the exact license files next to cached binaries instead of relying only on a manifest label.

---

## 9. Safe source ingestion

### Principle

Import text. Do not execute, render or interpret active content.

Accepted indexed file classes by default:

```text
.md
.markdown
.txt
.rst
```

Optional importers may normalize other formats into UTF-8 text during online preparation, but the search/index process itself should still consume only the normalized text artifact.

### HTML

If HTML ingestion is implemented:

- use Python's non-rendering parser to extract text;
- remove script/style/template content;
- do not launch a browser;
- do not execute JavaScript;
- do not fetch subresources;
- do not resolve external callbacks;
- write normalized UTF-8 text to `sources/text/`;
- keep raw HTML outside searchable/exported roots unless explicitly needed and licensed.

### Markdown

Treat Markdown as plain text.

Do not:

- render embedded HTML;
- follow image URLs;
- execute fenced code;
- evaluate MDX;
- invoke preprocessors based on file contents.

### File limits

Proposed import guards:

```text
maximum indexed file: 8 MiB by default
maximum line length retained for snippet display: 16 KiB
maximum displayed snippet: 600 characters
maximum query length: 1,024 characters
maximum result count: 100
default result count: 10
```

Files above the limit are rejected or marked `oversize` for deliberate review. These are safety/operability defaults, not fundamental SQLite limits.

### Encoding

Require UTF-8 for canonical indexed text.

An online normalizer may explicitly transcode known encodings, but must record the original encoding and the normalized snapshot hash.

---

## 10. SQLite schema

Avoid external-content FTS tables for this project. At this scale, a normal FTS table plus a metadata table is simpler and avoids synchronization traps.

Recommended schema:

```sql
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE docs (
    rowid INTEGER PRIMARY KEY,
    stable_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('card', 'source')),
    path TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    source_id TEXT,
    revision TEXT,
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
    title,
    aliases,
    body,
    tokenize='unicode61'
);
```

`docs_fts.rowid` is deliberately kept equal to `docs.rowid`.

Why not `content='docs'`:

- the canonical body is a file, not a SQL row;
- storing body text in `docs` just to make an external-content FTS table creates another database copy;
- external-content synchronization is easy to get subtly wrong;
- explicit application-managed insert/update/delete operations are clear at this scale.

### Insert transaction

For a new document:

1. validate path against the approved root and extension;
2. read UTF-8 text with size limit;
3. compute SHA-256;
4. insert `docs`;
5. obtain `rowid`;
6. insert `docs_fts(rowid, title, aliases, body)`;
7. insert tags/stacks;
8. commit.

### Update transaction

If hash, manifest metadata or indexed aliases changed:

1. fetch existing `rowid`;
2. update `docs`;
3. `DELETE FROM docs_fts WHERE rowid = ?`;
4. insert replacement FTS row with the same rowid;
5. replace tag/stack rows;
6. commit.

Do not use `INSERT OR REPLACE` on `docs`; it can change row identity. Use explicit `UPDATE`.

### Delete transaction

If the manifest entry or file is gone:

1. locate `rowid` by stable ID;
2. delete from `docs_fts`;
3. delete from `docs`;
4. commit.

Foreign keys should be enabled for the metadata relations:

```sql
PRAGMA foreign_keys = ON;
```

### Integrity

`kb verify` should perform:

```text
PRAGMA quick_check
FTS5 integrity-check
manifest-to-file hash verification
docs-to-FTS row count comparison
orphan tag/stack checks
stable ID uniqueness
path uniqueness
source reference validation
```

The FTS index is always rebuildable from files and manifests:

```text
python3 kb.py index --rebuild
```

---

## 11. Incremental indexing algorithm

Do not trust mtime alone.

For each manifest-backed document:

1. stat path;
2. compare `mtime_ns` and `size_bytes` to cached metadata;
3. if unchanged, skip hashing;
4. if changed or absent, read within size limit and calculate SHA-256;
5. if SHA-256 is unchanged, update stat metadata only;
6. if content or indexed metadata changed, replace the FTS row;
7. after scanning desired documents, delete indexed rows whose stable IDs are no longer present.

This keeps routine updates cheap while preserving content-hash correctness.

An interrupted index operation should not leave a half-updated document. Use one transaction per batch or per document. For a small corpus, one transaction per full incremental run is simplest.

Write the database to a temporary path on full rebuild:

```text
index/kb.sqlite3.new
```

After successful validation:

```text
atomic replace -> index/kb.sqlite3
```

This preserves the last known-good index if rebuilding fails.

---

## 12. Search modes

### 12.1 Ranked search

Command:

```text
python3 kb.py search "reverse proxy upstream" --tag attack-defend --stack nginx
```

Default behavior:

- FTS5 when available;
- query is converted into a safe phrase or safe token expression by the application;
- title and aliases receive greater BM25 weight than body;
- tag/stack filters are relational;
- snippets are plain text;
- ties break by stable ID.

Recommended SQL shape:

```sql
SELECT
    d.stable_id,
    d.kind,
    d.path,
    d.title,
    bm25(docs_fts, 8.0, 5.0, 1.0) AS score,
    snippet(docs_fts, 2, '[[', ']]', ' … ', 24) AS snippet
FROM docs_fts
JOIN docs AS d ON d.rowid = docs_fts.rowid
WHERE docs_fts MATCH ?
  AND (
      ? IS NULL OR EXISTS (
          SELECT 1
          FROM doc_tags t
          WHERE t.doc_rowid = d.rowid AND t.tag = ?
      )
  )
  AND (
      ? IS NULL OR EXISTS (
          SELECT 1
          FROM doc_stacks s
          WHERE s.doc_rowid = d.rowid AND s.stack = ?
      )
  )
ORDER BY score ASC, d.stable_id ASC
LIMIT ?;
```

Every value is bound as a parameter.

The query syntax itself still needs controlled construction. Binding a string to `MATCH ?` prevents SQL injection, but it does not make arbitrary text valid FTS syntax.

### 12.2 Phrase mode

Command:

```text
python3 kb.py search --phrase "path traversal"
```

Convert the user's input into one FTS5 quoted string by doubling embedded quote characters:

```python
def quote_fts5_string(value):
    return '"' + value.replace('"', '""') + '"'
```

This makes punctuation safe from the FTS expression parser, but it still uses tokenizer semantics.

Example:

```text
--phrase "CVE-2024-1234"
```

means the token phrase `cve 2024 1234`. It is not an exact punctuation match.

### 12.3 Optional advanced FTS mode

For teammates who know FTS5:

```text
python3 kb.py search --fts 'web AND NEAR("path traversal" nginx, 8)'
```

This mode passes the expression as one bound `MATCH` parameter but intentionally allows FTS grammar.

Errors should be caught:

```text
ERROR query: malformed FTS5 expression near "/"
HINT: use `kb literal "CVE/2024/1234"` for exact punctuation, or `kb search --phrase ...`.
```

No Python traceback by default. `--debug` may expose it.

### 12.4 Literal mode

Command:

```text
python3 kb.py literal "../etc/passwd"
```

Preferred backend:

```text
rg --no-config --json --sort path -F --line-number -- <pattern> cards sources/text
```

Parse JSON records. Do not parse colon-separated human output.

If ripgrep is absent, scan approved text paths in Python:

- open UTF-8 text;
- stream line by line;
- use `pattern in line`;
- collect path, line number and escaped display text;
- sort `(path, line_number, column)` before output.

This is slower than ripgrep but fully adequate as an emergency fallback for a few thousand text files.

### 12.5 Filters

Minimal filters:

```text
--tag web
--tag forensics
--stack php
--stack nginx
--kind card
--kind source
--limit 20
```

Repeated tag filters should default to AND semantics:

```text
--tag web --tag attack-defend
```

means both tags.

If OR semantics are needed later, add them deliberately rather than making the initial CLI ambiguous.

---

## 13. Minimal command surface

Keep event-time commands small:

```text
kb doctor
kb search QUERY [--phrase|--fts] [--tag TAG] [--stack STACK] [--kind card|source] [--limit N]
kb literal TEXT [--tag TAG] [--stack STACK] [--kind card|source] [--limit N]
kb show ID
kb index [--changed|--rebuild]
kb verify [--checksums]
kb export DEST [--shareable|--local-event]
```

`show` prints the canonical local file content and source metadata. It does not render Markdown as HTML.

Preparation-only import can remain a subcommand:

```text
kb ingest FILE_OR_URL_METADATA
```

But URLs should only be fetched during explicit online preparation. Event-time `ingest` should default to local paths unless an operator explicitly opts into networking.

---

## 14. Safe parameter and process handling

### SQLite

Always bind values:

```python
con.execute(
    "SELECT rowid FROM docs WHERE stable_id = ?",
    (stable_id,),
)
```

Never interpolate:

```python
# Wrong
con.execute(f"SELECT ... MATCH '{user_query}'")
```

Identifiers such as table names must be hard-coded, not user supplied.

### ripgrep

Use an argument list and `shell=False`:

```python
subprocess.run(
    [
        rg_path,
        "--no-config",
        "--json",
        "--sort", "path",
        "--fixed-strings",
        "--line-number",
        "--",
        pattern,
        str(cards_root),
        str(source_text_root),
    ],
    check=False,
    text=True,
    capture_output=True,
)
```

Do not construct a shell string.

Interpret exit codes explicitly:

```text
0 = matches
1 = no matches
2 = error
```

### Output rendering

Before terminal display:

- replace C0/C1 control characters except tab/newline with visible escapes;
- cap snippet length;
- do not emit raw ANSI escape sequences from indexed hostile strings;
- do not render Markdown or HTML;
- do not create clickable `file://` or command URLs from untrusted text;
- show local path as plain text.

---

## 15. Deterministic output

FTS:

```text
ORDER BY bm25_score ASC, stable_id ASC
```

Literal:

- ripgrep: `--sort path`, then wrapper sorts parsed matches by path, line, column as a final normalization;
- Python fallback: same tuple sort.

JSON output mode should use:

```text
sort_keys=True
ensure_ascii=False
separators=(",", ":")
```

and fixed field order if human-readable JSONL is preferred.

Do not include current timestamps in ordinary search results. They make snapshot tests noisy.

---

## 16. Representative result format

Human mode:

```text
1. [CARD] card-web-path-traversal-source-route
   Trace a web path back to its source route
   tags: attack-defend, source-review, web
   stacks: express, flask, generic, nginx
   cards/web/card-web-path-traversal-source-route.md
   … search the proxy [[upstream]] and then locate the application [[route]] …

2. [SOURCE] src-team-retro-2019-a932be41
   Attack-defend retrospective
   license: CC-BY-4.0
   sources/text/src-team-retro-2019-a932be41.md
   … exact matched text …
```

Machine mode:

```json
{"id":"card-web-path-traversal-source-route","kind":"card","path":"cards/web/card-web-path-traversal-source-route.md","score":-4.831,"snippet":"…"}
```

Do not promise BM25 score comparability across different index generations. Treat it only as within-query ranking.

---

## 17. Exclusions and boundary rules

The search roots are an allowlist, not a blacklist.

Indexed/searchable:

```text
cards/**/*.md
sources/text/**/*.md
sources/text/**/*.txt
sources/text/**/*.rst
```

Never indexed by default:

```text
captures/**
pcap/**
loot/**
runtime/**
tmp/**
secrets/**
.env
.env.*
*.pcap
*.pcapng
*.cap
*.dmp
*.core
*.sqlite*
*.db
*.pem
*.key
*.pfx
*.p12
id_rsa*
authorized_keys
known_hosts
shell-history/**
vendor/cache/**
dist/**
.git/**
```

The easiest enforcement is not to pass these locations to the engine at all.

Do not use `rg -uuu` in the wrapper. It deliberately disables filters and includes binary content, which is the opposite of the KB boundary.

---

## 18. Online preparation workflow

Recommended pre-event sequence:

```text
python3 kb.py doctor
python3 kb.py verify
python3 kb.py index --rebuild
python3 kb.py verify --checksums
python3 kb.py test
python3 kb.py export dist/rj-ctf-kb --local-event
```

For a shareable/public artifact:

```text
python3 kb.py export dist/rj-ctf-kb-shareable --shareable
```

Preparation tasks:

1. curate at least 100 original cards;
2. retrieve source material only while online;
3. normalize permitted source text;
4. populate exact source/revision/license metadata;
5. cache optional binaries/wordlists only after redistribution review;
6. build index;
7. run test queries;
8. generate checksums;
9. test the exported package on a clean machine or VM.

No online fetching should occur as a side effect of `search`, `literal`, `show`, `verify` or `doctor`.

---

## 19. Optional dependency and wordlist caching

### Vendor manifest

`vendor/manifest.jsonl`:

```json
{
  "name": "ripgrep",
  "version": "15.2.0",
  "platform": "x86_64-unknown-linux-musl",
  "source_url": "https://github.com/BurntSushi/ripgrep/releases/tag/15.2.0",
  "artifact": "vendor/bin/linux-x86_64/rg",
  "sha256": "…",
  "license_expression": "MIT OR Unlicense",
  "license_files": [
    "vendor/licenses/ripgrep-LICENSE-MIT",
    "vendor/licenses/ripgrep-UNLICENSE"
  ],
  "redistributable": true
}
```

Do not automatically use the vendored binary if a compatible system binary exists unless the package policy says so. `doctor` should show which one will be used.

### Wordlists

Treat wordlists as separate copyrighted works.

Manifest fields:

```text
name
version/revision
source URL
upstream commit
local path
SHA-256
license expression
license file
redistributable yes/no/unknown
```

If redistribution is unclear:

- do not include it in `--shareable`;
- keep an online preparation fetch instruction and expected checksum;
- do not silently relabel it as "public domain" because it is widely mirrored.

For the local event pack, the team should determine whether possession/sharing is allowed under the source's actual terms.

---

## 20. Export format and checksums

Prefer an ordinary directory plus ZIP for portability.

Example:

```text
dist/rj-ctf-kb/
├── kb.py
├── README.md
├── cards/
├── sources/
├── vendor/
├── index/
├── MANIFEST.json
└── SHA256SUMS
```

`MANIFEST.json` should record:

```text
kb format version
export mode
export timestamp UTC
Git commit if available
Python build version used for export
SQLite runtime version used for export
FTS5 available during export yes/no
ripgrep version used for validation
target architectures included
document counts
card count
source snapshot count
excluded source count by policy
file count
```

`SHA256SUMS` should cover every exported file except itself, sorted by normalized relative path.

The final ZIP should also receive a sidecar hash:

```text
rj-ctf-kb.zip
rj-ctf-kb.zip.sha256
```

Do not sign unless the team already has a signing workflow. A checksum catches accidental corruption; it is not proof of authorship.

---

## 21. Clean-machine rehearsal

Perform at least one rehearsal on a machine/VM that does not have the development repository or Python packages installed.

Test matrix:

### A. Python + FTS5 + ripgrep

Expected:
- ranked FTS works;
- literal uses ripgrep;
- all tests pass.

### B. Python + FTS5, no ripgrep

Expected:
- ranked FTS works;
- literal falls back to Python;
- output remains semantically identical.

### C. Python `sqlite3`, no FTS5 + ripgrep

Expected:
- `doctor` clearly reports FTS5 unavailable;
- `search` falls back to ripgrep token/phrase approximation or clearly directs the user to `literal`;
- literal works.

Recommended fallback behavior for `search` in this case:
- use ripgrep fixed-string search for the full user phrase against allowed roots;
- no pretend relevance ranking;
- print `backend=rg-fallback`.

### D. Python, no FTS5, no ripgrep

Expected:
- streaming Python literal fallback works;
- `search` uses the same plain phrase scan and labels the backend;
- no crash.

### E. Missing Python `sqlite3` module

Expected:
- CLI starts because `sqlite3` import is guarded;
- `doctor` reports missing module;
- literal/search fallback still works.

If the team expects Windows and Linux laptops, rehearse one export on each.

---

## 22. Proposed usability targets

These are **proposed acceptance targets, not measured performance claims**.

For the initial 100-card / few-thousand-document corpus on a normal laptop:

| Target | Proposed acceptance criterion |
|---|---|
| startup | `kb doctor` completes in under 1 s |
| ranked search | first 10 results returned in under 300 ms after warm filesystem cache |
| cold ranked search | under 1 s for normal queries |
| literal search | under 1 s for ordinary punctuation-heavy queries across the approved text corpus |
| index update | one changed card reflected in under 1 s |
| full rebuild | under 10 s for 10,000 small text documents |
| result usefulness | a known-answer card appears in top 5 for at least 90% of curated test queries |
| exactness | literal mode returns zero punctuation-normalization false positives in fixture tests |
| offline | all standard search/show/verify/test operations succeed with network disabled |
| portability | clean-machine tests pass on every architecture planned for the event |
| resilience | deleting `index/kb.sqlite3` never loses source content; rebuild restores full ranked search |

If the corpus later grows enough to miss these targets, measure before adding complexity.

---

## 23. Representative query/result test set

Store fixtures in `tests/queries.jsonl`.

Example records:

```json
{"id":"q001","mode":"search","query":"reverse proxy upstream","expect_any":["card-web-path-traversal-source-route"],"top_n":5}
{"id":"q002","mode":"search","query":"reconstruct HTTP request from pcap","tags":["forensics"],"expect_any":["card-forensics-http-stream-reconstruction"],"top_n":5}
{"id":"q003","mode":"search","query":"patch without breaking checker","tags":["attack-defend"],"expect_any":["card-ad-patch-verify-rollback"],"top_n":5}
{"id":"q004","mode":"literal","query":"CVE-2024-1234","expect_literal":true}
{"id":"q005","mode":"literal","query":"/api/v1/login","expect_literal":true}
{"id":"q006","mode":"literal","query":"../../etc/passwd","expect_literal":true}
{"id":"q007","mode":"literal","query":"C:\\Windows\\System32","expect_literal":true}
{"id":"q008","mode":"literal","query":"::1","expect_literal":true}
{"id":"q009","mode":"literal","query":"$2b$12$","expect_literal":true}
{"id":"q010","mode":"literal","query":"a=b&c=d","expect_literal":true}
{"id":"q011","mode":"search-phrase","query":"CVE-2024-1234","expect_tokenized_equivalence":["CVE/2024/1234"]}
{"id":"q012","mode":"search-fts-invalid","query":"CVE/2024/1234","expect_error":"query"}
{"id":"q013","mode":"literal","query":"--password","expect_safe_option_termination":true}
{"id":"q014","mode":"search","query":"ssrf metadata","stacks":["generic"],"top_n":10}
{"id":"q015","mode":"search","query":"xor repeating key","tags":["crypto"],"top_n":10}
```

### Required assertions

1. stable ordering across two identical runs;
2. filters never add a document that does not satisfy the filter;
3. search never traverses outside approved roots;
4. literal strings beginning with `-` are not parsed as CLI options by ripgrep;
5. malformed `--fts` expressions become controlled user errors;
6. quotes inside phrase input cannot break out of the FTS query string;
7. SQL metacharacters do not alter SQL structure;
8. snippets escape terminal control bytes;
9. result limit is enforced;
10. no search operation triggers network access.

---

## 24. Suggested test fixtures

Create tiny, synthetic, redistribution-safe files.

`tests/fixtures/punctuation.md`:

```text
Patch CVE-2024-1234 in /api/v1/login.
Authorization: Bearer REDACTED
GET /download?path=../../etc/passwd
C:\Windows\System32\drivers\etc\hosts
IPv6 loopback is ::1
bcrypt prefix example: $2b$12$REDACTED
query fragment: a=b&c=d
```

`tests/fixtures/punctuation-variant.md`:

```text
The identifier is written CVE/2024/1234 here.
```

Assertions:

```text
literal CVE-2024-1234
  -> only punctuation.md

phrase CVE-2024-1234
  -> may match both files because FTS tokenization removes punctuation boundaries

literal ::1
  -> only exact ::1 occurrence

phrase ::1
  -> not suitable for exact IPv6 lookup
```

This test makes the tokenizer limitation visible to contributors instead of leaving it as tribal knowledge.

---

## 25. Failure handling

### FTS5 absent

```text
NOTICE ranked FTS5 search unavailable: current SQLite runtime lacks usable FTS5.
backend: rg-fallback
```

No attempt to download or load an extension.

### ripgrep absent

```text
NOTICE ripgrep not found; using Python literal scanner.
```

### malformed FTS query

```text
ERROR query: malformed FTS5 expression.
HINT use --phrase for ordinary text or `kb literal` when punctuation must match exactly.
```

### corrupt index

If `PRAGMA quick_check` or FTS integrity check fails:

```text
ERROR index integrity failed.
ACTION run: python3 kb.py index --rebuild
```

Do not silently continue returning possibly incomplete ranked results.

### missing source file

Hard error during `verify`; remove from index during a deliberate `index --changed` only if the manifest has also been updated or `--prune` was explicitly requested.

This avoids an accidental directory mount/path problem looking like a legitimate deletion.

---

## 26. Architecture/version reporting

Example:

```text
$ python3 kb.py doctor

kb_format       1
platform        Linux 6.x
machine         x86_64
python          3.13.5
sqlite_module   yes
sqlite_runtime  3.46.1
fts5_probe      yes
fts5_compile    ENABLE_FTS5
ripgrep         /usr/bin/rg
ripgrep_version 14.1.1
cards           128
sources_local   742
docs_indexed    870
index_schema    1
index_status    clean
network_needed  no
```

Do not reject a machine only because its versions differ from the preparation machine. Reject only on required behavior:

- Python can run the CLI;
- files can be read;
- at least one search fallback is available.

---

## 27. Why not make ripgrep the only engine?

For 100 cards, ripgrep alone is viable. The reason to add FTS5 is not raw scale. It is event-time retrieval quality.

Examples:

```text
remembered concept: "patch checker rollback"
remembered phrase: "reverse proxy upstream"
topic + filters: tag=forensics stack=http
```

FTS5 gives ranked token search and snippets without adding a daemon or third-party Python package.

The SQLite component remains small enough to delete if it becomes troublesome.

---

## 28. Why not make FTS5 the only engine?

Because CTF lookup frequently depends on punctuation:

```text
../
/api/v1/
/etc/passwd
C:\Windows\
10.0.0.1:443
::1
CVE-2024-1234
$2b$12$
a=b&c=d
Content-Type:
--data-urlencode
```

Default FTS tokenization intentionally abstracts punctuation. That is useful for language search but wrong for exact technical lookup.

`literal` must search the actual local files.

---

## 29. Security properties of the design

The design deliberately avoids:

- executing imported code;
- rendering HTML;
- evaluating MDX;
- browser-based search;
- shell interpolation of queries;
- dynamic SQL construction from user values;
- loading arbitrary SQLite extensions;
- scanning captures/credentials by default;
- external callbacks;
- a listening network service;
- mandatory cloud/LLM use.

An attacker-controlled string in a stored writeup is treated as data throughout import, indexing and display.

The remaining main risks are ordinary parser/resource risks:

- huge files;
- pathological query sizes;
- terminal control sequences;
- corrupted databases;
- accidentally bundled copyrighted/private content.

The file-size/query/result caps, plain-text normalization, output escaping, integrity checks and export policy address those risks without adding a sandbox service.

---

## 30. Implementation priority

### Phase 1 - enough for the event

Implement only:

```text
doctor
index
search
literal
show
verify
test
export
```

with:

- JSONL manifests;
- Markdown/text corpus;
- FTS5 functional detection;
- ripgrep detection;
- pure-Python fallback;
- SHA-256;
- deterministic output;
- safe export.

### Phase 2 - only if actual use justifies it

Possible additions:

- interactive TUI;
- trigram secondary index;
- fuzzy title completion;
- source update checker;
- richer HTML/PDF normalizers;
- per-user notes;
- query history.

None are required for the first event.

---

## 31. Recommended default configuration

```text
index backend preference:
  1. sqlite-fts5
  2. rg phrase fallback
  3. python phrase fallback

literal backend preference:
  1. rg -F
  2. python substring scan

FTS tokenizer:
  unicode61

FTS fields and weights:
  title   8
  aliases 5
  body    1

search roots:
  cards/
  sources/text/

result limit:
  default 10
  hard max 100

query max:
  1024 characters

indexed file max:
  8 MiB

display snippet max:
  600 characters

network during ordinary commands:
  disabled/not used

server:
  none

LLM:
  none
```

---

## 32. Final implementation decision

Build the KB as a directory you can still use if every generated artifact breaks.

If SQLite FTS5 works, ranked search is better.

If FTS5 does not work, ripgrep still searches the canonical files.

If ripgrep is missing, Python still searches the canonical files.

If the index is deleted, the knowledge is still there.

That is the right failure model for a first attack/defend event.

---

## Primary references verified

Retrieved 2026-09-11.

1. SQLite FTS5 Extension  
   https://www.sqlite.org/fts5.html  
   Verified: FTS5 query syntax, quoted strings, phrases, prefixes, NEAR, `unicode61`, trigram behavior, BM25, snippets, external-content synchronization warnings, rebuild and integrity-check behavior.

2. SQLite compile-time options  
   https://www.sqlite.org/compile.html  
   Verified: `SQLITE_ENABLE_FTS5`.

3. SQLite PRAGMA documentation  
   https://www.sqlite.org/pragma.html  
   Verified: `PRAGMA compile_options`.

4. SQLite copyright  
   https://www.sqlite.org/copyright.html  
   Verified: SQLite deliverable code/documentation public-domain status.

5. Python 3.14 `sqlite3` documentation  
   https://docs.python.org/3/library/sqlite3.html  
   Verified: serverless SQLite interface, optional module status, parameter placeholders, `sqlite3.sqlite_version`, SQLite URI/read-only behavior and database errors.

6. Python license  
   https://docs.python.org/3/license.html  
   Verified: PSF License Version 2 and documentation/code licensing notes.

7. ripgrep repository / README  
   https://github.com/BurntSushi/ripgrep  
   https://github.com/BurntSushi/ripgrep/blob/master/README.md  
   Verified: cross-platform availability, line-oriented recursive search and licensing.

8. ripgrep user guide  
   https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md  
   Verified: `-F/--fixed-strings`, automatic filtering, globs, binary behavior, encodings and `--no-config`.

9. ripgrep FAQ  
   https://github.com/BurntSushi/ripgrep/blob/master/FAQ.md  
   Verified: deterministic sorting requirement using `--sort path`, JSON/operational guidance and licensing explanation.

10. ripgrep changelog and releases  
    https://github.com/BurntSushi/ripgrep/blob/master/CHANGELOG.md  
    https://github.com/BurntSushi/ripgrep/releases/  
    Verified: current release 15.2.0 dated 2026-07-15.

11. ripgrep UNLICENSE  
    https://github.com/BurntSushi/ripgrep/blob/master/UNLICENSE

12. ripgrep stable JSON output guidance from the maintainer  
    https://github.com/BurntSushi/ripgrep/discussions/3404  
    Verified: `--json` is the robust machine-readable output path.

---

## Notes on claims

- Local punctuation-query observations in this document were measured in the research environment identified in section 3.2. They are not performance benchmarks.
- Usability thresholds in section 22 are proposed acceptance targets, explicitly not measured performance.
- Event rules beyond the supplied preparation brief were not assumed here. In particular, this architecture does not require a second device, an extra service, an open port or Internet access.
- License/export policy is intentionally conservative. The tool records upstream terms and packaging decisions; it does not make legal determinations on the team's behalf.
