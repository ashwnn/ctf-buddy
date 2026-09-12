# Source record conventions (`sources/manifest.jsonl`)

One JSON object per line. JSONL (not YAML/TOML) so the repo needs no parser
dependency and records can be appended by parallel workers and merged.

## Required fields

| Field | Notes |
|---|---|
| `source_id` | `src-<slug>-<first8 of sha256(canonical_url)>`; assigned once, never regenerated |
| `title` | As published |
| `author` | Person, team, or organization. Specific — not "GitHub user" |
| `team` | Team/organization slug if the author is a team; `null` otherwise |
| `canonical_url` | Real, resolvable, non-tracking URL |
| `source_type` | `writeup` \| `article` \| `docs` \| `repo` \| `talk` \| `tool` \| `advisory` \| `dataset` |
| `event` | CTF/event name and year when applicable, else `null` |
| `retrieved_at` | ISO-8601 UTC date the URL was actually checked |
| `retrieval_method` | `manual-save` \| `http-fetch` \| `repo-clone` \| `metadata-only` |
| `license_expression` | SPDX-ish string, or `"unknown"` |
| `redistribution` | `allowed` \| `allowed-with-attribution` \| `private-only` \| `metadata-only` \| `unknown` |
| `storage` | `snapshot-text` \| `metadata-only` |
| `content_sha256` | Required when `storage` is `snapshot-text`; else `null` |
| `primary` | `true` when the author is the team that did the work, the tool maintainer, or the organizer |
| `notes` | One line: what this source is used for, and its limitations |

## Optional fields

`publisher`, `local_path`, `upstream_revision`, `etag`, `last_modified`,
`previous_urls`, `duplicate_of`, `verified_at`, `verification_method`.

## Policy

- `unknown` license behaves like `metadata-only` for anything shareable:
  cite it, do not redistribute its text.
- A source is **not** stored locally unless reuse permits it. Cards summarize
  and link; they never paste article prose.
- `primary: true` is what the corpus quota counts. Aggregator indexes, search
  result pages, and link collections are `primary: false` and cannot satisfy
  the "verified primary sources" target on their own.

## Verification

`tools/ctfctl/kb.py verify` checks structural validity (required fields, ID
format, duplicate URLs/hashes, card→source resolution). `--check-urls` (online
only, opt-in) confirms that `canonical_url` values still resolve; that must be
run as part of `prep-online`, never during the event.
