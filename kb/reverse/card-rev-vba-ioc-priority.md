# Rank macro indicators by consequence instead of reading VBA top to bottom

**First useful action.** Write the indicator list from the macro report into five consequence buckets
and work them in order: execution, network, persistence, file/registry, obfuscation.

```bash
olevba <DOCUMENT_OR_OLE_FILE> > <ANALYSIS_DIR>/macro-report.txt; less <ANALYSIS_DIR>/macro-report.txt
```

Expected: a report you can search for the buckets — shell/process invocation, URL or socket handling,
persistence hints, path/registry writes, and decode helpers. If the report contains no indicators at
all, the macro logic is likely data-driven or obfuscated; keep the report as evidence and treat the
obfuscation bucket as first priority.

## Symptoms

- A macro report lists dozens of hits and you need a triage order rather than volume.
- The challenge asks for specific recovered material (a URL, a key, a command) and you want the
  cheapest place to look.
- Different analysts disagree about which module matters.

## Prerequisites and assumptions

- The extraction/analysis report already produced by `card-rev-olevba-macro-triage`.
- A written-down definition of "consequence" for this challenge: in a CTF the question is usually
  "what does this document fetch, execute, or hide", not "how would a SOC score it".
- Tool version recorded with the report; the buckets are ours, the indicator text is the tool's.

## Diagnostic sequence

1. Bucket 1 — execution: anything that launches a process, interprets a string, or calls a shell.
   These reach outside the document and matter most.
2. Bucket 2 — network: URLs, hosts, ports, user agents, or socket APIs. This is usually where a
   challenge hides its download target or its exfiltration format.
3. Bucket 3 — persistence: registry keys, startup paths, scheduled tasks, or names that look like
   identifiers rather than code.
4. Bucket 4 — file/registry reads and writes: paths reveal configuration and often the flag's storage
   location.
5. Bucket 5 — obfuscation helpers: string concatenation, character-code math, or decode loops. Decode
   the data in an isolated script; do not run the macro to see the result.
6. Cross-check the top two buckets against the challenge prompt. If nothing in the top buckets matches
   the prompt, re-run the file-type decision — you may be looking at the wrong artifact.

If bucket 1 and 2 are empty but the document is clearly the intended artifact → the payload is probably
an embedded object or a second stage, so branch to `card-rev-oleobj-embedded-objects`. If the only
content is an obfuscation helper → decode it as data, and if the decoded result is text, hand it to the
encoding rules in `card-crypto-classify-before-decoding` rather than guessing a cipher.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `olevba <FILE> > <OUT>` | saved report | Evidence you can re-search and hand to a teammate |
| report line naming a process/shell API | macro invokes execution | Highest-value bucket: trace the argument string |
| report line naming a URL/host | network capability | Likely download/staging target or exfiltration |
| report line naming a path/registry key | file/persistence access | Points at configuration and stored secrets |
| report line naming string-building helpers | encoding/obfuscation | Data to decode offline, never to execute |

## Failure modes and things teams stopped doing

- Sorting indicators by "this looks scary" instead of by what the challenge asks for. The corpus's
  CryptoHack-based rule applies generally: plausible-looking output is a lead, and the answer must
  survive independent verification.
- Running the macro in a sandbox to observe the network request when the URL is already a literal in
  the source. Dynamic analysis adds a machine, a snapshot, and a rule question; static extraction
  answers most CTF questions.
- Assuming the first hit is the payload. Macro code frequently contains decoy or stale logic copied
  from public toolkits.
- Trusting one tool's report as complete. Where a bucket is suspiciously empty, look at the raw
  extracted source before concluding the capability is absent.

## Evidence status

- **Status:** source-supported but untested; bucket ordering is researcher inference.
- **What we actually ran:** nothing. No oletools run happened in this session, and no document was
  examined. The tool's stated ability to extract macros and surface indicators is
  documentation-derived; the five-bucket ranking is our operational construction.
- **Our adaptation vs the source:** the repository draft REV-006 told us to prioritise auto-execution
  hooks and shell/network calls. We kept that substance, removed the assumption that the tool itself
  labels every entry point (that depends on build/version), and made the challenge prompt the
  tiebreaker.

## Sources

- `src-oletools-olevba-30832d42` — documented macro extraction and indicator reporting, plus the warning
  that macro heuristics and supported formats evolve.
- `src-cryptohack-intro-401bf309` — the corpus-wide "verify, do not assume" discipline applied to tool
  output rather than to encoded strings.
