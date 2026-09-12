# Grep for trust-boundary sinks before reading routes line by line

**First useful action.** Run one keyword sweep over the service source, then follow only the hits
that sit on a request-to-sink path.

```bash
rg -n --no-config -e 'session|current_user|req\.user|user_id|user_guid|owner|admin' \
  -e 'open\(|send_file|send_from_directory|os\.path\.join|readFile|fs\.readFile' \
  -e 'subprocess|os\.system|exec\(|shell=True|child_process' \
  -e 'requests\.|urlopen|fetch\(|http\.Get|axios\.' \
  -e 'pickle|yaml\.load|deserialize|TypeNameHandling|getattr|globals\(' \
  -e 'execute\(|rawQuery|SELECT |INSERT |UPDATE ' \
  -e 'upload|multipart|extractall|tarfile|zipfile' \
  -e 'random\.|rand\(|Math\.random|uuid1|token' \
  <SERVICE_SRC>/ | head -n 200
```

Expected: a few dozen hits grouped by boundary type. Rank them by "is this reachable from a route
with attacker input?", not by how interesting the keyword looks. If the tree is large, exclude
vendored/generated directories first — grepping a bundled dependency list wastes the opening
minutes.

## Symptoms

- You received an unfamiliar service tree and have minutes, not hours.
- A previous keyword pass produced too many hits or none.
- The team is about to start reading the entrypoint top-down.

## Prerequisites and assumptions

- Local read access to the source, and `rg` (or `grep -Rn` as fallback).
- A rough idea of the language so the patterns match real call sites.
- Stack/version: the patterns are language-specific; extend them for Go, PHP, Rust, or Java as
  needed. Keyword absence is never evidence of safety.

## Diagnostic sequence

1. Identify the framework and entrypoint; find where routes are registered.
   → Gives you the attacker-reachable surface.
2. Sweep for the eight boundary families (identity, file, process, outbound, deserialization/dynamic
   dispatch, raw query, upload/extract, randomness/token).
   → Produces candidate sinks.
3. For each candidate, walk *backwards* to a route parameter. → Discard sinks with no
   attacker-controlled input; they are noise, not findings.
4. Rank by "what does this sink let an attacker read or change?" → Flag-reading sinks first
   (`card-web-025-flag-read-path-priority`).
5. Write the ranked list into the shared service board before touching anything.

If a boundary family returns zero hits, check the framework's helper names before concluding the
boundary does not exist — indirect calls hide from keyword greps.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'getattr\|globals\(' <SVC>` | a dynamic dispatch site | A string may select a callable; check whether the namespace is broad (`src-enowars-cyberalchemist-readme-3cef120f`). |
| `rg -n 'pickle\|TypeNameHandling\|yaml\.load\(' <SVC>` | a deserializer | Untrusted data may become code or arbitrary type construction (`card-web-018-deserialization-http-path`). |
| `rg -n 'os\.path\.join\|open\(' <SVC>` | file paths derived in code | Check for confinement (`card-web-003-traversal-source-recovery`). |
| `rg -n 'session\[\|req\.user' <SVC>` | session reads | The trusted identity sources; compare with request-supplied ids. |
| `rg -n 'random\.\|Math\.random\|uuid1' <SVC>` | non-crypto randomness | Token/authorization material may be predictable (`src-enowars-buggy-readme-f85b8d0e`, `src-thomasweigold-saarctf2025-eaa12cba`). |

## Failure modes and things teams stopped doing

- Reading the whole tree top-down. The indexed A/D services are small enough that this sometimes
  works, but the same habit fails the moment a service ships with a framework, a vendor directory,
  or a build output tree — sweep first, read second.
- Reporting keyword hits as vulnerabilities. A hit is a *candidate*; it becomes a finding only when
  a route reaches it with attacker input. This is the same discipline the #misec RuCTFE 2019
  retrospective describes as the difference between duplicated exploration and shared,
  actionable findings (`src-duchyoftaco-misec-ructfe2019-332d8e5b`).
- Trusting dynamic dispatch because "the service is a CTF toy". ENOWARS 3 CyberAlchemist was indexed
  precisely because a string-to-callable path reached a broad namespace
  (`src-enowars-cyberalchemist-readme-3cef120f`).
- Skipping the randomness family because it "is not a web bug". Predictable tokens in ENOWARS 4
  Buggy and SaarCTF 2025 Routerploit were authorization bypasses, not crypto trivia
  (`src-enowars-buggy-readme-f85b8d0e`, `src-thomasweigold-saarctf2025-eaa12cba`).
- Assuming SQL is safe because an ORM is present. Grep the raw-query escape hatch too:
  `card-web-013-raw-query-boundary-hunt`.
- Using a good writeup as a substitute for reading the code at hand. Google CTF's Postviewer v3
  release is indexed as an example of mapping source review to an exploit path, not as a template to
  paste (`src-google-ctf-postviewer3-r06-fd1f5b82`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. The sweep was not executed in this session; the pattern list is
  an operator synthesis over the indexed failure modes, not a measurement.
- **Our adaptation vs the source:** the individual boundary families come from separate indexed
  sources. This card merges them into a single ordered opening sweep. That ordering is our addition
  and is explicitly a heuristic: it can miss bugs that no keyword predicts, so treat the sweep as a
  prioritisation tool, never as coverage.

## Sources

- `src-enowars-cyberalchemist-readme-3cef120f` — dynamic dispatch to a broad namespace in a real A/D service.
- `src-enowars-buggy-readme-f85b8d0e` — predictable token and authorization logic defects.
- `src-thomasweigold-saarctf2025-eaa12cba` — IDOR plus predictable-token exploitation in SaarCTF 2025.
- `src-czechcyberteam-faust2024-todolist-225eeec1` — deserialization and identity collision in FAUST CTF 2024.
- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — weak ownership and duplicated/redundant analysis in a real A/D team.
- `src-google-ctf-postviewer3-r06-fd1f5b82` — official web challenge release showing source review driving an
  exploit path.
