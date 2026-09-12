# Triage Office macros with olevba before reading any VBA

**First useful action.** Run the macro extractor/analyzer once and let it rank the suspicious part
before you read a single line of VBA by hand.

```bash
olevba <DOCUMENT_OR_OLE_FILE>
```

Expected: a report stating whether macros were found plus extracted macro source and any
suspicion/IOC indications the installed build produces. If it reports no macro, that is not a
conclusion — go to `card-rev-oleobj-embedded-objects` and to the file-type check in
`card-rev-tool-family-by-content-type`.

## Symptoms

- A document format artifact arrived with the challenge (or as a "sample") and the flag or config is
  suspected to be inside macro logic.
- Someone wants to open the document in a real office suite to "see what it does".
- The document contains several modules and the relevant logic is buried.

## Prerequisites and assumptions

- A static copy of the document in an isolated working directory. The document is hostile data:
  never open it with macro execution enabled, and never let an office suite "fix" or re-save it.
- `oletools` installed. Stack/version: supported formats and macro heuristics change between releases,
  so read the installed `olevba --help` for exact flags instead of trusting a remembered invocation.
- The oletools documentation is the authority for behavior; this card is only the ordering discipline.

## Diagnostic sequence

1. `olevba <DOCUMENT_OR_OLE_FILE>` → does a macro exist at all, and what does the tool flag as
   suspicious? This single run replaces most manual reading.
2. Read the tool's own risk/IOC lines first → they point at the functions worth reading.
3. Read only the modules the report implicates. Order: auto-execution entry points, then process or
   shell invocation, then network/URL handling, then string deobfuscation helpers.
4. Record concrete indicators (URLs, file paths, mutex/registry keys, encoded blobs) as a short list
   with the module and line they came from.
5. If the macro is obfuscated with a decode routine, decode it as data in an isolated script — never
   by executing the macro.

If the report shows no macros → check the container for embedded objects or a different format branch
(`card-rev-oleobj-embedded-objects`). If the report shows macros but nothing flagged → continue with
a manual pass limited to entry points, because the tool's heuristics are not a completeness proof.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `olevba <FILE>` | macro stream listing with source | Macros exist; the rest of the card applies |
| `olevba <FILE>` | "no macro" / empty macro list | Not proof of safety: check objects and file type |
| `olevba <FILE>` | risk/suspicion indicators | Candidate attack commands worth reading first |
| `olevba <FILE>` | decoded/obfuscation notes | Strings were encoded; decode as data, do not execute |

## Failure modes and things teams stopped doing

- Opening the document to observe behavior. Static triage is the whole point; the repository treats
  ingested artifacts as data precisely so nobody has to run them.
- Treating "no macros found" as "document is clean". The corpus index for oletools records this
  limitation explicitly, and it is also why this card branches to the embedded-object path.
- Hand-reading every module before running the extractor. The tool exists to remove that step.
- Reusing a remembered flag set from a tutorial. oletools output and supported formats change between
  releases; the local `--help` and the tool's own report are the version-correct answer.

## Evidence status

- **Status:** source-supported but untested; version-sensitive by the maintainer's own documentation.
- **What we actually ran:** nothing. No oletools installation was invoked in this worker session and
  no document was processed. Behavior claims are documentation-derived via the repository index.
- **Our adaptation vs the source:** the repository draft REV-006 gave the ordering; we added the
  "no macro is not a safety verdict" branch, the read-only module-ordering rule, and the instruction to
  decode obfuscated content as data rather than executing the macro.

## Sources

- `src-oletools-olevba-30832d42` — the maintainer documentation for the macro extraction/analysis tool,
  including its stated scope and the caveat that heuristics and supported formats evolve.
- `src-oletools-oleobj-7dbd4193` — the follow-on path when macro analysis is inconclusive.
