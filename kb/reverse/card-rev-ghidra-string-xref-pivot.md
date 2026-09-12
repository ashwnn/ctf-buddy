# Pivot from one distinctive string to the security-relevant function

**First useful action.** Pick the single most distinctive string (an error message, route, filename,
or format string), show its references, and climb to the function that decides security.

```bash
strings -a -t x -n 10 <ARTIFACT> | grep -inE "<DISTINCTIVE_TOKEN>"
```

Expected: one or a few file offsets for the string, plus the surrounding literal text. If nothing
matches, the string may be dynamically constructed or encoded — the token is wrong or the artifact
builds text at runtime.

## Symptoms

- You have a decompiler open with hundreds of functions and no idea which one matters.
- A challenge mentions a specific message, header, filename, or endpoint that must exist in the
  binary somewhere.
- The interesting logic is not at `entry` and not at `main`.

## Prerequisites and assumptions

- The artifact imported into Ghidra (or an equivalent analyzer) and analysis completed. Creating the
  project is step zero; skipping the analysis run leaves references unbuilt.
- At least one distinctive literal from the challenge text, `strings` output, or the runtime behavior
  observed in an isolated fixture.
- Stack/version: Ghidra UI labels and analysis options change between releases; the workflow
  (locate literal → references → referencing function → callers) is stable.

## Diagnostic sequence

1. Find candidates: `strings -a -t x -n 10 <ARTIFACT>` and rank literals by specificity. Prefer
   "invoice_not_found" over "error"; prefer a route or filename over a word.
2. Locate the literal in the analyzer (search for the exact bytes) → confirms the string survived
   into the binary rather than being constructed at runtime.
3. Show references to that address → yields one or more code addresses. Zero references is the
   branch point: text may live in a table, be built on the stack, or be reached by computed offset.
4. Open the referencing function in the decompiler → the string's use (log, error path, comparison,
   format argument) tells you how close you are to the decision.
5. Climb callers until you reach a function that consumes external input (socket, stdin, file, argv)
   or makes an authorization decision. Stop when you can name the input and the decision.

If references exist → continue in `card-rev-ghidra-decompiler-judgment` to decide how much of the
decompiler output you should trust. If references do not exist → check for stack-built strings by
looking for suspicious immediate/`mov` sequences near the use site, and treat that as a separate,
more expensive task rather than cycling through more tokens.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `strings -a -t x -n 10 <ARTIFACT>` | `<offset> <literal>` | Literal plus its file offset: candidate search key |
| `strings -a -n 4 <ARTIFACT>` | short fragments | Short-string scan; more noise, occasionally finds split literals |
| Ghidra Search → For Strings (or byte search) | list of matching addresses | Confirms the literal is present in the image |
| Ghidra references view on that address | callers/data refs | Each ref is a candidate use site; zero refs is a real result |
| Decompiler view of the referencing function | C-like pseudocode | Tells you whether the literal is compared, printed, or used as a key |

## Failure modes and things teams stopped doing

- Reversing from `main` downward because "it is the entry point". For service binaries the security
  decision is often deep in a handler; the string-pivot route starts at the question you actually
  have instead of at the program's beginning.
- Treating the decompiler's variable names and types as facts. Ghidra's guide exposes both a listing
  view and a decompiler view precisely because the decompilation is a reconstruction; when the two
  disagree about a comparison or a structure field, the listing wins. **Researcher inference:** we
  promote that into a rule — resolve any contradiction in the disassembly before building an exploit
  or a patch on top of it.
- Trusting a string's meaning without checking its use. A literal that looks like a credential check
  is sometimes just a debug message; the referencing comparison is what matters.
- Over-decoding an obfuscated literal in the reverse-engineering phase and burning the clock. If the
  string is encoded, note it, move to imports/behavior, and come back only if it is on the flag path.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session. No Ghidra instance was started by this worker,
  and no artifact was analyzed; the workflow is derived from Ghidra's documented strings/xref and
  decompiler features plus the repository draft REV-003.
- **Our adaptation vs the source:** the repository draft supplied the string→xref→caller order. We
  added the "zero references is a real result" branch, the listing-wins-over-decompiler tiebreak
  (labelled as inference), and an explicit stop condition based on reaching input or an authorization
  decision rather than on understanding the entire binary.

## Sources

- `src-ghidra-intro-guide-a55dff83` — Ghidra's documented strings, cross-reference, and decompiler
  navigation features.
- `src-dttw-defcon2021-retro-14eb5491` — evidence that service binaries, not just standalone
  crackmes, are the target in attack/defend work; the reason this card aims at handlers and trust
  boundaries instead of at entry points.
