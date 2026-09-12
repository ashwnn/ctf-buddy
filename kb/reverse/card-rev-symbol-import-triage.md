# Separate library code from program logic before reading a function

**First useful action.** List the dynamic imports and the defined symbols so you can tell at a glance
which functions are the program's own logic and which are library machinery.

```bash
nm -D --undefined-only <ARTIFACT> | head -n 60; nm -D --defined-only <ARTIFACT> | head -n 60
```

Expected: an undefined (imported) list naming library entry points, and a defined list naming the
exported symbols of the artifact itself. If both lists are empty the artifact is probably fully
stripped and statically linked — skip to the branch below rather than repeating the command.

## Symptoms

- The call graph is dominated by names you recognize from libc and you cannot find the code you came
  for.
- You are about to spend time understanding a parsing routine that turns out to be a standard
  library function.
- A binary is statically linked, so imports give you nothing and you need a different discriminator.

## Prerequisites and assumptions

- ELF artifact, `nm`/`objdump` available; symbols may be stripped (this is the normal case for
  challenges).
- You accept that "which functions are library code" is a heuristic: function signatures, error
  strings, and well-known constants are evidence, not proof.

## Diagnostic sequence

1. `readelf -d <ARTIFACT>` → `NEEDED` libraries. If there are none, the artifact is statically linked:
   library-vs-program separation must come from string signatures instead.
2. `nm -D --undefined-only <ARTIFACT>` → the import list. Rank imports by consequence:
   process execution, file access, network, memory management, string comparison.
3. `nm -D --defined-only <ARTIFACT>` → exports. A short or empty list with a functioning program
   means the program's own functions have no names — expect to name them yourself.
4. In the analyzer, start from callers of the consequence-ranked imports, then work inward. Callers of
   an execution or file-write import are far closer to a security decision than a random function.
5. Skip anything whose only role is copying, comparing, or formatting standard data unless a caller
   passes it attacker-controlled input.

If the import list is empty → build the separation from strings (library error text and version
banners) and from repeated function shapes. If an import list exists but nothing looks consequential
→ the interesting logic may be in a bundled library; check `NEEDED` entries before assuming the
binary is self-contained.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `readelf -d <ARTIFACT>` | `NEEDED  libc.so.6` | Logic may live outside the artifact; scope your analysis |
| `nm -D --undefined-only <ARTIFACT>` | `U execve@GLIBC` | Imported execution capability: high-value anchor for finding its caller |
| `nm -D --defined-only <ARTIFACT>` | `T  main` only | Few or no program symbols: expect to name functions from behavior |
| Analyzer external-symbol list | entries marked as external/thunk | Navigation anchors, not code to read |

## Failure modes and things teams stopped doing

- Reversing a library routine because it sits on the flag path. The decision is in the caller: whose
  input reaches it, with what bounds, and what the caller does with the result.
- Reading an entire `main` top to bottom to find a vulnerability. The repository's RuCTFE-era
  operations guidance and the ENOWARS team retrospectives both push toward source/behavior-focused work
  with an explicit owner per codebase, precisely because unbounded reading is where time disappears.
- Assuming "stripped" means "unanalyzable". It means you have no names; imports, strings, and callers
  of sensitive functions still give you an entry point.
- Treating a bundled library version as evidence of a known CVE. Incidentally vulnerable dependencies
  are not the intended challenge path, and exploiting them can be out of the intended scope.

## Evidence status

- **Status:** source-supported but untested; the library-separation heuristic is inference.
- **What we actually ran:** nothing in this session. `nm`/`readelf` command shapes are standard and
  share the fixture-verified `readelf` family from the repository's 2026-09-11 pass, but no command
  in this card was executed here.
- **Our adaptation vs the source:** **Researcher inference** — ranking imports by consequence
  (exec/file/network) as the first navigation heuristic. It follows from Ghidra's documented
  import/analysis flow but is not a documented Ghidra recommendation. The service-ownership argument is
  attributed to the team retrospectives, not to a tool vendor.

## Sources

- `src-ghidra-intro-guide-a55dff83` — documented use of symbols/imports during analysis setup.
- `src-enowars-checker-tenets-bf4b0ac7` — organizer-side framing of what a service must do, which
  is what you are looking for in the code: parsing, state, and the flag path.
- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — team experience that unbounded code reading and unclear ownership
  wastes competition time; the reason this card pushes toward ranked, targeted reading.
