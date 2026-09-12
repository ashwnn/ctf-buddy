# Triage an unknown binary statically before opening a heavy tool

**First useful action.** Pin the container format, architecture, and linkage with `file` plus a
header dump before you invest a single minute in a disassembler.

```bash
file <ARTIFACT>; readelf -h <ARTIFACT> 2>/dev/null | head -n 20
```

Expected: a format line naming class/machine (for example an x86-64 ELF) followed by an ELF header
block with `Type`, `Machine`, and `Entry point`. If the first line says `data` or an archive type,
the artifact is probably not a compiled binary — go to `card-rev-tool-family-by-content-type`.

## Symptoms

- A challenge hands over one opaque blob and the clock is running; you do not know if it is ELF,
  PE, a script, an archive, or a document container.
- A teammate has already launched a decompiler without ever confirming the architecture.
- `strings` output looks thin and someone is about to declare "it is packed" without evidence.

## Prerequisites and assumptions

- A copy of the artifact on a disposable analysis host. You never execute the artifact to learn what
  it is (repository rule: downloaded files are data, never programs to run).
- `file`, `readelf`, `objdump`, `strings` available. Stack/version: binutils and `file(1)` differ
  between distributions; the wording changes, the field meaning does not.
- Roughly five minutes. This card is deliberately the cheapest step in a longer chain.

## Diagnostic sequence

1. `file <ARTIFACT>` → container, architecture, static/dynamic, PIE or not. If the answer is `data`
   or an archive, stop this card and branch to tool-family selection.
2. `readelf -h <ARTIFACT>` → class (32/64), endianness, machine, type (`EXEC`/`DYN`), entry address.
   `DYN` plus an interpreter means position-independent; fixed addresses in a writeup will not
   transfer directly.
3. `readelf -d <ARTIFACT>` (dynamic artifacts only) → `NEEDED` libraries. Library-heavy binaries put
   most logic outside the file you are reversing; note the libraries before you start browsing.
4. `strings -a -n 8 <ARTIFACT> | head -n 200` → read for URLs, routes, error strings, file paths,
   format strings, and library names. These become xref anchors, nothing more.

If step 1 reports a non-executable container → `card-rev-tool-family-by-content-type`.
If step 1 and 2 succeed but step 4 yields nothing usable → `card-rev-ghidra-decompiler-judgment`
for the stripped/packed decision path. If step 4 yields strong strings → `card-rev-ghidra-string-xref-pivot`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file <ARTIFACT>` | `ELF 64-bit LSB pie executable, x86-64` | Compiled PIE binary; set the matching language/compiler in the analyzer |
| `file <ARTIFACT>` | `PE32+ executable (GUI) x86-64` | Windows target; expect different calling convention and no ELF tooling |
| `readelf -h <ARTIFACT>` | `Type: DYN`, `Entry point 0x<ADDR>` | Shared/PIE object: compute runtime base before trusting addresses |
| `readelf -d <ARTIFACT>` | `NEEDED  libc.so.6` | Substantial logic may live in a library you should triage separately |
| `strings -a -n 8 <ARTIFACT>` | readable route/URL/format text | Candidate xref pivots, not proof of behavior |

## Failure modes and things teams stopped doing

- Using `strings` as a completeness test. Nothing in this corpus supports "no strings means packed":
  stripped or dynamically constructed text legitimately yields little. The repository draft this card
  replaces (REV-001 lineage) already made that stop rule explicit, and the lesson is the same one
  CryptoHack records for opaque blobs generally — a negative heuristic result is not a finding.
- Guessing the architecture from the file extension or size. A wrong guess selects the wrong
  processor language; every decompile after that is fiction.
- Executing the artifact "just to see the usage text". Repository rule 4 treats fetched binaries as
  untrusted data; usage text is obtainable statically, or inside an isolated fixture.
- Running `strings` for ten minutes with changing `-n` values instead of switching to imports and
  decompiler inspection. Variation of a cheap probe is not new information.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session (this worker has no execution tool). The command
  shapes `file` and `strings -a -n 8` were recorded as fixture-verified in the repository's
  2026-09-11 build pass (research/02); they are not re-run here.
- **Our adaptation vs the source:** Ghidra's own beginner training guide is the source for the
  import/analysis flow; the ordering rule, the archive/document branch, and the "empty strings is not
  proof" stop condition are our operational rewrite of the repository draft REV-001.

## Sources

- `src-ghidra-intro-guide-a55dff83` — Ghidra's documented import and analysis flow, and the role of file
  type/architecture in setting up an analysis session.
- `src-dttw-defcon2021-retro-14eb5491` — first-hand evidence that attack/defend service binaries
  are worked under constraint; used only to justify why cheap static triage exists at all.
- `src-cryptohack-intro-401bf309` — the "do not treat every opaque value as a decodable/labelable
  artifact" discipline, applied here to file triage rather than to crypto.
