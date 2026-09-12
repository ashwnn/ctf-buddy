# Pick the analysis tool family from real content type, not the file extension

**First useful action.** Read the first bytes and, if they look like an Office container, list the
archive members — the true content type selects the tool, and the extension is only a hint.

```bash
head -c 16 <ARTIFACT> | xxd; file <ARTIFACT>; unzip -l <ARTIFACT> 2>/dev/null | head -n 30
```

Expected: a magic-string line (`PK\x03\x04`, `MZ`, `\x7fELF`, `%PDF`, script shebang) plus, for a
zip-family container, a member listing naming `word/`, `xl/`, or `ppt/` paths. If `unzip -l` prints
nothing, the artifact is not a zip container — use the magic bytes only.

## Symptoms

- A challenge gives a `.doc`, `.docm`, `.xls`, or a document with no extension at all, and the team
  is unsure whether it belongs in a decompiler, a macro tool, or a text editor.
- Two tools both "open" the file and produce different nonsense.
- Somebody is trying to import an Office document into a software reverse-engineering suite.

## Prerequisites and assumptions

- A static copy of the artifact and a read-only analysis directory.
- `file`, `xxd`/`od`, `unzip` available; `oletools` installed for the Office branch.
- Stack/version: oletools' supported formats and macro heuristics evolve between releases; treat the
  installed `--help` as authoritative for exact flags.

## Diagnostic sequence

1. `head -c 16 | xxd` → magic bytes decide the family: `\x7fELF` compiled ELF, `MZ` compiled PE,
   `PK\x03\x04` zip/OOXML container, `\xd0\xcf\x11\xe0` legacy OLE compound file, `%PDF` document.
2. `file <ARTIFACT>` → independent confirmation. Extension-vs-magic disagreement is itself a finding
   worth writing on the board; renamed containers are a deliberate challenge pattern.
3. Zip-family content (`PK`) → `unzip -l` for a member listing. Names under `word/`, `xl/`, `ppt/`
   identify an Office OOXML package; OLE signature with the same suffix identifies the legacy format.
4. Compile-family content (`ELF`/`MZ`) → `card-rev-static-triage-order`, then
   `card-rev-ghidra-string-xref-pivot` for navigation.
5. Office container → `card-rev-olevba-macro-triage`, then `card-rev-oleobj-embedded-objects` if the
   macro or the member listing points at embedded content.

If the artifact is script or plain text → read it directly; no reverse-engineering tool adds value.
If the magic bytes match no known family → treat it as `data` and hand it to the artifact-recovery
path in `card-misc-partial-credit-artifacts`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `head -c 16 <ARTIFACT> \| xxd` | `00000000: 504b 0304` | Zip-family container: inspect members before opening it |
| `head -c 16 <ARTIFACT> \| xxd` | `00000000: 7f45 4c46` | ELF: normal static/RE tool chain applies |
| `file <ARTIFACT>` | `Composite Document File V2` | Legacy OLE compound document: oletools family |
| `unzip -l <ARTIFACT>` | `word/document.xml`, `vbaProject.bin` | OOXML package; `vbaProject.bin` is the macro payload location |
| `unzip -l <ARTIFACT>` | `zip: not a valid zip file` | Not a zip container despite the extension |

## Failure modes and things teams stopped doing

- Trusting the extension. Challenge authors rename containers on purpose; every branch in this card
  starts from bytes, never from the filename.
- Feeding Office documents to a software decompiler and reading the resulting pseudo-disassembly as
  data. It is container metadata, not code.
- The inverse error: treating a compiled binary as "a document" because `olevba` produced an empty
  report. The repository's S033 note is explicit that a no-macro result does not rule out embedded
  objects, a different document format, or a non-Office file entirely.
- Spending an hour on format identification instead of extracting artifacts. Once the family is
  known, the value is in the members and strings, not in the identification itself.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session (no execution tool in this worker). The
  `file`-family command shape is repository build-pass verified (2026-09-11); `head | xxd`,
  `unzip -l`, and the OOXML-as-zip reasoning were not executed here.
- **Our adaptation vs the source:** the mapping "Office containers → oletools" comes from the
  oletools maintainer documentation we cite. **Researcher inference:** that OOXML packages are zip
  containers whose members are visible with `unzip -l`. That is common format knowledge and is stated
  as our inference, not as a claim from a cited source in this corpus.

## Sources

- `src-oletools-olevba-30832d42` — the supported document families for macro analysis and the explicit
  limitation that "no VBA found" is not a safety verdict.
- `src-oletools-oleobj-7dbd4193` — OLE/embedded-object handling, which is the branch after a container is
  identified.
- `src-ghidra-intro-guide-a55dff83` — the compiled-code branch of the decision.
