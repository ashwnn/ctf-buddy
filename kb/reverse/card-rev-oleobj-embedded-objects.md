# Extract embedded OLE objects and keep their provenance

**First useful action.** List and extract embedded objects into a dedicated directory, then hash and
provenance-label every artifact before anyone looks inside it.

```bash
mkdir -p <ANALYSIS_DIR>/objects && cd <ANALYSIS_DIR>/objects \
  && oleobj <DOCUMENT_OR_OLE_FILE> \
  && sha256sum ./* 2>/dev/null | tee <ANALYSIS_DIR>/objects.sha256
```

Expected: one or more extracted files plus a hash list naming each artifact. If nothing is extracted,
the document may contain no embedded object — record that as a negative result with the document hash,
and move on rather than re-running with random flags.

## Symptoms

- The macro report references a filename, a resource, or a stream that does not appear in the extracted
  macro source.
- The document is unexpectedly large for its visible content.
- A challenge prompt mentions a payload, a second stage, or an "attachment".

## Prerequisites and assumptions

- An OLE/OOXML container already confirmed via `card-rev-tool-family-by-content-type`.
- `oletools` installed; embedded-object support and output naming vary across versions, so confirm
  names from the tool's own output rather than from a tutorial.
- A dedicated output directory. Extracted artifacts are hostile files: they are handled as data, never
  executed, and never opened by an application that can act on them.

## Diagnostic sequence

1. Run the extractor into an empty directory so that everything present is attributable to this run.
2. `file` each extracted object and hash it. Hash-first means a teammate can tell whether they are
   looking at the same artifact you are.
3. Record provenance for each object: parent document name, parent hash, extraction command, tool
   version, timestamp of the run. An artifact without provenance is nearly useless in a team setting.
4. Classify by content, then branch: compiled binary → `card-rev-static-triage-order`; another Office
   container → repeat this card one level down; text or script → read directly; unknown → treat as data
   and route through `card-misc-partial-credit-artifacts`.
5. Only after classification, decide whether the object is the intended payload or a decoy.

If extraction yields an object that is itself a container → recurse once, with the depth written down,
so that a later reader knows how many layers exist. If extraction fails → inspect the container
structure with the archive/format tooling available, and record the failure as a negative finding
instead of concluding the payload does not exist.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `oleobj <FILE>` | extracted object names | Objects exist; each must be triaged separately |
| `oleobj <FILE>` | no output files | No extractable object in the supported format — a real, reportable result |
| `file <OBJECT>; sha256sum <OBJECT>` | type + digest | Classification and identity for team handoff |
| `unzip -l <FILE>` | container member list | Cross-check for objects the extractor did not surface |

## Failure modes and things teams stopped doing

- Double-clicking or executing an extracted object to find out what it is. Repository rule 4 is
  explicit: downloaded/ingested content is data. `file` and strings answer the classification question.
- Extracting into a shared downloads directory and losing the parent link. In a team event, an
  unlabelled binary on a shared share gets attributed to the wrong challenge within minutes.
- Assuming the extraction is complete. Embedded-object support changes between tool versions, and a
  container can hold content the tool does not model; use the container listing as a cross-check.
- Treating the extracted payload as proof of intent. An object's presence shows the document carries
  it, not that the document's logic uses it — check the macro or the document flow before writing that
  down.

## Evidence status

- **Status:** source-supported but untested; version-sensitive in output naming.
- **What we actually ran:** nothing. No extraction was performed in this session; the command family is
  from the tool maintainer's documentation via the repository index, and the provenance/hashing
  workflow is our addition.
- **Our adaptation vs the source:** the repository draft REV-007 covered extraction plus `file`/strings.
  We added the provenance record, the one-level recursion rule with a written depth, and the explicit
  "no object extracted is a reportable negative result" branch.

## Sources

- `src-oletools-oleobj-7dbd4193` — maintainer documentation for embedded-object extraction, including the
  caveat that support and output names can change between versions.
- `src-oletools-olevba-30832d42` — the macro-side path that usually motivates the extraction.
- `src-zeek-file-analysis-4f12a413` — independent precedent that network/file artifacts should be
  inventoried by hash and type before anyone inspects content.
