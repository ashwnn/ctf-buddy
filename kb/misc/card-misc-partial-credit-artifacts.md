# Bank partial credit from artifacts before you understand the challenge

**First useful action.** Extract, hash, and label every artifact you can reach safely, then hand each one
to the matching specialist path while one person keeps working on the challenge itself.

```bash
mkdir -p <WORK_DIR>/artifacts && cd <WORK_DIR>/artifacts \
  && tshark -r <PCAP> --export-objects http,./ 2>/dev/null; \
  file ./* 2>/dev/null; sha256sum ./* 2>/dev/null | tee <WORK_DIR>/artifacts.sha256
```

Expected: named objects with a type and a digest list. If nothing is exported, the capture may be
encrypted, truncated, or not HTTP — record that, then use protocol-level extraction or raw stream
carving rather than repeated attempts at the same exporter.

## Symptoms

- The challenge combines a capture, a document, a binary, or an unusual protocol and full understanding
  will take longer than the clock allows.
- A teammate is deep in protocol reconstruction while clearly recoverable material sits untouched.
- You need any points, not all points.

## Prerequisites and assumptions

- At least one artifact boundary you can cross safely without executing anything.
- `file`/hash tooling and an isolated working directory; extracted content is hostile data
  (repository rule 4).
- A rule-aware mindset: extraction happens on data already in your possession, not by probing other
  teams' systems.

## Diagnostic sequence

1. List extraction opportunities in order of cost: exported protocol objects, embedded objects in
   documents, drawn text from a device capture, plain files inside archives.
2. Extract into a dedicated directory. Never extract into a shared or default downloads directory —
   provenance dies there.
3. For each artifact: type it, hash it, and write one line of provenance (parent artifact, extraction
   command, tool version).
4. Classify and route: image/office/binary/capture/text. Each class has a next owner; see
   `card-rev-tool-family-by-content-type` for containers and
   `card-misc-hid-descriptor-as-spec` for device-capture text.
5. Submit or use whatever the artifacts directly yield (a key, a decoded message, a flag fragment)
   before investing in full challenge understanding. Partial credit now beats a complete answer later.

If the extraction yields nothing → check the capture's completeness and whether the protocol was
recognized at all; a failed export is a hypothesis about the capture, not a proof that no artifact
exists. If the extraction yields too much → rank by type and size and triage the smallest, most
structured items first, because those are cheapest to interpret.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark --export-objects http,./` | a directory of files | Reassembled objects available; hash and classify each |
| `file ./<OBJECT>` | type name | Determines the specialist path to hand it to |
| `sha256sum ./*` | digest list | Identity for team handoff and dedup across analysts |
| empty export directory | no files | Wrong protocol, truncated capture, or encrypted content |
| `oleobj <DOC>` output | extracted object files | Document-side artifact recovery path |

## Failure modes and things teams stopped doing

- Chasing full comprehension first. In a timed hybrid event, artifact-first recovery is usually the
  cheapest points on the board, and it can also reveal the challenge's mechanism.
- Executing a recovered artifact to find out what it is. `file` and strings answer that question; the
  rule against executing ingested content exists precisely for this moment of curiosity.
- Extracting into a shared directory with no labels. Unlabeled artifacts get attributed to the wrong
  challenge and then re-extracted by someone else.
- Assuming an exporter's output is byte-identical to the original transfer. Reassembly and export
  behavior depends on the protocol dissector and capture completeness, so record the method and keep the
  source capture for re-extraction.

## Evidence status

- **Status:** source-supported but untested; the exporter command is documentation-derived and was not
  executed anywhere in this project (neither `tshark` nor Wireshark is available in the build fixture).
- **What we actually ran:** nothing. `file` and hashing were exercised in the repository's 2026-09-11
  build pass on trivial files; that does not validate this extraction chain.
- **Our adaptation vs the source:** repository draft MISC-005 supplied the artifact-first idea; we added
  the provenance line, the cost-ordered extraction list, the "empty export is a hypothesis" branch, and
  the rule that partial credit is claimed before understanding completes.

## Sources

- `src-wireshark-export-objects-4056c43f` — documented object export from captures, including the caveat that
  support is protocol-dependent and does not guarantee byte-identical originals.
- `src-zeek-file-analysis-4f12a413` — file inventory by type and hash as a discipline before inspection.
- `src-oletools-oleobj-7dbd4193` — the document-side artifact extraction path.
- `src-metactf-key-evidence-9f635ac3` — organizer writeup recovering text from a device capture;
  an example of artifact-level partial credit.
