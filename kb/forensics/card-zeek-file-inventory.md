# Inventory transferred files with Zeek instead of extracting everything

**First useful action.** Run Zeek over the capture, then read `files.log` as a sortable inventory of every file transferred — MIME type, size, and hashes — before you extract a single payload.

```bash
cd <OUTDIR>/zeek-<RUN_TAG> && zeek -C -r <CAPTURE.pcap> ; head -n 1 files.log ; cat files.log | zeek-cut ts fuid mime_type filename total_bytes sha256 tx_hosts rx_hosts
```

Expected: one row per observed file flow with a MIME guess, byte count, and hashes. If `files.log` is missing, the capture contained no supported file transfers, the protocol was not one Zeek handles, or Zeek failed on the input — read `reporter.log` before concluding "no files".

## Symptoms

- Many distinct files cross the capture and you need to rank them without extracting megabytes.
- You want a second, independent artifact inventory to cross-check Wireshark's object export.
- You need to answer "which file was transferred by which host, and when" at scale.

## Prerequisites and assumptions

- Zeek installed and able to read the capture; writable scratch directory (Zeek writes several logs into the working directory — never run it inside the repo tree).
- `zeek-cut` available for column selection; otherwise read the TSV headers directly.
- Stack/version: our source record is the 8.1.1 documentation; older or newer builds may load extraction policies differently, so verify locally.

## Diagnostic sequence

1. `zeek -C -r <CAPTURE.pcap>` in a dedicated directory → branch: `files.log` created → continue; `reporter.log` shows errors → fix the input path/format first.
2. Sort the inventory by size and by MIME type → branch: an expected type (executable, archive, office document, image) appears → prioritise; everything is `application/octet-stream` → the transfer is encrypted or only partially understood (card-unknown-payload-encoding).
3. Cross-check one row against Wireshark's view of the same file (`--export-objects` size, or `http.content_length`) → agreement strengthens extraction; disagreement means one tool saw an incomplete stream. Record which you trust and why.
4. Extract only the selected files (by hash/fuid) rather than the whole inventory, then triage as untrusted data.

If a file's MIME type is wrong or the sizes look impossible, go to card-wrong-dissector-encapsulation. If you have the artifact but not its origin, go to card-artifact-connection-correlation.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `zeek -C -r <CAPTURE.pcap>` | log files in cwd | Full protocol log set for this capture |
| `... \| zeek-cut ts fuid mime_type filename total_bytes sha256` | TSV rows | Sortable artifact inventory with stable IDs |
| `sort -t$'\t' -k4 -nr files.log` | largest transfers first | Where to spend first analysis minutes |
| `grep -c '^' files.log` | number of file flows | Whether "a file" is rare or routine in this capture |
| `cat reporter.log` | warnings/errors | Whether Zeek silently skipped streams |

## State-changing actions (only if the card changes a host or service)

Not applicable to the target service. On the workstation, Zeek writes multiple log files into the current directory — run it in a dedicated scratch folder so it cannot overwrite anything tracked, and delete or archive the folder per event policy.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — Zeek analysis does not modify a service. If an extracted artifact turns out to be attacker tooling, the follow-up work belongs to the reverse-engineering and attack-defend cards.

## Failure modes and things teams stopped doing

- **Extracting everything "just in case".** It burns disk, floods the notes, and creates untrusted files nobody tracks; the file-analysis framework exists precisely to let you see metadata first (S029). Rule now: inventory, then extract by hash.
- **Trusting one extractor's completeness.** Zeek's and Wireshark's reassembly differ, and both depend on having the whole stream (S029, S027). Rule now: cross-check a size/hash pair between two tools before making a provenance claim.
- **Running analysis tools inside the service tree.** Maple Bacon's patching retrospective separates deployable code from mutable runtime state (src-maplebacon-faustctf-patcher-bf21013c); our extension of that principle is a dedicated scratch directory for every analysis run, so generated logs can never appear as service modifications.
- **Reading only the filenames.** Attackers choose reassuring filenames; hash and MIME type are the durable identifiers. Rule now: rank by hash/type, not by name.
- Narrower replacement: run Zeek → sort inventory → cross-check one row → extract selectively → hash and label.

## Evidence status

- **Status:** documentation-derived, untested (Zeek is not installed in this environment).
- **What we actually ran:** nothing — commands and `zeek-cut` usage are taken from the Zeek file-analysis documentation (S029) and require local version verification.
- **Our adaptation vs the source:** drafted card PCAP-005 stopped at "use Zeek logs"; this version adds the cross-tool size/hash check and the scratch-directory rule, which are the two failure modes we can actually foresee for a first-time team.

## Sources

- `src-zeek-file-analysis-4f12a413` — files.log fields, extraction model, and framework limits (version-pinned documentation).
- `src-wireshark-export-objects-4056c43f` — the independent extraction path used for cross-checking.
- `src-maplebacon-faustctf-patcher-bf21013c` — separation of deployable code from mutable runtime state, applied here to analysis scratch space.
