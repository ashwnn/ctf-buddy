# Carve only after export fails, and validate every carved artifact

**First useful action.** Scan the container for embedded signatures first, then carve into a scratch directory and validate each hit — a signature match is a hypothesis, not a file.

```bash
file <CONTAINER_IMAGE> ; binwalk <CONTAINER_IMAGE> ; foremost -i <CONTAINER_IMAGE> -o <OUTDIR>/foremost -t <TYPE>
```

Expected: `binwalk` prints decimal offsets with signature names, `foremost` writes candidate files under `<OUTDIR>/foremost/<type>/`. If nothing is found but you expect embedded content, the data is likely compressed/encrypted or stored differently (`foremost -h` lists the type names and config `<FOREMOST_CONF>` accepted by your build).

## Symptoms

- You have a disk image, firmware blob, or opaque file that should contain other files.
- Protocol-aware extraction (card-http-object-export, card-zeek-file-inventory) produced nothing, or was not applicable.
- A teammate is about to run a recursive extractor on the only copy of the evidence.

## Prerequisites and assumptions

- Read-only copy of the container, with its hash recorded; generous scratch space (carving produces many candidates).
- Disposable analysis environment: `binwalk -e` shells out to external extractors, so untrusted bytes are handed to other programs. Repo convention forbids executing untrusted artifacts on the analysis host.
- Stack/version: `binwalk` 2.x (maintainer ReFirmLabs) and `foremost` 1.5.x; extractor availability (`unsquashfs`, `7z`, …) determines whether automatic extraction succeeds, and both tools change defaults between releases.

## Diagnostic sequence

1. `file` → identify the container type. Branch: it is a recognised filesystem/image → use filesystem-aware tools first (card-image-triage-memory-and-disk) instead of signature carving.
2. `binwalk <CONTAINER>` (scan only) → note offsets and signature names. Interpretation: a list of *candidate* regions; compressed-format signatures appear inside random data, and offsets near each other usually belong to one embedded object (for example a compressed stream and its header).
3. Carve a copy: `binwalk -e` in a scratch dir, or `foremost -i … -o … -t <TYPE>` for a targeted type list. Branch: `binwalk -e` reports "extractor not installed" → install nothing mid-event; carve manually instead.
4. Validate every candidate: `file`, size sanity, internal end markers (IEND for PNG, EOI for JPEG, central directory for ZIP), and `sha256sum` for the provenance row. Delete candidates that fail validation and say in your notes that they were signature false positives.
5. Only then analyse contents — and treat them as untrusted data.

If a validated carved file is an executable or document, hand it to the reverse-engineering cards. If a validated file is opaque high-entropy data, go to card-unknown-payload-encoding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file <CONTAINER>` | container/filesystem guess | Chooses filesystem-aware vs signature carving |
| `binwalk <CONTAINER>` | offsets + signature names | Candidate regions, not confirmed files |
| `binwalk -e <CONTAINER>` | extraction log + output dir | Automatic extraction; depends on external tools |
| `foremost -i <IMG> -o <OUT> -t jpg,pdf,zip` | per-type output dirs | Targeted carving with fewer false positives than "all types" |
| `dd if=<IMG> bs=1 skip=<OFFSET> count=<N> of=<OUT>` | exact byte slice | Manual carve once you know the real start/length |
| `file <OUT>/* ; sha256sum <OUT>/*` | types + hashes | Validation and provenance before interpretation |

## State-changing actions (only if the card changes a host or service)

Not applicable to the target service. Two host-side cautions: run extractors in a disposable VM/container, and never write carving output into the tracked repository (recovered content may be hostile and is frequently confidential).

## Exploit → patch pair (web/service cards where applicable)

Not applicable in this lane: carving changes no service. The reusable judgment is the ordering rule — framed extraction beats signature carving whenever the transport is understood, because carving discards framing, filenames, and timestamps.

## Failure modes and things teams stopped doing

- **Carving as the first move.** It produces fragments, duplicates, and false positives, and it cannot recover compressed or encrypted containers; the protocol-aware path (S027, S029) preserves framing and metadata. Rule now: export → inventory → carve leftovers only.
- **Extracting on the evidence host.** `binwalk -e` invokes other programs on attacker-controlled bytes, which is exactly the case repo conventions forbid running on a shared or tracked filesystem. Rule now: extraction happens in a disposable environment, and the original container stays untouched and hashed.
- **Losing the offset.** A carved file without its byte offset cannot be correlated back to structure in the original image. Rule now: every carved artifact carries its offset and the tool/version that produced it (feeds card-artifact-connection-correlation).
- **Trusting size alone.** A correctly sized candidate can still be padding or a decoy. Rule now: validate with `file` plus an internal-structure check before analysis.

## Evidence status

- **Status:** operator-derived and tool-behaviour-sensitive; untested (neither `binwalk` nor `foremost` is installed here, and no container image exists in this environment).
- **What we actually ran:** nothing.
- **Our adaptation vs the source:** drafted note PCAP/MISC-005 ranked artifact recovery; this card converts it into a carving-specific order of operations plus a validation step. **Disclosed gap:** we hold no verified maintainer-documentation record for `binwalk` or `foremost` in this session (the orchestrator reported such records exist in `sources/verified-index.jsonl`, which this worker could not read), so the tool-specific flag names are marked as requiring local confirmation via `binwalk --help` and `foremost -h`.

## Sources

- `src-wireshark-export-objects-4056c43f` — protocol-aware extraction, the preferred first step.
- `src-zeek-file-analysis-4f12a413` — metadata-first inventory as the alternative to blind carving.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time-team failure modes about running defensive/analysis processes carelessly.
