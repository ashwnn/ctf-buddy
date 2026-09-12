# Export HTTP objects through the dissector before you carve bytes

**First useful action.** List and export HTTP objects with the dissector's own reassembly first; only carve raw bytes when the protocol-aware path produces nothing.

```bash
tshark -r <CAPTURE.pcap> -Y "http.response" -T fields -e frame.number -e http.host -e http.request.uri -e http.content_type -e http.content_length
tshark -r <CAPTURE.pcap> --export-objects http,<OUTDIR>/http-objects
```

Expected: a table of responses, then files named by the dissector inside `<OUTDIR>/http-objects`. If the folder is empty, the traffic is not decoded as HTTP (card-wrong-dissector), the capture missed response segments (truncation/rotation), or the transfer used a protocol variant this dissector does not export.

## Symptoms

- A capture contains downloads, uploads, or an application returning a file the challenge expects you to recover.
- You need to hash or `file` every transferred artifact before deciding what matters.
- Someone is already piping the whole capture through a carver and drowning in false positives.

## Prerequisites and assumptions

- An HTTP dissector that supports object export (HTTP/1.x responses; support for other protocols such as SMB/TFTP exists in the GUI export dialog, not necessarily via this CLI flag).
- Output directory outside the tracked repository (payloads may be hostile; repo conventions forbid committing them).
- Stack/version: Wireshark/TShark 3.6+; export support is dissector-dependent and the CLI flag exists in TShark 3.0+.

## Diagnostic sequence

1. `-Y "http.response" -T fields …` → branch: responses listed → continue; nothing listed but the flow looks like web traffic → card-wrong-dissector.
2. Export to a scratch directory → `ls -l` and compare exported sizes with the `http.content_length` values you just printed → branch: sizes disagree → transfer was chunked/compressed or the capture is incomplete; treat the exported file as a partial artifact and say so.
3. Triage each artifact **without opening it**: `file`, `sha256sum`, `strings -a -n 8 | head`, and record which frame/stream produced it (card-artifact-connection-correlation).
4. Only if step 3 leaves the artifact unexplained, fall back to raw carving (card-carving-binwalk-foremost) and compare what carving finds against what export already produced.

If an exported artifact is a document/binary that needs behavioural analysis, hand it to the reverse-engineering cards; do not open it in a viewer that runs active content.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <C> -Y "http.response" -T fields -e http.response.code -e http.content_type -e http.content_length` | codes/types/lengths | Inventory before touching bytes |
| `tshark -r <C> --export-objects http,<OUTDIR>` | files written by the dissector | Reassembled response bodies, not raw packet slices |
| `tshark -r <C> -Y "http.request.method==\"POST\"" -T fields -e tcp.stream -e http.content_type` | streams with POSTs | Upload bodies are *not* exported as objects; reconstruct from the stream |
| `file <OUTDIR>/http-objects/*` | detected types | Classify before any viewer is opened |
| `sha256sum <OUTDIR>/http-objects/*` | preimage hashes | Stable identifier for notes, dedup, and cross-source correlation |

## State-changing actions (only if the card changes a host or service)

Not applicable — exports only write files into team scratch space. Two operational side effects still matter: artifacts may contain live flags (keep them out of shared logs), and any viewer used on them is an execution risk.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — no service under test is modified by this card's workflow.

## Failure modes and things teams stopped doing

- **Carving first.** Signature carving ignores protocol framing, so it produces fragments and false positives; the Wireshark User's Guide presents object export as the protocol-aware route and both the export and file-analysis documentation warn that results depend on complete, supported streams (S027, S029). Rule now: export → validate → carve only for leftovers.
- **Assuming the exported file is the original.** Chunked transfer, content encoding, and missing segments mean the exported bytes can differ from what the server stored; the export documentation does not promise byte-identical originals (S027). Rule now: compare exported size against the declared length before asserting provenance.
- **Opening the recovered artifact to "see what it is".** Repo convention treats every downloaded artifact as data; a first-time A/D team's WAF/monitoring misadventure (D0GL0V3R, UMCS 2026) is the same family of self-inflicted risk. Rule now: `file`/`strings`/hash first, container or throwaway VM for anything else.
- Narrower replacement: export → size/type/hash triage → only then decide whether the artifact earns analysis time.

## Evidence status

- **Status:** documentation-derived, untested (no `tshark` available; no capture fixture in this environment).
- **What we actually ran:** nothing. The `file`/`sha256sum`/`strings` command shapes are standard but were not run against real exported objects here.
- **Our adaptation vs the source:** drafted card PCAP-004 described export-then-triage; this version makes the declared-vs-actual length check explicit, because "export succeeded" is the usual false confidence in challenge traffic.

## Sources

- `src-wireshark-export-objects-4056c43f` — export workflow, protocol support, and the limits of reassembled output.
- `src-tshark-man-page-d914bcdd` — `--export-objects` and field-extraction options.
- `src-zeek-file-analysis-4f12a413` — an independent protocol-aware extraction path used as the cross-check.
- `src-d0gl0v3r-umcs2026-c85f0c19` — untrusted-artifact and resource-misuse failure story from a first-time team.
