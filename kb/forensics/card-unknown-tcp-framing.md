# I cannot tell where the messages end: find the framing rule and prove it holds

**First useful action.** Dump the byte stream to a file and test framing hypotheses by *coverage*: a length-prefix or delimiter rule is only real if it explains every byte of at least ten consecutive records, including the last one.

```bash
tshark -r <CAPTURE.pcap> -Y "tcp.stream==<STREAM> && tcp.len>0" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > <OUTDIR>/stream.bin
ls -l <OUTDIR>/stream.bin ; xxd <OUTDIR>/stream.bin | head -n 20
```

Expected: a binary file you can analyse with ordinary tools, plus a first look at repeated header patterns. If the file is empty, `tcp.payload` is not populated in your build — use `-e data.data` on the same flow before rewriting anything.

## Symptoms

- You can see repetitive structure in hex but cannot say where one message ends.
- Extraction tools report one giant "message" or thousands of 1-byte messages.
- Two different parsing attempts both produce plausible-but-incomplete results.

## Prerequisites and assumptions

- The flow is binary or length-delimited text (from card-unknown-protocol-triage).
- Reassembly is trustworthy: the capture contains the handshake and no significant loss.
- Stack/version: TShark 3.6+/4.x; `xxd`, `awk`, and a local Python interpreter for the hypothesis test.

## Diagnostic sequence

1. Check for a repeating header: compare the first bytes of successive candidate records from the length histogram. Interpretation: identical leading bytes at a constant stride indicate a fixed header plus a length field.
2. Test length-prefix hypotheses mechanically: for prefix sizes 1/2/4 bytes and both endiannesses, take the value at offset k and see whether `offset + prefix + value` lands exactly on the next record start. Branch: one hypothesis reaches the end of the buffer with 100% coverage → proceed; none does → test delimiters (0x0A, 0x00, 0x03/0x04-style terminators) and fixed-size records.
3. Control for transport artefacts: retransmissions, out-of-order segments, or segmentation offload on a locally captured host can shift bytes. Branch: `tcp.analysis.flags` shows retransmissions or the capture came from the sending host → reassemble at TCP level and re-extract, or state that boundaries are uncertain.
4. Validate the winning rule on records you did not use to derive it (hold out the last third). Interpretation: a rule that needs special-casing in the middle is probably wrong, or there are two message types with different layouts — check whether record lengths cluster into groups.
5. Write the minimal parser and assert the invariants: every record consumes its declared length, no leftover bytes except a documented partial record at the end, and no negative lengths.

If parsing succeeds but the contents are unstructured → card-unknown-payload-encoding. If the contents are recognisable protobuf/JSON/XML → you now have a decoding task rather than a framing task, and the field-level extraction work belongs to card-tshark-filter-and-fields plus a local parser.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `... -e tcp.payload \| tr -d '\n' \| xxd -r -p > stream.bin` | binary file | Reassembled application bytes for offline analysis |
| `tshark -e tcp.len \| sort -n \| uniq -c` | segment-size histogram | Constant ⇒ fixed records; few huge ⇒ length-prefixed bulk |
| `xxd stream.bin \| head` | repeating headers | Header stride and candidate length-field offsets |
| `tshark -Y "tcp.analysis.flags" -T fields -e frame.number -e _ws.expert.message` | expert warnings | Reassembly caveats that invalidate boundary claims |
| coverage check per hypothesis (`awk` or 15 lines of Python) | percentage of bytes explained | Evidence that the rule is complete rather than approximately right |

## State-changing actions (only if the card changes a host or service)

Not applicable — this card analyses bytes already captured. If you later implement a client for the protocol, point it only at team-owned fixtures (`<LOCAL_FIXTURE>`, `http://127.0.0.1:<PORT>`).

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. The framing rule you derive here is what makes a later exploit or patch test meaningful, because it defines what "one request" means for that service.

## Failure modes and things teams stopped doing

- **Assuming ASCII line framing.** Binary protocols often contain 0x0A bytes inside records, producing many short "lines" that look like a valid text protocol. Rule now: test the delimiter hypothesis against the full byte coverage, not against apparent readability.
- **Parsing before controlling for reassembly.** A locally captured flow can contain oversized segments from segmentation offload, which breaks offset-based length checks. Rule now: check expert flags before believing boundaries.
- **Accepting "mostly works".** Parsers that skip a byte when a check fails hide the real error. Rule now: the parser fails loudly on any invariant violation.
- **Rewriting the same guess repeatedly.** Two failed hypotheses switch you to extraction of raw records plus manual reading of the first few messages, which usually reveals the header by inspection. Rule now: hypothesis → coverage test → pivot, in that order.

## Evidence status

- **Status:** operator-derived, untested (no capture, no `tshark`, no sample stream available here).
- **What we actually ran:** nothing — even the `xxd`/`awk` steps are described rather than executed.
- **Our adaptation vs the source:** this is one of the four decision procedures the brief asked for; no source describes a coverage-metric method for deriving framing, so the method is presented as team practice (our inference), while the extraction mechanics come from the TShark documentation (S028).

## Sources

- `src-tshark-man-page-d914bcdd` — `tcp.payload`/`data.data` extraction and expert information.
- `src-wireshark-follow-stream-00828e3e` — the transcript view used for the first visual pass.
- `src-maplebacon-ad-primer-23bd534f` — understanding the protocol before attacking it.
