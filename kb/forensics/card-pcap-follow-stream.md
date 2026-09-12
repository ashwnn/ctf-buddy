# Reconstruct one stream and record its index before interpreting it

**First useful action.** Select any packet in the candidate flow and open Follow → TCP Stream, then write down the stream index that the follow window shows — that index is the reproducible key for every later CLI command.

```bash
tshark -r <CAPTURE.pcap> -q -z follow,tcp,ascii,<STREAM>
```

Expected: an ordered transcript with client bytes and server bytes separated. If the transcript is empty, the stream index is wrong for this capture or the conversation only exists in the other direction — re-derive the index with `tshark -r <CAPTURE.pcap> -T fields -e tcp.stream | sort -n | uniq -c`.

## Symptoms

- Packets are interleaved across several conversations and the request/response is unreadable in the packet list.
- You need the exact request bytes, credentials, object IDs, or uploaded payload from a flow.
- A teammate is copy-pasting packet payloads by hand from the packet-detail pane.

## Prerequisites and assumptions

- A capture where the transport layer is intact (handshake and enough packets present).
- Wireshark/TShark installed; you know the candidate flow from card-pcap-first-pass-triage.
- Stack/version: Wireshark/TShark 3.6+ for `Follow` over TCP/UDP/TLS/HTTP/HTTP2/QUIC; older releases support fewer stream types, so state which layer you followed.

## Diagnostic sequence

1. Follow the candidate TCP stream → branch: readable text → capture is cleartext (continue); high-entropy bytes → card-unknown-payload-encoding.
2. Switch representation deliberately: `ascii` for text protocols, `hex` when byte offsets matter, `raw` when you must reproduce exact bytes. Interpretation: the direction marker in the transcript separates client→server from server→client, so record which side said what.
3. Look for reassembly warnings (`TCP segment of a reassembled PDU`, retransmissions, a missing handshake). Branch: gaps are present → check `capinfos` snaplen and whether the capture started mid-session; a transcript with holes can silently "decode" into wrong text.
4. Extract the concrete artifacts you need (path, header values, body, file bytes) into a notes file with the frame numbers that produced them.

If the stream is cleartext but structurally unfamiliar, go to card-unknown-tcp-framing. If it is a familiar protocol that Wireshark did not decode, go to card-wrong-dissector-encapsulation.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -q -z follow,tcp,ascii,<STREAM>` | transcript with direction markers | Human-readable ordered payload |
| `tshark -q -z follow,tcp,raw,<STREAM>` | raw dump | Byte fidelity for re-assembly; no packet attribution |
| `tshark -r <C> -Y "tcp.stream==<STREAM>" -T fields -e frame.number -e ip.src -e tcp.len` | per-frame listing | Which frames carry which chunk; proves reassembly coverage |
| `tshark -r <C> -T fields -e tcp.stream \| sort -n \| uniq -c \| sort -rn` | stream indexes by frame count | Ranking candidate streams when the first pick was empty |
| `tshark -r <C> -Y "tcp.analysis.flags" -T fields -e frame.number -e _ws.expert.message` | expert warnings | Retransmission/gap evidence that undermines byte-level claims |

## State-changing actions (only if the card changes a host or service)

Not applicable — read-only analysis of an existing capture. Replaying anything derived from it is a separate decision: see card-remote-live-capture for capture-side caveats, and use the web/attack-defend cards for replay rules.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — no service is modified. If the transcript yields an exploit request, the artifact belongs in the web/attack-defend patch workflow, not here.

## Failure modes and things teams stopped doing

- **Treating the followed stream as "the conversation".** A follow view shows one TCP stream; multiplexed protocols carry many logical streams over one TCP connection, and the User's Guide documents the stream types Wireshark can follow (S026). Our rule: always state which layer you followed.
- **Losing packet attribution.** A transcript without frame numbers cannot be used to justify where an artifact came from; Down to the Wire's retrospectives are about evidence and prioritisation under time pressure (S007). Our rule: keep `frame.number` beside every extracted artifact.
- **Trusting a transcript that skipped the handshake.** Maple Bacon's primer treats captured traffic as defensive evidence, which only works if you captured the beginning of the session (S005). Our rule: check for the handshake before claiming you have the full request.
- **Assuming the stream is complete because decoding produced readable text.** Wrong boundaries can still yield plausible strings; verify coverage (step 3) before drawing conclusions.
- Narrower replacement for all of these: follow stream → record index and frames → check coverage → then interpret.

## Evidence status

- **Status:** source-supported but untested (no Wireshark/TShark binary in this environment; the repo's earlier research pass recorded the same gap).
- **What we actually ran:** nothing — commands are documentation-derived from the Wireshark User's Guide follow-stream section (S026) and the TShark manual (S028).
- **Our adaptation vs the source:** drafted card PCAP-002 described the GUI action; this version adds the stream-index recording step and the reassembly-gap check, because both are what make the result reproducible and defensible.

## Sources

- `src-wireshark-follow-stream-00828e3e` — follow-stream semantics, direction display, and representation choice.
- `src-tshark-man-page-d914bcdd` — `-z follow,tcp,<mode>,<stream>` CLI equivalent.
- `src-maplebacon-ad-primer-23bd534f` — traffic analysis as defender-side evidence gathering.
- `src-dttw-defcon2018-retro-83e7e6ea` — prioritisation/evidence discipline under time pressure.
