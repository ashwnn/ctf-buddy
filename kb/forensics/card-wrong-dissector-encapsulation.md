# I cannot tell what this protocol is: the port and the dissector are lying

**First useful action.** Check the capture's own framing before trusting any protocol label: identify the link-layer encapsulation, whether the TCP handshake is present, and whether the snaplen cut the identifying bytes off every frame.

```bash
capinfos <CAPTURE.pcap> ; tshark -r <CAPTURE.pcap> -q -z io,phs
```

Expected: `capinfos` names the encapsulation (`Ethernet`, `Linux cooked capture v1/v2`, `Raw IP`, …) and the packet-size limit; the hierarchy shows where dissecting stops. If the file's encapsulation is a cooked/`any` capture, field names and even address semantics differ from an Ethernet capture — that alone explains many "weird protocol" observations.

## Symptoms

- Traffic on a well-known port that Wireshark refuses to decode, or decodes into obviously wrong fields.
- A flow whose payload clearly contains another packet (tunnels, VLAN tags, VXLAN, GRE).
- Enormous TCP segments (tens of kilobytes) or duplicated frames that look like protocol mutations.
- The first bytes of the application protocol are missing on every frame.

## Prerequisites and assumptions

- The capture may be truncated, mid-session, tunneled, or taken from a pseudo-interface — all four are confounders, not protocol discoveries.
- You are allowed to re-capture on a better path if the current capture cannot answer the question.
- Stack/version: Wireshark/TShark 3.6+/4.x; encapsulation naming and cooked-capture field names differ across releases.

## Diagnostic sequence

1. Encapsulation: `capinfos` names it. Branch: `Linux cooked capture` (typical of `-i any`) → expect different link-layer fields, and expect to see packets once per interface they traverse; re-capture on the specific interface if addresses/paths matter.
2. Completeness: does the flow include SYN/SYN-ACK and the first application byte? Branch: no handshake → you may have joined mid-stream; reassembly can still work but you cannot prove the message start. Missing first bytes on *every* frame with a small snaplen → truncation; stop making byte-level claims (card-capture-hygiene).
3. Nested packets: if the "payload" of your flow starts with an IP header (`45 ..`), an Ethernet header, or recognisable VLAN/GRE/VXLAN fields, you are looking at encapsulation. Branch: nested → inspect the inner packet (`tshark -Y "vxlan"`, or the tunnel protocol's own fields), or re-capture at a point where the inner protocol is not encapsulated.
4. Port versus bytes: enumerate the first two bytes of each direction of the suspect flow. Branch: `16 03` → TLS on a non-TLS port (or the reverse); `50 52 49 20 2a` (`PRI *`) → HTTP/2 preface; `47 45 54 20` (`GET `) → HTTP on an unusual port. Then force the dissector to test the hypothesis: `tshark -d tcp.port==<PORT>,http2`.
5. Capture artefacts: oversized segments and duplicated frames come from capture offload/pseudo-interfaces, not from the protocol. Branch: sizes far above the path MTU, or identical frames 0 s apart → re-capture on the physical interface before drawing conclusions.

If the layers are clean, complete, and still unrecognised, go to card-unknown-protocol-triage. If framing is the problem once you accept the family, go to card-unknown-tcp-framing. If truncation or loss is the problem, go back to card-capture-hygiene and re-capture.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `capinfos <CAPTURE>` | `Encapsulation: …`, `Packet size limit: …` | Cooked capture and/or truncation confounders |
| `tshark -q -z io,phs` | `eth:ip:tcp:data` | Nothing dissected the application layer |
| `tshark -r <C> -T fields -e frame.len -e tcp.len \| sort -nr \| head` | largest frames/segs | Offload/pseudo-interface artefacts |
| `tshark -r <C> -Y "tcp.flags.syn==1 && tcp.flags.ack==0"` | handshake start | Whether you captured the beginning of the session |
| `tshark -r <C> -d tcp.port==<PORT>,<proto>` | forced decode | Hypothesis test for "protocol on the wrong port" |
| `tshark -r <C> -Y "vlan \|\| vxlan \|\| ip.proto==47"` | encapsulated frames | The payload is a packet, not an application message |

## State-changing actions (only if the card changes a host or service)

Not applicable to a capture file. The implied action — re-capturing on a different interface — is covered by card-capture-hygiene, which requires an interface dry run before committing to a long capture.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. This card exists to stop a wrong service-level conclusion ("the service speaks a weird protocol") from being drawn out of a capture artefact.

## Failure modes and things teams stopped doing

- **Blaming the service for a capture artefact.** Wrong-interface and pseudo-interface captures produce exactly this confusion; a first-time team documented monitoring the wrong interface and reasoning from it (D0GL0V3R, UMCS 2026, src-d0gl0v3r-umcs2026-c85f0c19). Rule now: characterise the capture before characterising the protocol.
- **Renaming the column instead of checking the bytes.** Forcing a dissector and calling it solved hides the underlying issue; the TShark manual makes clear `-d` binds a dissector to a port as an operator choice, not as evidence (src-tshark-man-page-d914bcdd). Rule now: force only to *test* a hypothesis, then verify by prediction.
- **Concluding from a truncated capture.** When the snaplen cuts payload, the identifying bytes of many protocols simply are not there. Rule now: state the packet-size limit in any byte-level claim.
- **Treating duplicate frames as retransmission floods.** Duplicates from an `any`-style capture look identical to real retransmissions and distort timing analysis. Rule now: confirm the capture path first.
- Narrower replacement: encapsulation → completeness → nesting → bytes-versus-port → artefacts.

## Evidence status

- **Status:** documentation-derived and version-sensitive; untested (no capture, no `tshark`, `capinfos` unavailable here).
- **What we actually ran:** nothing.
- **Our adaptation vs the source:** this is one of the four "I cannot tell" decision procedures; no single source covers encapsulation/truncation/offload confounders together, so the ordering is our inference while the tool behaviour comes from Wireshark/TShark documentation (S028, S026) and the wrong-interface failure story (TR3).

## Sources

- `src-tshark-man-page-d914bcdd` — dissector binding, field names, and statistics options used above.
- `src-wireshark-follow-stream-00828e3e` — follow-stream behaviour when the protocol is not dissected.
- `src-d0gl0v3r-umcs2026-c85f0c19` — wrong-interface capture failure story.
