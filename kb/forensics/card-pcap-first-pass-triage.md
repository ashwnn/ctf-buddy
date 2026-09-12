# Rank protocols and conversations before reading packets one by one

**First useful action.** Do not open the packet list first: print the protocol hierarchy and the conversation table, then spend attention only on the flows those two views justify.

```bash
tshark -r <CAPTURE.pcap> -q -z io,phs ; tshark -r <CAPTURE.pcap> -q -z conv,tcp | head -n 25
```

Expected: a protocol tree that names at least one application protocol, and a short table of address pairs with packet/byte counts. If the hierarchy stops at `eth:ip:tcp` and payload only appears as `data`, the capture is dissector-blind — go to card-wrong-dissector-encapsulation instead of scrolling packets.

## Symptoms

- A capture with hundreds of thousands of frames and no known relevant host, port, or protocol.
- A teammate is already scrolling the packet list looking for "something weird".
- You know the challenge involves "network traffic" but not which flow carries the flag or the payload.

## Prerequisites and assumptions

- Local `tshark`/Wireshark (or `tcpdump` + Zeek) available; capture headers are intact.
- The capture is in organizer/team scope and may be analyzed freely; treat its contents as untrusted data.
- Stack/version: Wireshark/TShark 3.6+ or 4.x; option sets and automatic protocol names differ slightly between releases.

## Diagnostic sequence

1. `capinfos <CAPTURE.pcap>` → read duration, frame count, encapsulation, and the reported packet-size limit (snaplen). If the snaplen is small, payload may be truncated and byte-level reconstruction is unreliable — record that before drawing conclusions.
2. `tshark -q -z io,phs` → branch: application protocols named → continue; only `data`/generic TCP → card-wrong-dissector-encapsulation.
3. `tshark -q -z conv,tcp` → rank by bytes, then re-rank by packet count and by duration. Branch: one dominant peer pair → filter to it and follow the stream (card-pcap-follow-stream); many equal-sized flows → look for the smallest stable flow and for periodic timing first (that ordering is our inference, not a sourced claim).
4. Confirm the candidate with a targeted filter, e.g. `tshark -r <CAPTURE.pcap> -Y "tcp.stream==<STREAM>" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len | head`.

If the interesting flow turns out to be an unrecognized protocol, go to card-unknown-protocol-triage. If the flow is recognizable but its payload is opaque, go to card-unknown-payload-encoding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `capinfos <CAPTURE.pcap>` | `Packet size limit: … bytes (inferred)` | Forced snaplen; large payloads may be cut off in every frame |
| `tshark -q -z io,phs` | `eth:ip:tcp:http` vs `eth:ip:tcp:data` | Protocol known to the dissector vs unknown byte stream |
| `tshark -q -z conv,tcp` | address pair, frames, bytes, duration | Candidate flows ranked by volume, not by relevance |
| `tshark -q -z endpoints,ip` | per-address in/out totals | Whether traffic is one-directional (beacon/exfil shape) |
| `tshark -r <C> -Y "tcp.stream==<STREAM>" -T fields -e tcp.len \| sort -n \| uniq -c` | histogram of segment sizes | Fixed-size records or a text protocol with line-sized writes |

## State-changing actions (only if the card changes a host or service)

Not applicable — this card is read-only analysis of a capture file already held by the team.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — no service under test is touched.

## Failure modes and things teams stopped doing

- **Reading packets in order as a first move.** The DEF CON-finals retrospectives from Down to the Wire describe analysing and prioritising under hard time pressure rather than consuming data exhaustively (src-dttw-defcon2018-retro-83e7e6ea). Our rule: rank, hypothesise, then confirm.
- **Trusting the top talker.** Automated exploit loops produce large volumes of repeated, near-identical traffic that says nothing about the vulnerability you need (NTT Security Japan / Team Enu, ENOWARS 8 retrospective, src-ntt-enowars8-writeup-8b4ecb49). Volume is a hint about automation, not about relevance.
- **Assuming you captured the right interface at all.** A first-time A/D team documented monitoring the wrong interface and defending from false confidence (D0GL0V3R, UMCS 2026, src-d0gl0v3r-umcs2026-c85f0c19). A capture that misses the container/host veth makes every later card in this category misleading.
- Narrower rule that replaced these: rank, hypothesize, then *confirm the flow carries the artifact you need* before deep analysis.

## Evidence status

- **Status:** source-supported but untested (this offline session has no packet-capture tooling; the repo's earlier research pass also recorded `tshark`/`tcpdump` as unavailable locally).
- **What we actually ran:** nothing — no `tshark`, `capinfos`, or capture file exists in this environment. Commands are documentation-derived from the TShark manual (S028) and Wireshark User's Guide sections (S026, S027).
- **Our adaptation vs the source:** the drafted card PCAP-001 described the GUI conversation view; this version leads with CLI equivalents and adds the snaplen/encapsulation check because the CLI is what survives on a locked-down event laptop.

## Sources

- `src-tshark-man-page-d914bcdd` — option surface (`-r`, `-q`, `-z`, `-T fields`) used by every command here.
- `src-wireshark-follow-stream-00828e3e` — stream/conversation workflow that this ranking feeds into.
- `src-dttw-defcon2018-retro-83e7e6ea` — workload and prioritisation lesson for high-volume traffic.
- `src-ntt-enowars8-writeup-8b4ecb49` — automated exploit loops generate repeated traffic; volume is not relevance.
- `src-d0gl0v3r-umcs2026-c85f0c19` — wrong-interface monitoring failure story.
