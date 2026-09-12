# PCAP triage: tshark one-liners that answer the question

**First useful action.** Count the conversations before reading a single packet: the answer is
usually in the protocol mix or the one stream with unusual byte counts.

```bash
PCAP='<FILE>.pcap'
tshark -r "$PCAP" -q -z io,phs 2>/dev/null | head -30        # protocol hierarchy
tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null | head -30       # who talks to whom, how much
```

Expected: one protocol you did not expect (a custom port, `data` instead of HTTP), or one
conversation with a byte count nothing else matches. Both are worth following; the rest is noise.

## Symptoms

- "Here is a PCAP" and no other information.
- The capture has 200k packets and you have ten minutes.
- A flag is supposed to be inside a stream, a file transfer, or a tunnelled protocol.

## Prerequisites and assumptions

- `tshark` (Wireshark CLI) for scripted extraction; Wireshark GUI for visual work.
- `tcpdump` if you need to capture live (`ctfctl watch` shells out to it).
- The repo ships `python drills/assets/make-synthetic-pcap.py` if you want a deterministic file to
  practise on before the event.

## Diagnostic sequence

1. Protocol hierarchy + conversations (above) → pick the anomalous protocol or stream.
2. If HTTP: list hosts and URIs before looking at bodies.
   `tshark -r "$PCAP" -Y http.request -T fields -e http.host -e http.request.uri | sort -u`
3. Follow exactly one stream and read it as text; do not export everything.
   `tshark -r "$PCAP" -q -z follow,tcp,ascii,<STREAM>`
4. If nothing readable, try the unknown-protocol path
   (`kb/forensics/card-unknown-protocol-triage`, `card-unknown-tcp-framing`).
5. Export the objects only after you know which stream matters
   (`card-http-object-export`, `card-zeek-file-inventory`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r "$PCAP" -q -z io,phs` | protocol tree with packet counts | where the interesting traffic lives |
| `tshark -r "$PCAP" -q -z conv,tcp` | per-conversation bytes | the outlier stream |
| `tshark -r "$PCAP" -Y 'http.request' -T fields -e http.host -e http.request.uri \| sort -u` | host+path pairs | the application's real surface |
| `tshark -r "$PCAP" -Y 'http.response.code >= 400' -T fields -e http.response.code -e http.request.uri` | error responses | what the attacker/fuzzer was looking for |
| `tshark -r "$PCAP" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst \| sort \| uniq -c` | scan sources | port scanning before an exploit |
| `tshark -r "$PCAP" -Y 'dns' -T fields -e dns.qry.name \| sort -u` | queried names | DNS tunnelling or exfil (`card-dns-tunneling-triage`) |
| `tshark -r "$PCAP" -Y 'usb.capdata' -T fields -e usb.capdata` | HID reports | keystroke reconstruction (`card-usb-hid-keyboard-decode`) |
| `tshark -r "$PCAP" -Y '<filter>' -w out.pcap` | filtered capture | hand a small file to a teammate |

Filter cheat sheet: `tcp.stream eq N`, `ip.addr == A && tcp.port == P`, `frame contains "flag"`,
`http.request.method == "POST"`, `tls.handshake.type == 1`, and `!arp` to cut the noise floor.

## State-changing actions (only if the card changes a host or service)

None. Reading a capture never changes a host. `ctfctl watch` is the only capture path that touches
the network, and it is bounded (`--seconds`) and read-only.

## Failure modes and things teams stopped doing

- Opening the GUI and scrolling for twenty minutes. Count first, read second.
- Exporting every object "just in case": you then search the same haystack with more files in it.
- Reassembling the wrong dissector over a custom protocol
  (`card-wrong-dissector-encapsulation`) and concluding the traffic is encrypted.
- Assuming a TLS stream is unreadable before checking for the key log
  (`card-tls-keys-and-cleartext-shortcuts`).

## Evidence status

- **Status:** source-supported; every command is from the tshark manual with the exercise flow from
  drill 02.
- **What we actually ran:** the shipped synthetic PCAP through the drill-02 workflow
  (`python drills/assets/make-synthetic-pcap.py captures/drill02.pcap --json`), and the drill's
  reconstruction answers in `drills/answers.md`.
- **Our adaptation vs the source:** the ordering (counts → streams → objects) is ours; the sources
  document the individual mechanisms.

## Sources

- `src-tshark-man-page-d914bcdd` — `-z` statistics, `-T fields`, `-Y` display filters, `-w` output.
- `src-wireshark-display-filters-be1e834c` — filter syntax used above.
- `src-wireshark-follow-stream-00828e3e`, `src-wireshark-export-objects-4056c43f` — follow/export.
- `src-tcpdump-man-page-91256cee` — live capture flags behind `ctfctl watch`.
- `src-pcapng-spec-af5985f7` — file format questions (why a file will not open).
