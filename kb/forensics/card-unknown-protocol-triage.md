# I cannot tell what this protocol is: classify from bytes and predict before believing

**First useful action.** Dump the first payload bytes of *both* directions of the flow and classify the family from those bytes — then state what else you must see if your classification is right, and go look for it.

```bash
tshark -r <CAPTURE.pcap> -Y "tcp.stream==<STREAM> && tcp.len>0" -T fields -e frame.number -e ip.src -e tcp.len -e tcp.payload | head -n 6
```

Expected: a handful of hex payload lines with the frame's direction. If the first data frame is from the server, the protocol is server-speaks-first (banner/greeting style); if it is from the client with no server greeting, it is request-first. That single observation eliminates half the candidate families before you identify any magic bytes.

## Symptoms

- The protocol hierarchy shows only `data` under TCP, or shows a protocol you do not believe.
- The port number is non-standard, or standard ports carry something unexpected.
- The challenge says "custom protocol" or hands you a capture with no documentation at all.

## Prerequisites and assumptions

- One candidate flow isolated (card-pcap-first-pass-triage) and at least the start of the conversation captured.
- `tshark` capable of dumping `tcp.payload`; if the field is empty for your build, fall back to `-e data.data` or `-x`.
- Stack/version: Wireshark/TShark 3.6+/4.x; heuristic dissectors and some field names differ between releases.

## Diagnostic sequence

1. Who speaks first? Server-first with a printable banner → greeting-style protocol (SMTP/SSH/FTP/MySQL family). Client-first with binary → request/response with its own framing (card-unknown-tcp-framing).
2. Read the first 4-16 bytes of each direction and compare against the signature table below. Interpretation: one match → continue to step 3; several plausible matches → the bytes are ambiguous and you must use structural evidence instead.
3. **Predict, then verify.** For every hypothesis, name the cheap observable that must exist: HTTP/1.x implies `HTTP/1.` and CRLF headers; TLS implies 0x16/0x15/0x17 record types; SSH implies a binary KEXINIT after the banner; a length-prefixed protocol implies a length field that matches the following byte count. Search the flow for that observable.
4. If nothing in the capture confirms the hypothesis, test it against a local copy: reproduce the client side against `<LOCAL_FIXTURE>` (or a team-owned instance) and see whether the service answers with the predicted grammar. A failed prediction is information, not wasted time.
5. Only after the family is settled, decide whether you can extract content (text) or need framing work (binary) — the two branches below.

If the family is binary and structured → card-unknown-tcp-framing. If the payload is high-entropy with no recognisable structure → card-unknown-payload-encoding. If your classification contradicts the port or the capture's encapsulation looks wrong → card-wrong-dissector-encapsulation.

## Commands and interpretation

| Observation in the first bytes | Candidate family | Confirming prediction |
|---|---|---|
| `48 54 54 50 2f` (`HTTP/`) | HTTP/1.x | A response containing `HTTP/1.` and CRLF-terminated headers |
| `53 53 48 2d 32 2e 30` (`SSH-2.0-`) | SSH | Banner line ending CRLF, then binary `SSH-2.0` KEXINIT |
| `16 03 01`..`16 03 04` | TLS handshake record | Later records start with `15`, `16`, `17` |
| `1f 8b` / `78 01/9c/da` | gzip / zlib stream | Valid decompression output, not noise |
| `7b`/`3c` (`{`/`<`) | JSON / XML message | Parseable structure and repeated keys or tags |
| Numeric banner such as `220 ` or `+OK` | Mail/POP3 family | Command/response alternation with a fixed status grammar |
| Fixed-length binary records | Custom length-prefixed protocol | Record boundaries repeat at a constant offset |
| Uniformly high-entropy bytes, no readable strings | Encrypted or compressed payload | No structure emerges from any framing hypothesis |

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <C> -q -z follow,tcp,ascii,<STREAM>` | printable transcript | Text protocols become readable immediately |
| `tshark -r <C> -Y "tcp.stream==<STREAM>" -T fields -e tcp.payload \| head` | hex payload | Byte-level identification |
| `tshark -r <C> -Y "tcp.stream==<STREAM>" -d tcp.port==<PORT>,http` | dissected fields | Forces the hypothesis and shows whether it survives |
| `tshark -r <C> -T fields -e tcp.len \| sort -n \| uniq -c` | length histogram | Constant sizes ⇒ fixed records; varied ⇒ text/delimited |

## State-changing actions (only if the card changes a host or service)

Not applicable — this card reads a capture and, at most, talks to a team-owned fixture. Do not point a custom protocol client at any host outside the event scope.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. The output of this card is a protocol identification, which is the prerequisite for any later exploit or patch decision.

## Failure modes and things teams stopped doing

- **Trusting the port.** Ports are hints written by whoever ran the listener; a challenge can put anything on 8080 or 443. Rule now: bytes over ports, always.
- **Stopping at a name.** "It's Redis, done" without checking whether the framing actually matches Redis's RESP grammar produces wrong extraction later. Rule now: every classification needs one confirming observable.
- **Iterating hypotheses forever.** Ten minutes of guessing is worse than one prediction test on a fixture. Rule now: two unconfirmed hypotheses ⇒ switch to the framing/encoding cards, which are mechanical.
- **Assuming Wireshark's silence means no protocol.** `data` just means no dissector matched; the TShark manual documents that dissectors can be bound with `-d`, and that a heuristic dissector may simply be absent in that build (S028).
- Narrower replacement: first bytes → family → predicted observable → verify → then extract.

## Evidence status

- **Status:** documentation-derived (extraction mechanics) plus operator-derived (decision order); untested — no capture, no `tshark`, no fixture traffic available in this environment.
- **What we actually ran:** nothing.
- **Our adaptation vs the source:** the brief asked for "I cannot tell what this protocol is" procedures rather than tool cheatsheets; this card deliberately provides no tool feature list, only a classify-and-falsify loop. The prediction step is our inference, chosen because it converts guesswork into a testable claim.

## Sources

- `src-tshark-man-page-d914bcdd` — payload/field extraction and dissector-binding (`-d`) behaviour.
- `src-wireshark-follow-stream-00828e3e` — transcript view for text protocols.
- `src-maplebacon-ad-primer-23bd534f` — read the traffic before designing attacks or defences against it.
