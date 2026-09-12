# Unknown artifact: one decision sheet for "what is this?"

**First useful action.** Answer three questions in order — *is it text or bytes?*, *is it one layer or
many?*, *does it have structure at a fixed offset?* — and only then reach for a tool. Most unknowns
collapse at the first question.

```bash
ART='<FILE_OR_STRING>'
file "$ART"; xxd "$ART" | head -5; wc -c "$ART"
strings -n 6 "$ART" | head -20
```

Expected: either printable text with a recognisable alphabet (encoding challenge), or bytes with a
recognisable header (format challenge), or high entropy with no structure (encrypted/compressed —
look for the key, not the tool).

## Symptoms

- A blob, string, or service banner that no tool recognises.
- The challenge text names nothing ("decode this").
- A custom TCP service with no dissector (`card-unknown-protocol-triage`).

## Prerequisites and assumptions

- `file`, `xxd`, `strings`, Python 3.
- A rule: never run an unknown artifact; this sheet reads only.
- Stack/version: stack-agnostic.

## Diagnostic sequence

1. Text vs bytes vs mixed (above) → text goes to the encoding path, bytes to the format path, entropy
   to the key path.
2. Entropy check: `python3 -c "import math,collections,sys;d=open('$ART','rb').read();print(len(collections.Counter(d))/256)"`
   → near 1.0 means compressed/encrypted; near 0.2 means structured or text.
3. Signal vs structure: `xxd` again for repeating 4/8/16-byte patterns (block cipher), a magic header
   (`7f 45 4c 46`, `50 4b 03 04`), or a length-prefixed frame (custom protocol).
4. If it is a custom network protocol, capture traffic and build a field table before writing a
   parser (`card-unknown-tcp-framing`, `card-misc-unusual-protocol-no-dissector`).
5. If it is an esoteric encoding, decode layer by layer and stop when the output stops being
   meaningful (`card-misc-esoteric-encoding-layer`, `card-crypto-layered-decode-stop-rule`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file "$ART"` | `ASCII text`, `data`, `ISO Media` | first split of the decision tree |
| `xxd "$ART" \| head -5` | hex dump | magic bytes and repeating structure |
| `strings -n 6 "$ART" \| head` | words, paths, banners | built-in context; often names the format |
| `python3 -c "...Counter..."` | 0.2 vs 0.9+ | structured/text vs compressed/encrypted |
| `python3 -c "d=open('$ART','rb').read();print(d[:16].hex())"` | header hex | compare against known signatures |
| `tshark -r cap.pcap -z follow,tcp,hex,0` | raw stream | framing for a custom protocol |
| `python3 -c "import zlib;print(zlib.decompress(open('$ART','rb').read())[:80])"` | plaintext | it was zlib; try raw-deflate/gzip variants next |

## State-changing actions (only if the card changes a host or service)

None. If the "artifact" is a running service, use the read-only probe instead:
`ctfctl remote probe <TEAM_VM_IP> --save` gives listeners, banners, and process names without guessing.

## Failure modes and things teams stopped doing

- Running the artifact to "see what it does". Run-once binaries end events early.
- Reaching for a bespoke parser before writing down the field widths; the field table *is* the work
  (`card-unknown-tcp-framing`).
- Assuming "high entropy = encrypted" when it is a compressed log or a well-packed binary.
- Automating a guess loop instead of writing one falsifiable hypothesis per attempt
  (`card-misc-automation-challenge-discipline`).

## Evidence status

- **Status:** source-supported; the decision order is ours.
- **What we actually ran:** the classification block against the repository's own drill assets
  (synthetic PCAP) and fixture files; nothing exotic.
- **Our adaptation vs the source:** the three-question gate condenses the triage order used by the
  `kb/misc` and `kb/forensics` cards.

## Sources

- `src-wireshark-display-filters-be1e834c` — stream inspection for custom protocols.
- `src-tshark-man-page-d914bcdd` — hex follow mode used above.
- `src-rfc4648-0da70d4b` — encoding alphabets when the artifact turns out to be text.
- `src-pcapng-spec-af5985f7` — an example of a format the tools already understand; check before
  hand-rolling.
- `src-molteniluca-homerooter-ff20860b`, `src-ustc-hackergame2024-r06-c446ee16` — source challenges
  where identification was the actual problem.
