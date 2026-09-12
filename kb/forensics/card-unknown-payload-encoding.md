# I cannot tell if this payload is encoded, compressed, or encrypted

**First useful action.** Write the payload bytes to a file and run a fixed hypothesis order on it; require two independent signals before you name the transform.

```bash
tshark -r <CAPTURE.pcap> -Y "tcp.stream==<STREAM>" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > <OUTDIR>/blob.bin
file <OUTDIR>/blob.bin ; python3 -c "d=open('<OUTDIR>/blob.bin','rb').read(); print(len(d), round(sum(32<=b<127 or b in (9,10,13) for b in d)/max(len(d),1),3))"
```

Expected: length plus a printable-ratio between 0 and 1. If `file` names a format, that name is a hypothesis worth testing immediately by attempting a real parse; if the ratio is near 1.0 the payload is text-like; if it is near 0 the payload is binary, compressed, or encrypted.

## Symptoms

- You extracted a payload and every decoder you try "almost" works.
- A teammate is applying decode → decode → decode chains hoping one sticks.
- The challenge description says nothing about encryption, but the data looks random.

## Prerequisites and assumptions

- The payload boundary is known (card-unknown-tcp-framing) — deciding an encoding on a mis-framed blob is wasted effort.
- Local Python 3.9+ for the cheap statistical checks; no online decoders.
- Stack/version: any; the checks below are format-level, not tool-level.

## Diagnostic sequence

1. All-printable check. Branch: printable and the alphabet is restricted (base64/hex/URL-safe) → test a **strict** decode, i.e. fail loudly on invalid characters rather than ignoring them.
2. Magic-number check (`file`, plus the first bytes in hex): gzip `1f 8b`, zlib `78 01/9c/da`, bzip2 `42 5a 68`, xz `fd 37 7a 58 5a 00`, zstd `28 b5 2f fd`, PKZIP `50 4b 03 04`, PNG `89 50 4e 47`. Branch: match → attempt decompression and require *valid* output (decompression that yields noise is a false positive).
3. Structure check on high-entropy data: look for repeated 16-byte blocks. Interpretation: identical blocks in a high-entropy payload indicate a block cipher in a deterministic mode (classic ECB), which means the payload has exploitable structure and is *not* a random key stream.
4. Crib check: if you know any plaintext prefix (flag format, JSON header, file signature) at a known offset, derive candidate XOR key bytes and test them across the whole blob. A key that explains only the crib is not a key.
5. Context check before any further codec roulette: is there a key, password, or handshake in the *same* capture or an earlier flow? A very common challenge layout sends the key in cleartext shortly before the encrypted blob. Search the capture for the blob's stream neighbours and for plausible secrets in the surrounding streams.

If the payload turns out to be text with an internal grammar, go to card-unknown-protocol-triage. If it is a valid container (archive, image, executable), go to card-carving-binwalk-foremost or the reverse-engineering cards.

## Commands and interpretation

| Observation | Reading | Next action |
|---|---|---|
| printable ratio ≈ 1, restricted alphabet | Text encoding | Strict decode once; stop if it does not decode |
| `file` names a compressed/container format | Real structure | Decompress/parse and validate output |
| Entropy high, no magic, no repeated blocks | Encrypted or already-compressed | Look for keys/context; do not brute force |
| Identical 16-byte blocks in high-entropy data | Block cipher in ECB-like mode | Attack structure/pattern, not the key |
| Crib-derived XOR key explains only the crib | Coincidence | Discard; return to the framing/context questions |
| Decode chain grows but structure does not improve | Rabbit hole | Stop; use the context check |

## State-changing actions (only if the card changes a host or service)

Not applicable — offline computation on an extracted blob. Keep extracted bytes out of the tracked repository if they may contain live flags.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. The transferable rule: if a service you own uses a deterministic mode or a reused key, that is a patch decision with a regression test — not something you conclude from a capture alone.

## Failure modes and things teams stopped doing

- **Treating heuristic suggestions as findings.** CyberChef's Magic is documented as a speculative, bounded search whose suggestions are leads (S035); the same applies to `file`, entropy scores, and your own printable-ratio check. Rule now: two independent signals plus a validation step.
- **Decoding repeatedly when structure stops improving.** The corpus's stop rule for layered decoding exists because each extra layer multiplies false positives. Rule now: after two structure-free transforms, switch to context.
- **Calling high entropy "encryption".** Already-compressed data is high entropy too; check magic numbers and container evidence first. Rule now: name the transform only after an attempt at the alternative family fails.
- **Brute-forcing a key space instead of reading the challenge.** Keys in CTF designs are usually provided (in the capture, the source, or the description); a brute force is the last resort, not the first.

## Evidence status

- **Status:** operator-derived decision procedure; untested (no blob, no capture, no tooling here).
- **What we actually ran:** nothing — no statistics were computed for this card, and no example numbers are quoted.
- **Our adaptation vs the source:** this is one of the four "I cannot tell" decision procedures requested by the brief; the only sourced claim is the heuristic-not-proof character of automated transform suggestion (S035). Everything else is team practice and is labelled as such.

## Sources

- `src-cyberchef-magic-source-2a3dcc0a` — automated transform suggestion is heuristic and speculative; validation is mandatory.
- `src-tshark-man-page-d914bcdd` — payload extraction used to produce the blob.
- `src-maplebacon-ad-primer-23bd534f` — read the capture (including neighbouring cleartext) before assuming the hard path.
