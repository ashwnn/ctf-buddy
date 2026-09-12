# Decode hex only when its structure supports the claim

**First useful action.** Check alphabet and length, decode exactly once, and inspect the resulting
bytes for structure before doing anything else.

```bash
printf '%s' '<HEX_VALUE>' | grep -Ex '([0-9A-Fa-f]{2})+' >/dev/null && printf '%s' '<HEX_VALUE>' | xxd -r -p | tee <ANALYSIS_DIR>/hex.out | file -
```

Expected: a `file` name for the decoded bytes (PNG, zip, ELF, ASCII text) or `data` with some
printable characters. If the alphabet check fails, the string is not pure hex — re-read it for
separators, a prefix, or a different base before decoding anything.

## Symptoms

- A value is composed only of `[0-9a-f]` characters and has an even character count.
- A challenge or service returns something that is "probably hex" but nothing decoded so far has
  helped.
- You are about to decode a 32-character hex string that is actually a digest.

## Prerequisites and assumptions

- A copy of the value; a local decoder (`xxd`, `python3`).
- The distinction this card depends on: hex is an encoding of bytes, while a hex-looking digest is an
  output of a hash function. Length and alphabet cannot separate them — usage can.
- Stack/version: `xxd -r -p` behavior is stable across common distributions; `file` wording differs but
  its verdicts are stable enough for triage.

## Diagnostic sequence

1. Alphabet and parity check. Non-hex characters mean either a different base or a mixed format
   (`0x` prefixes, spaces, dashes). Do not guess around them; inspect.
2. Classify by usage *before* decoding when source is available: a value that is stored and later
   compared is a digest or identifier, and decoding it is wasted effort
   (`card-crypto-classify-before-decoding`).
3. Decode once. Inspect the first bytes: recognizable magic, all-printable text, or unstructured random
   bytes.
4. Recursive only with evidence: printable text may be another encoding; a magic prefix means you now
   have a file, so route to the artifact pipeline (`card-misc-partial-credit-artifacts`).
5. If the decoded bytes are random, stop and reconsider. Random output after a *correct* decode is
   normal for compressed, encrypted, or key material — `card-crypto-layered-decode-stop-rule`.

If the decoded output is ASCII text → treat as a new value and restart this sequence once.
If it is high-entropy → check whether a source clue says "compressed"/"encrypted" before spending more
time; otherwise move to `card-crypto-xor-known-prefix-crib` only if a crib or XOR context exists.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `printf '<V>' \| xxd -r -p \| file -` | `PNG image data` | Decode produced a real file: switch to file handling |
| `printf '<V>' \| xxd -r -p \| file -` | `data` | Unstructured bytes: either wrong transform or genuinely random |
| `printf '<V>' \| xxd -r -p \| head -c 200` | readable words | One more layer is plausible with evidence |
| `printf '<V>' \| wc -c` | length in characters | Only useful against a specific expected length |
| `printf '<V>' \| xxd -r -p \| xxd \| head -n 4` | byte dump | Ground truth for inspecting magic and padding |

## Failure modes and things teams stopped doing

- Decoding a digest. A 32- or 64-character hex string with a stable value that the service compares is
  not a layer to peel; the local corpus already records low-entropy/hash-shaped tokens as
  generation-side problems (ENOWARS Buggy lineage), not encoding problems.
- Adding or removing characters "to make the length even". Padding errors hide the real structure; the
  rule is to explain the odd length (separator, prefix, truncation) before decoding.
- Treating `xxd -r` non-strictness as a success signal. Some hex tools accept malformed input; a
  successful exit is not evidence that the input was valid hex.
- Chaining decode steps without re-checking structure. Every layer must earn the next one; see
  `card-crypto-layered-decode-stop-rule`.

## Evidence status

- **Status:** source-supported but untested in this session.
- **What we actually ran:** nothing. The repository's 2026-09-11 build pass recorded a hex-decode
  round-trip as fixture-verified on a trivial value; that is the basis for the command shape, and it is
  not a verification of this card's chain on a real challenge artifact.
- **Our adaptation vs the source:** repository draft CRYPTO-001 supplied the "decode only when
  structure supports it" rule; we added the odd-length explanation requirement, the strictness warning,
  and the explicit digest branch.

## Sources

- `src-cryptohack-intro-401bf309` — the encoding primitives taught as encodings, plus the warning not to
  treat every opaque value as decodable.
- `src-enowars-buggy-readme-f85b8d0e` — evidence that hex/hash-looking service values are often identifiers
  produced by application logic.
