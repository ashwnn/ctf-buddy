# Rank all 256 single-byte XOR keys instead of guessing them

**First useful action.** Score every one-byte key locally and look at the top of the ranked list rather
than trying favourites.

```bash
python3 - <<'PY'
ct = open('<CIPHERTEXT_FILE>','rb').read()
def score(b):
    printable = sum(32 <= c < 127 or c in (9,10,13) for c in b) / max(len(b),1)
    common = sum(chr(c).lower() in 'etaoin shrdlu' for c in b if 32 <= c < 127) / max(len(b),1)
    return printable + common
ranked = sorted(((score(bytes(c ^ k for c in ct)), k) for k in range(256)), reverse=True)
for s, k in ranked[:8]:
    print(f'key=0x{k:02x} score={s:.3f} :: {bytes(c ^ k for c in ct)[:80]!r}')
PY
```

Expected: a short head of candidates with visibly higher scores, one of which shows coherent text.
If the top candidates are all similar and none is readable, stop — this is not a single-byte XOR.

## Symptoms

- Ciphertext is short (one line, one field) and could plausibly come from a one-byte key.
- A previous crib attempt produced a candidate key with a single repeated byte value.
- Someone has been hand-typing `0x41`, `0x20`, `0xff` and eyeballing the result.

## Prerequisites and assumptions

- The ciphertext is raw bytes. Hex/base64 must be decoded first; text XOR is a different operation.
- The keyspace is exactly 256 keys. If the evidence points at a two-byte or repeating key, use the crib
  path (`card-crypto-xor-known-prefix-crib`) instead; 65536 keys is still cheap, but "cheap" is not the
  same as "the right model".
- Short inputs make language scoring unreliable — treat the score as a ranking device, not as proof.

## Diagnostic sequence

1. Decode to bytes and confirm the length. Under about 20 bytes, expect the score to be noisy.
2. Score all 256 keys with a printable-ratio term plus a language term, and print the top few.
3. Read the top candidates' plaintexts. Coherence across the *whole* string is the acceptance test;
   "some letters appeared" is not.
4. For each plausible candidate, look for an external confirmation: a flag prefix, a known header, or a
   consistent field boundary.
5. If nothing is coherent, stop this attack. Note the negative result (it eliminates a whole model) and
   move to `card-crypto-xor-known-prefix-crib` or `card-crypto-when-not-to-brute-force`.

If one candidate decodes coherently → keep it and record the scoring function you used, because a
teammate reproducing the search needs it. If two candidates are close → prefer the one that also
satisfies the challenge's structural expectations (flag format, printable-only, expected field layout).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| top ranked key with printable output | coherent words | Strong single-byte XOR candidate; verify against a known prefix |
| several keys with partial printability | fragments | Short-input noise: use structural evidence, not scores |
| no candidate above baseline | all garbage | Not single-byte XOR: change model |
| key `0x00` scoring high | unchanged bytes | Your input is likely already plaintext or your scoring is misconfigured |

## Failure modes and things teams stopped doing

- Eyeballing a few favourite keys. The 256-key space is trivially enumerable; manual selection just
  reduces coverage.
- Trusting language scoring on very short inputs. Frequency scoring needs text; five bytes of ciphertext
  can score well for dozens of keys, which is exactly the false-positive behaviour the corpus warns
  about for heuristic decoding generally.
- Escalating into a huge brute force after the 256-key attempt fails. If a single-byte model is
  eliminated, the next step is a *different model with evidence*, not a larger key space; see
  `card-crypto-when-not-to-brute-force`.
- Assuming XOR because "it looks base64-ish". The model choice must come from the source, a crib, or
  structure before the search starts.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing. The scoring script is this worker's construction for documentation
  purposes and was not executed; XOR coverage is sourced from the cryptography course we cite, and the
  ranking discipline extends repository draft CRYPTO-004.

## Sources

- `src-cryptohack-intro-401bf309` — XOR as a primitive with a small, enumerable single-byte keyspace when
  the model applies.
- `src-cyberchef-magic-source-2a3dcc0a` — evidence that automated XOR brute-force and crib matching exist in
  standard tooling, together with the warning that such results need verification.
