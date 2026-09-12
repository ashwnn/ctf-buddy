# Classify an opaque value before attempting to decode it

**First useful action.** Decide what kind of object the value is by how it is *used*, not by how it
looks, before running any decoder.

```bash
grep -rIn --exclude-dir=.git -E "<VALUE_OR_FIELD_NAME>" <SERVICE_SRC> | head -n 40
```

Expected: the code that produces or compares the value, which tells you whether it is an encoded blob,
an identifier, or a random token. If the value is only ever passed around and never compared or parsed,
its role is unknown — do not decode yet; hunt for the producer.

## Symptoms

- A challenge hands you a long string and the obvious next move ("try Base64") has already failed or
  produced garbage.
- A service returns a token whose length and alphabet could be a digest, an encoded ID, a nonce, or a
  random session key.
- Two teammates are decoding the same value with different assumptions.

## Prerequisites and assumptions

- At least one of: the source, several samples of the value, the field name, or a documented
  producer/consumer relationship.
- The discipline that a decoder's success is not proof of intent. The corpus records explicitly that
  educational crypto material teaches primitives rather than providing a classifier for arbitrary
  blobs, and that CyberChef's Magic is a heuristic, not proof.
- Stack/version: the classification rules are format-independent; the tools are not.

## Diagnostic sequence

1. Ask three questions in order. Is the value compared for equality (login, dedup, lookup key)? Is it
   parsed by a decoder that can fail (strict decode, checksum, length field)? Does it carry structure
   such as an IV/nonce/tag or a fingerprint prefix?
2. Equality comparison, stable across samples, no parse path → treat as an identifier or digest. Stop
   trying to decode it. Attack its *generation* instead: `card-crypto-low-entropy-token-space` or
   `card-crypto-prng-seed-predictable-token`.
3. Strict-decodable with a plausible length for its alphabet and a meaningful result structure →
   treat as an encoding and continue with `card-crypto-hex-structure-check` or
   `card-crypto-strict-base64`.
4. Looks random, is used once, has a companion MAC/tag → treat as encrypted or keyed material; look for
   the key management and mode in the source before any cryptanalysis.
5. Record the classification with the evidence that supports it. A wrong early label costs more time
   than a missing one.

If two classifications both fit → pick the one that predicts a testable consequence (for example "if
this is a timestamp-derived identifier, a token requested one second later will change in a predictable
way") and run that test instead of arguing.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -rIn -E "<TOKEN_NAME>" <SERVICE_SRC>` | producer function + comparison site | The usage decides the class, not the appearance |
| `printf '%s' '<VALUE>' \| wc -c` | exact character length | Length is weak evidence; useful only against a specific candidate scheme |
| `printf '%s' '<VALUE>' \| base64 -d >/dev/null; echo $?` | exit status | Exit 0 means "Base64-shaped", not "Base64 by design" |
| `file <DECODED_OUTPUT>` | format name | Structure after decode is real evidence; random bytes are not |
| source grep for the encoder | explicit encode/decrypt call | The authoritative answer when source is available |

## Failure modes and things teams stopped doing

- Running every decoder in a toolkit over a value until something "looks right". The corpus's own note
  on CyberChef's Magic is the general rule: bounded brute force and heuristic scoring can produce
  plausible false positives, so a hit must be validated independently.
- Assuming everything that looks random is encrypted. Service implementations routinely emit random
  identifiers that are never meant to be reversed (the ENOWARS Buggy service is recorded in this
  corpus as a case where token/hash behavior was challenge-specific and tied to low-entropy
  generation, not to a cipher).
- Decoding a digest and then hunting for the "next layer" inside the bytes. A digest has no next layer;
  the answer is to attack the input space.
- Letting the field name pick the class (`?token=` does not mean "crypto token"). Names are written by
  developers, not by cryptanalysts.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session. No decoder, grep, or service was exercised by this
  worker; the `printf | base64 -d` shape shares the fixture-verified command family recorded in the
  repository's 2026-09-11 pass but is not re-run here.
- **Our adaptation vs the source:** the repository draft CRYPTO-008 supplied the
  "distinguish encoding from identifier" idea; the three-question test and the routing into the
  PRNG/token-space cards are our operational rewrite.

## Sources

- `src-cryptohack-intro-401bf309` — records that intro crypto exercises teach primitives and explicitly
  warn that this does not amount to a classifier for arbitrary opaque values.
- `src-cyberchef-magic-source-2a3dcc0a` — documents that automatic decoding is heuristic/speculative, the basis
  for refusing to treat a decode success as proof.
- `src-enowars-buggy-readme-f85b8d0e` — source-specific evidence that token/hash construction in a service
  is challenge-specific and often about generation rather than encoding.
