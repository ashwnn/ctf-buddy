# Crypto triage: classify, then decode, then stop

**First useful action.** Classify the alphabet before decoding: length, character set, and whether
the data is an integer, a hex blob, a base64 string, or a stream. Guessing the wrong layer first
costs more time than any computation.

```bash
DATA='<CIPHERTEXT_OR_TOKEN>'
printf '%s' "$DATA" | wc -c                       # length
printf '%s' "$DATA" | LC_ALL=C grep -o '[^ ]' | sort -u | tr -d '\n'   # alphabet
printf '%s' "$DATA" | base64 -d 2>/dev/null | xxd | head             # strict base64 test
```

Expected: a length that matches a block size (16/32) or a key (8/16/32), and an alphabet that tells
you base64/hex/decimal/byte values. If the base64 decode fails, it was not base64 — do not force it.

## Symptoms

- A token, hash, or blob with no algorithm named.
- "Encrypted" data produced by a script you also have (often the way in).
- A PRNG-generated value you need to predict.

## Prerequisites and assumptions

- CyberChef (offline copy) for interactive work, Python 3 for anything scripted.
- Base64/hex knowledge: `card-crypto-strict-base64`, `card-crypto-hex-structure-check`.
- Stack/version: Python 3.9+ stdlib covers hashes, HMAC, and `secrets`; no third-party required.

## Diagnostic sequence

1. Classify (above) → if it decodes, iterate until the layer stops making sense
   (`card-crypto-layered-decode-stop-rule`).
2. If it is an integer/hex with a modulus, look for RSA structure: `n`, `e`, small exponent, or a
   shared modulus between two ciphertexts (`card-crypto-*` in `kb/crypto/`).
3. If it is a PRNG output, find the seed or the leaked state before brute-forcing anything
   (`card-crypto-prng-seed-predictable-token`, `card-crypto-prng-state-leak`).
4. If it is a repeating-key XOR, use the known-prefix crib or single-byte ranking rather than guessing
   (`card-crypto-xor-known-prefix-crib`, `card-crypto-xor-single-byte-ranking`).
5. If it is a hash, check whether it is a *password* hash (rate-limit yourself, then `hashcat`/`john`)
   or an integrity check (no cracking; find the preimage instead).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `python3 -c "import base64;print(base64.b64decode('<B64>',validate=True)[:32])"` | bytes or `binascii.Error` | strict base64 or not base64 at all |
| `python3 -c "print(int('<HEX>',16).bit_length())"` | bit length | 1024/2048 = RSA modulus, 512 = hash output, etc. |
| `python3 -c "from math import gcd; print(gcd(n1,n2))"` | a factor or 1 | two moduli sharing a prime (classic RSA break) |
| `hashcat -m 0 -a 0 hash.txt wordlist.txt` | recovered password | MD5 example; mode number matters |
| `john --format=raw-md5 --wordlist=wl.txt hash.txt` | recovered password | alternative engine |
| `xxd -r -p hex.txt > out.bin` | binary | hex to bytes without a scripting detour |
| `openssl enc -d -aes-256-cbc -K <HEXKEY> -iv <HEXIV> -in ct.bin` | plaintext | you already have key material; otherwise the mode is the challenge |

```bash
# XOR known-prefix crib: assume the plaintext starts with a known banner
python3 - <<'PY'
ct = bytes.fromhex('<HEX>')
crib = b'flag{'
key = bytes(c ^ p for c, p in zip(ct, crib))
print(key.hex())          # then test the key against the whole ciphertext
PY
```

## State-changing actions (only if the card changes a host or service)

None. Crypto work is offline. The one discipline that matters: keep the search space honest — if you
cannot say what the key space *is*, you are not brute-forcing, you are guessing
(`card-crypto-when-not-to-brute-force`).

## Failure modes and things teams stopped doing

- Feeding data to a "magic" decoder and accepting whatever appears; CyberChef Magic is a hypothesis
  generator, not an oracle (`card-crypto-cyberchef-magic-hypotheses`).
- Brute-forcing a space that was actually a leaked-state problem.
- Assuming a non-standard alphabet is encryption; it is usually an encoding with a shift or a
  substitution (classify first).
- Cracking a strong hash with a wordlist for twenty minutes when the challenge intent was the key
  derivation bug.

## Evidence status

- **Status:** source-supported; the XOR crib and classification steps are exact, the hash modes are
  tool-version-sensitive.
- **What we actually ran:** the classification and XOR-crib blocks against synthetic inputs while
  writing `kb/crypto/` cards (recorded there per card).
- **Our adaptation vs the source:** the "classify before decoding" gate is our ordering; the sources
  describe the individual attacks.

## Sources

- `src-cyberchef-magic-source-2a3dcc0a` — what the Magic operation actually does.
- `src-rfc4648-0da70d4b` — base16/32/64 alphabets and padding rules.
- `src-rfc8017-31deb889` — RSA structure (modulus, exponent, padding).
- `src-fips180-4-1755d2c9` — SHA-2 family and digest sizes.
- `src-python-random-docs-0f728645`, `src-python-secrets-docs-1e9766a6` — PRNG vs CSPRNG, the root of
  most "predictable token" challenges.
- `src-hashcat-example-hashes-2d14bb12`, `src-john-docs-9e58b8fd` — hash mode/format references.
- `src-cryptohack-intro-401bf309`, `src-cryptohack-intro-f2f02ea6` — the beginner progression these
  cards follow.
