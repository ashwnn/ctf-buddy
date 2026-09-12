# Derive an XOR key from a known plaintext prefix, then test it beyond the crib

**First useful action.** XOR the ciphertext's first bytes against your known plaintext (flag format,
file magic, or a constant from the source) to recover candidate key bytes.

```bash
python3 - <<'PY'
import sys, itertools
ct = bytes.fromhex('<CIPHERTEXT_HEX>')      # or read from <CIPHERTEXT_FILE>
crib = b'<KNOWN_PLAINTEXT_PREFIX>'
key = bytes(c ^ p for c, p in zip(ct, crib))
print('candidate key bytes:', key.hex())
print('key period guess:', next((n for n in range(1, len(key)+1) if len(set(key[i] for i in range(n)))-0 and all(key[i] == key[i % n] for i in range(len(key)))), None))
PY
```

Expected: key bytes and, when the key repeats, a small period such as 1, 3, 4, or 8. If no period
emerges, the cipher is not a simple repeating-key XOR under that crib — do not force it.

## Symptoms

- Ciphertext-like bytes and a strong belief that the plaintext starts with a known string (a flag
  format, a file header, an HTTP request line, a JSON opening).
- A source constant, a protocol header, or a challenge prompt supplies plaintext at a known offset.
- A single-byte XOR assumption has already failed.

## Prerequisites and assumptions

- Byte-aligned ciphertext (not hex text: convert first) and a crib at a *known* offset. A crib whose
  position is unknown is a different, harder problem.
- Alignment assumption, stated explicitly: XOR only yields the key when the plaintext bytes line up
  with the keystream bytes.
- No additional transform (compression, truncation, base64) between plaintext and ciphertext; if there
  is one, invert it first.

## Diagnostic sequence

1. Normalize everything to bytes. Hex digits XORed with ASCII produce garbage, and this mistake looks
   exactly like a failed attack.
2. Derive candidate key bytes from the crib. Read the candidate as a *pattern*: repeated bytes mean a
   short repeating key; all-distinct bytes over a long crib mean a keystream.
3. Test the pattern beyond the crib: XOR the whole ciphertext with the inferred key and check whether
   the result is coherent *outside* the crib region. This is the step that separates a real key from a
   coincidence.
4. If a period appears, extend the key by solving each residue class independently — that is the
   repeating-key structure made explicit.
5. If the crib assumption is wrong, the derived "key" explains only the crib. Detect this by checking
   whether the tail decodes to structure; when it does not, revert and question the crib, not the
   arithmetic.

If the derived key explains the whole message → done, record key, alignment, and crib as evidence.
If it explains only the crib → try a different crib (another known header) or branch to
`card-crypto-xor-single-byte-ranking` if the key pattern suggests a single byte.
If the bytes are not byte-aligned at all → consider bit-shifted or multi-byte-block constructions
rather than XOR.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `bytes.fromhex(...)` | raw bytes | Normalization; required before any XOR work |
| candidate key with one repeated byte | e.g. `4b 4b 4b ...` | Single-byte XOR: go to the 256-key ranking card |
| candidate key with period 3-16 | repeated n-byte pattern | Repeating-key XOR: solve per residue class |
| candidate key all-distinct over a long crib | keystream-like | Not a repeating key; look for a stream generator in the source |
| full-message decrypt after applying the key | coherent text | Evidence; the crib alone is not |

## Failure modes and things teams stopped doing

- XORing hex *characters* instead of decoded bytes. Every result looks like "almost text" and the time
  sink is real; this mistake is the reason step 1 exists.
- Stopping at the crib. A key that only reproduces the bytes you used to derive it is a tautology, not
  a break. Beyond-crib coherence is the actual test.
- Assuming a repeating key when the ciphertext was produced by a stream generator or a one-time pad. The
  candidate-key pattern tells you which case you are in; read the pattern instead of the message.
- Treating a partially coherent decode as success and writing it into the findings note. Half-readable
  plaintext usually means the crib was offset by one byte — check the offset before accepting.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session. The script above is an illustration of the
  procedure written by this worker; it was not executed, and no ciphertext was broken. XOR-as-a-
  primitive material is sourced from the cryptography course we cite; the workflow is our adaptation of
  repository draft CRYPTO-003.

## Sources

- `src-cryptohack-intro-401bf309` — XOR recorded as a core primitive in the intro course, including the
  properties that make crib-based key recovery valid.
- `src-cyberchef-magic-source-2a3dcc0a` — the caution that an XOR candidate produced by a heuristic search must be
  verified rather than believed; the reason for the beyond-crib test.
