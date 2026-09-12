# Use strict Base64 decoding so failures mean something

**First useful action.** Decode with validation enabled so that an invalid alphabet or length is an
error rather than silent garbage.

```bash
python3 -c "import base64,sys;print(base64.b64decode(sys.argv[1],validate=True))" '<B64_VALUE>'
```

Expected: decoded bytes, or a `binascii.Error` naming the bad character. If it errors, the value is
either not Base64, a URL-safe variant, or unpadded — and those are different conclusions that need
different evidence.

## Symptoms

- A string matches the Base64 alphabet and ends with `=` padding, or matches the alphabet but has no
  padding at all.
- A previous decoder call with the default (non-validating) settings returned bytes that later turned
  out to be meaningless.
- The value contains `-` or `_` instead of `+` or `/`.

## Prerequisites and assumptions

- Python 3 (`base64.b64decode` with `validate=True`).
- The value is expected to be encoded bytes. If it is an identifier produced by a service, this card
  does not apply — see `card-crypto-classify-before-decoding`.
- Stack/version: standard-library semantics are stable across Python 3.9+; the corpus's tooling rule is
  Python 3.9+ standard library only.

## Diagnostic sequence

1. Strict decode with the standard alphabet. Success → step 3. Failure naming a character →
   inspect that character; `-`/`_` means URL-safe Base64, anything else means the value is not Base64.
2. Length-only failure → check for omitted padding before "fixing" it. A producer that intentionally
   strips padding is a documented pattern; a producer that truncated the value is not. Look for the
   producer in source or in a longer sample.
3. Inspect the decoded bytes: `file -`, printable ratio, magic prefix. This is the step that turns a
   decode into evidence.
4. If the decoded bytes are ASCII text of a different alphabet (base32/base85-like), that is a new
   candidate layer with evidence — continue in `card-misc-esoteric-encoding-layer`. If the bytes are
   high-entropy, stop and apply `card-crypto-layered-decode-stop-rule`.
5. Only after a successful strict decode plus meaningful structure should you write "this value is
   Base64" anywhere.

If strict decode fails and the value is URL-shaped (contains `_` and `-`) → retry with the URL-safe
alphabet once, then stop. If it fails for any other reason → treat the value as not-Base64 and re-run
the classification step instead of iterating on padding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `base64.b64decode(v, validate=True)` | bytes | Valid standard Base64: continue to structure inspection |
| `binascii.Error: Invalid base64-encoded string` | exception | Not standard Base64: variant, different encoding, or not an encoding |
| `binascii.Error: Incorrect padding` | exception | Padding question: verify the producer before adding `=` |
| `base64.urlsafe_b64decode(v)` | bytes | URL-safe variant is plausible only with context (JWT, URL parameter) |
| `file -` on decoded bytes | format name | The only real evidence about what the value encodes |

## Failure modes and things teams stopped doing

- Padding repair loops. Repeatedly appending `=` until the decoder stops complaining converts a
  "this is not Base64" signal into an incorrect decode; teams lose time chasing structure that does not
  exist.
- Accepting non-validating decode output as success. The default decoder ignores invalid characters,
  which is exactly how plausible garbage gets manufactured — the same failure class the corpus records
  for heuristic auto-decoding tools.
- Assuming URL-safe alphabet for anything with a `-` in it. Hyphenated identifiers are extremely
  common; the URL-safe branch requires a second, independent reason.
- Decoding and immediately declaring the answer (for example "the flag is base64"). Decode and
  structure inspection are separate steps, and only the second one produces evidence.

## Evidence status

- **Status:** source-supported but untested in this session; the underlying primitive was fixture-
  verified in the repository's 2026-09-11 build pass (strict Base64 decode).
- **What we actually ran:** nothing here. The `validate=True` semantics are standard-library behavior,
  consistent with the cryptography/encoding material recorded in the corpus index.
- **Our adaptation vs the source:** repository draft CRYPTO-002 provided the strict-decode rule; we
  added the URL-safe second-condition test, the padding-verification rule, and the branch into the
  stop-rule and esoteric-encoding cards.

## Sources

- `src-cryptohack-intro-401bf309` — Base64 recorded as one of the encoding primitives, with the standing
  caution against treating every opaque value as crypto or as layered encoding.
- `src-cyberchef-magic-source-2a3dcc0a` — the general warning that automated decoding is heuristic; the reason
  non-validating decoders must not be trusted as evidence.
