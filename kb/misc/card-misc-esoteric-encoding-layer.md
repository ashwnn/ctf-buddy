# Handle the hidden encoding layer after an artifact decode

**First useful action.** Identify the alphabet of the decoded text and test the one candidate encoding
that its alphabet and length actually support, instead of trying encodings in a loop.

```bash
python3 - <<'PY'
import base64
s = open('<DECODED_TEXT_FILE>','rb').read().strip()
print('length:', len(s), 'charset:', sorted(set(s))[:12])
for name, fn in (('base32', base64.b32decode), ('base64', base64.b64decode), ('base85', base64.b85decode)):
    try:
        out = fn(s)
        print(name, 'ok ->', out[:60])
    except Exception as e:
        print(name, 'failed:', type(e).__name__)
PY
```

Expected: at most one decoder succeeds and produces plausible structure. If several succeed, the alphabet
is ambiguous and you need an independent discriminator (padding, length modulo, expected output type)
rather than the first success.

## Symptoms

- An artifact decode (device capture text, embedded object, header field) yields a second layer of
  letters and digits that is clearly not plain language.
- Base32-style uppercase-plus-2..7 patterns, or Base85 punctuation, or a fixed-width custom alphabet.
- A challenge prompt hints at "an encoding your tools do not recognize".

## Prerequisites and assumptions

- Decoded bytes in hand, plus the encoding the schema expects. Where a source or writeup names the
  encoding (for example a Base32 stage after a device decode), start there rather than searching.
- The corpus's version of the discipline: automated decoding is heuristic; a successful decode is a
  candidate, and structure is the evidence.
- Local-only tooling; no challenge data leaves the machine.

## Diagnostic sequence

1. Compute the character set and length. Alphabet size and padding are the primary discriminators.
2. Try exactly the encodings that discriminator admits (one or two, not a list). Strict decoders only.
3. Validate the output: recognizable magic, plausible language, expected field structure, or a checksum
   if the challenge provides one.
4. If the output is text in a further alphabet, recurse once with the same discipline. If it is binary or
   high-entropy, stop and re-examine the model (`card-crypto-layered-decode-stop-rule`).
5. If nothing decodes, consider that the layer may be a *custom table* rather than a standard encoding:
   compare the observed alphabet with the expected standard alphabet and look for a substitution
   mapping. A challenge's non-standard piece is usually visible as a deviation from a standard table, and
   the corpus records device-challenge designs where the non-standard element was the point.

If a standard encoding explains the data → done; log the layer and its evidence.
If the alphabet deviates from every standard table → treat it as a substitution and derive the mapping
from structure (frequencies, separators, known prefix), rather than cycling encoders.
If the prompt names an encoding → use that name and stop searching.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| character set print | `A-Z2-7` style | Base32-family candidate; uppercase plus digits 2-7 |
| strict decoder success | bytes | A candidate layer, not yet an answer |
| several decoders succeed | ambiguity | Use padding/length/expected-type as tiebreakers |
| output recognizably structured | context or magic present | The layer is justified; continue |
| alphabet off by one or two symbols | custom table | Derive the substitution instead of searching encoders |

## Failure modes and things teams stopped doing

- Running the whole encoding toolbox until something decodes. Ambiguous alphabets give multiple "successes"
  and the resulting text can look plausible while being wrong; this is the same false-positive class the
  corpus records for heuristic auto-decoding.
- Skipping the writeup that names the encoding. An organizer writeup for a device challenge may state
  explicitly that there is a Base32 stage after the descriptor decode; reading it turns a search into a
  single command.
- Assuming standard alphabet for a deliberately unusual device. Non-standard descriptors and non-standard
  alphabets are how these challenges are built; check before substituting.
- Escalating to "it must be encrypted" after encodings fail. That is a model change requiring evidence
  (from source, entropy analysis, or the prompt), not a fallback.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing; the script above is illustrative and was not executed. The
  existence of a post-decode encoding stage is recorded from the organizer challenge writeup we cite, and
  the alphabet-first discrimination rule is our construction.
- **Our adaptation vs the source:** specifically, the "several decoders succeed means ambiguity, not an
  answer" rule and the custom-table branch are ours; the source only establishes that a further encoding
  stage existed in one challenge.

## Sources

- `src-snakectf-ordinary-keyboard-19216912` — organizer writeup recording a device challenge with a
  non-standard HID descriptor and a subsequent Base32-style stage.
- `src-cyberchef-magic-source-2a3dcc0a` — the caution that heuristic decoding yields candidates requiring
  independent verification.
- `src-cryptohack-intro-401bf309` — encoding primitives as named, testable schemes rather than vague "try
  everything" territory.
