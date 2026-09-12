# Stop recursive decoding when a layer stops adding structure

**First useful action.** Before applying the next transform, write down what evidence that transform
*should* produce, and abandon the layer if the evidence does not appear.

```bash
for l in 1 2 3; do : ; done  # discipline, not a command: log each layer's evidence to <ANALYSIS_DIR>/layers.md
printf '%s' '<VALUE>' | base64 -d 2>/dev/null | file -
```

Expected: a file-type verdict or clearly structured text change per layer. If a layer produces
unstructured bytes, record the layer count and stop — a correct decode can legitimately leave
high-entropy data behind (compressed or encrypted), and continuing tells you nothing.

## Symptoms

- You have applied three or more transformations and the output is still "looks like maybe another
  Base64".
- Each layer is easier to justify after the fact than to predict beforehand.
- Two teammates disagree about whether a fourth layer exists.

## Prerequisites and assumptions

- A definition of evidence per layer: valid strict decode, recognized magic bytes, parseable syntax,
  a known crib, or a checksum that matches.
- The corpus's standing caution: heuristic auto-decoders are speculative and can generate plausible
  false positives, so "the tool suggested this chain" is not evidence.
- A log file for layers. Without it, a later reader cannot tell whether you used five layers or
  fifteen.

## Diagnostic sequence

1. Layer 0: record the raw value, its length, and its alphabet. That is the baseline.
2. For each candidate transform, predict the shape of the output *before* running it: a magic prefix,
   a JSON/XML opening token, a language-plausible character distribution, or a known flag prefix.
3. Run the transform with a strict, failing decoder where one exists. Silent-garbage decoders are not
   allowed to generate candidates.
4. Compare with the prediction. Match → keep the layer, log it, continue. Mismatch → revert the layer
   and log it as a dead end.
5. After two consecutive structure-free layers, switch strategies rather than continuing: check the
   container/file type, entropy, the source code, or the challenge prompt for a stated mechanism.

If the prompt or source names a mechanism (for example "XOR with a repeating key", "RSA", "a custom
keystream") → jump straight to the corresponding card instead of peeling encodings: that is a huge time
saving and it is the normal case in well-written challenges. If it names nothing and two layers have
failed → re-read the prompt for a hint you skipped, then treat the artifact as binary data.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file -` after a layer | new format name | Real structure: the layer is justified |
| `file -` after a layer | `data` | No evidence: stop unless a source states a further mechanism |
| `base64 -d` exit status | `0` with unstructured output | Alphabet-matched but probably not the intended layer |
| layer log with transform + prediction + result | audit trail | Lets a teammate resume instead of restarting |

## Failure modes and things teams stopped doing

- Recursive decoding until something "looks like text". Executable presence of a valid decoder is not
  evidence that the value was encoded by that method; this is the same false-positive class the corpus
  records for heuristic auto-decoding, and it is the most common time sink in encoding challenges.
- Measuring success with printable-character ratio alone. Compressed and encrypted data are legitimately
  non-printable; a base64 text blob followed by a second base64 blob can also be printable throughout,
  so the metric does not discriminate between progress and noise.
- Erasing the layer history. Without a log, a team cannot tell whether the current blob is the original
  value or the result of a wrong transform applied three steps ago.
- Letting a tool's suggested recipe decide the answer. Tools propose; only structure, source, or a crib
  confirms.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session. This card is a procedure, and the one command shown
  is an illustration of a strict-decoder check rather than a verified chain on a real artifact.
- **Our adaptation vs the source:** repository draft CRYPTO-007 supplied the stop rule ("require each
  transform to increase evidence"). We added the predict-then-test gate, the two-layer switch trigger,
  and the explicit "prompt names a mechanism → skip to that card" shortcut.

## Sources

- `src-cyberchef-magic-source-2a3dcc0a` — the source-level basis for "automatic decoding is heuristic and can
  produce plausible false positives in intensive modes".
- `src-cryptohack-intro-401bf309` — educational material that teaches named primitives; the reason a
  challenge usually has a stated mechanism worth looking for instead of guessing layers.
