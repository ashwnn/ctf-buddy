# Treat CyberChef Magic as a hypothesis list, never as an answer

**First useful action.** Run Magic on the raw blob with a known crib if you have one, then verify the
top suggestion by hand with a strict decoder before believing it.

```bash
# offline CyberChef instance only; challenge data stays local
curl -s -X POST http://127.0.0.1:<PORT>/ -H 'Content-Type: application/json' \
  -d '{"input":"<RAW_BLOB>","recipe":[{"op":"Magic","args":[false,false,false,true]}]}' \
  | head -c 400
```

Expected: a small set of candidate transformations with scores or a suggested output. If the response
is empty or an error, the local recipe/argument shape differs from your installed build — read the
operation's own arguments in the local UI instead of guessing.

## Symptoms

- An unknown blob survives file-typing and no mechanism is named anywhere in the challenge.
- A teammate wants to paste the full dataset into an online auto-decoder (never do this with challenge
  data).
- Magic returns several plausible-looking candidates and someone is about to take the first one.

## Prerequisites and assumptions

- A *local* CyberChef build (pinned version recorded alongside the finding). Challenge data is not sent
  to third-party services.
- An optional crib: a known flag format, a magic byte sequence, or a constant from the source.
- The documented nature of the operation: the project's own source records that Magic is a heuristic
  search — including bounded brute-force behaviour in more intensive modes — and that its output is a
  suggestion rather than proof.

## Diagnostic sequence

1. Establish the baseline: raw bytes, length, and any known plaintext. Magic is much more useful with a
   crib than without one; a crib turns scoring into verification.
2. Run Magic shallow first. Treat each candidate as a hypothesis with an implicit claim ("this is ROT13",
   "this is XOR with key X", "this is a base64 layer").
3. Verify the top candidate with a strict, independent decoder outside the tool. Success means the
   claimed scheme actually applies, not that the tool was persuasive.
4. Ask the discriminating question: does the verified result explain more of the input than the
   candidate was fitted to? A key derived from a crib that only explains the crib is not a key.
5. Only then continue the workflow in the matching card — XOR candidates go to
   `card-crypto-xor-known-prefix-crib`, encoding candidates to `card-crypto-layered-decode-stop-rule`.

If no candidate survives verification → record "heuristic search found nothing" and move to the source,
the metadata, or the challenge prompt. That is a legitimate, reportable result, not a failure.
If a candidate looks perfect but is untestable → do not write it into the findings note as a fact.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| local Magic run, shallow | one or a few candidates | Leads only; each needs independent verification |
| local Magic run, intensive | many candidates, brute-forced keys | Higher false-positive rate by construction; verify harder |
| manual `base64.b64decode(..., validate=True)` | bytes or exception | Independent check of an encoding hypothesis |
| crib match position/count | off-by-N, repeats | Structural evidence that survives beyond the tool's score |

## Failure modes and things teams stopped doing

- Uploading the challenge data to an online decoder. It is convenient, breaks event rules in many
  formats, and leaks the artifact you were given to work on.
- Accepting a candidate because the score is high. Scoring is a heuristic ranking function; the corpus's
  own note on this operation says its suggestions are not proof of encoding or encryption.
- Letting intensive mode run on a large blob and then reading its output as a result set. Bounded brute
  force produces plausible junk; it is a search, and searches need validation.
- Burning the clock on automated candidates while the challenge prompt already names the mechanism.
  Read the prompt once more before running any heuristic search.

## Evidence status

- **Status:** source-supported but untested; explicitly version-sensitive (the operation is under active
  development and behaviour differs by release).
- **What we actually ran:** nothing. No CyberChef instance was started in this session, and the HTTP
  example is a construction of ours showing the shape of an offline call, not a verified invocation.
- **Our adaptation vs the source:** the repository draft CRYPTO-006 supplied "hypothesis generator, not
  proof"; we added the local-only requirement, the crib-based verification gate, and the
  "no candidate survives is a reportable result" branch.

## Sources

- `src-cyberchef-magic-source-2a3dcc0a` — maintainer source for the operation, documenting its heuristic and
  speculative-search nature (including bounded brute force) via the repository index's reading of it.
- `src-cryptohack-intro-401bf309` — the standing caution against treating any single decode as a
  classification of an arbitrary blob.
