# Treat an exposed PRNG state as disclosure of future service secrets

**First useful action.** Find whether anything in the service exposes generator state or raw generator
output, then decide whether the same generator instance produces security-relevant values.

```bash
grep -rIn -E "(getstate|setstate|state\(\)|random_state|rand_state|debug|_internal)" <SERVICE_SRC> | head -n 50
```

Expected: either an endpoint/debug path that returns state-like data, or the generator's state being
serialized somewhere user-reachable. If nothing is exposed, this card does not apply and the token
problem is a seeding problem (`card-crypto-prng-seed-predictable-token`).

## Symptoms

- A debug, status, or "info" feature returns a long structure of numbers that looks internal.
- The challenge hands you an alleged snapshot of random state alongside ciphertext or a token.
- Values from the service can be reproduced locally after setting a generator state.

## Prerequisites and assumptions

- Source access or a strong behavioural hypothesis, plus a local instance for modelling.
- A willingness to distinguish two questions that look similar: (a) is state exposed, and (b) does the
  *security-relevant* value come from that same generator instance? The repository's attack/defend draft
  records this state-leak pattern from an ENOWARS service and treats generator-instance mapping as
  essential.
- Offline modelling only until scope is confirmed by the organizer.

## Diagnostic sequence

1. Enumerate exposed state: HTTP endpoints, debug routes, error payloads, saved files, or template
   outputs containing internal numbers.
2. Reproduce the generator locally. Set its state from the exposed value, generate the next outputs, and
   compare with what the service issues.
3. If predictions match → state exposure is confirmed and linked to issued values.
4. If predictions do not match → the exposed state belongs to a different generator instance or to a
   different algorithm version. Map generator instances before continuing; guessing wastes more time
   than the mapping costs.
5. Write down the linkage evidence. "The state leak lets us predict tokens" is only true with a
   demonstrated prediction.

If the leak predicts issued values → fix by separating concerns (below).
If the leak exists but is unrelated to tokens → downgrade it: a debug artifact is still a defect, but it
is not the flag path, and it should not displace higher-value work.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| source grep for state accessors | `getstate`/`setstate`-style uses | Generator state is handed around in code — look for exposure |
| endpoint returning arrays of integers | state-like blob | Candidate leak; needs a prediction test |
| local set-state-and-generate | predicted value matching the service | Confirmed linkage: the primitive is real |
| mismatch after modelling | no correlation | Different generator instance or algorithm: map before retrying |

## State-changing actions

- **Impact:** changing where random values come from can invalidate in-flight sessions and stored
  tokens, and can break the checker if the format or length changes.
- **Preconditions:** a demonstrated prediction on the local fixture; the exact legitimate flow the
  checker exercises; a rollback commit.
- **Health check before:** `curl -s http://127.0.0.1:<PORT>/<LEGITIMATE_ENDPOINT>` — expect the baseline
  response.
- **Apply:** stop exposing generator state (remove or gate the debug output) and generate
  security-relevant values from a cryptographically secure source, leaving the value's external format
  unchanged so clients and the checker still parse it.
- **Health check after:** rerun the legitimate request — expect the same shape of response; regression
  probe: existing sessions still work and the affected feature still issues usable values.
- **Rollback:** revert the commit and restart; if clients depend on the pre-existing format, keep the
  format and change only the entropy source.

## Exploit → patch pair

- **Flaw:** an external interface reveals pseudo-random state that also drives a security-relevant
  value, so future values are computable.
- **Reproduce on the isolated fixture:** query the debug/exposure path on `http://127.0.0.1:<PORT>`,
  set local state, and print the next predicted value → it matches the value the fixture subsequently
  issues.
- **Narrow patch:** remove the exposure and change the entropy source for that one value type; do not
  refactor unrelated generator usage.
- **Legitimate functionality that must keep working:** the exposed feature's *non-sensitive* purpose
  (if the checker or a UI depends on the endpoint existing, keep it returning only non-sensitive data).
- **Verify:** prediction fails **and** the legitimate feature still returns a usable response.

## Failure modes and things teams stopped doing

- Concluding "the service uses Python's `random`, therefore we win". Instance mapping and value linkage
  are the actual work; the draft corpus card on this pattern says exactly that — if the identifiers come
  from a separate cryptographic generator, the leak is irrelevant.
- Reading a debug structure as an encoded blob and decoding it. State is numbers, not base64; see
  `card-crypto-classify-before-decoding`.
- Deleting the debug endpoint as the whole fix while leaving token generation on the predictable
  generator. The exposure is a symptom; the entropy source is the defect.
- Assuming the leak persists after a service restart. State-based predictions are tied to process
  lifetime; record restitution boundaries when reporting results, since the checker may run against a
  restarted process.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing. No service, endpoint, or generator was exercised in this session.
  The pattern is attributed to the repository's own attack/defend draft, which records it against an
  ENOWARS service; the patch shape is our construction.
- **Our adaptation vs the source:** we added the instance-mapping gate, the explicit "leak unrelated to
  tokens is not the flag path" downgrade, and the restart-boundary note. The linkage requirement is our
  operational rule.

## Sources

- `src-enowars-cyberalchemist-readme-3cef120f` — organizer-repository service documentation that the
  repository records as the origin of the exposed-PRNG-state pattern (and of related
  dynamic-dispatch/pickle hazards in the same service family).
- `src-enowars-checker-tenets-bf4b0ac7` — the constraint that the patch must preserve checker-visible
  behavior.
- `src-cryptohack-intro-401bf309` — the general rule that a plausible-looking value is not by itself a
  classified object; here applied to "state" versus "token".
