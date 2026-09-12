# Decide against brute force before you start it

**First useful action.** Write the space size, the per-attempt cost, and the acceptance criterion on
one line; if any of the three is unknown, the brute force is not ready to start.

```bash
python3 - <<'PY'
space = <KEYS_OR_INPUTS_COUNT>   # e.g. 256, 65536, 10**6, 2**32
per_attempt_ms = <MS_PER_ATTEMPT> # measured locally, not guessed
budget_s = <SECONDS_YOU_CAN_SPEND>
print('needed seconds:', space * per_attempt_ms / 1000)
print('fits budget:', space * per_attempt_ms / 1000 <= budget_s)
PY
```

Expected: an arithmetic verdict — fits or does not fit. If you cannot fill in a number honestly, the
answer is "do not brute force yet"; get the measurement first.

## Symptoms

- Someone proposes "let's just brute force it" without a keyspace or a rate limit in hand.
- A hash-shaped value is being handed to a lookup or cracking workflow with no candidate wordlist or
  mask theory.
- You are considering sending thousands of requests to a service in a timed event.

## Prerequisites and assumptions

- A measured per-attempt cost from your own machine or fixture. Offline cost and network cost differ by
  orders of magnitude and must not be conflated.
- Knowledge of which space you are enumerating: keys, inputs, seeds, or identifiers. Brute force without
  a model usually enumerates the wrong space.
- Any rule constraints on automation and request volume — unknown means dry-run only.

## Diagnostic sequence

1. State the space and where the number came from (source, observed collision, or measured property).
   A space you cannot bound is an argument for a smarter attack, not a bigger one.
2. Measure the per-attempt cost locally with the exact implementation you plan to use.
3. Multiply, compare with the clock you have left, and write the verdict down.
4. If it does not fit, look for a structural shortcut: cancellation, a crib, a state leak, a smaller
   effective space (see the sibling crypto cards).
5. If it fits, add an acceptance criterion and a stop condition *before* the first attempt, so a
   partial run produces a decision rather than a pile of candidates.

If the space is small but the target is a live service → check the automation rules and rate budget
first; the repository's rule gate keeps cross-team execution disabled until the organizer confirms scope.
If the space is unbounded but structure exists → prefer the structural attack; that is almost always
faster than hardware.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `space * cost` arithmetic | seconds needed | Decision input; unknown inputs forbid the run |
| measured local throughput | attempts/second | Offline ceiling; network attempts will be far slower |
| candidate list length vs. acceptance test | fraction accepted | If acceptance is vague, every candidate looks plausible — the corpus's warning about heuristic search |
| observed repeat/collision in samples | effective space estimate | Real evidence about how small the space is |

## Failure modes and things teams stopped doing

- Brute-forcing a digest or identifier before checking whether the plaintext space is even in the
  candidate set. A lookup only helps when the answer is inside the wordlist or mask you chose; the
  digest's length says nothing about feasibility.
- Treating hash length as an entropy estimate. Length is a property of the output, not of the input
  space; see `card-crypto-low-entropy-token-space`.
- Running large searches against live services in a timed event. Availability loss and rate limits are
  scored in attack/defend formats, and the repository's operations research records a first-time team
  damaging its own host with an over-eager defensive control.
- Starting a search without an acceptance criterion. Heuristic scoring then decides the answer, which is
  precisely the false-positive behaviour the corpus records for automated decoding: bounded brute force
  produces plausible results that still need verification.
- Escalating hardware instead of re-reading the source. The source frequently states the mechanism and
  makes the search unnecessary.

## Evidence status

- **Status:** source-supported but untested; the arithmetic template is our construction.
- **What we actually ran:** nothing. No search, cracker, or service request was executed in this
  session; the budget template is illustrative Python that a teammate must fill with real measurements.
- **Our adaptation vs the source:** repository draft CRYPTO-004's "if no candidate is coherent, stop"
  rule is extended into an explicit cost model. The automation caution is attributed to the
  attack/defend operations research in this repository, not to a cryptography source.

## Sources

- `src-cyberchef-magic-source-2a3dcc0a` — documentation that bounded brute force inside heuristic tooling yields
  candidates rather than answers, which is why an acceptance criterion is mandatory.
- `src-enowars-buggy-readme-f85b8d0e` — organizer evidence that token/hash spaces in services are often
  small-and-specific rather than large; the reason the space must be bounded from the source.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time-team failure story about aggressive defensive tooling
  consuming host resources; the reason request-volume and resource budget belong in this decision.
- `src-maplebacon-ad-primer-23bd534f` — attack/defend primer material noting that automation depends on
  competition-specific rules and APIs; hence "unknown rules means dry-run".
