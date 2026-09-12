# Model a hash-shaped identifier's input space before enumerating it

**First useful action.** Read the identifier's construction in the source and estimate its real entropy
from the inputs actually available to an attacker, not from the digest's length.

```bash
grep -rIn -E "(sha|md5|hash|digest)" <SERVICE_SRC> | head -n 40
```

Expected: the hash call plus the values that feed it. If the input includes a server-side secret you
cannot obtain, stop treating the identifier as predictable — that is a different problem.

## Symptoms

- Object URLs contain long hex/base64 values that look unguessable but are generated from public data
  (username, timestamp, order number, sequence).
- Hash values repeat or collide for related inputs.
- A challenge prompt implies enumeration is possible ("find the order").

## Prerequisites and assumptions

- Source or a set of samples with known creation context (account, time window).
- Precision about what is being claimed: the digest function may be perfectly strong while the *input
  space* is tiny. The repository records an organizer service where the token/hash behaviour was
  explicitly challenge-specific — including a small variant set rather than a cryptographic break.
- Enumeration is bounded and local until scope is confirmed.

## Diagnostic sequence

1. Identify the hash function and, more importantly, its inputs. Entropy is determined by the inputs,
   not by the algorithm.
2. Bound the input space: which parts do you know exactly (your own username), approximately (creation
   time), or not at all (server secret)?
3. Recreate the construction locally across that bounded space and check whether it reproduces a value
   you *already hold*. Reproduction of a known value is the gate to enumeration; do not enumerate first
   and hope.
4. Only if reproduction succeeds, plan bounded enumeration of the smallest space that contains the
   target, with a request budget and a stop condition.
5. Report the entropy estimate alongside the result so the team can decide whether the finding is worth
   defending against in the remaining time.

If reproduction fails → the construction includes unknown data; treat the identifier as unguessable and
move to `card-crypto-classify-before-decoding` for a fresh classification.
If reproduction succeeds but the space is huge → the primitive exists but is not yet practical; record
it and apply `card-crypto-when-not-to-brute-force`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| source grep for the hash call | function + arguments | Shows which inputs exist; entropy starts here |
| local reconstruction matching a known sample | hit | Construction reproduced: enumeration is now a bounded search |
| local reconstruction failing across the full space | no hit | Hidden input (salt/secret/PID) or wrong assumption |
| sample comparison across two accounts | identical/related digests | Collisions or shared inputs; strengthens predictability |

## State-changing actions

- **Impact:** replacing identifier construction changes existing URLs/keys and may orphan stored
  objects; it can also break a checker that expects lookups to keep working.
- **Preconditions:** reproduced construction on a local fixture, plus a baseline of the legitimate
  lookup flow that must survive.
- **Health check before:** `curl -s http://127.0.0.1:<PORT>/<OBJECT_PATH_FOR_YOUR_OWN_OBJECT>` — expect
  the baseline response for your own object.
- **Apply:** generate identifiers with a cryptographically secure random value of sufficient length,
  bound to the owning account server-side, while keeping the identifier's external format (length,
  charset) unchanged so clients and the checker still parse it.
- **Health check after:** your own object still resolves; a value produced by the old construction for a
  different account no longer resolves; existing records remain reachable if the event requires it.
- **Rollback:** revert and restart; if old records must remain reachable, keep a lookup path for
  legacy identifiers during the event rather than migrating data under time pressure.

## Exploit → patch pair

- **Flaw:** object access is keyed by an identifier whose inputs are public and whose space is small, so
  identifiers can be enumerated instead of guessed.
- **Reproduce on the isolated fixture:** compute the identifier for an object you did not create
  (using known fields on `http://127.0.0.1:<PORT>`) → the fixture returns that object's content.
- **Narrow patch:** use a random identifier at creation time and enforce ownership server-side at
  lookup; do not change the response format.
- **Legitimate functionality that must keep working:** your own object lookup, and any checker flow that
  creates then retrieves an object.
- **Verify:** the computed foreign identifier no longer resolves **and** create-then-retrieve still
  passes.

## Failure modes and things teams stopped doing

- Judging by length. A 64-character hex string from a hash function over `username+timestamp` has far
  less entropy than its length suggests; length is not an entropy measure.
- Assuming "hashed" means "safe". Hashing with a public input is a deterministic function of that input;
  the digest adds no secrecy.
- Enumerating before reproducing. Requests against a live service cost availability and may trip rate
  limits; local reproduction first is both cheaper and more convincing.
- Calling a digest "encryption" and hunting for a key. There is no key in this construction, so key
  recovery has no meaning; the fix is input entropy, not key management.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing; no fixture, service, or hash computation ran in this session. The
  pattern and the "tiny variant set" observation come from the organizer repository we cite as recorded
  by the repository index; the entropy-estimation workflow is our adaptation.
- **Our adaptation vs the source:** repository draft CRYPTO/AD-022 material gave the timestamp/tiny-space
  idea. We added the reproduce-before-enumerate gate, the entropy-estimate reporting rule, and the
  legacy-identifier consideration in the patch.

## Sources

- `src-enowars-buggy-readme-f85b8d0e` — organizer-repository evidence that hash/token construction in a
  service was challenge-specific and small-space rather than cryptographically broken.
- `src-thomasweigold-saarctf2025-eaa12cba` — first-hand evidence of a predictable identifier in a
  real attack/defend service, plus a patch the corpus declines to recommend.
- `src-cryptohack-intro-401bf309` — the "an opaque value is not automatically crypto" discipline used to
  separate key-recovery thinking from entropy thinking.
