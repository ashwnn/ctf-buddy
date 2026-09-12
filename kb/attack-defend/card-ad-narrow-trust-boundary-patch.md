# Patch the narrow trust-boundary condition, not the whole feature

**First useful action.** Freeze the two-request regression pair — one exploit, one legitimate — *before* editing a single line, so the patch has a pass/fail test the moment it exists.

```bash
mkdir -p <WORKDIR>/regression && \
  curl -s -o <WORKDIR>/regression/exploit.before -w 'exploit:%{http_code}\n' <EXPLOIT_REQUEST_ARGS> '<EXPLOIT_URL>' && \
  curl -s -o <WORKDIR>/regression/health.before  -w 'health:%{http_code}\n'  <HEALTH_REQUEST_ARGS>  '<HEALTH_URL>'
```

Expected: two different results — the exploit crosses a boundary the legitimate request does not. If both look identical, you do not yet have a discriminator; return to `card-ad-diff-attack-vs-checker-traffic` and find one before patching.

## Symptoms

- A route accepts attacker-controlled identity, path, action, or object owner data and acts on it.
- The obvious fix is "disable the endpoint", "deny that parameter", or "add a regex filter".
- A previous defensive change blocked the exploit and also broke normal use.

## Prerequisites and assumptions

- One reproducible exploit and one legitimate flow through the same code path.
- Knowledge of the concrete comparison or sink being abused, not just the payload.
- Assumption: the checker contract is known at least approximately; if not, read the checker first (`card-ad-read-checker-contract`).

## Diagnostic sequence

1. Record the pre-patch results of both requests, including status, body invariant, and any state change → this is your only objective before-picture.
2. Locate the smallest condition that re-establishes server-side authority: the place where the request value *replaces* a trusted value, not every place the value appears.
3. Change only that condition, restart only if the runtime requires it → branch A: exploit fails and legitimate flow passes, deploy after the transaction checks in `card-ad-patch-deploy-transaction`; branch B: either both fail (patch too broad) or both pass (patch missed the boundary).
4. If both pass, re-read the code path: the sink may be reached earlier than the check you edited, or the value may be consumed in a second location.

If branch B because both fail, revert immediately and narrow the change. If the patch "works" but changes response format, error codes, or field names, treat it as over-broad and re-narrow before deploying.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl ... '<EXPLOIT_URL>'` before/after | status plus body | the exploit must fail for the *right* reason; a 403 for everything means you broke authorization wholesale |
| `curl ... '<HEALTH_URL>'` before/after | status plus body | the legitimate path is the constraint that keeps the service scoreable |
| `git diff --stat` | files and line counts | a small diff is reviewable under pressure; a large diff is a hypothesis, not a patch |

## State-changing actions

- **Impact:** edits service code that the checker exercises; an over-broad change removes graded functionality while appearing to improve security.
- **Preconditions:** exploit reproduced, legitimate flow saved, rollback commit reachable, checker contract at least approximately known.
- **Health check before:** the `health.before` request — expect the baseline body invariant.
- **Apply:** edit only the condition that restores server-side authority; keep identifiers, field names, and status codes unchanged where the checker could observe them.
- **Health check after:** `curl ... '<HEALTH_URL>'` matches `health.before`, and a legitimate write-then-read round trip still returns the earlier value. Regression probe: the exact workflow the checker performs (store then retrieve), not a generic ping.
- **Rollback:** `git revert <patch-commit>` and redeploy; then re-run both requests. It is now unsafe to keep the patch if the legitimate body invariant changed in any way you cannot explain.

## Exploit → patch pair

- **Flaw:** an authorization decision that trusts a request-supplied owner/identity value instead of the server-side session identity.
- **Reproduce on the isolated fixture:** against your own copy only, send `<EXPLOIT_REQUEST_ARGS> 'http://127.0.0.1:<PORT>/<ROUTE>?owner=<OTHER_OWNER_ID>'` to `<LOCAL_FIXTURE>` → expect a 200 carrying another identity's record.
- **Narrow patch:** bind the lookup to the server-side identity (session or derived context) and ignore or validate the request-supplied owner field; do not add a deny-list of known-bad values.
- **Legitimate functionality that must keep working:** the normal authenticated fetch of your *own* record, including any legitimate sharing feature the service advertises.
- **Verify:** re-send the exploit → it fails; re-send the legitimate request → it still returns your own record with the same status and body shape.

## Failure modes and things teams stopped doing

- Teams stopped patching before understanding the exploit. A first-time retrospective reports building a defensive control before understanding the payload, which then consumed the host's memory — the general rule is reproduce first, then change one condition. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped writing broad filters where a specific fix was testable. Team guidance from a mature event describes precise defence: the checker exercises service functionality, and a binary or code patch has to preserve behaviour, so the smallest change that closes the primitive wins. [src-ntt-enowars8-writeup-8b4ecb49]
- Teams stopped "fixing" a predictable token by changing a constant seed. Where a security decision rests on a weak generator, the correction is to replace the token construction, not to reseed it — and only after regression-testing anything that reads stored tokens. [src-thomasweigold-saarctf2025-eaa12cba]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No request was issued and no patch was written in this session. `<LOCAL_FIXTURE>` must be a team-created local copy of the service; never the graded instance.
- **Our adaptation vs the source:** the two-request regression pair is our template. The "narrow fix" principle and the specific anti-patterns (seed change, blanket filter) come from the cited team and organizer material.

## Sources

- `src-thomasweigold-saarctf2025-eaa12cba` — worked example of a small authorization/identity fix and a rejected reseeding approach.
- `src-ntt-enowars8-writeup-8b4ecb49` — team retrospective on precise patching that must not change graded behaviour.
- `src-enowars-checker-tenets-bf4b0ac7` — patchability expectations for services.
- `src-d0gl0v3r-umcs2026-c85f0c19` — the cost of changing things before understanding them.
