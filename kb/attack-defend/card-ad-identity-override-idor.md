# Prove client-supplied identity is overriding session identity

**First useful action.** Change only the identity-bearing value in the request and keep the session identical; if the returned object changes owner, you have found a trust-boundary defect.

```bash
curl -sS -b '<SESSION_COOKIE>' '<BASE_URL>/<ROUTE>?<OWNER_PARAM>=<OTHER_OWNER_ID>' \
  -o <WORKDIR>/idor.foreign -w 'foreign:%{http_code}\n' && head -c 300 <WORKDIR>/idor.foreign
curl -sS -b '<SESSION_COOKIE>' '<BASE_URL>/<ROUTE>?<OWNER_PARAM>=<MY_OWNER_ID>' \
  -o <WORKDIR>/idor.mine -w 'mine:%{http_code}\n'
```

Expected: the foreign request returns another owner's record with a success status, while the same session's own request returns your record. If both return the same object regardless of the parameter, the parameter is being ignored — which is a different finding (possibly safe, possibly a missing feature).

## Symptoms

- An authenticated route accepts `user_id`, `owner`, `account`, `tenant`, `guid`, or a filename that names an object.
- A profile or invoice page returns another user's data when one identifier is edited.
- The authorization check exists but appears to consult the same value the client supplies.

## Prerequisites and assumptions

- Two controlled identities, or one identity plus a known foreign object identifier.
- Session handling you understand well enough to keep constant while varying one field.
- Assumption: you know what the object's intended authorization policy is. A public or shared object returning the same content is not a finding.

## Diagnostic sequence

1. Enumerate every authority-bearing value in the request: path segment, query parameter, body field, header, cookie, and derived values such as a filename → mark each as session-derived or client-supplied.
2. Vary one value at a time while holding the session constant → branch A: ownership changes, so the client value reaches the authorization decision; branch B: nothing changes, so look for a different parameter or a server-side derivation.
3. Follow which value reaches the object lookup and which reaches the authorization comparison → if they are different values, the defect is in the comparison, not the lookup.
4. Confirm the effect is data, not just presentation: check whether the foreign record is complete and whether any write operation is also addressable.

If the lookup and the check use the same client value, go to `card-ad-narrow-trust-boundary-patch` and bind the lookup to the server-side identity. If only reads are affected but the object is genuinely shared, record it as expected behaviour rather than a bug.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| foreign request with own session cookie | 200 plus another owner's data | the session did not constrain the object; the client parameter did |
| own request with own identifier | 200 plus your data | the legitimate path you must preserve in the patch |
| `diff <(head -c 200 <WORKDIR>/idor.foreign) <(head -c 200 <WORKDIR>/idor.mine)` | differences or none | proves the response is owner-dependent rather than constant |
| `grep -rnE '<OWNER_PARAM>\|session\|current_user' <SERVICE_DIR>` | source hits | whether both identities are read in the same handler — the actual defect site |

## State-changing actions

- **Impact:** read probes are low risk, but a write endpoint exercised the same way mutates another identity's data; never vary identifiers on a write path outside your own fixture.
- **Preconditions:** two owned identities, the legitimate request saved, and a fixture or owned instance.
- **Health check before:** the legitimate own-object request returns its baseline response.
- **Apply:** patch the authorization comparison to use server-side identity; keep the request and response schema unchanged.
- **Health check after:** the foreign request fails, the own request succeeds unchanged. Regression probe: the checker's own use of the same route, including any legitimate cross-owner sharing feature.
- **Rollback:** `git revert --no-edit <patch-commit>`; re-verify both requests. Rollback is unsafe if the patch also wrote data under a reassigned owner.

## Exploit → patch pair

- **Flaw:** the handler derives the object owner from a client-supplied value instead of the authenticated session, so a valid session can address other owners' objects.
- **Reproduce on the isolated fixture:** `curl -b '<SESSION_COOKIE>' 'http://127.0.0.1:<PORT>/<ROUTE>?<OWNER_PARAM>=<OTHER_OWNER_ID>'` against `<LOCAL_FIXTURE>` → expect a 200 containing the other owner's record.
- **Narrow patch:** replace the client-supplied owner with the session-derived owner at the lookup, or verify the client value equals the session value before use; do not delete the parameter if a legitimate administrative or sharing flow depends on it.
- **Legitimate functionality that must keep working:** your own object fetch, plus any documented sharing/delegation flow, plus whatever the checker calls on that route.
- **Verify:** foreign request returns an authorization failure, own request returns the same body as before, and the checker still passes.

## Failure modes and things teams stopped doing

- Teams stopped fixing identifier leakage by obscuring identifiers. In a worked A/D example the vulnerable route accepted a client-side identity and returned foreign data; the durable fix was to make the server's own identity authoritative rather than to make the identifier unguessable. [src-thomasweigold-saarctf2025-eaa12cba]
- Teams stopped writing patches that disable the endpoint. A patch that removes a graded feature fails the checker, and the cited defence guidance is that patches must preserve service behaviour. [src-ntt-enowars8-writeup-8b4ecb49]
- Teams stopped trusting "the parameter is validated" as a conclusion. Where two identity sources exist in one request, the question is which one reaches the authorization decision — a question only source review answers. [src-maplebacon-ad-primer-23bd534f]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No request was sent and no patch was written; all placeholders must be replaced with values from your own service and fixture.
- **Our adaptation vs the source:** the vary-one-field protocol and the minimal paired patch test are our templates. The identity-override example and the "make the server authoritative" fix come from the cited team write-up.

## Sources

- `src-thomasweigold-saarctf2025-eaa12cba` — worked example of client-supplied identity overriding session identity, with the narrow fix.
- `src-ntt-enowars8-writeup-8b4ecb49` — patching that must preserve graded behaviour.
- `src-maplebacon-ad-primer-23bd534f` — A/D primer framing of trust boundaries and defence.
- `src-enowars-checker-tenets-bf4b0ac7` — expectations a patched service must continue to satisfy.
