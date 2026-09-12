# Change how identity is resolved without breaking login or persistence

**First useful action.** Record a full login → create → retrieve → restart → retrieve cycle as the
baseline, then make exactly one change to how the server derives identity.

```bash
<CHECKER_COMMAND> --base-url http://127.0.0.1:<PORT> baseline > <EVIDENCE_DIR>/checker-before.json
curl -sS -c <JAR> -d 'username=<USER>&password=<PASS>' 'http://127.0.0.1:<PORT>/login' -o /dev/null -w 'login:%{http_code}\n'
```

Expected: green baseline and a `200` login. If login already fails, stop — you cannot attribute a later
failure to your change.

## Symptoms

- `card-web-016-session-token-integrity` found a forgeable or predictable session mechanism.
- The identity value is stored in the session/cookie and used directly by handlers.
- The checker logs in with generated credentials, creates objects, then returns in a later cycle to
  retrieve them.

## Prerequisites and assumptions

- The exact code path that reads the identity, and every other place that reads the same token.
- A rollback reachable in one command.
- Stack/version: server-side session stores, signed cookies, and framework auth middleware all require
  different patches; the invariant is the same.

## Diagnostic sequence

1. Baseline the full cycle, including a service restart before the final retrieval. → This is the
   regression test that matters.
2. List every consumer of the identity value (grep for the session key name). → Patch scope, not just the
   login route.
3. Apply one change: read identity from the server-side store / verified token rather than from the
   client-supplied payload.
4. Re-run the pair from `card-web-009-exploit-availability-regression-pair`: the tampered token must
   fail, login and object access must pass.
5. Restart the service and re-run the retrieval step. → Catches patches that invalidate persisted
   sessions or stored objects.

If login passes but the cross-cycle retrieval fails, your patch broke persistence (for example by
clearing the session store or rotating keys). Revert and narrow it.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n '<SESSION_KEY_NAME>' <SERVICE_SRC>` | every read of the token | Patch scope; anything missed stays vulnerable. |
| tampered token → `401` | intended | Integrity now enforced. |
| tampered token → `200` with the modified identity | failed patch | Another consumer still trusts the payload. |
| fresh login `200` + object create/read `200` | intended | Legitimate flow intact. |
| checker green before restart, red after | persistence broken | The patch invalidated stored state or keys. |

## State-changing actions

- **Impact:** authentication paths are used by the checker and by every legitimate user; mistakes here
  can log out the checker or lock the team out of its own service.
- **Preconditions:** reproduced forgery, enumerated consumers, recorded baseline, one-command rollback,
  permission to modify the service.
- **Health check before:** `<CHECKER_COMMAND> ... baseline` — expect green; plus one working login.
- **Apply:** one change to identity resolution (server-side lookup or verified signature), applied to
  every consumer found in step 2.
- **Health check after:** `<CHECKER_COMMAND> ... cycle` — expect green; regression probe: login, create,
  restart, retrieve.
- **Rollback:** `git revert <PATCH_COMMIT>` and redeploy; if sessions were invalidated, legitimate users
  must log in again — warn the team rather than silently rotating keys during a scored window.

## Exploit → patch pair

- **Flaw:** a client-supplied identity is treated as authoritative.
- **Reproduce on the isolated fixture:** `fixtures/d3-notehub-patch` (planned) — modify the session value
  and observe the response following the modified identity (not yet run here).
- **Narrow patch:** resolve identity server-side; where a signed token is used, verify it with the
  framework's mechanism instead of parsing the payload and trusting it.
- **Legitimate functionality that must keep working:** login, logout, session expiry, and cross-cycle
  persistence of checker-created objects.
- **Verify:** the tampered value is rejected **and** the full login → create → restart → retrieve cycle
  passes.

## Failure modes and things teams stopped doing

- Rotating the signing key as the "fix". It invalidates every existing session, including the checker's,
  and converts a security bug into an availability incident
  (`src-enowars-checker-tenets-bf4b0ac7`, `src-faust-attackdefense-beginners-e53569f0`).
- Patching the login handler only. If three handlers read the cookie payload, two of them remain
  vulnerable.
- Assuming persistence is unaffected because "sessions are stateless". Framework session stores,
  database-backed sessions, and file-backed sessions all interact with restarts.
- Changing authentication and authorization in the same commit. Keep them separate so a failure can be
  attributed; the drill design in `research/06-drills-and-validation.md` separates the two steps for the
  same reason.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No login, session change, or checker run happened in this session.
- **Our adaptation vs the source:** the predictable-token and authorization-logic context comes from
  `src-enowars-buggy-readme-f85b8d0e`; the availability constraint from `src-enowars-checker-tenets-bf4b0ac7` and
  `src-faust-attackdefense-beginners-e53569f0`. The "enumerate every consumer before patching" step is our
  adaptation, prompted by the multi-route failure pattern indexed from `src-thomasweigold-saarctf2025-eaa12cba`.

## Sources

- `src-enowars-buggy-readme-f85b8d0e` — authorization/token logic defects in an indexed A/D service.
- `src-enowars-checker-tenets-bf4b0ac7` — checker-visible functionality must survive defensive changes.
- `src-faust-attackdefense-beginners-e53569f0` — organizer guidance on availability and legitimate behaviour.
- `src-thomasweigold-saarctf2025-eaa12cba` — real service where multiple paths reached the same protected data.
- `src-fluix-faust2020-marsu-8b6084b7` — framework-era web service where the trust-boundary reasoning transferred but
  the framework details did not.
