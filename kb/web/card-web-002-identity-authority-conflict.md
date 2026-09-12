# Label every authority source in a request before believing an ownership check

**First useful action.** In the handler for the suspicious route, write down each value that
answers "who is this?", then mark which one reaches the object lookup and which one is used at
the final authorization decision.

```bash
rg -n --no-config -e 'user_id|userid|user_guid|guid|owner|tenant|account|session|current_user' \
  -e 'WHERE|filter|get\(|findOne|SELECT' <SERVICE_SRC>/ | head -n 60
```

Expected: a short list of places where a request-supplied identity and a session/DB identity
coexist. If the route has exactly one identity source and it is server-derived, this card does
not apply — the bug is elsewhere.

## Symptoms

- The handler has both `session[...]`/`req.user` and a request field such as `user_id`,
  `user_guid`, `owner`, or `account`.
- One call site uses the session value and a nearby one uses the request value.
- The service was patched once already and the exploit still works through a different route.

## Prerequisites and assumptions

- Read access to handler source, or two controlled identities plus a baseline request.
- One working request that the application treats as legitimate.
- Stack/version: stack-agnostic; the pattern appears in Flask/Django/Express/PHP and in
  hand-written Python services alike.

## Diagnostic sequence

1. Enumerate identity-bearing values in the request (path, query, body, header, cookie) and in
   the server context (session, token claims, DB lookup). → You get a two-column list.
2. For each, trace **forward** to the first place it is consumed. → Consumption points split
   into "selects an object" and "decides whether the action is allowed".
3. Mark which identity is used at the object-selection predicate and which at the decision.
   → If selection uses request identity and the decision uses *no* identity, that is IDOR
   (`card-web-001-idor-object-swap`).
4. If selection uses session identity but a later branch re-reads a request identity (for
   example an "act-as" or "shared with" field), test the branch with only that field moved.
   → Branch B of this card: authority is *replaced* mid-handler.
5. Check whether the client-supplied value is merely a filter, with a server-side authorization
   check on the result. → If so, downgrade: this is a hypothesis, not a finding.

If the request value replaces authority only after a cached or memoised lookup, go to
`card-web-016-session-token-integrity`. If the request value is a *path* rather than an
identity, go to `card-web-027-canonicalization-order-tests`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'current_user\|session\[\|req\.user\|request\.user' <SERVICE_SRC>` | handler lines | Enumerate the *trusted* identity sources actually available. |
| `rg -n 'request\.(args\|form\|json)\[.user' <SERVICE_SRC>` | request identity reads | Candidate attacker-controlled authority. |
| `rg -n 'WHERE .*= ?\?' <SERVICE_SRC>` then read each | bound-parameter queries | Shows whether the ownership column is in the predicate or applied afterwards. |
| `diff` of two responses with only the identity field changed | differing objects | Request identity genuinely controls the result. |

## Exploit → patch pair

- **Flaw:** a client-supplied identity is consumed as if it were the authenticated identity.
- **Reproduce on the isolated fixture:** against an owned local fixture only, hold the session
  cookie for User A and set the request identity field to User B. Expected: the response body
  follows User B while the session never changed (not yet run here).
- **Narrow patch:** delete the request-supplied authority from the decision path and resolve the
  principal from the server-side session; where the field has a legitimate purpose (a filter or
  an explicit "shared" feature), keep it but require that the *owner column* still equals the
  session identity.
- **Legitimate functionality that must keep working:** any legitimate use of the same parameter
  name (search filter, admin impersonation for support, public share links) plus the checker's
  ordinary read/write flow.
- **Verify:** the same request now returns the session user's own resource or a denial **and**
  the ordinary list/read/create flow still returns the same status codes and schema.

## Failure modes and things teams stopped doing

- Patching the parameter in the template or client only. If the server still accepts a foreign
  identity, the defect is server-side (`src-portswigger-idor-c6997693`).
- Adding another `if` instead of removing the competing authority. Two identity sources with
  three checks is how the second bug gets introduced; the ENOWARS 4 Buggy service is indexed
  precisely because its authorization logic special-cases default values, and the analogous
  lesson is to simplify the predicate, not to stack conditions (`src-enowars-buggy-readme-f85b8d0e`).
- Trusting that a successful patch means the conflict is gone: the Czech Cyber Team's FAUST 2024
  Todo writeup documents an identity-collision problem in the same service family, so identity
  derivation deserves a second look even after the first exploit is closed
  (`src-czechcyberteam-faust2024-todolist-225eeec1`).
- Assuming an "admin" flag in the request is harmless because the UI never sends it. The
  request body is attacker-controlled regardless of the UI.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. This card is a reasoning procedure; the grep pattern was
  not executed against any service in this session.
- **Our adaptation vs the source:** the two-identity conflict pattern is documented in the
  SaarCTF 2025 Routerploit writeup (`src-thomasweigold-saarctf2025-eaa12cba`) and generalised by
  PortSwigger's access-control material (`src-portswigger-idor-c6997693`). We turned it into a
  labelling procedure plus an explicit downgrade rule (a filter with a server-side check is not
  a finding), which the sources state only implicitly.

## Sources

- `src-portswigger-idor-c6997693` — server-side authorization and the principle that object access
  must be bound to the trusted principal.
- `src-thomasweigold-saarctf2025-eaa12cba` — concrete A/D service with a client-supplied parameter
  competing with session identity.
- `src-enowars-buggy-readme-f85b8d0e` — indexed A/D service whose authorization logic has default-value
  edge cases; used here as the reason to simplify rather than layer predicates.
- `src-czechcyberteam-faust2024-todolist-225eeec1` — identity-collision failure in a real FAUST service.
