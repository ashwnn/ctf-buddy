# Build a route × method × role matrix and find the one cell with no check

**First useful action.** List every route with its methods and its authorization decoration, then list
which roles may call each; the missing cell is the finding.

```bash
rg -n --no-config -B2 -e '@app\.(get|post|put|delete|patch|route)|router\.(get|post|put|delete)|url\(' \
  -e 'app\.(all|use)\(|Route::|add_url_rule' <SERVICE_SRC>/ | head -n 120
rg -n --no-config -e 'login_required|requires_auth|is_admin|role|permission|before_request|middleware' \
  <SERVICE_SRC>/ | head -n 60
```

Expected: pairs of "route declaration" and "auth decorator/middleware". Routes without any decorator and
without a global `before_request`/middleware are unprotected by construction. If the service has one
global auth middleware, the matrix changes shape: the question becomes which routes explicitly opt out.

## Symptoms

- The service has admin functionality, an internal API, an export route, or a debug route.
- Some routes take a `role` or `admin` parameter, or check it inconsistently.
- One route was fixed after an exploit and a sibling route kept the old behaviour.

## Prerequisites and assumptions

- Read access to the source, or two accounts with different privileges plus the ability to enumerate
  routes.
- A way to distinguish "denied" from "absent" responses.
- Stack/version: decorator names and middleware mechanisms are framework-specific; the matrix is not.

## Diagnostic sequence

1. Extract all route declarations with their methods. → Rows of the matrix.
2. Extract all authorization mechanisms and where they are applied. → Columns.
3. Mark each cell: protected by global middleware, protected by decorator, protected inside the handler,
   or unprotected. → The unprotected column is the target list.
4. For each unprotected route, request it with each account. → Determines real impact rather than
   theoretical exposure.
5. Prioritise by what the route returns: anything that reads user data or the flag store first
   (`card-web-025-flag-read-path-priority`).

If one route reads another user's data while requiring *some* session, the defect is object-level
authorization, not authentication — go to `card-web-001-idor-object-swap` for the proof and the patch.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| route list with no decorator | `@app.get('/admin/export')` | Candidate: no per-route check; confirm middleware. |
| `rg 'before_request\|middleware'` | a global hook | Authentication is centralised; look for opt-out paths. |
| same request as two accounts | same body and status | The route does not differentiate roles. |
| protected route returning the login page for one account | `302` + login template | Denial; not a finding. |
| sibling route that answers `200` for both accounts | role-blind handler | Finding, usually the same root cause as the fixed route. |

## Exploit → patch pair

- **Flaw:** a route performs a privileged action without evaluating the caller's authority.
- **Reproduce on the isolated fixture:** `fixtures/d2-notehub-diagnose` (planned in
  `research/06-drills-and-validation.md`) with two seeded accounts and at least one route that should be
  owner-scoped (not yet run here).
- **Narrow patch:** add the same authorization helper the already-correct routes use, applied to the
  resource rather than to the path spelling. Do not add a second, differently implemented check.
- **Legitimate functionality that must keep working:** the legitimate callers of that route — including
  any checker flow and any internal service-to-service call, which may need a service credential rather
  than a user role.
- **Verify:** the unprivileged account is denied **and** the privileged/legitimate caller still gets the
  same response.

## Failure modes and things teams stopped doing

- Fixing the reported route and not its siblings. Duplicated authorization is how the second bypass
  appears; the SaarCTF 2025 Routerploit service is indexed as a case where the same user data was
  reachable through more than one path (`src-thomasweigold-saarctf2025-eaa12cba`).
- Adding `login_required` where `role_required` is needed. Authentication is not authorization
  (`src-portswigger-idor-c6997693`).
- Blocking the route at the proxy as the fix. The handler remains callable from inside the network or via
  another route (`src-nginx-proxy-module-f3430c5a`).
- Spreading the matrix work across several teammates without one owner. The #misec RuCTFE 2019
  retrospective describes duplicated and non-complementary findings caused by exactly this
  (`src-duchyoftaco-misec-ructfe2019-332d8e5b`).
- Assuming the framework hides routes that lack a decorator. A decorator that was simply forgotten is
  invisible in the UI and visible in the router (`src-fluix-faust2020-marsu-8b6084b7` shows framework-era route/service
  mapping work in the same spirit).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No route list was extracted and no request was issued in this
  session.
- **Our adaptation vs the source:** the authorization principle is from `src-portswigger-idor-c6997693`; the
  multi-path failure pattern from `src-thomasweigold-saarctf2025-eaa12cba`; the coordination failure mode from
  `src-duchyoftaco-misec-ructfe2019-332d8e5b`. The matrix format itself is our adaptation for making missing
  authorization visible under time pressure.

## Sources

- `src-portswigger-idor-c6997693` — server-side authorization on the resource, distinct from authentication.
- `src-thomasweigold-saarctf2025-eaa12cba` — A/D service where multiple paths reached the same protected data.
- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — coordination and duplicated-analysis failure modes in a real A/D team.
- `src-fluix-faust2020-marsu-8b6084b7` — FAUST CTF 2020 web service; route/service mapping reasoning.
- `src-maplebacon-ad-primer-23bd534f` — attack-defend primer covering service analysis practice.
