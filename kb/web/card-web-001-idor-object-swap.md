# Swap one object identifier under a valid session to test for IDOR

**First useful action.** Log in as one seeded user, request your own object, then change
**only** the object identifier and keep the session cookie byte-identical.

```bash
# 1) your own object
curl -sS -i -b <SESSION_JAR_USER_A> 'http://127.0.0.1:<PORT>/api/notes?id=<OBJECT_ID_USER_A>'
# 2) same session, one token changed
curl -sS -i -b <SESSION_JAR_USER_A> 'http://127.0.0.1:<PORT>/api/notes?id=<OBJECT_ID_USER_B>'
```

Expected: request 2 returns User B's object body while the cookie still identifies User A.
If request 2 returns 401/403, the endpoint is authenticated *and* authorized — stop here and
move to `card-web-026-object-id-mutation-matrix`. If request 2 returns 404, the handler may
filter by owner but the identifier space may still be enumerable elsewhere.

## Symptoms

- An authenticated route addresses a single object by id, filename, slug, or key in the URL,
  query string, JSON body, or a form field.
- The same identifier appears in a list endpoint that already returned only your own objects.
- Two seeded accounts exist and at least one object is owned by the other account.

## Prerequisites and assumptions

- Two identities you control on an instance the team owns, or one identity plus a known
  foreign object identifier.
- A cookie jar file so the session is provably unchanged between the two requests.
- Stack/version: stack-agnostic. The class is "the object lookup does not include the
  authenticated principal in its selection or authorization predicate".

## Diagnostic sequence

1. List your own objects; record the exact identifier form (`?id=2`, `/notes/2`, `{"id":2}`).
   → This gives you the baseline shape of a legitimate request.
2. Replay your own read and confirm it returns your object. → Baseline proven; do not
   continue until this works, otherwise you cannot tell authorization from broken routing.
3. Change only the identifier to the other identity's object, keeping cookie, method, headers,
   and content type fixed. → Cross-owner data returned = IDOR. Denied = authorization present
   on this route.
4. Change the identifier to a value that cannot exist (`<LARGE_INTEGER>`). → Comparing the
   missing-object response with the denied-object response tells you whether "denied" and
   "absent" are distinguishable. Endpoints that answer 404 for both still leak existence
   if timing or body length differs.
5. For write paths, repeat with `PUT`/`PATCH`/`DELETE` only against the team's own fixture,
   because a successful cross-owner write mutates state and may break the checker.

If step 3 succeeds on read but fails on write, keep both results: the read case is enough to
prove the missing authorization predicate, and the write case usually shares the same handler.
If step 3 is denied but a sibling route (export/download/print/email) returns the same object,
go to `card-web-023-route-method-role-matrix`, because that is the same bug on a second route.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' -b <JAR_A> '...?id=<ID_B>'` | `200 <large>` | Body returned for a foreign object — authorization predicate likely missing. |
| same, as above | `403` / `404` | Authorization or lookup filtering exists on this route. |
| `curl -sS -i -b <JAR_A> '...?id=<NONEXISTENT>'` | `404` with same body as denied case | Denied and absent are indistinguishable; ownership proof still stands from step 3. |
| `diff <(curl -sS -b <JAR_A> '...?id=<ID_A>') <(curl -sS -b <JAR_A> '...?id=<ID_B>')` | differing bodies | Two distinct objects addressable by one session. |

## Exploit → patch pair

- **Flaw:** the single-object query selects by identifier only, so the authenticated principal
  never participates in the decision.
- **Reproduce on the isolated fixture:** `fixtures/d2-notehub-diagnose` (planned in
  `research/06-drills-and-validation.md`) with `GET /api/notes?id=<OTHER_NOTE_ID>` while
  holding User A's cookie. Expected: the seeded foreign note body is returned (not yet run
  here — see Evidence status).
- **Narrow patch:** add the owner to the retrieval predicate, or check ownership immediately
  after fetching, using the server-side session identity:
  `WHERE id = ? AND owner = ?` with bound parameters `(<note_id>, <session_user>)`. Do not
  obscure identifiers, do not randomise ids, do not delete the route.
- **Legitimate functionality that must keep working:** the owner still reads their own object
  by id; list-my-objects; create; login; and any checker flow that stores and later retrieves
  an object it created.
- **Verify:** the identical cross-owner request now returns 403/404 **and** the own-object read
  still returns the same body and status as before the patch.

## Failure modes and things teams stopped doing

- Randomising or hiding numeric ids as the "fix". The repository's own drill design explicitly
  rejects this: the object identifier must be treated as attacker-controlled, and the control
  belongs in the authorization decision (`research/06-drills-and-validation.md`). PortSwigger's
  access-control material frames the same rule as server-side authorization on the object
  (`src-portswigger-idor-c6997693`).
- Comparing the wrong user: changing the session *and* the identifier together proves nothing.
  The whole evidence value of this card is that exactly one variable moves.
- Assuming a denied write plus an allowed read means "half fixed". Both routes usually share
  the same object-fetch helper (`src-thomasweigold-saarctf2025-eaa12cba` documents an IDOR-style parameter
  and predictable-token problem in the same service).
- Treating a successful `200` as proof without checking the body. A route can return 200 with an
  empty object when the lookup silently fails, which is a different (and differently patched)
  defect.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No request was issued in this session; the fixture named
  above is planned, not confirmed present in `fixtures/`.
- **Our adaptation vs the source:** PortSwigger teaches the vulnerability class in a lab
  environment (`src-portswigger-idor-c6997693`); the SaarCTF 2025 Routerploit writeup shows the
  same class in an attack/defend service (`src-thomasweigold-saarctf2025-eaa12cba`). We adapted both into
  an attack/defend decision rule: prove the read, then patch with a bound-parameter ownership
  predicate, then re-run the checker. The specific parameter names (`id`, `user_guid`) are
  service-specific and must be read from the target source.

## Sources

- `src-portswigger-idor-c6997693` — the object-reference / missing-server-side-authorization class
  and the rule that the fix is authorization, not identifier secrecy.
- `src-thomasweigold-saarctf2025-eaa12cba` — real A/D service where an identifier and a predictable token
  combined into user-data access, plus the observation that the team's patch changed seed
  behaviour rather than the trust boundary.
