# Move the object identifier through every position before calling it safe

**First useful action.** Take the identifier from the working request and move it through each request
position in turn, keeping the session constant.

```bash
ID=<OTHER_USERS_OBJECT_ID>; S=<SESSION_JAR_USER_A>; B=http://127.0.0.1:<PORT>
curl -sS -o /dev/null -w 'path   %{http_code}\n' -b $S "$B/<RESOURCE>/$ID"
curl -sS -o /dev/null -w 'query  %{http_code}\n' -b $S "$B/<ROUTE>?id=$ID"
curl -sS -o /dev/null -w 'body   %{http_code}\n' -b $S -H 'Content-Type: application/json' -d "{\"id\":$ID}" "$B/<ROUTE>"
curl -sS -o /dev/null -w 'form   %{http_code}\n' -b $S -d "id=$ID" "$B/<ROUTE>"
curl -sS -o /dev/null -w 'header %{http_code}\n' -b $S -H "X-Object-Id: $ID" "$B/<ROUTE>"
```

Expected: a matrix of statuses. Any position that returns another user's data is a finding; positions that
return 403/404 tell you where the check does exist. If all positions deny, the defect is not object
selection — check whether the object is addressed by a *name* rather than an id, and repeat with the
filename/slug.

## Symptoms

- `card-web-001-idor-object-swap` showed one position is vulnerable but a fix was applied.
- The same resource is addressable through more than one route (read/export/print/email/preview).
- The API accepts both a path id and a body id.

## Prerequisites and assumptions

- Two identities or one identity plus one known foreign object.
- Knowledge of the resource's alternative identifiers (id, uuid, slug, filename).
- Stack/version: stack-agnostic; framework routing determines which positions even exist.

## Diagnostic sequence

1. Start from the request that the application itself generates for your own object (browser devtools,
   proxy history, or your fixture's client). → Real positions, not guessed ones.
2. Move the identifier one position at a time with the session fixed. → Status matrix.
3. Repeat for the alternative identifier forms (uuid, slug, filename, numeric). → A fix often covers the
   numeric id and forgets the slug.
4. Repeat for alternative routes that touch the same resource (export/download/preview). → Second routes
   frequently share the storage layer but not the check.
5. Record which combinations authorise correctly. → The patch must make all of them use one decision.

If you find a route that returns the object with no session at all, that is an authentication gap; escalate
it above the object-level finding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `path` and `query` both `403` | consistent authorization | Good sign; move to other routes/identifiers. |
| `body` returns the foreign object | `200` with foreign data | Object-level authorization missing on the write path. |
| `header` returns the same object | `200` | A header id is trusted; a client-controlled authority problem. |
| export route `200`, API route `403` | inconsistent control | The same resource has two different authorization decisions. |
| slug works, numeric id denied | fix incomplete | The patch covered one identifier form only. |

## Exploit → patch pair

- **Flaw:** authorization is implemented per identifier/route rather than per resource, so at least one
  address form reaches the object without the owner condition.
- **Reproduce on the isolated fixture:** `fixtures/d2-notehub-diagnose` (planned) with two accounts and a
  seeded foreign object; run the five positions and record which ones leak (not yet run here).
- **Narrow patch:** resolve the object through a single lookup that always includes the owner condition,
  and route every alternative address form through it. Do not add a check per position.
- **Legitimate functionality that must keep working:** every legitimate address form the UI, API, and
  checker use — including exports and downloads by the owner.
- **Verify:** every position that previously leaked now denies, and every legitimate form still returns
  the owner's object byte-identically.

## Failure modes and things teams stopped doing

- Fixing the reported URL and not the resource. The SaarCTF 2025 Routerploit service is indexed as a case
  where a user-data read was reachable through a specific parameter combination rather than through any
  hidden trick (`src-thomasweigold-saarctf2025-eaa12cba`).
- Making ids unguessable as the fix. It changes the size of the search space, not the authorization
  decision (`src-portswigger-idor-c6997693`).
- Ignoring the "export" style route. Export paths usually skip the UI's filters, which is why they are
  the first thing worth checking (same service, second path).
- Treating a `404` as proof of a correct fix. Confirm the same request returns your own object when you
  swap the id back; a broken lookup also returns 404.
- Building the matrix against a peer. Cross-owner requests are state-changing in the write direction and
  out of scope unless the event says otherwise (`AGENTS.md`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No request matrix was executed in this session.
- **Our adaptation vs the source:** PortSwigger documents multiple object-reference forms in the access
  control material (`src-portswigger-idor-c6997693`); the multi-path failure pattern in a real A/D service is
  from `src-thomasweigold-saarctf2025-eaa12cba`. The five-position matrix and the alternative-identifier step are our
  adaptation for quickly checking the completeness of someone else's patch.

## Sources

- `src-portswigger-idor-c6997693` — object references and server-side authorization.
- `src-thomasweigold-saarctf2025-eaa12cba` — A/D service where the same data was reachable through more than one
  parameterisation.
- `src-czechcyberteam-faust2024-todolist-225eeec1` — identity handling defects in a real service, relevant to
  alternative identity forms.
- `src-fluix-faust2020-marsu-8b6084b7` — framework-era route/model mapping for a web service.
