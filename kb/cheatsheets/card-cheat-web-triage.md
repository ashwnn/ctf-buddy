# Web service triage: the first ten commands

**First useful action.** Send one request to every known route with `curl -i` and write the status
codes down before touching a payload. The fastest win in a web challenge is the route you have not
tried yet, not the exploit you have not written yet.

```bash
TARGET='http://127.0.0.1:<PORT>'   # fixture, drill container, or your own team VM
for p in / /index.php /api /login /admin /robots.txt /sitemap.xml /.git/HEAD; do
  printf '%-16s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code} %{size_download}b' "$TARGET$p")"
done
```

Expected: a short list where one route differs from the rest (200 with a body, 302 to `/login`,
401 vs 404 on `/admin`). A route that answers 500 to a plain GET is usually the interesting one.

## Symptoms

- You have a host and a port but no source, no route list, and no idea where the flag is served.
- A teammate already found one endpoint and everyone is standing on it.
- The organiser gave a service name and a protocol ("todo list on port 8080") and nothing else.

## Prerequisites and assumptions

- `curl` (the toolkit's built-in HTTP client covers verification, not exploration).
- Target is a fixture or your own team VM. Never spray any of this at a scored peer: a probe is a
  connection the defender sees.
- Stack/version: stack-agnostic. Route names, not exploitability, are what this sheet establishes.

## Diagnostic sequence

1. Route sweep above → note cookie names, redirect targets, and default pages (Apache/PHP/Flask/nginx
   banners identify the stack and therefore the likely vuln class).
2. `curl -sS -i "$TARGET/<INTERESTING_ROUTE>"` → read headers: server, framework, `Set-Cookie` flag
   names, and whether errors are echoed.
3. Send the obvious parameter with and without a mutation: `?id=1` vs `?id=999` (IDOR), `?file=a` vs
   `?file=../etc/passwd` (traversal), `?url=` (SSRF), `?q='` (SQL error), `?name={{7*7}}` (SSTI).
4. Only after a mutation changes behaviour, move to the matching card
   (`kb/web/`): `card-web-001-idor-object-swap`, `card-web-003-traversal-source-recovery`,
   `card-web-013-raw-query-boundary-hunt`.
5. Record the minimal working request as a reproducer (`card-web-008-minimal-http-reproducer`) before
   writing the patch or the exploit.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl -sS -i "$TARGET/route"` | `HTTP/1.1 200`, headers, body | the baseline you will compare against |
| `curl -sS -o /dev/null -w '%{http_code}\n' "$TARGET/x"` | `404` vs `200` vs `500` | route existence or a broken handler |
| `curl -sS -i "$TARGET/.git/HEAD"` | `ref: refs/heads/main` | a deployable tree is exposed: pull it and read the source |
| `curl -sS -i "$TARGET/?file=../../etc/passwd"` | file bytes | traversal; stop and switch to the traversal card |
| `curl -sS -i -H 'X-Forwarded-For: 127.0.0.1' "$TARGET/admin"` | 200 instead of 302 | trust placed in client-supplied headers |
| `curl -sS -i --path-as-is "$TARGET/a//b"` | different status to `/a/b` | proxy/normaliser disagreement worth probing |

Grep the evidence instead of re-reading it:

```bash
rg -i 'flag\{|ctf\{|password|secret|token' <(curl -sS "$TARGET/")   # source, not the wire
```

## State-changing actions (only if the card changes a host or service)

- **Impact:** none in this sheet; every command is a read.
- **Preconditions:** the target is a fixture or a team-owned host.
- **Health check before:** the route sweep itself is the baseline.
- **Apply:** none.
- **Health check after:** re-run the sweep after any patch; a route that was 200 and is now 404 is a
  regression, not a fix.
- **Rollback:** n/a.

## Failure modes and things teams stopped doing

- Spraying a directory brute-forcer at a peer service and calling it "scanning the target": it is
  scored traffic against another team, and the defender earns points for noticing.
- Chasing `/admin` forever when the interesting route was `/api/v2/export` on the same host.
- Treating `403` as "not there". `403` means the object exists: try the identity that owns it
  (`card-web-002-identity-authority-conflict`).

## Evidence status

- **Status:** version-sensitive (route names and default pages differ by image); commands are plain
  `curl`.
- **What we actually ran:** the route sweep pattern against the repository's own
  `fixtures/p1-flask-compose` during drill 01; output observed in `drills/answers.md`.
- **Our adaptation vs the source:** the sweep is our own ordering of OWASP WSTG's information-gathering
  step, reduced to one copy-paste block.

## Sources

- `src-owasp-wstg-dc0a99fe` — information gathering and route/method mapping for a web target.
- `src-portswigger-path-traversal-8145dc01`, `src-portswigger-idor-c6997693`,
  `src-portswigger-ssrf-f8039f92`, `src-portswigger-ssti-34b21c43` — the four first mutations above.
- `src-portswigger-access-control-84fb6fde` — 401/403 vs 404 as an authorization signal.
