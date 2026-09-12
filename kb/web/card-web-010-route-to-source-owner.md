# Walk a path back to the process and source file that actually owns it

**First useful action.** Start from the listener, not the URL: follow proxy → upstream → process →
working directory, then confirm the route in the source.

```bash
ss -ltnp; nginx -T 2>/dev/null | grep -nE 'server_name|location|proxy_pass|fastcgi_pass' | head -n 40
```

Expected: a small chain like `0.0.0.0:80 -> nginx -> /location / -> proxy_pass http://127.0.0.1:<PORT>`
and then a listener on `<PORT>` owned by the application process. If a path serves a static file
instead, `proxy_pass` will be absent for that location and the file comes from a `root`/`alias`
directory — a different fix path entirely.

## Symptoms

- A request path appears in traffic, a log, or a checker failure, and nobody knows which component
  answers it.
- Two services listen on the same host and it is unclear which one owns a route.
- A teammate patched "the route" in one codebase and the exploit still worked.

## Prerequisites and assumptions

- Local access to the team's own VM/container, or the ability to read the deployed config.
- `ss`, plus `nginx`/`apachectl` where those servers are present.
- Stack/version: nginx `-T` exists from 1.9.2; older builds need the include files read individually.
  Apache exposes vhost mapping through `apachectl -S` (`src-apachectl-o20-98508984`).

## Diagnostic sequence

1. `ss -ltnp` — list every listener with its owning process. → Identifies front proxies and app servers
   before any URL reasoning.
2. For a front proxy, dump the effective config and extract `server_name`, `location`, `proxy_pass`,
   `fastcgi_pass`, `uwsgi_pass`. → Builds the path-to-upstream map
   (`src-nginx-proxy-module-f3430c5a`).
3. Resolve each upstream address to a listener and process. → The app server, its PID, and its
   container/namespace.
4. Map process → working directory → source root (`readlink /proc/<PID>/cwd`). → The tree you will read.
5. In the source, find the route pattern for the path and confirm the handler, its decoration/
   middleware, and whether a second route pattern also matches the same path. → Two matching routes is
   the most common reason "the patch did not work".

If step 2 shows the path is served statically, go to
`card-web-011-seeded-content-discovery` to enumerate what is actually exposed. If a listener has no
attributable process, go to `card-web-030-upstream-exposure-narrowing` before changing anything.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ss -ltnp` | `LISTEN 0 511 0.0.0.0:80 ... users:(("nginx",pid=...))` | Front proxy and PID; anything bound to `0.0.0.0` is reachable from outside. |
| `nginx -T 2>&1 \| grep -n 'proxy_pass'` | `/ -> http://127.0.0.1:8000` | Explicit upstream edge; the app owns the route, not nginx. |
| `apachectl -S 2>&1` | vhost and config file lines | Which config file defines the host (`src-apachectl-o20-98508984`). |
| `readlink -f /proc/<APP_PID>/cwd` | `/srv/<APP_NAME>` | Source root candidate; confirm with the route definition. |
| `rg -n 'route\|@app\.\|@get\|@post\|app\.(get\|post)\|HandleFunc' <SRC>` | route registrations | Definitive list of paths; compare with what you believed. |
| `ss -ltnp \| grep ':631\|:5432\|:3306'` | host services on shared ports | An unrelated host daemon can occupy the port you expect — the saarCTF 2024 material notes a host CUPS conflict of this kind (`src-saarctf-2024-readme-6dacbfcc`). |

## State-changing actions

- **Impact:** binding changes (for example an upstream that listens on all interfaces) alter who can
  reach the application directly.
- **Preconditions:** the proxy edge is proven, the upstream process is proven, and there is no
  evidence that the checker contacts the upstream port directly.
- **Health check before:** `curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: <EXPECTED_HOST>'
  'http://127.0.0.1:<FRONT_PORT>/<HEALTH_PATH>'` — expect the documented healthy response.
- **Apply:** change only the upstream bind address (or the single proxy directive), never both at once.
- **Health check after:** repeat the front-port request through the proxy — expect the same status and
  body; regression probe: the checker's own read/write flow still completes through the front port.
- **Rollback:** restore the one changed directive/unit file from its committed revision, reload only
  that service, and re-verify. Do not flush firewall state or restart unrelated units.

## Exploit → patch pair

- **Flaw:** applies to whatever defect the route search reveals; this card's job is to guarantee you
  patch the code that actually answers the path.
- **Reproduce on the isolated fixture:** `fixtures/d2-notehub-diagnose` (planned) — confirm which
  process answers `GET /api/notes?id=<ID>` before touching anything (not yet run here).
- **Narrow patch:** edit the handler in the owning tree, not in a mirror, a generated copy, or a
  container image layer.
- **Legitimate functionality that must keep working:** the front-port path, its `Host` header
  handling, and any static asset the checker fetches.
- **Verify:** the exploit fails through the same front port the checker uses.

## Failure modes and things teams stopped doing

- Patching the reverse proxy when the handler is the problem. The proxy is a router, not an
  authorization layer; the vulnerable code stays reachable until the handler changes
  (`src-nginx-proxy-module-f3430c5a`).
- Editing a file inside a container's writable layer. The change disappears when the container is
  recreated; identify the build source or the bind mount first.
- Grepping a vendored or generated directory first. Confirm the working directory and route table
  before widening the search.
- Assuming "port 8000 must be internal because nginx exists". Unless the team has proved it, treat the
  upstream as possibly scored (`research/03-discovery-and-defense.md` classifies that change as
  review-only for exactly this reason).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. `ss`, `nginx -T`, and `apachectl -S` were not executed in this
  session; no fixture is confirmed present.
- **Our adaptation vs the source:** the individual commands come from the nginx proxy module
  documentation (`src-nginx-proxy-module-f3430c5a`), the nginx command-line switches documentation
  (`src-nginx-switches-o19-a2887699`), and the Apache `apachectl` documentation (`src-apachectl-o20-98508984`). The drill
  itself (listener → proxy → upstream → source root) is adapted from the Nginx→systemd→Flask profile
  in `research/03-discovery-and-defense.md`, which is a design document, not a tested procedure.

## Sources

- `src-nginx-proxy-module-f3430c5a` — explicit upstream relationships (`proxy_pass`) and their semantics.
- `src-nginx-switches-o19-a2887699` — config validation/dump switches used to read the effective proxy config.
- `src-apachectl-o20-98508984` — Apache config testing and virtual-host mapping.
- `src-saarctf-2024-readme-6dacbfcc` — real A/D packaging where a host service/port conflict changed the
  behaviour of an otherwise correct setup.
