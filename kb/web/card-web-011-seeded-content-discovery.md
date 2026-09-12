# Enumerate the routes the deployment actually exposes before using a wordlist

**First useful action.** Derive the candidate path list from the effective proxy config and the
service's own route table, then request those paths — not a generic directory wordlist.

```bash
nginx -T 2>/dev/null | grep -nE 'location|try_files|root|alias|proxy_pass' | head -n 50
rg -n --no-config -e '@app\.(get|post|route)|url\(|path\(|router\.(get|post)|Route::' <SERVICE_SRC>/
```

Expected: a concrete list of server-known paths, including any `location` blocks that serve files
directly from disk. If both commands return nothing (config not readable, source not available), fall
back to bounded requests of well-known metadata paths rather than a 10,000-entry wordlist.

## Symptoms

- You need to know what is exposed, and a brute-force run has already burned minutes with no result.
- A route exists in source but returned 404 externally, or vice versa.
- The proxy serves static content the application knows nothing about.

## Prerequisites and assumptions

- Read access to the proxy config or the service source, or a small curated list of framework paths.
- A request budget you are willing to spend against your own/assigned service.
- Stack/version: path handling, trailing slashes, and case sensitivity differ by framework and
  filesystem.

## Diagnostic sequence

1. Dump proxy locations. → Every `location` + `root`/`alias` pair is a real path, and static locations
   are often overlooked (`src-nginx-switches-o19-a2887699`).
2. Extract the application route table. → Real paths with their methods; note which have no
   authorization decoration.
3. Request each discovered path with the method it declares. → Confirms reachability through the front
   proxy, not just presence in code.
4. For framework defaults, request the framework's own metadata paths (health, admin, docs, static,
   API schema) that the source/config implies exist. → Cheapest source of new surface.
5. Only then, if still short, run a small wordlist with a hard cap and low concurrency against your own
   service.

If a discovered path returns data belonging to another user, stop discovery and go to
`card-web-001-idor-object-swap` — one authorization finding outranks ten new paths.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `nginx -T \| grep -n 'location\|root\|alias'` | `/static/ { root /srv/app/public; }` | Static tree served outside the app; check it for backups, configs, and source maps. |
| `rg -n '@app\.route\|@app\.get' <SRC>` | route declarations | Authoritative path list; compare with external results to find proxy-only or app-only paths. |
| `curl -sS -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:<PORT>/<DISCOVERED_PATH>'` | `200`/`302`/`401`/`404` | Distinguishes existing-but-protected from absent — a 401 is a finding about surface, not a dead end. |
| `curl -sS -i 'http://127.0.0.1:<PORT>/<PATH>/'` (trailing slash) | different status than without | Path normalisation differences worth recording (`card-web-022-canonicalization-authz-bypass`). |

## Exploit → patch pair

- **Flaw:** not a flaw by itself; this card changes the *order* of discovery so that real surface is
  found from the deployment rather than guessed.
- **Reproduce on the isolated fixture:** against a local fixture, list routes from source, then confirm
  each externally through the front port (not yet run here).
- **Narrow patch:** not applicable — this is a triage card. If a discovered path exposes files it
  should not, the fix belongs in the proxy `location`/`root` configuration or the handler, whichever
  owns the path (see `card-web-010-route-to-source-owner`).
- **Legitimate functionality that must keep working:** every static asset and metadata path the
  checker or the application's own front end fetches.
- **Verify:** after any exposure change, re-request the legitimate asset paths and compare bytes.

## Failure modes and things teams stopped doing

- Leading with a large wordlist against a scored service. It is slow, noisy, and answers a question
  the source already answers (`src-nmap-reference-r06-45db80c0` frames scanning as a tool for services whose
  configuration you do not control; here you usually do).
- Treating 404 as absence. A framework can return 404 for an existing-but-unauthorized path; combine
  external results with the source route table before concluding.
- Ignoring static roots. Files served by the proxy bypass the application entirely and therefore bypass
  every fix you apply inside the application.
- Re-enumerating from scratch every tick. Write the discovered list to the shared service board once;
  the USTC Hackergame writeup corpus is indexed as evidence that web challenge surface is usually
  small and enumerable by reading, and `src-ustc-hackergame2024-r06-c446ee16` should be used as a study corpus
  rather than a scanner input.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No discovery request was sent; the route-list commands were not
  executed in this session.
- **Our adaptation vs the source:** `src-nmap-reference-r06-45db80c0` and `src-nginx-switches-o19-a2887699` supply the
  configuration-reading commands. The reordering — config and source first, scanning last and bounded —
  is our adaptation, driven by the project rule that everything must be safe to run against
  team-owned services.

## Sources

- `src-nmap-reference-r06-45db80c0` — service/version discovery mechanics and `-sV`-style probing.
- `src-nginx-switches-o19-a2887699` — reading the effective server configuration.
- `src-ustc-hackergame2024-r06-c446ee16` — organizer writeup corpus as a study reference for web challenge
  surface.
- `src-nginx-proxy-module-f3430c5a` — how location blocks map to upstreams or static content.
