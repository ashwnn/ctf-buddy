# Use path traversal to recover config and source, not to fish for random host files

**First useful action.** Prove the escape with one harmless readable target, then immediately
aim at the application's own config and source, because that is what shortens the rest of the
service analysis.

```bash
curl -sS -i --path-as-is \
  'http://127.0.0.1:<PORT>/download?name=../../<APP_CONFIG_FILENAME>'
```

Expected: the response body contains application configuration or source rather than the
intended download. If the body is identical to the legitimate download response, the value is
being confined — read `card-web-027-canonicalization-order-tests` before trying encodings.
If the request is rejected with a stack trace naming a filter, note the filter name; it tells
you whether canonicalization or a substring check is in play.

## Symptoms

- A route maps a request value onto a filesystem path: download, export, preview, avatar, log
  viewer, theme/template loader, or static-file wrapper.
- The route accepts absolute-looking or dot-segment values without error.
- The service directory contains config, a database file, or a flag store nearby in the tree.

## Prerequisites and assumptions

- One legitimate request that returns a real file, so you have a baseline body and length.
- A guess of the working directory or an error message that leaks a path fragment.
- Stack/version: stack-agnostic. Path semantics differ by platform (separators, drive letters,
  case sensitivity) and by framework helper — read the helper before assuming.

## Diagnostic sequence

1. Request a filename you know exists under the intended root. → Confirms the route and its
   baseline response shape.
2. Request `<KNOWN_FILE>` with one extra `../` and observe status/body. → Any change in
   resolution means the join is not confined.
3. Escalate depth one segment at a time until you reach the application root. → Confirms the
   real working directory rather than a guess.
4. Target, in priority order: application config (credentials, DB path, admin flags), the
   application entrypoint and route table, then the code that builds the flag-store path.
   → This is the highest-yield use of the primitive.
5. Only after step 4, consider adjacent system files. Keep it read-only: never open devices,
   `/proc` writables, or anything that changes state.

If step 3 reveals the app root but the config is outside it, go to
`card-web-010-route-to-source-owner` to map the deployment layout properly. If the filter
rejects `../` but accepts an encoded variant, go to
`card-web-027-canonicalization-order-tests`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' --path-as-is '...?name=<BASELINE_FILE>'` | `200 <n>` | Baseline: route serves the intended root. |
| same with `../../<APP_CONFIG_FILENAME>` | `200 <different n>` | Traversal works; you are reading outside the intended root. |
| same with an absurd depth (`../../../../../../<APP_CONFIG_FILENAME>`) | `200` while shallower fails | The root is deeper than assumed, or the value is normalised before joining. |
| response headers | `Content-Disposition: attachment; filename=...` with a leaked absolute path | Path disclosure that also helps you target the next request. |
| `--path-as-is` vs default | different results | Your client, not the server, was normalising the dot segments. This is the single most common false negative. |

## Exploit → patch pair

- **Flaw:** user-controlled path material is concatenated onto a base directory and opened
  without confinement, so `..` escapes the intended root.
- **Reproduce on the isolated fixture:** `fixtures/d3-notehub-patch` (planned in
  `research/06-drills-and-validation.md`) or a local static fixture serving from a fixed
  directory; request `<BASELINE_FILE>` then `../../<APP_CONFIG_FILENAME>`. Expected: the second
  request returns a file outside the served root (not yet run here).
- **Narrow patch:** replace the manual join with the framework helper that serves a
  client-selected name from a *fixed trusted directory* — for example Flask's
  `send_from_directory(<FIXED_ROOT>, <name>)` instead of
  `send_file(os.path.join(<FIXED_ROOT>, <name>))` (`src-flask-send-from-directory-24ec5c2a`). Keep the route path,
  auth decorator, `as_attachment` choice, and response headers unchanged.
- **Legitimate functionality that must keep working:** downloading a legitimate file by its
  normal name, including names with subdirectories that are *inside* the root, plus correct
  content type and `Content-Length`.
- **Verify:** the traversal request fails while the baseline filename still returns identical
  bytes, and any checker flow that fetches a file by name still succeeds.

## Failure modes and things teams stopped doing

- Cycling encodings forever when the real issue is ordering: a single useless double-encoding
  loop is a signal to stop and inspect whether decoding happens before or after the check
  (`card-web-027-canonicalization-order-tests`; `src-portswigger-path-traversal-8145dc01`).
- Reading `/etc/passwd` first and calling it a finding. It proves the primitive but does not
  help you patch or exploit the scored flow; the config and route source do.
- Patching by blocking the string `..`. PortSwigger's material exists because filter-based
  approaches miss canonicalization and platform-specific forms
  (`src-portswigger-path-traversal-8145dc01`). The durable fix is confinement at the open/serve
  call, not string rejection.
- Adding a new reverse proxy or static file server as a "fix" without checking that the upstream
  route is still reachable — the vulnerable handler usually remains exposed
  (`card-web-010-route-to-source-owner`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. The fixture named above is planned, and no request was
  issued in this session.
- **Our adaptation vs the source:** `src-portswigger-path-traversal-8145dc01` covers the class and
  the canonicalization problem. The Flask documentation for `send_from_directory`
  (`src-flask-send-from-directory-24ec5c2a`) is used only as the shape of the *narrow patch*, per the profile in
  `research/03-discovery-and-defense.md`; we deliberately keep the patch to one call site rather
  than a source-wide search-and-replace.

## Sources

- `src-portswigger-path-traversal-8145dc01` — traversal mechanics and why canonicalization order
  matters more than the literal `../` string.
- `src-flask-send-from-directory-24ec5c2a` — the safe fixed-root file-serving helper used as the narrow patch shape.
- `src-thomasweigold-saarctf2025-eaa12cba` — real A/D service where patching a parameter's construction
  (rather than the trust boundary) was the team's first instinct; used as a caution.
