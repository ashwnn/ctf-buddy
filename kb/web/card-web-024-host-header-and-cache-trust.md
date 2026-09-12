# Stop trusting client-supplied headers in security decisions and cache keys

**First useful action.** List every header the application reads, then check which of them participates in
a security decision or in absolute URL generation.

```bash
rg -n --no-config -e 'Host|X-Forwarded-|X-Original|Forwarded|X-Real-IP|X-Rewrite|Origin|Referer' \
  <SERVICE_SRC>/ | head -n 60
nginx -T 2>/dev/null | grep -nE 'proxy_set_header|add_header|location' | head -n 40
```

Expected: a short list. Headers used for logging or analytics are low priority; headers that decide a
redirect target, an absolute URL in an email/reset link, an allow/deny rule, or an object identity are the
finding. If the proxy overwrites the header before the application sees it, the application's trust is
backed by the proxy — verify that the overwrite actually happens for the route in question.

## Symptoms

- Password-reset, invitation, or callback links are built from the request `Host`.
- An internal route is reachable via a header such as a rewrite/original-URL header.
- Responses differ depending on a header the client controls, and the response is cached.

## Prerequisites and assumptions

- Read access to source and proxy config.
- One working request per affected route.
- Stack/version: proxies differ in which headers they set, strip, or pass through, and in what they
  include in a cache key (`src-nginx-proxy-module-f3430c5a`, `src-nginx-switches-o19-a2887699`).

## Diagnostic sequence

1. List application reads of client headers. → Candidate set.
2. Classify each: identity, access decision, URL construction, logging only. → Only the first three matter.
3. Determine whether the proxy unconditionally sets that header on every request path (including the
   affected location). → If not, the value is client-controlled at the application.
4. Test with a modified header on your own fixture: does the response body, redirect target, or access
   decision change? → Behavioural confirmation.
5. For anything cached, record which headers vary the response and whether the cache key includes them.
   → A response that varies on an unkeyed header is served to the wrong client.

If the header only affects logging, go back to `card-web-027-debug-and-error-output-narrowing` — the risk
there is information exposure, not access control.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'request\.host\|req\.headers\.host' <SRC>` | host used in URL building | Reset/invite/callback links may point at an attacker-chosen host. |
| `rg -n 'X-Forwarded-For\|X-Real-IP' <SRC>` | client IP from a header | Rate limits or allowlists keyed on a spoofable value. |
| `nginx -T \| grep proxy_set_header` | explicit header overwrites | Shows which headers the application can trust — for the locations that have them. |
| `curl -H 'Host: <OTHER_HOST>' '<ROUTE>'` (own fixture) | changed redirect or link in body | The header reaches a security-relevant decision. |
| two responses differing only by an unkeyed header | different bodies | Cache-key gap, if a cache is in front. |

## State-changing actions

- **Impact:** header handling is shared by every request; tightening it can break redirects, proxy
  integrations, and any legitimate multi-hostname deployment.
- **Preconditions:** identified decision point, the set of legitimate hostnames, and a baseline response
  for the affected route.
- **Health check before:** `curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: <EXPECTED_HOST>'
  'http://127.0.0.1:<FRONT_PORT>/<ROUTE>'` — expect the normal response.
- **Apply:** derive absolute URLs from configured values rather than from the request; make the proxy
  unconditionally set (or strip) the forwarding header on the relevant location; never treat a
  client-supplied header as identity.
- **Health check after:** repeat the request with the legitimate host — expect the same status and body;
  regression probe: the checker's own request through the front port, plus any redirect the application
  performs (trailing-slash, login redirect).
- **Rollback:** restore the single config/code file from its committed revision, `nginx -t`, reload. Do not
  rotate the hostname or invalidate sessions as part of this change.

## Exploit → patch pair

- **Flaw:** a value the client can set is used where the client must not be trusted, or a response that
  varies on that value is cached without keying on it.
- **Reproduce on the isolated fixture:** against a local proxy+application fixture you own, send a request
  with a modified `Host` (or forwarding header) and record whether the response, redirect, or access
  decision changes (not yet run here).
- **Narrow patch:** replace request-derived values with configuration-derived ones at the decision point,
  and make the proxy set/strip the header for every path that reaches that code.
- **Legitimate functionality that must keep working:** any multi-hostname deployment, trailing-slash and
  login redirects, and the checker's URL expectations.
- **Verify:** the modified header no longer changes the outcome; the legitimate hostname still produces
  identical responses.

## Failure modes and things teams stopped doing

- Trusting the header because "nginx sets it". Header overwrites are per-location; a location added later
  may not have the directive.
- Fixing the app and not the cache. If the response is cached upstream and the key omits the varying
  header, the application fix does not stop the wrong response being served.
- Rejecting all foreign `Host` values outright in an event with an undocumented hostname set. That can
  break the checker; enumerate the legitimate hostnames first, and record the answer from the organizer.
- Rotating secrets or invalidating sessions to "reset" after a header-based incident. Prefer a narrow,
  attributed change; broad invalidations are availability events in an A/D format
  (`src-enowars-checker-tenets-bf4b0ac7`).
- Inserting or changing a proxy layer for convenience during the event. Proxies alter `Host` and
  forwarding-header behaviour, request buffering, and timeouts — a change in this layer is a change to
  every request (`research/04-observation-and-decoys.md`, `src-maplebacon-ad-primer-23bd534f`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No header was modified and no proxy config was read in this session.
- **Our adaptation vs the source:** the proxy's control over upstream headers is documented by nginx
  (`src-nginx-proxy-module-f3430c5a`) and the switch to dump the effective config by
  `src-nginx-switches-o19-a2887699`; the operational warning about proxies changing host/forwarding behaviour is
  from `research/04-observation-and-decoys.md`. The specific "header reaches a security decision" test
  procedure is our adaptation and must be validated on the local stack.

## Sources

- `src-nginx-proxy-module-f3430c5a` — proxy-set headers and upstream request construction.
- `src-nginx-switches-o19-a2887699` — reading the effective configuration that decides header handling.
- `src-maplebacon-ad-primer-23bd534f` — attack-defend traffic/proxy analysis practice.
- `src-enowars-checker-tenets-bf4b0ac7` — defensive changes must not break service functionality.
- `src-maplebacon-faustctf-patcher-bf21013c` — narrow, versioned configuration changes with precise rollback.
