# Check which component owns request framing before claiming a smuggling primitive

**First useful action.** Confirm that a proxy and an application are chained, then look at the raw bytes
on the wire between them before forming any smuggling hypothesis.

```bash
ss -ltnp | head
nginx -T 2>/dev/null | grep -nE 'proxy_pass|proxy_set_header|proxy_http_version|proxy_request_buffering' | head
tshark -r <PCAP> -Y 'tcp.port==<FRONT_PORT>' -T fields -e frame.number -e ip.src -e ip.dst \
  -e tcp.stream -e http.request.method -e http.request.uri 2>/dev/null | head -n 20
```

Expected: a front listener, a proxy directive pointing at an upstream, and, if a capture exists, the
request bytes as the backend received them. If there is no proxy in the chain, framing ambiguity has no
place to hide and this card does not apply — record that and stop.

## Symptoms

- A reverse proxy (nginx, Apache, HAProxy, Caddy) fronts the scored application.
- A request that "should" be a single request produces two application actions, or one request appears
  twice in the application log.
- Investigations differ depending on whether you look at the front or the back of the chain.

## Prerequisites and assumptions

- Permission to observe your own service's traffic, or an organizer-provided capture.
- Read access to the proxy configuration.
- Stack/version: proxy buffering, HTTP version, and header handling all change with proxy version and
  explicit `proxy_*` directives. Verify against the local build — do not assume an upstream default.

## Diagnostic sequence

1. Prove the chain: listener → proxy config → upstream listener → application process
   (`card-web-010-route-to-source-owner`). → Without a chain there is no ambiguity between components.
2. Read the proxy's body/header handling directives from the effective config. → Tells you whether the
   proxy buffers, re-frames, or forwards requests as-is.
3. For a specific suspicious request, compare what your client sent with what the application received
   (capture, or the application's own log of the request). → Any difference in framing is the object of
   interest.
4. Only if you can observe a real disagreement should you consider the classic framing-ambiguity
   classes. Treat this as version- and configuration-specific, and never test it against a scored peer.
5. Prefer the defensive question: can the front component be made to reject ambiguous framing outright?

If step 1 shows the application is reached directly with no proxy, go to
`card-web-009-exploit-availability-regression-pair` — you have a different problem.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `nginx -T \| grep proxy_pass` | explicit upstream | A proxy is in the path; framing passes through two parsers. |
| `nginx -T \| grep proxy_request_buffering` | explicit buffering directive | The proxy may alter how bodies reach the backend. |
| `tshark -Y 'http.request' -T fields -e http.request.uri` twice for one client action | two request URIs | Either the client sent two requests or the chain produced two. |
| application log shows one request where the client sent one | consistent | No evidence of framing disagreement; stop. |
| application log shows two requests for one client action | inconsistency | Investigate the exact bytes between the components. |

## State-changing actions

- **Impact:** changing proxy request handling affects every request the service receives, including
  checker traffic.
- **Preconditions:** the chain is proven, the current effective config is saved, and one legitimate
  request through the front port is recorded as a baseline.
- **Health check before:** `curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: <EXPECTED_HOST>'
  'http://127.0.0.1:<FRONT_PORT>/<HEALTH_PATH>'` — expect the documented healthy response.
- **Apply:** the single narrow directive change (for example, make the front component reject requests it
  cannot unambiguously frame). Do not modify proxy body-buffering behaviour while a capture is your only
  source of truth.
- **Health check after:** the same request through the front port — expect identical status and body;
  regression probe: a legitimate multi-part upload and a legitimate keep-alive request sequence still
  complete.
- **Rollback:** `git revert <CONFIG_COMMIT>` (config under version control), `nginx -t` before reload,
  then reload only that service. If the config is not version-controlled, copy the pre-image file first
  and restore that exact file.

## Exploit → patch pair

- **Flaw:** a front component and a backend component disagree about where a request ends, and one of them
  acts on the wrong boundary.
- **Reproduce on the isolated fixture:** against a local proxy+app fixture you own, compare the client's
  bytes with the application's log for the same request. **Do not** craft ambiguous framing against a
  scored service or a peer (`AGENTS.md` scope rules). Expected: either the two views agree (no finding)
  or a specific disagreement can be described (not yet run here).
- **Narrow patch:** make the front component reject framing it cannot parse unambiguously, rather than
  normalising it silently; keep the proxy's documented behaviour for legitimate requests.
- **Legitimate functionality that must keep working:** ordinary GETs, POSTs with bodies, multipart
  uploads, keep-alive reuse, and chunked responses.
- **Verify:** the legitimate request set still returns the same statuses and bodies; the specific
  ambiguous input is rejected by the front component.

## Failure modes and things teams stopped doing

- Testing smuggling classes against a live scored service. The repository's scope rule limits everything
  to team-owned or event-authorized targets; framing experiments belong on a local fixture.
- Assuming the proxy is transparent. Proxies change source address handling, `Host` and forwarding
  headers, request-body buffering, chunked encoding, upgrade handling, timeouts, and connection reuse —
  the observation-work research lists these as breakage risks when a proxy is inserted for visibility
  (`research/04-observation-and-decoys.md`).
- Inserting a new proxy "to see the traffic". That changes the request path of a scored service; the
  attack-defend primer's traffic-analysis advice assumes capture, not interception
  (`src-maplebacon-ad-primer-23bd534f`).
- Declaring a finding from one captured request. Capture/dissector limits can make a single request look
  like two; confirm with the application's own log before drawing conclusions
  (`src-tshark-man-page-d914bcdd`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No capture was parsed and no proxy configuration was read in this
  session.
- **Our adaptation vs the source:** no in-repo source documents request smuggling in an indexed service.
  This card's sourced parts are structural: nginx defines explicit upstream relationships and request
  forwarding behaviour (`src-nginx-proxy-module-f3430c5a`), the switches documentation covers config validation
  (`src-nginx-switches-o19-a2887699`), TShark exposes raw request fields (`src-tshark-man-page-d914bcdd`), and the
  attack-defend primer covers traffic-analysis practice (`src-maplebacon-ad-primer-23bd534f`). The framing-
  disagreement reasoning itself is our judgment and must be validated locally before acting.

## Sources

- `src-nginx-proxy-module-f3430c5a` — proxy-to-upstream relationships and request forwarding behaviour.
- `src-nginx-switches-o19-a2887699` — validating and dumping the effective proxy configuration.
- `src-tshark-man-page-d914bcdd` — extracting raw request fields for comparing front and back views.
- `src-maplebacon-ad-primer-23bd534f` — attack-defend traffic analysis practice and its limits.
