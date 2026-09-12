# Prove an SSRF with your own listener before scanning anything internal

**First useful action.** Point the server-side fetch at a listener you control on the team's own
fixture, and read the request it makes — not at internal infrastructure.

```bash
# terminal 1: your own listener, team-owned host only
nc -lvnp <LISTENER_PORT>
# terminal 2: make the target fetch you
curl -sS -i -X POST -d 'url=http://<TEAM_OWNED_CALLBACK_HOST>:<LISTENER_PORT>/probe' \
  'http://127.0.0.1:<PORT>/api/fetch'
```

Expected: your listener sees a request for `/probe` with the server's source address, proving
the fetch happens server-side. If nothing arrives, the fetch is client-side, cached, queued, or
the response is fully opaque — treat it as unproven and stop.

## Symptoms

- A parameter holds a URL, hostname, webhook, image, feed, or "remote import" location.
- The server makes outbound requests during a normal operation (link preview, favicon, PDF from
  URL, import-from-URL).
- Source contains an HTTP client call whose destination is derived from request data.

## Prerequisites and assumptions

- A listener you control on a team-owned host, plus permission to run it.
- An observable effect: callback received, timing change, or response body containing fetched
  content.
- Stack/version: URL parsing, redirect handling, and DNS resolution differ per language and
  library; do not assume a bypass list from one stack applies to another.

## Diagnostic sequence

1. Send a benign absolute URL to your own listener. → Callback proves a server-side fetch.
2. Send a URL that resolves to your listener through a different form (uppercase host, trailing
   dot, integer/octal-looking address, redirect from your own host). → Each acceptance tells you
   which parsing/normalisation the destination check uses.
3. Send a URL whose *first* hop is allowed and whose *second* hop is not (a redirect you host).
   → Reveals whether redirects are re-validated after the initial check.
4. Only now, and only within the event's declared scope, probe a short, deliberate list of
   internal destinations derived from the source/config you already read. Keep it to the ports
   that actually appear in the service's config.

If the response body already contains fetched internal content, go straight back to step 4 with
a tiny list — do not sweep a full port range at a scored service.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `nc -lvnp <LISTENER_PORT>` | an inbound HTTP request line from `<SERVER_SOURCE_ADDR>` | Server-side fetch proven; the client never contacted you. |
| `curl -sS -o /dev/null -w '%{time_total}\n' -d 'url=http://<TEAM_OWNED_CALLBACK_HOST>:<LISTENER_PORT>/slow'` | latency jump when your listener delays | Confirms the response is built from the fetch result. |
| Response body containing your listener's page | reflected remote content | Full-read SSRF; internal data likely reachable. |
| No callback, no latency change, no body change | — | Not yet a finding; the parameter may be inert or client-side. |

## State-changing actions

- **Impact:** narrowing a fetch feature can break legitimate remote imports, previews, and
  checker flows that use the same endpoint.
- **Preconditions:** a proven callback, the exact source line performing the fetch, and the
  checker's ordinary import path recorded as a baseline response.
- **Health check before:** `curl -sS -o /dev/null -w '%{http_code}\n' '<LEGITIMATE_IMPORT_URL>'`
  — expect the same status and body shape the checker expects.
- **Apply:** restrict the feature to an explicit allowlist of destinations *and* re-validate the
  final destination after every redirect hop; disable redirect following if the feature does not
  need it.
- **Health check after:** rerun the legitimate import — expect the same status and body shape;
  regression probe: the checker's own import/export workflow still completes end to end.
- **Rollback:** restore the previous handler from the committed pre-patch revision of that one
  file and restart only that service. Do not roll back a whole tree or any mutable data
  directory — that was the operational lesson from Maple Bacon's FAUST patch workflow
  (`src-maplebacon-faustctf-patcher-bf21013c`).

## Exploit → patch pair

- **Flaw:** a destination chosen by the client is fetched with the server's network position and
  without re-validation, so the trust boundary between client and server is crossed.
- **Reproduce on the isolated fixture:** against an owned local fixture, post a URL pointing at
  `<TEAM_OWNED_CALLBACK_HOST>:<LISTENER_PORT>` and observe the callback made by the service
  process, not by `curl` (not yet run here).
- **Narrow patch:** validate the *parsed destination* immediately before the request, not the
  raw string; re-validate after redirects; prefer an allowlist of schemes and hosts already used
  by the product.
- **Legitimate functionality that must keep working:** the intended remote-fetch feature the
  checker uses, including its expected timeout and error responses.
- **Verify:** the callback no longer arrives for a disallowed destination **and** the legitimate
  import still returns the same content.

## Failure modes and things teams stopped doing

- Starting with a large internal port scan from a scored service. It is noisy, can be read as
  hostile by other teams or organizers, and it is not needed to prove the primitive.
- Assuming one parser bypass generalises. `src-portswigger-ssrf-f8039f92` is explicit that cloud
  metadata behaviour and URL-parser quirks vary, and that historical bypasses are not universal.
- Blocking the request by string-matching the hostname. Denylists based on substrings are the
  first thing a re-encoded destination defeats (`src-portswigger-ssrf-f8039f92`).
- Treating "no callback" as "not vulnerable". Queued jobs, cached fetches, and fire-and-forget
  workers all hide the effect; the correct conclusion is "unproven".

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No listener or request was started in this session; the
  callback host is a placeholder, not real infrastructure.
- **Our adaptation vs the source:** PortSwigger describes the SSRF class and its bypass surface
  (`src-portswigger-ssrf-f8039f92`); Maple Bacon's patcher retrospective supplies the operational
  constraint that rollback must be narrow and must not touch mutable state
  (`src-maplebacon-faustctf-patcher-bf21013c`). The "prove with your own listener first" ordering is our
  adaptation for a live attack/defend service where a broad internal scan is expensive and
  visible.

## Sources

- `src-portswigger-ssrf-f8039f92` — SSRF definition, server-side trust boundary, and the warning that
  parser/metadata behaviours are environment-specific.
- `src-maplebacon-faustctf-patcher-bf21013c` — narrow, version-controlled patching and the requirement that
  rollback not disturb live mutable data.
