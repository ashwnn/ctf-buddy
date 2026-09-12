# Cut what an error page reveals without breaking the status the checker expects

**First useful action.** Trigger a controlled error and record the exact status, body shape, and headers
before changing anything — that triple is the regression probe.

```bash
curl -sS -i -o <EVIDENCE_DIR>/error-before.http 'http://127.0.0.1:<PORT>/<ROUTE>?<PARAM>=<INVALID_VALUE>'
curl -sS -i -o <EVIDENCE_DIR>/health-before.http 'http://127.0.0.1:<PORT>/<HEALTH_PATH>'
```

Expected: the error response reveals something it should not (stack trace, absolute paths, query text,
configuration values, dependency versions) and the health endpoint returns the normal healthy response. If
the error body is already generic, this card does not apply — look instead at what the application *writes
to its logs* and whether an attacker can read the logs.

## Symptoms

- Error responses contain framework debug pages, stack traces, or SQL fragments.
- Source shows a debug/verbose flag enabled by default.
- Logs contain full request bodies, tokens, or flag-adjacent values.

## Prerequisites and assumptions

- A deterministic way to trigger the error (invalid parameter, wrong type, missing object).
- The checker's expected status for the same logical failure, if the checker exercises error paths.
- Stack/version: framework debug modes differ; several frameworks expose much more in debug than in
  production and some change the status code as well.

## Diagnostic sequence

1. Trigger the error and capture status, body, headers. → Baseline.
2. Identify what is disclosed: paths, versions, query text, source snippets, configuration values.
   → Decide whether this is information exposure, a read primitive, or an authentication leak.
3. Check the checker's expectation for a failing request. → If it expects `404` and debug mode returns
   `500`, turning debug off is also a checker fix — verify both.
4. Check the log side: does the application log request bodies, cookies, or tokens? → Logs are the more
   common leak in A/D services, and our own logs are also our best forensic evidence
   (`card-web-005-command-injection-trace` and the log-recovery pattern in `src-vicevirus-ihack2024-12725f0d`).
5. Apply the narrowest change: disable debug in the way the framework documents, or route unexpected
   exceptions to a generic response while logging details server-side.

If the disclosure includes query text or credentials, treat it as a read primitive and rank it with
`card-web-025-flag-read-path-priority`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| error body containing a file path or traceback | verbose error | Information disclosure; also a map of the codebase. |
| error body containing the SQL statement | query text echoed | Confirms statement construction, useful for `card-web-012-safe-query-construction`. |
| debug page with an interactive console | framework debug mode | Highest-severity variant; assume code execution is available to whoever reaches it. |
| `500` where the checker expects `404` | wrong status | The fix changes checker-visible behaviour; verify the expectation. |
| logs containing request bodies | logging leak | Anyone with log access reads attacker-visible data; also means your own logs expose secrets if shared. |

## State-changing actions

- **Impact:** error handling is on every route; changing it can alter status codes the checker depends on.
- **Preconditions:** recorded baseline triple (status, body, headers) for the error and the health path, and
  the checker's expectation for failing requests.
- **Health check before:** the health-path request returns its documented healthy response.
- **Apply:** disable the framework's debug mode in configuration, or replace the specific handler's
  verbose output with a generic body plus server-side logging.
- **Health check after:** the health path is unchanged; regression probe: the legitimate request set from
  `card-web-009-exploit-availability-regression-pair` still returns its recorded statuses and body shapes.
- **Rollback:** restore the one config/code file from its committed revision and restart only that service.
  Keep the pre-image: debug flags are often the only thing making a failing checker diagnosable.

## Exploit → patch pair

- **Flaw:** error output crosses a confidentiality boundary, or an exception handler converts a security
  decision into an information leak.
- **Reproduce on the isolated fixture:** against a local fixture, request an invalid parameter and capture
  the response body (not yet run here).
- **Narrow patch:** generic client-facing error plus detailed server-side log; disable debug where the
  framework documents it.
- **Legitimate functionality that must keep working:** the documented status codes for client errors, and
  the health endpoint's content.
- **Verify:** the invalid request no longer discloses internals **and** the health path and the legitimate
  request set behave exactly as before.

## Failure modes and things teams stopped doing

- Turning off all error output during the event and losing your own diagnosis path. Keep server-side
  logging; only the client-facing body changes.
- Assuming a debug page is "just a leak". Framework debug consoles are an execution path; treat it as
  urgent.
- Fixing the error page while leaving bodies in the logs. The I-Hack 2024 writeup is indexed for the
  reverse case — logs were the *evidence* of an attack — and the same property makes our logs sensitive
  (`src-vicevirus-ihack2024-12725f0d`).
- Sharing raw logs or captures with teammates without checking them for flags and credentials; keep
  runtime state out of the shared repository (`src-maplebacon-faustctf-patcher-bf21013c` describes keeping mutable data
  out of the deployment path for the same reason).
- Changing the status code to a "nicer" one. If the checker expects `404`, a `200` with an error body is a
  checker failure (`src-enowars-checker-tenets-bf4b0ac7`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No error was triggered and no response was captured in this session.
- **Our adaptation vs the source:** the log-as-evidence pattern is from `src-vicevirus-ihack2024-12725f0d`; the
  "do not change checker-visible behaviour" rule is from `src-enowars-checker-tenets-bf4b0ac7`; the mutable-data
  separation is from `src-maplebacon-faustctf-patcher-bf21013c`. The specific debug-mode toggle is framework-specific
  and must be read from the local framework configuration rather than assumed.

## Sources

- `src-vicevirus-ihack2024-12725f0d` — attacker payloads recovered from service logs; shows both the value and the
  sensitivity of application logs.
- `src-enowars-checker-tenets-bf4b0ac7` — checkers depend on service behaviour, including failure behaviour.
- `src-maplebacon-faustctf-patcher-bf21013c` — narrow changes and keeping mutable/secret-bearing data out of the deploy
  path.
- `src-fluix-faust2020-marsu-8b6084b7` — framework-era web service context for debug/configuration reasoning.
