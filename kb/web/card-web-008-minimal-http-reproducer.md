# Rebuild the smallest HTTP request that still preserves the exploit

**First useful action.** Strip the working request one class of noise at a time and stop the moment
the effect disappears; the last removed element is required.

```bash
# working request captured from the wire, then reduced
curl -sS -i -X POST 'http://127.0.0.1:<PORT>/<ROUTE>' \
  -H 'Content-Type: application/json' \
  -b '<SESSION_COOKIE_NAME>=<SESSION_VALUE>' \
  --data '<MINIMAL_BODY>'
```

Expected: the same observable effect as the original request (data returned, action accepted) with a
request you can put in a script and use as a regression test. If the effect disappears, restore the
last removed element and record it as required rather than guessing.

## Symptoms

- A working request exists in a proxy history, a browser "copy as cURL", or a teammate's notes.
- It carries twenty headers, several unrelated cookies, and a traceparent.
- You need the request in a script, in a patch regression pair, or in a replayed capture.

## Prerequisites and assumptions

- One request that demonstrably works, and the ability to reset the service state if the request
  mutates data.
- A safe target: your own instance or a fixture, never a scored peer for state-changing requests.
- Stack/version: stack-agnostic. Authentication mechanisms, CSRF tokens, and content negotiation add
  genuinely required elements.

## Diagnostic sequence

1. Capture the full request verbatim as the reference (proxy export, or TShark fields for a
   captured request: `tshark -r <PCAP> -Y 'http.request' -T fields -e tcp.stream -e http.request.method
   -e http.request.uri -e http.host`).
2. Remove browser-only headers in one group; test. → If the effect survives, they were noise.
3. Remove unrelated cookies in one group; test. → Session and anti-CSRF cookies usually survive this
   step; note which ones did not.
4. Reduce the body to the minimum fields that produce the effect, removing one field at a time.
   → The remaining field set is the exploit's real input surface.
5. Re-run the reduced request twice from a clean state. → Determinism is the goal; a request that
   works once is not a harness.

If the reduced request stops working only after removing a header whose value came from a previous
response, you have a token-precondition, not a bug: record the dependency chain instead of chasing
the header.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl -sS -o /dev/null -w '%{http_code}\n' '<FULL_REQUEST>'` | `200` | Reference behaviour; your baseline. |
| `curl ... -H 'User-Agent' removed` | still `200` | Header was noise. |
| `curl ... -b '<ONLY_SESSION_COOKIE>'` | `200` | Only the session cookie is security-relevant. |
| `curl ... -b '' ` | `302`/`401` | The session element is required; do not minimise it away. |
| `curl ... twice` | identical results | Deterministic enough to use as a regression pair. |

## Exploit → patch pair

- **Flaw:** not a flaw by itself. This card exists to produce the *input* half of an
  exploit → patch pair, so that the same request can prove the vulnerability before a patch and fail
  after it.
- **Reproduce on the isolated fixture:** run the reduced request against `fixtures/d2-notehub-diagnose`
  or `fixtures/d3-notehub-patch` (planned in `research/06-drills-and-validation.md`) and record the
  status, an invariant of the body, and whether state changed (not yet run here).
- **Narrow patch:** apply the fix from the corresponding defect card, then replay this exact request.
- **Legitimate functionality that must keep working:** the ordinary request that the checker uses;
  keep a second reduced request for it (`card-web-009-exploit-availability-regression-pair`).
- **Verify:** this exact command fails after the patch, and the ordinary request still succeeds.

## Failure modes and things teams stopped doing

- Minimising against a peer's service. If the request changes state, you are mutating another team's
  data; minimise only against your own instance (project rule and the scope discipline in
  `AGENTS.md`).
- Deleting a header because its name looks irrelevant. Reverse proxies change `Host` and forwarding
  header behaviour, so a header that looks cosmetic can decide routing
  (`src-maplebacon-ad-primer-23bd534f`).
- Copy-pasting from a captured exploit without understanding which byte matters. The I-Hack 2024
  writeup documents recovering attacker payloads from logs, where the payload's *shape* mattered
  more than its exact bytes (`src-vicevirus-ihack2024-12725f0d`).
- Keeping the request as a shell one-liner with six inline escapes. Store it as a file
  (`<REQUEST_FILE>`) so a teammate can review and rerun it.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No request was captured or replayed in this session, and TShark
  was not invoked.
- **Our adaptation vs the source:** the stream/field extraction shape comes from the Wireshark
  follow-stream documentation (`src-wireshark-follow-stream-00828e3e`) and the TShark manual
  (`src-tshark-man-page-d914bcdd`). The "remove one class at a time, record what was required"
  procedure is our adaptation for turning a captured request into a deterministic exploit harness.

## Sources

- `src-wireshark-follow-stream-00828e3e` — reconstructing a single conversation, the basis for copying a
  request out of a capture.
- `src-tshark-man-page-d914bcdd` — field-based extraction of requests from a capture file.
- `src-vicevirus-ihack2024-12725f0d` — recovering attacker payloads from service logs when captures are
  unavailable.
- `src-maplebacon-ad-primer-23bd534f` — attack-defend primer covering traffic analysis and the risk that
  proxy/header handling changes request semantics.
