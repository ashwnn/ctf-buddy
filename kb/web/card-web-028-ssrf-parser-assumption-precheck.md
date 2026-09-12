# Verify the parser's assumptions before attempting any SSRF bypass

**First useful action.** Before trying encodings, decide what the destination check actually validates:
the raw string, the parsed host, the resolved address, or the connection peer.

```bash
rg -n --no-config -B4 -A8 -e 'urlparse|URL\(|parse_url|new URL|uri\.parse|follow_redirects|allow_redirects' \
  <SERVICE_SRC>/ | head -n 80
```

Expected: the validation code and the request code, ideally adjacent. If the check parses one way and the
request library parses another way, you have a parser-differential candidate. If the check resolves DNS and
pins the address, most string-based bypasses are irrelevant.

## Symptoms

- `card-web-004-ssrf-internal-pivot` proved a server-side fetch but the destination filter blocks your first
  attempts.
- Source contains both a validation function and an HTTP client call with different parsing.
- The filter rejects some URLs and accepts others with no obvious pattern.

## Prerequisites and assumptions

- A working callback (your own listener) so you can tell blocked from unexecuted.
- The validation code, or enough samples to infer its rules.
- Stack/version: URL parsing differs across languages and libraries even for the same input; never import a
  bypass list from another stack or another year.

## Diagnostic sequence

1. Find the validation and the request call. → Do they share a parser and a code path?
2. Determine the check's granularity: whole-string match, parsed host, resolved IP, or connection peer.
   → Only the last two are robust against string tricks.
3. Determine whether redirects are followed and whether the destination is re-checked after each hop.
   → Unrechecked redirects are the single most durable bypass and are a *design* finding, not a parsing
   curiosity.
4. Determine whether the validator and the client disagree on a benign input (for example a trailing dot,
   an unusual but resolvable notation, or a mixed-case host). → Behavioural evidence of a differential,
   tested only against your own listener.
5. Stop as soon as one differential is demonstrated. Enumerate no further: the patch must not depend on the
   bypass list.

If no differential exists and the check includes the resolved address, record "destination validation
appears robust" and move on — the fetch feature may still be abusable for scheme-level effects, but that is
a different card.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'urlparse\|new URL\|parse_url'` | one parse site | Compare with the client's parse site before drawing conclusions. |
| `rg -n 'follow_redirects\|allow_redirects\|max_redirects'` | redirect policy | `true` without re-validation = durable bypass. |
| callback observed for an input the validator "rejects" | differential | Validation and request disagree. |
| callback observed only for an allowed host | consistent | No differential found on that input family. |
| `rg -n 'getaddrinfo\|gethostbyname\|resolved'` | DNS resolution in the check | Address-level validation; string bypasses mostly moot. |

## Exploit → patch pair

- **Flaw:** the destination decision and the actual request use different parsers or different stages, so
  the check can be satisfied while the request goes elsewhere.
- **Reproduce on the isolated fixture:** against a local fixture, send a URL that the validator accepts and
  whose *effective* destination is your own listener on a team-owned host; confirm the callback (not yet run
  here).
- **Narrow patch:** perform the request to an address chosen by the server after normalisation, disable
  redirect following for the feature, and re-validate every hop if redirects are required. Validate the
  *effective* destination, not the original string.
- **Legitimate functionality that must keep working:** the remote-fetch feature the product and checker use,
  including its timeout and error responses.
- **Verify:** the differential input no longer reaches your listener **and** the legitimate URL still
  fetches successfully.

## Failure modes and things teams stopped doing

- Collecting bypass lists. `src-portswigger-ssrf-f8039f92` warns that parser behaviours and special destinations
  are environment-specific and that historical bypasses are not universal; a list is also unmaintainable
  during an event.
- Validating a string, then requesting a URL. The classic differential; check the two call sites are the
  same object.
- Forgetting redirects. A one-hop allowlisted redirect to a disallowed destination defeats host allowlists
  unless each hop is re-checked.
- Reporting "SSRF blocked" because the first payload failed. A blocked payload proves the filter exists, not
  that the feature is safe. `card-web-004-ssrf-internal-pivot` keeps the callback-first rule for this
  reason.
- Changing the destination filter without a legitimate-workflow probe, which turns a security fix into a
  functional regression (`src-enowars-checker-tenets-bf4b0ac7`), or rolling it out by overwriting a whole tree instead
  of the one file (`src-maplebacon-faustctf-patcher-bf21013c`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No URL parsing was inspected and no callback was attempted in this
  session.
- **Our adaptation vs the source:** the parser/environment variability caveat comes from
  `src-portswigger-ssrf-f8039f92`. The "decide the check's granularity before payload work" ordering, and the
  "stop after one demonstrated differential" rule, are our adaptations for a scored environment where
  payload iteration is expensive and visible.

## Sources

- `src-portswigger-ssrf-f8039f92` — SSRF mechanics, variable parsing/metadata behaviour, and the warning that
  bypasses are not universal.
- `src-maplebacon-faustctf-patcher-bf21013c` — narrow patching and rollback discipline.
- `src-enowars-checker-tenets-bf4b0ac7` — legitimate functionality must survive the fix.
