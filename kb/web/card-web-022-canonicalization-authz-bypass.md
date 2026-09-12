# Use canonicalisation differences to test whether an access check can be skipped

**First useful action.** Compare the path the proxy used for its rule match with the path the application
used for its authorization decision, for one protected route.

```bash
for p in '<PROTECTED_PATH>' '<PROTECTED_PATH>/' '//<PROTECTED_PATH>' '/./<PROTECTED_PATH>' \
         '/%2e/<PROTECTED_PATH>' '/<PUBLIC_PREFIX>/../<PROTECTED_PATH>'; do
  printf '%-40s ' "$p"
  curl -sS -o /dev/null -w '%{http_code}\n' --path-as-is "http://127.0.0.1:<PORT>$p"
done
```

Expected: identical status codes for all variants if normalisation is consistent. Any variant that
returns protected content (or a different status indicating it reached a different handler) is a
canonicalisation mismatch. If everything returns the same 404, check that the baseline path itself works
before concluding anything — a broken baseline invalidates the whole comparison.

## Symptoms

- A protected area is defined by a path prefix in the proxy or in a route-matcher.
- The application has its own path handling on top of the proxy's (`request.path`, `PATH_INFO`,
  framework router).
- Different casings, trailing slashes, or dot segments produce different results.

## Prerequisites and assumptions

- One protected and one public route on the same service, both reachable.
- `--path-as-is` (or an equivalent) so your own client does not normalise before sending.
- Stack/version: dot-segment handling, percent-decoding order, and case sensitivity all vary by proxy,
  framework, and filesystem.

## Diagnostic sequence

1. Confirm the protected route denies you without the required session. → Baseline denial.
2. Request the public route. → Baseline success.
3. Request the protected route using each variant in the loop above, with `--path-as-is`.
   → Compare status and body, not just status: a 200 with the login page is not an access.
4. For each interesting variant, ask *which* component decided: proxy location match, framework router,
   or application authorization. → The fix goes where the decision is made.
5. If the proxy is the only gate, check whether the application independently authorizes; if not, the
   finding is "the control is in one place, and that place can be normalised around".

If a variant reaches protected content, patch at the application's authorization layer, not only at the
proxy (`card-web-023-route-method-role-matrix`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `--path-as-is` with `<PROTECTED_PATH>` | `302`/`401` | Baseline: the control works for the plain path. |
| variant returning `200` with protected body | access bypass | Normalisation difference; the gate does not cover this form. |
| variant returning `200` with the login page | still protected | Distinguish body content from status before calling it a finding. |
| variant returning `500` | parser disagreement | Also useful evidence: two components disagree about the path. |
| `nginx -T \| grep -n '<PUBLIC_PREFIX>\|<PROTECTED_PATH>'` | location blocks | Shows exactly which prefix the proxy protects. |

## Exploit → patch pair

- **Flaw:** a security decision is made on a path representation that differs from the one the protected
  handler sees.
- **Reproduce on the isolated fixture:** against a local proxy+application fixture you own, iterate the
  variant list and record which forms reach the protected handler (not yet run here).
- **Narrow patch:** make the application authorize the *resource*, independent of the path spelling, and
  make the proxy's rule match the same normalised form the application uses. One change where the
  decision lives; do not add a second, differently-normalised check.
- **Legitimate functionality that must keep working:** the public prefix including its trailing-slash and
  sub-path behaviour, plus any redirect the application performs for canonical URLs.
- **Verify:** every variant that previously reached protected content is denied, and the public paths
  return the same statuses as the baseline.

## Failure modes and things teams stopped doing

- Judging by status code alone. A redirect to login is a denial; a `200` carrying the login template is
  also a denial. Compare bodies or check for protected content.
- Blocking the variants one by one at the proxy. It becomes an unbounded list; the durable fix is a single
  normalised authorization decision (`src-portswigger-path-traversal-8145dc01` covers the same canonicalisation
  problem for file paths).
- Hiding the route (renaming `/admin` to something obscure). That is not authorization
  (`src-portswigger-idor-c6997693` conveys the same principle for objects).
- Assuming the framework normalises identically to the proxy. Two components, two normalisers, one
  mismatch — that is the entire class this card is about.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No request was sent and no proxy configuration was read in this
  session.
- **Our adaptation vs the source:** the canonicalisation problem is documented for file paths in
  `src-portswigger-path-traversal-8145dc01` and the authorization principle in
  `src-portswigger-idor-c6997693`. Extending it to route-prefix access checks across a proxy/application
  boundary is our adaptation, and the specific variant list must be validated against the local stack
  because normalisation order is implementation-specific.

## Sources

- `src-portswigger-path-traversal-8145dc01` — canonicalisation order and why string filters fail.
- `src-portswigger-idor-c6997693` — authorization must be a server-side decision about the resource.
- `src-nginx-proxy-module-f3430c5a` — proxy location matching and upstream forwarding behaviour.
- `src-nginx-switches-o19-a2887699` — reading which prefix the effective configuration protects.
