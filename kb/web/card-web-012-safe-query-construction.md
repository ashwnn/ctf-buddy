# Build queries with bound parameters, and prove the fix with the same input

**First useful action.** Find every place a request value reaches a query, and check whether it is
bound as a parameter or interpolated into the statement text.

```bash
rg -n --no-config -e 'execute\(|query\(|cursor\.|prepare\(|rawQuery' \
  -e 'f"SELECT|f.SELECT|\+ *".*SELECT|% *\(|\.format\(' <SERVICE_SRC>/
```

Expected: a short list of query call sites. Interpolation (`f"..."`, `+`, `%`, `.format`) inside the
statement text is the defect; a placeholder (`?`, `$1`, `%(name)s`) with a separate parameter argument
is the safe form. If every query is bound, this card's finding is "clean" — record that explicitly,
because it changes where you look next.

## Symptoms

- Source contains a query whose text is built from a request value.
- Search, filter, sort, or report parameters accept free text.
- An error message from the database surfaces in the response (a strong sign the statement text is
  being manipulated and echoed).

## Prerequisites and assumptions

- Read access to the source, or a reachable endpoint that returns distinguishable database errors.
- One legitimate query request as a baseline.
- Stack/version: placeholder syntax is driver-specific (`?`, `%s`, `:name`, `$1`). The principle is the
  same, the syntax is not.

## Diagnostic sequence

1. Grep the query call sites. → Candidate list.
2. For each hit, read the full statement plus its argument tuple. → Determine bound vs interpolated.
3. Trace backwards to the route parameter. → Discard statements that only use server constants.
4. For a suspected hit, compare behaviour on a valid baseline value versus a value containing a quote
   character. → A syntax/500 error where the baseline was 200 raises confidence substantially.
5. Determine the flavour (boolean, union, error-based, time-based) only if you actually need data out.
   For the *patch*, you do not need the flavour at all.

If a hit is in a "search" or "sort" parameter, remember that some parts of a statement (column and
keyword positions) cannot be parameterised and must instead be validated against a fixed allowlist.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'execute\(f"' <SRC>` | `execute(f"SELECT ... {q}")` | Interpolated statement text — defect. |
| `rg -n 'execute\(.*\?' <SRC>` | `execute("SELECT ... WHERE id = ?", (x,))` | Boundary defect. |
| `curl ...?q=<BASELINE>` vs `curl ...?q=<VALUE_WITH_QUOTE>` | `200` vs `500` | The quote changed statement parsing; interpolation is confirmed behaviourally. |
| `curl ...?q=<VALUE_WITH_QUOTE>` vs a second control character | same 500 | Consistent with parsing, not with a generic input filter. |

## Exploit → patch pair

- **Flaw:** request data is concatenated into statement text, so data becomes syntax.
- **Reproduce on the isolated fixture:** against a local fixture with a known query and one seeded
  table, send a baseline value then a quote-bearing value and compare status and body (not yet run
  here). Keep SQL injection in a dedicated fixture — the repository's drill design keeps the primary
  NoteHub fixture parameterised so the intended authorization bug is not confused with accidental
  injection elsewhere (`research/06-drills-and-validation.md`).
- **Narrow patch:** bind the value as a parameter rather than formatting it into the statement
  (`src-python-sqlite3-r06-d14c7d1a` documents placeholders versus string formatting for the Python sqlite3
  module; the equivalent exists in every mainstream driver). For non-parameterisable positions
  (identifiers, `ORDER BY` columns, table names), validate against an explicit allowlist of permitted
  values.
- **Legitimate functionality that must keep working:** the identical legitimate query returns the same
  rows in the same order; sorting and filtering controlled by fixed values still work; and the response
  schema is unchanged.
- **Verify:** the quote-bearing input now returns the ordinary "no results" or validation response
  **and** the baseline query returns exactly the rows it returned before the patch.

## Failure modes and things teams stopped doing

- Escaping quotes by hand. Escaping is a filter; binding is a boundary
  (`src-python-sqlite3-r06-d14c7d1a`).
- Building an "intermediate" safe layer that re-introduces formatting one call deeper. Check the helper
  functions too, not just the route handlers.
- Fixing only the route that was exploited. If the same helper serves three routes, patch the helper
  and regression-test all three.
- Assuming an ORM makes the code safe and skipping the sweep. Most ORMs expose a raw-query escape hatch
  — see `card-web-013-raw-query-boundary-hunt`.
- Treating a database error in the response as only an information leak. It is also direct evidence
  about statement construction, which is what you need for the patch.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No query was executed and the grep was not run in this session.
- **Our adaptation vs the source:** the binding rule and the explicit "placeholder vs string
  formatting" contrast come from the Python `sqlite3` documentation (`src-python-sqlite3-r06-d14c7d1a`). The
  allowlist rule for non-parameterisable positions is standard engineering practice and is labelled
  here as our judgment, not as a claim from that source. `src-enowars-buggy-readme-f85b8d0e` is the indexed
  example of a service whose authorization/data layer defects were worth tracing through query code.

## Sources

- `src-python-sqlite3-r06-d14c7d1a` — parameter binding instead of string formatting for user-supplied values.
- `src-enowars-buggy-readme-f85b8d0e` — indexed A/D service with token/authorization logic defects worth tracing
  through data-access code.
- `src-c4tbuts4d-stayhomectf2022-61868263` — cross-language service corpus used as evidence that the same data-access
  patterns recur in different runtimes.
