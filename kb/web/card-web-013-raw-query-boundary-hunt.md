# Hunt the raw-query escape hatch even when an ORM is in use

**First useful action.** List every module that imports the database layer directly and every string
that looks like statement text, then compare them with the ORM usage.

```bash
rg -n --no-config -e 'cursor|execute\(|raw\(|rawQuery|createNativeQuery|session\.connection|\.query\(' \
  <SERVICE_SRC>/ | grep -v -E '<ORM_SAFE_HELPER_PATTERN>' | head -n 80
```

Expected: a short list of direct-statement call sites, often in a "reports", "search", "export", or
"migration" module rather than in the main model code. If the list is empty and the source truly has no
string statements, record "ORM-only access path" and deprioritise query work in favour of access
control.

## Symptoms

- The application uses an ORM, so the team assumed "SQL is handled".
- A route exposes sorting, grouping, date ranges, or free-text search.
- Response errors include SQL fragments, table names, or driver messages.

## Prerequisites and assumptions

- Read access to the source and a working baseline request for the suspect endpoint.
- Knowledge of the ORM in use, so the safe helper pattern can be excluded correctly.
- Stack/version: the escape-hatch names differ per ORM and per language.

## Diagnostic sequence

1. Identify the data-access module(s) and the ORM. → Tells you what "normal" looks like.
2. Sweep for direct statement construction. → Candidate escape hatches.
3. Read each candidate: is any part of the statement text non-constant? → Constant statements are fine;
   any variable part that is not a bound parameter is the defect.
4. Focus on ORDER BY, LIMIT, and identifier positions, which cannot be parameterised in most drivers and
   are therefore where allowlists are required.
5. Confirm behaviourally only if needed: baseline value vs quote-bearing value on the same endpoint.

If the statement text is variable but the variable is a fixed enum chosen server-side, the risk drops
sharply — verify that the client cannot influence it before writing a finding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'ORDER BY' <SRC>` | `"... ORDER BY " + sort` | Classic non-parameterisable position with attacker influence. |
| `rg -n 'LIMIT \|fetchmany' <SRC>` | interpolated limit | Same class; allowlist integers. |
| `rg -n 'raw(\|execute(' <SRC>` | direct statement | The escape hatch; read the interpolation. |
| `curl ...?sort=<VALID_COLUMN>` vs `?sort=<NONEXISTENT>` | `200` vs `500` | The column name flows into the statement; allowlist required. |

## Exploit → patch pair

- **Flaw:** a value from the request becomes part of the statement's syntax (identifier or keyword
  position) rather than data.
- **Reproduce on the isolated fixture:** against a local fixture, request a valid sort value and an
  invalid one, and compare status/body (not yet run here).
- **Narrow patch:** map the request value to a fixed server-side list
  (`{"created": "created_at", "name": "name"}`) and use the mapped constant in the statement. Never
  pass the raw request value, even after "sanitising" it with a regex that permits identifier
  characters.
- **Legitimate functionality that must keep working:** every sort/filter value the UI and the checker
  legitimately use, including the default when the parameter is absent.
- **Verify:** the invalid value now falls back to the default (or 400) **and** each legitimate value
  returns rows in the expected order.

## Failure modes and things teams stopped doing

- Declaring the data layer clean because an ORM is imported. The raw escape hatch is the whole reason
  this card exists.
- Regex "sanitising" identifiers instead of allowlisting them. A regex that permits `[A-Za-z_]+` still
  accepts any column name that exists.
- Patching the endpoint but not the shared query builder, so the second caller keeps the defect.
- Ignoring the export/report path because "nobody uses it". Exports frequently reach the same data with
  a different code path and a weaker parameterisation discipline — the same "second path to the same
  data" pattern that made the A/D export routes in real services worth checking first
  (`src-thomasweigold-saarctf2025-eaa12cba`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. The sweep was not executed in this session.
- **Our adaptation vs the source:** the binding/allowlist distinction is drawn from the Python `sqlite3`
  documentation (`src-python-sqlite3-r06-d14c7d1a`). The "look for the second data path (export/report)" habit is
  our adaptation of the multi-route authorization failures indexed from SaarCTF 2025 and duplicated in
  `card-web-023-route-method-role-matrix`; it is a heuristic, not a sourced claim about any specific
  service.

## Sources

- `src-python-sqlite3-r06-d14c7d1a` — bound parameters instead of string formatting for user-supplied values.
- `src-thomasweigold-saarctf2025-eaa12cba` — real A/D service where a second code path reached the same user data
  with different validation.
- `src-c4tbuts4d-stayhomectf2022-61868263` — cross-language service corpus used as evidence that the same data-access
  patterns recur across runtimes.
