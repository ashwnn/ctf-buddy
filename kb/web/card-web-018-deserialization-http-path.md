# Decide whether untrusted input reaches a deserializer, and which kind

**First useful action.** Find the deserialization call and the endpoint whose body or uploaded file
reaches it, then classify the danger by *what the format can construct*.

```bash
rg -n --no-config -e 'pickle\.load|yaml\.load|unserialize\(|Marshal\.load|ObjectInputStream' \
  -e 'TypeNameHandling|newtonsoft|JsonSerializer|jackson|readObject|eval\(' <SERVICE_SRC>/
```

Expected: a short list. `pickle`, PHP `unserialize` without an allowed-classes list, Java
`ObjectInputStream`, and .NET type-name handling are in the "can construct objects / run code" family.
Plain JSON or XML-to-struct parsing without type metadata is in the "data only" family. If the call is
data-only, this card's answer is "not the vector" — record that and move on, because it protects the
team's time.

## Symptoms

- The service accepts structured imports: saved state, templates, recipes, filters, project files.
- Source contains a serializer call with a polymorphic or type-name option enabled.
- The response to a slightly malformed input includes type/class names from the runtime.

## Prerequisites and assumptions

- Read access to the source and knowledge of the language runtime.
- A legitimate import payload, so you can see what a valid object looks like.
- Stack/version: behaviour is language- and library-version-specific. The JSON/.NET example in the
  indexed FAUST CTF 2024 material is one concrete case, not a universal rule
  (`src-czechcyberteam-faust2024-todolist-225eeec1`).

## Diagnostic sequence

1. Locate the deserializer call sites. → Candidate set.
2. For each, trace backwards to the request parameter, uploaded file, cookie, or header that supplies
   the bytes. → Attacker reachability. A deserializer fed only by server-generated data is not a vector.
3. Classify the format's capability: can it name and construct types, or only populate fields of a fixed
   schema? → This decides whether the finding is RCE-class or data-manipulation-class.
4. Check whether the payload is integrity-protected (signed, HMAC'd, encrypted). → Signed payloads with
   server-held keys are a different problem from raw client-supplied bytes.
5. Confirm with the smallest benign manipulation available in a local fixture: a field swap that changes
   application behaviour without constructing anything new.

If the format is data-only, go to `card-web-002-identity-authority-conflict` — a manipulated object often
means a manipulated identity field. If it can construct types, continue to
`card-web-019-deserialization-narrow-patch`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'TypeNameHandling' <SRC>` | a serialization setting | Type names are part of the data; attacker-chosen types may be constructed. |
| `rg -n 'pickle\.load' <SRC>` | unpickling call | Standard pickle semantics allow code execution during load. |
| `rg -n 'yaml\.load\(' <SRC>` | a YAML load call | Check whether the safe loader is used; the unsafe loader resolves arbitrary tags. |
| `rg -n 'JsonSerializer\|json.load' <SRC>` | plain JSON parse | Data-only unless a custom type resolver is configured. |
| response containing runtime class names | verbose serializer errors | Confirms the type layer is present and visible. |

## Exploit → patch pair

- **Flaw:** untrusted bytes are turned into runtime objects (or code) by a format whose semantics permit
  more than data assignment.
- **Reproduce on the isolated fixture:** against a local fixture with an import endpoint, submit a
  slightly modified payload and observe a behaviour change that a pure data field swap would not cause
  (not yet run here). Do not attempt code execution on any shared host.
- **Narrow patch:** remove the type/polymorphism capability (disable type-name handling, switch to the
  safe loader), or replace the interchange format for that path with a schema-bound one. The FAUST CTF
  2024 Todo service published exactly this shape of patch on its import path
  (`src-faust-todo-patches-r06-abf8d3d1`).
- **Legitimate functionality that must keep working:** importing a legitimate saved object, and every
  field the checker or the product stores through that path.
- **Verify:** the manipulated payload is rejected **and** a legitimate import still produces the same
  stored state.

## Failure modes and things teams stopped doing

- String-filtering dangerous names in the payload. It is fragile and the transformed payload usually
  survives; the correct change is at the deserializer configuration
  (`src-faust-todo-patches-r06-abf8d3d1`).
- Removing the import feature entirely. It is a checker-visible regression; the published FAUST patch
  narrows the deserialization rather than deleting the feature (`src-czechcyberteam-faust2024-todolist-225eeec1`).
- Assuming "it is only JSON, so it is safe". JSON plus a type-name resolver is not data-only.
- Ignoring persistence. Changing a serializer can break stored objects; test retrieving an object created
  *before* the patch (`card-web-009-exploit-availability-regression-pair`).
- Treating a `pickle`-based import as data parsing. The ENOWARS 3 CyberAlchemist service is indexed as a
  case where Python service internals (including deserialization-style constructs) became the security
  boundary (`src-enowars-cyberalchemist-readme-3cef120f`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No payload was crafted and no deserializer was executed in this
  session.
- **Our adaptation vs the source:** the .NET/JSON deserialization case and its narrow patch come from the
  FAUST CTF 2024 Todo writeup and service repository (`src-czechcyberteam-faust2024-todolist-225eeec1`,
  `src-faust-todo-service-r06-58bee3ce`, `src-faust-todo-patches-r06-abf8d3d1`). The "classify by what the format can
  construct, and stop early for data-only formats" gate is our addition, intended to prevent time being
  spent on a non-vector.

## Sources

- `src-czechcyberteam-faust2024-todolist-225eeec1` — FAUST CTF 2024 Todo: unsafe deserialization and the narrow patch
  that preserved the import workflow.
- `src-faust-todo-service-r06-58bee3ce` — the organizer-published service whose import path this class is drawn
  from.
- `src-faust-todo-patches-r06-abf8d3d1` — the published patch that narrows deserialization instead of deleting the
  feature.
- `src-enowars-cyberalchemist-readme-3cef120f` — Python A/D service where internal constructs became the security
  boundary.
