# Render user data as data, not as a template

**First useful action.** Find where the service composes a string from request data and then evaluates
or renders it, and decide whether the value is being *substituted into* a template or *treated as* one.

```bash
rg -n --no-config -e 'render_template_string|Template\(|\|safe|mark_safe|bracket|eval\(|format_map' \
  -e 'renderToString|Handlebars|mustache|jinja2|twig|smarty' <SERVICE_SRC>/
rg -n --no-config -e 'process_template|render\(|\brender\b.*request\.' <SERVICE_SRC>/
```

Expected: a small number of hits. The dangerous shape is a request value passed to a template *engine*
(as source) or to `eval`-like evaluation; the safe shape is a request value passed as a template
*variable* (a context key) to a fixed template file. If every hit is the safe shape, record it and stop.

## Symptoms

- The service supports configurable messages, emails, PDF/ticket layouts, or "custom scripts".
- A response reflects an arithmetic or expression-like parameter back evaluated.
- Errors show template syntax from a user-supplied string.

## Prerequisites and assumptions

- Read access to the source, and one working request to the feature.
- Knowledge of which template engine is in use; engines differ in defaults.
- Stack/version: auto-escaping defaults, sandboxing, and "safe" markers are engine- and
  version-specific.

## Diagnostic sequence

1. Locate template/evaluation call sites. → Candidate set.
2. Trace the input backwards to the request. → Reachability. A template built only from server constants
   is not a vector.
3. Determine whether the engine receives the user value as template source or as context data. → This is
   the whole distinction.
4. Look for escaping/sandbox changes: `|safe`, `mark_safe`, disabled auto-escape, or a sandboxed
   environment that was turned off. → These convert a benign parameter into a finding.
5. Confirm with a value that is syntactically meaningful to the engine but harmless if literal — do not
   attempt to run commands on any shared host.

If the value is data in a fixed template, the vector is more likely the deserialization or identity path
(`card-web-018-deserialization-http-path`, `card-web-002-identity-authority-conflict`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'render_template_string' <SRC>` | rendering a string built at runtime | If that string contains request data, it is template injection. |
| `rg -n 'Template\(' <SRC>` | constructing a template object | Same question: whose string is it? |
| `rg -n '\|safe\|mark_safe' <SRC>` | escaping deliberately disabled | Escaping was removed for a value that may be user-controlled. |
| `rg -n 'render_template\(.*request\.', <SRC>` | request data passed as a context value | Normal pattern, provided the template file is fixed. |
| response echoing a rendered expression | evaluated output | The engine processed user-controlled template source. |

## Exploit → patch pair

- **Flaw:** user-controlled text is passed to a template engine as source rather than as data.
- **Reproduce on the isolated fixture:** against a local fixture with a "custom message" feature, submit a
  value containing template syntax and observe whether the rendered output evaluates it (not yet run
  here).
- **Narrow patch:** keep the user value out of the template source: pass it as a context variable to a
  fixed template, and remove the deliberate escaping bypass for that value.
- **Legitimate functionality that must keep working:** the customisation feature itself — the user must
  still be able to supply their own text, and the checker's rendered output must keep its expected shape.
- **Verify:** the template-syntax input is rendered literally **and** the legitimate customisation still
  appears in the output.

## Failure modes and things teams stopped doing

- Sandboxing the template engine instead of removing the source/user distinction. Sandboxes are
  version-sensitive and easy to leave misconfigured; the structural fix is smaller.
- Stripping braces from user input as the fix. It breaks legitimate text containing braces and is trivial
  to bypass in engines with alternative syntax.
- Removing the customisation feature. It is a functional regression; the checker may depend on the
  rendered output (`src-enowars-checker-tenets-bf4b0ac7`).
- Treating a framework as automatically safe. A framework's default escaping only applies to the paths
  that use its escaping; the "escape hatch" functions are part of the surface — the internal-dispatch
  boundary in the ENOWARS 3 CyberAlchemist service is the indexed reminder that framework conveniences
  become security boundaries (`src-enowars-cyberalchemist-readme-3cef120f`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No template was rendered and no payload was sent in this session.
- **Our adaptation vs the source:** no in-repo source describes server-side template injection in any
  indexed service. The card's structural claim (a dynamic-dispatch/string-evaluation boundary inside a
  Python web service becomes the security boundary) is adapted from the ENOWARS 3 CyberAlchemist
  boundary (`src-enowars-cyberalchemist-readme-3cef120f`) and the Flask-era service context of
  `src-fluix-faust2020-marsu-8b6084b7`. The template-engine specifics are standard engineering knowledge and are
  labelled here as our judgment, not as sourced claims. Verify the engine's actual semantics locally
  before acting.

## Sources

- `src-enowars-cyberalchemist-readme-3cef120f` — Python/Flask A/D service where string-driven dispatch became the
  exploitable boundary.
- `src-fluix-faust2020-marsu-8b6084b7` — FAUST CTF 2020 Django service; framework context where trust-boundary reasoning
  mattered more than framework trivia.
- `src-enowars-checker-tenets-bf4b0ac7` — a defensive change must preserve legitimate functionality.
