# Card template (required section order)

Cards live at `kb/<category>/<card-id>.md`. Metadata is **not** in the file —
it goes in `kb/manifest.jsonl`. Use the section headings exactly so that search
snippets and human scanning behave predictably.

**Cheat sheets** (`kb/cheatsheets/card-cheat-*.md`) follow the same order and the
same rules, with two adaptations: the *Symptoms* section reads as "when does this
sheet apply", and the *Diagnostic sequence* is a single ordered command walk
rather than per-card branching. They carry the `cheatsheet` tag in the manifest so
`ctfctl kb cheat [topic]` can list them; every other rule (evidence status,
sources, no fabricated output) is unchanged.

```markdown
# <Descriptive title: verb + object>

**First useful action.** <One sentence naming the single highest-value move.>

```bash
# Exact command with clear placeholders. <PLACEHOLDER> is uppercase in <ANGLE>.
<command> --target <LOCAL_OR_TEAM_OWNED_HOST>
```

Expected: <the observation that means it worked>. If nothing appears, <the most
likely benign reason>.

## Symptoms

- <what the operator sees when this card applies>
- <a second observable>

## Prerequisites and assumptions

- <tool, access level, or file that must exist>
- Stack/version: <e.g. nginx >= 1.18, Flask 2.x, PHP 8; or "stack-agnostic">

## Diagnostic sequence

1. <cheapest discriminating check> → <interpretation>
2. <next check> → <branch A / branch B>
3. <confirming check>

If <branch A condition>, go to <card id>. If <branch B>, <action>.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `<cmd>` | `<output>` | <interpretation> |

## State-changing actions (only if the card changes a host or service)

- **Impact:** <what changes, and what could break>
- **Preconditions:** <proven facts required before running>
- **Health check before:** `<command>` — expect <result>
- **Apply:** <the exact narrow change>
- **Health check after:** `<command>` — expect <result>; regression probe: <the
  legitimate workflow that must still work>
- **Rollback:** <exact inverse, plus how to detect that it is now unsafe>

## Exploit → patch pair (web/service cards where applicable)

- **Flaw:** <one sentence, concrete>
- **Reproduce on the isolated fixture:** `<command>` against `fixtures/<name>`
  only → <observed result>
- **Narrow patch:** <exact change; nothing broader>
- **Legitimate functionality that must keep working:** <endpoint/workflow>
- **Verify:** `<command>` → exploit fails **and** legitimate flow still passes

## Failure modes and things teams stopped doing

- <failure story or abandoned practice, attributed to its source>
- <the narrower rule that replaced it>

## Evidence status

- **Status:** reproduced locally | source-supported but untested |
  version-sensitive | unresolved
- **What we actually ran:** <exact command and result, or "nothing — the claim
  comes from the source only">
- **Our adaptation vs the source:** <what we changed and why>

## Sources

- `src-...` — <what this source supports in the card>
```

## Rules that reviewers enforce

1. **First useful action is near the top.** No card starts with background.
2. **Every substantive claim traces to a `src-...` id** that exists in
   `sources/manifest.jsonl` with a real, resolvable URL.
3. **No fabricated output.** If we did not run it, the evidence status says so.
4. **No copy-paste of source prose.** Cards are written in our words. Full text
   is only stored in `sources/text/` when the license permits redistribution.
5. **Placeholders never look like real infrastructure.** Use `<TEAM_VM_IP>`,
   `<LOCAL_FIXTURE>`, `http://127.0.0.1:<PORT>` — never a real organizer or
   corporate hostname.
6. **Attribution is specific.** "Author/team, event/year" — not "someone on
   GitHub".
