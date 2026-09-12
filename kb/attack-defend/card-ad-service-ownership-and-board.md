# One accountable owner per service, one board everyone can read

**First useful action.** Create the board file and write one row per service with owner, health, last proven fact, and next action — then read the row aloud to the team.

```bash
cat >> <WORKDIR>/service-board.md <<'EOF'
| service | owner | backup | health | vuln status | patch status | rollback | next action |
|---|---|---|---|---|---|---|---|
| <SERVICE_A> | <NAME> | <NAME> | HEALTHY | HYPOTHESIS | NONE | <COMMIT> | read checker |
| <SERVICE_B> | <NAME> | <NAME> | UNKNOWN | NONE_KNOWN | NONE | none | baseline |
EOF
awk -F'|' 'NR>2 {print $2, $3, $5}' <WORKDIR>/service-board.md
```

Expected: one line per service naming a current owner and a health state. A row whose owner is blank or whose health is `UNKNOWN` for more than a few minutes is the team's next action, ahead of any technical work.

## Symptoms

- Two teammates are editing the same service, or nobody is.
- A question ("did we patch that?") is answered differently by two people.
- Analysis is duplicated while an obvious service sits unread.

## Prerequisites and assumptions

- A shared, writable location everyone can reach during the event, and a rule that only the owner changes a service's deploy state.
- Roughly one service per available person before anyone becomes a full-time specialist.
- Assumption: you do not yet know which lane (offense, defense, availability, jeopardy) carries the most points; do not hard-split the team around a guessed weighting.

## Diagnostic sequence

1. Assign every service exactly one current owner, plus a backup where capacity allows → branch A: every service has a name against it; branch B: someone holds three, which is the trigger for `card-ad-small-team-role-stacking`.
2. Fill only fields you can defend: health from the smoke test, vuln status from evidence, patch status from a commit → "suspected" and "confirmed" must be different words.
3. At short checkpoints, read the board rather than broadcasting questions → this is the documented antidote to the coordination failure where a team was unsure whether work was duplicated.
4. When ownership changes, do a spoken handoff using `card-ad-handoff-under-pressure` and update the row in the same minute.

If a service has two owners, pick one now — shared ownership is the state in which nobody restores it. If a service has no owner, that is the next action regardless of what else is on fire.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `awk -F'\|' 'NR>2 {print $2, $3, $5}' <WORKDIR>/service-board.md` | service, owner, vuln status | the team's actual allocation, in one screen |
| `grep -c 'HEALTHY' <WORKDIR>/service-board.md` | count | how many services are provably working right now |
| `git log --oneline -n 1` per service | one hash each | the board's patch column is only truthful if it names a revision |
| `date -u +%H:%M:%S` next to each update | timestamps | stale rows are the ones nobody has touched since the last checkpoint |

## State-changing actions

- **Impact:** the board itself changes nothing, but the discipline behind it decides who may deploy: a board that names one owner per service prevents two people from deploying conflicting changes.
- **Preconditions:** a shared writable file, agreement that the board is authoritative over memory, and a checkpoint rhythm.
- **Health check before:** current owner and health for every service recorded.
- **Apply:** add or update the rows; do not introduce a second board or a private notes file.
- **Health check after:** every row has an owner and a next action. Regression probe: each service's legitimate smoke test state still matches its row.
- **Rollback:** if the board becomes wrong faster than it is updated, shrink it to four columns (service, owner, health, next action) rather than abandoning it.

## Failure modes and things teams stopped doing

- Teams stopped assuming everyone knows who is doing what. A first-time retrospective from a named team reports weaker internal communication and unclear division of labour, leaving the team unsure whether work had been duplicated or whether findings had failed to meet up. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped routing every question through one analyst. The same retrospective describes juggling several codebases while fielding many concurrent conversations — the board exists so status lives in a file instead of in a person. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped treating "we have a checklist" as organisation. Written guidance on service handoff only helps if ownership is explicit and current, otherwise the checklist documents nobody's responsibility. [src-ntt-enowars8-writeup-8b4ecb49]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No board was created and no team was coordinated in this session.
- **Our adaptation vs the source:** the tabular board is our format, kept deliberately smaller than a full handoff template so it survives a slow tick. Ownership as the fix for coordination collapse comes from the cited first-time team retrospective.

## Sources

- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — first-hand account of coordination, context switching, and division of work.
- `src-ntt-enowars8-writeup-8b4ecb49` — team workflow that separates recurring exploitation from precise defence.
- `src-dttw-defcon2021-retro-14eb5491` — team retrospective on workload and division under finals conditions.
