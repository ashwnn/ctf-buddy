# Stack hats deliberately when the team is smaller than the work

**First useful action.** Write down how many people you actually have, list the hats, and assign every hat to a named person *before* the live window — accepting that one person will hold several.

```bash
cat > <WORKDIR>/hats.md <<'EOF'
people: <N_MEMBERS>
hats:
  coordinator_rules_keeper: <NAME>
  service_owner_<SERVICE_A>: <NAME>
  service_owner_<SERVICE_B>: <NAME>
  restore_capable: <NAME>          # someone who can always bring a service back
  offense_runner: <NAME>           # only after a reproduced primitive exists
  observer_defense: <NAME>
  jeopardy_queue: <NAME>
  platform_git_deploy: <NAME>
EOF
awk '/: /{print $1, $2}' <WORKDIR>/hats.md | sort -k2 | uniq -c -f1 | sort -rn
```

Expected: a list where every hat has a name and the last command shows how many hats each person carries. If any person carries four or more, mark the two you will drop first — decide that now, not at minute 90.

## Symptoms

- The team is one or two people plus someone "helping with the box".
- Everyone is doing a bit of everything and the same service is reviewed twice.
- A person is deep in one codebase while an obvious service sits unread.

## Prerequisites and assumptions

- A written list of assigned services and a shared board (`card-ad-service-ownership-and-board`).
- Honest staffing numbers, including anyone who is only available part-time.
- Assumption: you do not begin with a permanent half-red/half-blue split. Role allocation is a mapping from hats to people, and it changes as the game reveals which lane is worth staffing.

## Diagnostic sequence

1. Enumerate services and count them against people → branch A: more services than people, so each person owns at least one service and no one is a pure specialist yet; branch B: more people than services, so assign a backup owner and an observer.
2. Assign the non-negotiable hats first: coordinator, one restore-capable person, one owner per service → these three matter more than offence at minute zero.
3. Add an offense runner only after a service owner has produced a reproduced primitive → a runner without a primitive is a scanner operator.
4. Reallocate at fixed checkpoints using the board and the actual scoring weights → move a person only when the current assignment has produced no progress for a whole tick.

If a person owns three or more services and none has a documented health test, cut scope: keep ownership, drop analysis ambition (go to `card-ad-availability-first-sla-protection`). If the team is two people, accept that one hat — offense or jeopardy — goes unstaffed this event and say so out loud.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| the `hats.md` file | hat → name mapping | the team's real structure; unnamed hats are the failure mode |
| `awk '/: /{print $1, $2}' ... \| sort -k2 \| uniq -c -f1` | hats per person | concentration risk; five hats on one person predicts burnout |
| board rows without a backup | count | which services will stay broken if one person is unavailable |
| `grep -c 'HYPOTHESIS' <WORKDIR>/service-board.md` | count | whether an offense runner would have something to run |

## State-changing actions

- **Impact:** changes who may deploy to a service; overlapping assignment is how two people produce conflicting patches on the same tree.
- **Preconditions:** the service list, the people list, and agreement that the mapping is written down rather than assumed.
- **Health check before:** every service has a health state on the board.
- **Apply:** write the mapping; rotate hats explicitly, with a handoff, rather than by saying "someone should look at this".
- **Health check after:** every hat has exactly one name, and every service has an owner plus a backup where capacity exists. Regression probe: at the next checkpoint, can the named backup describe the service's current state from the board alone?
- **Rollback:** if the mapping is already stale, revert to the minimum viable structure — one coordinator, one owner per service, one restore-capable person — and add hats back only when a hat has produced value.

## Failure modes and things teams stopped doing

- Teams stopped treating one person's depth as free capacity. A documented solo participant's setup leans on automation and traffic analysis specifically to compensate for being one person; that is a legitimate answer to a staffing problem, but it only works after the manual path is proven. [src-onemanparty-faustctf2025-6368aeaf]
- Teams stopped spreading a small team across every lane. Hybrid events with challenge and live-service scoring pull staffing in two directions at once, so the queue of low-cost challenge work needs a named holder rather than "whoever is free". [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped assuming the person who knows a service will always be available. The restore-capable hat exists because a broken service with an absent expert is the most expensive state in the game. [src-maplebacon-faustctf-patcher-bf21013c]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No staffing was assigned in this session.
- **Our adaptation vs the source:** the hat list and the "assign the non-negotiables first" ordering are ours, written for a first-time team. Team-shape evidence (solo participant, coordination collapse, restore machinery) is cited; no source prescribes this exact mapping.

## Sources

- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — coordination failures and context-switching load in a real team.
- `src-onemanparty-faustctf2025-6368aeaf` — a solo participant's automation-heavy approach as a staffing answer.
- `src-maplebacon-faustctf-patcher-bf21013c` — why someone must always be able to restore.
- `src-dttw-defcon2021-retro-14eb5491` — workload and role observations from a finals retrospective.
