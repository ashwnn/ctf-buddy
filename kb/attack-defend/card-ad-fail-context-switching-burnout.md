# Failure story: context switching across codebases until the team burned out

**First useful action.** Count how many open problems a single person is holding, and freeze that person's queue to one service until the next checkpoint.

```bash
cat > <WORKDIR>/focus.md <<'EOF'
person: <NAME>
current_service: <SERVICE>
open_questions_redirected_to_this_person: 0
checkpoint: <UTC_TIME_AT_NEXT_BOARD_READ>
EOF
grep -c 'open_questions_redirected_to_this_person: 0' <WORKDIR>/focus.md
```

Expected: a written freeze. The counter exists so that a teammate interrupting with "quick question" adds one line to a file instead of fragmenting the work — and so the team can see the load rather than guess at it.

## Symptoms

- One person is the only one who understands two or three services simultaneously.
- Progress stops around minute 60 of every tick while people re-explain context to each other.
- Someone is answering coding questions while nominally holding a service that is currently broken.

## Prerequisites and assumptions

- A board with owners, and an agreed checkpoint rhythm (every N minutes) rather than continuous broadcast.
- At least one teammate who can answer status questions from the board instead of asking.
- Assumption: the switch cost is real but unmeasurable here. Treat this as a discipline rule, not as a measured productivity claim.

## Diagnostic sequence

1. Ask each person to name their current service and the one thing they are doing → branch A: one service each; branch B: someone names three, so pick the service whose health state is worst and freeze the rest even if they are interesting.
2. Route questions by destination: board-update questions go to the board file, deployment questions go to the owner, research questions go to whoever is not under a freeze → the goal is fewer live conversations, not fewer questions.
3. At the checkpoint, unfreeze explicitly and reassign → branch A: the frozen service progressed, so the discipline works; branch B: it did not, so the problem was scope, not interruptions, and the service needs to be cut down to its health test only.
4. If a service is genuinely blocked on one person's knowledge, spend the time to write the handoff once (`card-ad-handoff-under-pressure`) instead of answering the same question three times.

If branch B repeats, drop ambition on that service to "healthy and unpatched" for the event and say so on the board. A working unpatched service beats a half-understood one.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -n 'person:' <WORKDIR>/focus.md` | one freeze per person | visible load instead of inferred load |
| `awk -F'\|' 'NR>2 {print $2,$3,$5}' <WORKDIR>/service-board.md` | owner, backup, vuln status | whether a frozen service has a fallback owner |
| `git log --oneline -n 1` per service | revision per service | a service with no recent commit is the one likely stuck |
| `date -u +%H:%M:%S` at each checkpoint | timestamps | intervals between updates show how much of the tick is spent re-explaining |

## Failure modes and things teams stopped doing

- **The documented failure.** In #misec's RuCTFE 2019 write-up, one contributor describes holding several codebases in mind while talking to many teammates, and reaching exhaustion; the write-up also reports weaker-than-desired internal communication and unclear awareness of who was doing what. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- **The practice that replaced it.** Give every service a current owner; keep one shared status file with one-line next actions; require explicit handoffs; route exploit development and patch review through the owner instead of interrupting every analyst.
- Teams stopped broadcasting questions and started reading the board at checkpoints. That is the direct substitute for the "asking everyone everything all the time" pattern in the retrospective. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped assuming a small team can carry the same breadth as a large one. A solo participant's documented setup substitutes automation and pcap tooling for headcount; choosing that deliberately is different from accidentally spreading one person across four codebases. [src-onemanparty-faustctf2025-6368aeaf]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No freeze file was created and no checkpoint was run in this session.
- **Our adaptation vs the source:** the freeze file and checkpoint mechanism are ours. The burnout and coordination narrative is reported first-hand by the cited team; no source measures the cost of context switching.

## Sources

- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — first-hand account of juggling codebases and teammates; coordination and awareness problems.
- `src-onemanparty-faustctf2025-6368aeaf` — deliberate automation-as-headcount approach by a solo participant.
- `src-dttw-defcon2021-retro-14eb5491` — workload and role observations from a finals retrospective.
- `src-ntt-enowars8-writeup-8b4ecb49` — separating recurring offence and defence workstreams so neither interrupts the other.
