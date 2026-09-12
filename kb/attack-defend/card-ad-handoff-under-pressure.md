# Hand a service over with five sentences, not a brain dump

**First useful action.** Fill the handoff block for the service and read the five-line summary aloud to the person taking over; if they cannot repeat it back, the handoff failed.

```bash
cat > <WORKDIR>/handoff/<SERVICE>.md <<'EOF'
service: <SERVICE>
owner: <NAME>            next_owner: <NAME>          updated: <UTC_TIME>
health: <HEALTHY|DEGRADED|DOWN>  health_test: <EXACT_COMMAND>
what_i_proved: <one sentence, evidence only>
what_changed: <commit or "nothing">   rollback: <EXACT_COMMAND>
where_it_lives: <exploit path>, <patch path>, <capture path>
next_highest_value_action: <one sentence>
blocker: <one sentence or "none">
EOF
wc -l <WORKDIR>/handoff/<SERVICE>.md
```

Expected: a file short enough to read in twenty seconds. If it runs past a screen, it has become documentation instead of a handoff — cut it to the five facts.

## Symptoms

- Ownership is changing mid-tick and the incoming person starts by re-reading the same code.
- Two people are unsure which revision is live, or whether an exploit already exists.
- Someone says "I thought you were handling that".

## Prerequisites and assumptions

- A board row for the service and a written, testable health check.
- A repository or snapshot so `what_changed` can name a revision rather than a description.
- Assumption: the incoming person has no context. If the handoff only works for the original author, it is not a handoff.

## Diagnostic sequence

1. Fill the block from the board, not from memory → branch A: `what_i_proved` can cite a command and its output; branch B: it turns into "I think it's vulnerable", which means the state is still hypothesis and must be labelled that way.
2. Read the five lines aloud and ask for a repeat-back → branch A: the incoming person restates the state and the next action; branch B: the wording is ambiguous and must be rewritten before either person moves on.
3. Have the incoming person run the health test and the rollback command *before* they change anything → the fastest way to find an undocumented dependency.
4. Update the board row and retire the outgoing owner from the service's deploy path.

If the repeat-back fails twice, do not hand over — finish the concrete step (health test, or a minimal patch) and hand over after that. If the incoming person finds the rollback command does not work, treat it as an incident and record it as the service's block.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `wc -l <WORKDIR>/handoff/<SERVICE>.md` | a small number | size proxy for whether this is a handoff or a document |
| `git log --oneline -n 1` | one hash | `what_changed` must resolve to this, not to a narrative |
| the service's health test | baseline response | the incoming person can independently confirm the health column |
| the rollback command, executed once as a dry look | the inverse diff or revert plan | proves a rollback path exists before it is needed under pressure |

## State-changing actions

- **Impact:** the handoff itself changes nothing; the dangerous step is testing the rollback, which touches the live service. The safer form is to inspect the rollback (`git show`, `git diff --stat`) rather than execute it during handoff.
- **Preconditions:** health test saved, revision named, board row current.
- **Health check before:** run the saved health test — expect the baseline response.
- **Apply:** hand over ownership in the board and give the incoming person the deploy path; the outgoing person stops deploying to that service immediately.
- **Health check after:** the incoming person reproduces the health test unchanged. Regression probe: they can name the exploit's success condition without re-deriving it.
- **Rollback:** if the handoff is clearly failing, the outgoing owner resumes ownership — and the board must be updated in the same minute, otherwise both people believe they are in charge.

## Failure modes and things teams stopped doing

- Teams stopped communicating by broadcast. A first-time retrospective describes holding several codebases in mind while fielding many concurrent conversations, ending in exhaustion — a written handoff moves that load into a file. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped assuming findings will meet. The same retrospective notes that the team was unsure whether work had been duplicated or whether complementary findings had failed to connect; the explicit "what I proved / where it lives" pair is the countermeasure. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped accepting handovers without a rollback. The patch-infrastructure write-up exists because manual, undocumented changes were the source of pain; a handoff without a rollback path preserves exactly that problem. [src-maplebacon-faustctf-patcher-bf21013c]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No handoff was performed in this session.
- **Our adaptation vs the source:** the five-fact format and the repeat-back test are ours; the underlying need for explicit ownership and recorded state comes from the cited team retrospective and the patch workflow.

## Sources

- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — coordination, context switching, and duplicated work in a first-hand team account.
- `src-maplebacon-faustctf-patcher-bf21013c` — version-controlled change and rollback as the basis for handing work over.
- `src-ntt-enowars8-writeup-8b4ecb49` — parallel but separate workstreams (offence loop versus defence) needing explicit state.
