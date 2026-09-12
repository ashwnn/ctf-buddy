# Failure story: edited a service someone else was already working in

**First useful action.** Check the owner column before you touch a file, and claim the service on the board before the first edit rather than after.

```bash
grep -n '<SERVICE>' <WORKDIR>/service-board.md && \
  cd <SERVICE_DIR> && git log --oneline -n 3 --date=iso --format='%h %ad %an %s'
```

Expected: a row naming one current owner and a commit history whose last entries match that person. If the last commit author is someone else and the board row still names them, you are about to become the second writer.

## Symptoms

- Two people report different behaviour for the same service minutes apart.
- A change is live that nobody admits making, or an obvious fix was reverted by someone unaware of it.
- Merge-conflict-shaped confusion in a repository that only two people touch.

## Prerequisites and assumptions

- A shared board with an owner column and a repository the service is committed to.
- Agreement that deploying to a service is a single-writer operation.
- Assumption: analysis is unlimited and shared, while *deployment* must be serialised through one owner.

## Diagnostic sequence

1. Read the board row and the commit history → branch A: one owner, no recent foreign commits, proceed; branch B: recent commits from another author, so talk first.
2. If the other person is mid-task, ask one question: "what is the next action and do you want this or me?" → branch A: they hand over via `card-ad-handoff-under-pressure`; branch B: they keep it and you move to a different service.
3. If you must edit immediately (active exploitation, service down), make the restore-class change only — revert to a known-good revision — and log it on the board as an emergency action with the reason.
4. Reconcile afterwards: one commit per deployed change, attributed in the commit subject so the history shows who did what.

If the service is broken and the owner is unreachable, restore first and inform them, rather than starting a parallel rewrite. If the service is healthy and you disagree about the fix, write your reasoning in the board row and let the owner deploy.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -n '<SERVICE>' <WORKDIR>/service-board.md` | row with owner | the single source of truth for who deploys |
| `git log --oneline -n 3` | hashes, authors, subjects | whether the working tree has a second writer |
| `git status --short` | pending edits | uncommitted changes from someone else that you would overwrite |
| `ps -eo etimes,args \| grep <SERVICE_PROCESS>` | process age | whether you are looking at a service someone restarted 30 seconds ago |

## State-changing actions

- **Impact:** overriding another person's uncommitted work destroys information that may not exist anywhere else; deploying over their deployed change makes attribution impossible.
- **Preconditions:** board row read, history reviewed, other person contacted when reachable.
- **Health check before:** the legitimate smoke test, so you know the state you are inheriting.
- **Apply:** either take ownership explicitly on the board, or make only the narrow restore-class change and record it as an emergency action.
- **Health check after:** smoke test passes; the board row now includes your change with the time you made it. Regression probe: whoever owns the service next can see the change in `git log` with a matching subject.
- **Rollback:** `git revert --no-edit <your-commit>`; if your change was a deployment over theirs, restoring their revision is the rollback. Re-applying your overwritten edits is unsafe once their context is lost.

## Failure modes and things teams stopped doing

- Teams stopped leaving ownership implicit. A first-hand team retrospective from RuCTFE describes weak internal communication and unclear awareness of who was doing what, with the team unsure whether work had been duplicated or whether complementary findings had failed to connect. Explicit single-writer ownership is the countermeasure to exactly that. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped treating every analyst as a writer. The same account describes one contributor holding several codebases in mind while answering many concurrent conversations; routing deployment through a service owner removes that load without removing the analysis. [src-duchyoftaco-misec-ructfe2019-332d8e5b]
- Teams stopped making undocumented live edits. Manual, unlogged changes to a service were the pain that motivated the version-controlled deploy workflow in the first place; a second writer who edits outside that workflow recreates the original problem. [src-maplebacon-faustctf-patcher-bf21013c]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No board or repository was queried in this session.
- **Our adaptation vs the source:** the explicit "check owner before editing" gate is ours; the escalation rule (restore-class changes only, logged as emergency) is our addition for first-time teams. The coordination failure is reported first-hand by the cited team.

## Sources

- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — first-hand record of ownership confusion and duplicated work.
- `src-maplebacon-faustctf-patcher-bf21013c` — version-controlled deployment replacing undocumented manual edits.
- `src-dttw-defcon2021-retro-14eb5491` — team workflow observations under finals workload.
