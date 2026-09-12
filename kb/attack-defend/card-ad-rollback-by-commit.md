# Roll back by commit, then diagnose the failure offline

**First useful action.** Revert to the last known-good commit and redeploy, then run the legitimate smoke test — do not debug the broken service in place.

```bash
cd <SERVICE_DIR> && git log --oneline -n 5 && \
  git revert --no-edit <BAD_COMMIT> && \
  git log --oneline -n 1 && \
  <REDEPLOY_COMMAND> && \
  curl -sS -o /dev/null -w 'health:%{http_code}\n' '<HEALTH_URL>'
```

Expected: the revert creates a new commit whose subject names the reverted change, and the smoke test returns the baseline status. If the redeploy is not a single command, that is the defect to fix before the next incident.

## Symptoms

- The service reported down, faulty, or recovering immediately after a change you made.
- The legitimate request that worked ten minutes ago no longer returns its baseline response.
- Two people are editing the same service and neither is sure which change caused it.

## Prerequisites and assumptions

- Every change was committed separately, and mutable state was excluded from the tracked tree.
- A redeploy command that is known to work, plus a saved legitimate smoke test.
- Assumption: a code rollback is sufficient. It is **not** sufficient when the patch also changed on-disk state or schema.

## Diagnostic sequence

1. Identify whether the failure correlates with your last commit (`git log --oneline -n 5` plus deployment timestamps) → branch A: correlation, revert now; branch B: no correlation, the cause is elsewhere and reverting may hide evidence.
2. Before reverting, copy the failing state aside for offline analysis (`cp -a <SERVICE_DIR> <WORKDIR>/failed-<SERVICE>-$(date -u +%H%M%S)`) → this preserves the evidence you will need.
3. Revert, redeploy, smoke test → branch A: healthy, so continue forensics offline; branch B: still broken, so the failure is stateful or environmental, not just code.
4. If still broken, ask whether the failure predates your change by comparing against the baseline inventory from `card-ad-baseline-snapshot-before-edit`.

If state changed as part of the patch (migration, file format, deleted records), go to `card-ad-restore-patch-exploit-triage` instead of trusting the revert alone.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `git log --oneline -n 5` | five commit subjects | correlation between deployment time and failure time |
| `git revert --no-edit <BAD_COMMIT>` | new commit `Revert "..."` | rollback that preserves history, so the failed attempt stays reviewable |
| `git show <KNOWN_GOOD>:<FILE>` | file contents at that revision | inspection of the pre-change code without touching the working tree |
| `curl -sS -o /dev/null -w '%{http_code}\n' '<HEALTH_URL>'` | `200` | the only acceptable post-revert proof |

## State-changing actions

- **Impact:** replaces live code and, depending on the runtime, restarts the process; a revert that does not match the state on disk can produce an inconsistent service.
- **Preconditions:** known-good commit identified, state paths excluded from the tree, redeploy command tested, failure preserved for offline analysis.
- **Health check before:** capture the failing response and the process state — you want evidence, not just a fix.
- **Apply:** `git revert --no-edit <BAD_COMMIT>` followed by the redeploy command, as one deliberate sequence with the board updated.
- **Health check after:** legitimate smoke test returns the baseline status and body invariant; regression probe: one write-then-read cycle that also retrieves data created before the incident.
- **Rollback:** the inverse of a revert is `git revert --no-edit <REVERT_COMMIT>`. Re-applying the bad patch is unsafe while the underlying defect is unexplained — and a `git reset --hard` on a live tree is unsafe whenever state files were ever tracked.

## Failure modes and things teams stopped doing

- Teams stopped reconstructing edits by hand. The patch-infrastructure write-up exists because manual SSH edits were painful and unauditable; a rollback target recorded as a commit is the direct replacement. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped debugging a dead service while it is dead. A first-time retrospective describes effort spent merely keeping containers alive; the cheaper sequence is restore first, understand second, with the failed artifact preserved. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped assuming a revert also repairs data. Where a change touches stored state, the framework concept of data that must survive between rounds means data loss continues to hurt after the code is back. [src-enowars-engine-readme-7933cf37]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No repository was reverted and no service was restarted in this session.
- **Our adaptation vs the source:** the "preserve the failure before reverting" step is ours; the cited workflow motivates version-controlled patching and rollback but does not describe evidence preservation. `<REDEPLOY_COMMAND>` is left as a placeholder because the deployment method is event- and host-specific.

## Sources

- `src-maplebacon-faustctf-patcher-bf21013c` — version history and rollback as the reason the workflow exists.
- `src-enowars-engine-readme-7933cf37` — framework-level expectation that stored state persists across rounds.
- `src-d0gl0v3r-umcs2026-c85f0c19` — the time cost of babysitting a broken service instead of restoring it.
- `src-ructfe-rules-95d7c601` — availability-sensitive scoring that makes fast restoration worth more than perfect diagnosis during a tick.
