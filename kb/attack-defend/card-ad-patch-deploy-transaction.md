# Treat patch deployment as a transaction with a rollback already written

**First useful action.** Write the rollback command into the service board *before* you deploy, then run the fixed sequence: health → exploit regression → state persistence → resource sanity.

```bash
printf 'rollback: cd %s && git revert --no-edit %s\n' '<SERVICE_DIR>' "$(cd <SERVICE_DIR> && git rev-parse HEAD)" \
  | tee -a <WORKDIR>/service-board.md && \
  cd <SERVICE_DIR> && git add -A && \
  git -c user.name=team -c user.email=team@<LOCAL_FIXTURE> commit -qm 'patch: <ONE_LINE_DESCRIPTION>' && \
  git log --oneline -n 1
```

Expected: a commit hash and a rollback line recorded in the board *before* the change reaches the running service. If you cannot express the rollback as one command, you are not ready to deploy.

## Symptoms

- A patch "worked" but the score moved the wrong way, or the service reported faulty afterwards.
- Nobody can say which revision is currently running on the instance.
- Multiple small edits are live and none of them can be individually reverted.

## Prerequisites and assumptions

- Baseline commit, saved legitimate smoke test, and a reproducible exploit that the patch should stop.
- A deployment path (restart, container rebuild, or push-to-deploy) that you actually understand.
- Assumption: whether a restart is observable by the grader, and whether it is penalised, is event-specific. Confirm before making restarts routine.

## Diagnostic sequence

1. Commit the patch on its own before touching the running service → branch A: the change is isolated and revertable; branch B: unrelated edits rode along, so split them before deploying.
2. Deploy and immediately run the legitimate smoke test → branch A: unchanged, continue; branch B: changed, roll back now and investigate offline.
3. Run the exploit regression → expect it to fail for the intended reason, not with a generic error affecting everyone.
4. Re-check persistence: retrieve something the service stored *before* the patch → branch A: still readable, so state survived; branch B: gone, which means the patch (or its restart) destroyed data the checker will look for.
5. Measure resource sanity: process RSS, CPU, and p95 latency over the next minute → a defensive control that costs an unbounded amount of memory is an outage waiting to happen.

If step 2 or 4 fails, go straight to `card-ad-rollback-by-commit`. If step 5 shows a large regression, treat the patch as unsafe even though it "works".

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `git log --oneline -n 1` | one hash and subject | what is deployed now; record it on the board next to the service name |
| `git diff <known-good>..HEAD --stat` | changed files/line counts | a large diff increases both regression risk and rollback risk |
| `curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' '<HEALTH_URL>'` repeated | status and latency sequence | availability after the restart, and whether the service is now slower |
| `/proc/<PID>/status` `VmRSS` sampled over a minute | resident memory trend | an always-on defensive component that grows without bound [src-d0gl0v3r-umcs2026-c85f0c19] |

## State-changing actions

- **Impact:** replaces the code that the checker exercises and may restart the process, momentarily dropping connections; a restart can also clear in-memory caches the service relied on.
- **Preconditions:** patch committed alone, rollback line written, saved legitimate smoke test, known-good commit reachable, state paths excluded from the deployment (`card-ad-untrack-mutable-state`).
- **Health check before:** run the saved legitimate request → expect the baseline body invariant and status.
- **Apply:** deploy the single commit and restart only if the runtime requires it; do not combine a restart with config or state migration in the same step.
- **Health check after:** legitimate smoke test unchanged; exploit regression fails; a pre-patch stored value is still retrievable; resource trend flat. Regression probe: the full checker or the documented store-then-retrieve cycle, not just a ping.
- **Rollback:** `git revert --no-edit <patch-commit>` and redeploy, then re-run the health and exploit checks. Rollback becomes unsafe if the patch changed on-disk state or schema in a way the old code cannot read — in that case restore state first and treat the revert as incomplete.

## Exploit → patch pair

- **Flaw:** the deployed condition let an unauthenticated or under-privileged request reach a privileged operation.
- **Reproduce on the isolated fixture:** `curl ... '<EXPLOIT_URL>'` against `http://127.0.0.1:<PORT>` (`<LOCAL_FIXTURE>`) → expect the privileged result before the patch.
- **Narrow patch:** deploy exactly the tested commit; if the deployment pipeline also rebuilds or syncs other files, stop and make the pipeline narrower first.
- **Legitimate functionality that must keep working:** the checker's store/retrieve path *and* retrieval of previously stored data.
- **Verify:** exploit fails after deployment while the legitimate flow still passes; then re-run the checker.

## Failure modes and things teams stopped doing

- Teams stopped keeping patches only in a terminal history. The documented patch-infrastructure experience is that manual edits hurt and version control gave both history and a rollback path; deployment state belongs on a shared board, not in one person's scrollback. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped treating every patch as automatically good. Team material from a mature event stresses that a code or binary change must preserve the behaviour the checker exercises; a patch that wins the exploit test and loses the correctness test is a net loss. [src-ntt-enowars8-writeup-8b4ecb49]
- Teams stopped letting one emergency control become permanent and undocumented. The first-time retrospective's WAF consumed the whole host's memory precisely because nobody had bounded it or written a removal step. [src-d0gl0v3r-umcs2026-c85f0c19]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No commit, deployment, or restart was performed in this session.
- **Our adaptation vs the source:** the five-step transaction is ours; it formalises the order (health → regression → persistence → resources) that the cited team material implies. The requirement to record the rollback command *before* deployment is our addition for a first-time team.

## Sources

- `src-maplebacon-faustctf-patcher-bf21013c` — patch deployment, history, and rollback as infrastructure.
- `src-ntt-enowars8-writeup-8b4ecb49` — defence discipline: precise patches that preserve graded behaviour.
- `src-enowars-checker-tenets-bf4b0ac7` — what a checkable service must keep doing.
- `src-d0gl0v3r-umcs2026-c85f0c19` — unbounded defensive control as an outage.
- `src-faust-ad-beginners-779c0a5e` — organizer framing of legitimate behaviour as the thing that is graded.
