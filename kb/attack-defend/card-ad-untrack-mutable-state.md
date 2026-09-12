# Keep mutable service state out of the patch repository

**First useful action.** Untrack the runtime state paths while leaving the files on disk, and commit the ignore rules as their own change.

```bash
cd <SERVICE_DIR> && git rm -r --cached <STATE_DIR> >/dev/null && \
  printf '%s/\n' '<STATE_DIR>' >> .gitignore && \
  git add .gitignore && git -c user.name=team -c user.email=team@<LOCAL_FIXTURE> \
  commit -qm 'do not track mutable state' && \
  git status --short | head -n 20
```

Expected: the state directory no longer appears in `git status`, while code edits still do. If the state files reappear as untracked noise, add the specific generated paths rather than ignoring the whole tree.

## Symptoms

- `git status` is permanently dirty and every tick adds or modifies files you did not write.
- A deploy step refuses or behaves oddly because the working tree never matches the recorded revision.
- Someone is about to run a destructive sync or checkout over a tree that also contains the live flag store.

## Prerequisites and assumptions

- A baseline repository already exists (`card-ad-baseline-snapshot-before-edit`).
- A written list of runtime paths: databases, uploads, caches, generated keys, logs, and the flag store.
- Assumption: you can tell mutable state from code. Where they are interleaved, this card does not apply — use a whole-tree tarball for rollback instead.

## Diagnostic sequence

1. Watch the tree during ordinary traffic and list what changes → those paths are state; anything that changes without you editing it is state by definition.
2. Untrack only those paths and inspect `git status --short` again → branch A: status now reflects real edits; branch B: churn continues from other paths, so repeat for each one.
3. Before any deployment, verify that no destructive operation touches state: read the deploy command and confirm it does not delete or overwrite `<STATE_DIR>`.
4. Record the ignored paths in the service board so a teammate who joins later does not "clean up" the ignored directory.

If branch A, move on to `card-ad-patch-deploy-transaction`. If the state and code are inseparable, stop using code-only deployment for this service and switch to snapshot-and-restore.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `git status --short` | list of `M`/`??` entries | any entry you did not create is runtime state you have not handled yet |
| `git rm -r --cached <STATE_DIR>` | `rm 'data/app.db'` lines | the file stays on disk but leaves the index — this is not a delete |
| `cat .gitignore` | your ignore rules | review this list during incidents: an ignored path can hide attacker writes |
| `git log --oneline -n 3` | three commits | ignore-rule changes must be their own commit so a rollback does not silently re-track state |

## State-changing actions

- **Impact:** changes repository bookkeeping only; service files are untouched. However, ignore rules can mask attacker modifications inside ignored paths, and a later deploy that "resets the tree" may still delete state if the deploy tool honours cleanliness rather than ignore rules.
- **Preconditions:** baseline commit exists; the state paths are identified and are not needed in the patch history.
- **Health check before:** `curl -sS -o /dev/null -w '%{http_code}\n' '<HEALTH_URL>'` — expect the baseline code.
- **Apply:** `git rm -r --cached <STATE_DIR>` plus a `.gitignore` entry, committed separately from code patches.
- **Health check after:** the smoke test still passes; regression probe: perform one legitimate write that mutates state (for example a store operation) and confirm the data survives the next deployment.
- **Rollback:** `git rm -r --cached -r --ignore-unmatch .gitignore` — no; the correct inverse is to restore the ignore commit (`git revert <ignore-commit>`) and re-add only the paths you trust. It is unsafe to revert ignore rules mid-incident: re-tracking a live database can copy secrets into the repository.

## Failure modes and things teams stopped doing

- Teams stopped syncing a whole tree over a running service. The published patch-infrastructure workflow keeps deployment data separate from deployable code, precisely because overwriting the tree can destroy the state the checker depends on. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped treating a dirty working tree as cosmetic. A permanently dirty tree means the "known-good commit" on the board is not actually the code that is running, which silently invalidates every rollback plan. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped ignoring what their deploy step deletes. Patching is described in the same workflow as a deployment action with a history, which implies knowing exactly which paths a deployment may touch. [src-maplebacon-faustctf-patcher-bf21013c]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No repository state was modified in this session.
- **Our adaptation vs the source:** the untrack-now rule is our operational reading of Maple Bacon's separation of deployable code from data. The original workflow runs its Git service under elevated privileges; we deliberately do not, and instead treat "untrack state" as a local hygiene step.

## Sources

- `src-maplebacon-faustctf-patcher-bf21013c` — team patch workflow: version history, rollback, and keeping deployment data out of the deployable tree.
- `src-enowars-engine-readme-7933cf37` — framework expectation that stored flag data survives between rounds.
- `src-enowars-checker-tenets-bf4b0ac7` — what services must guarantee about stored data.
