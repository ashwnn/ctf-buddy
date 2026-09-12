# Failure story: restored a whole tree and destroyed the state the checker needed

**First useful action.** Before any restore, list what the restore will overwrite and confirm that the flag store, database, uploads, and generated keys are not on the list.

```bash
tar -tzf <SNAPSHOT_ARCHIVE> | sed 's|^\./||' | cut -d/ -f1 | sort -u > <WORKDIR>/restore-would-touch.txt; \
  printf '%s\n' '<STATE_DIR>' > <WORKDIR>/state-paths.txt; \
  grep -Fxf <WORKDIR>/state-paths.txt <WORKDIR>/restore-would-touch.txt && echo 'DANGER: restore covers state' || echo 'state not in archive root'
```

Expected: `state not in archive root`. If the check prints `DANGER`, the archive contains live state and a plain restore will roll the service's data back to snapshot time — including flags the checker expects to still be readable.

## Symptoms

- A restore is proposed as the fix for a broken service.
- The snapshot was taken before the game started, or before anyone knew which paths were mutable.
- After an earlier restore, the service answered but stored data was missing.

## Prerequisites and assumptions

- A snapshot or repository, and a written list of runtime state paths (`card-ad-untrack-mutable-state`).
- Permission to restore the assigned instance, if the organizers provide a reset mechanism.
- Assumption: in frameworks with round-based flag validity, data written in *earlier* rounds must remain readable. Restoring pre-game state therefore removes data the grader still looks for.

## Diagnostic sequence

1. Inspect the restore's file list and compare it against the state paths → branch A: disjoint, so restore is safe for state (though it still discards recent code edits); branch B: overlapping, so use a code-only restore (revert/copy) and leave state in place.
2. If overlap is unavoidable, decide what the checker actually needs: run the checker's read path, or check whether flags from the previous cycle are still expected → this decides whether losing recent state is survivable.
3. Perform the code-only restore, then verify that new writes still work and old reads still succeed → branch A: both, so the incident is closed; branch B: old reads fail, so the state was damaged and the case must be reported to the organizer rather than hidden.
4. Record on the board whether the service's state and code can be restored independently — this determines every future recovery decision for that service.

If the restore must include state, stop and ask the organizer about the documented reset mechanism before destroying anything.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tar -tzf <SNAPSHOT_ARCHIVE> \| head` | archive contents | what the restore would overwrite |
| `git status --short` on the service | tracked vs ignored files | if state is ignored, a Git-based restore is already state-safe |
| the checker's read path after restore | expected value or empty | whether earlier-round data survived |
| `systemctl show -p ActiveEnterTimestamp <UNIT>` | start time | confirms the restore actually took effect |

## State-changing actions

- **Impact:** a whole-tree restore overwrites live state and recent code; an unqualified restore can convert a temporary fault into permanent data loss.
- **Preconditions:** the restore inventory has been reviewed against the state-path list, and a copy of the current (pre-restore) tree has been preserved for analysis.
- **Health check before:** capture the failing response and a copy of the current tree.
- **Apply:** restore code only (revert commits, or copy files excluding state paths); use a full-image restore only when state is known to be disposable.
- **Health check after:** legitimate smoke test passes, a new write succeeds, and a value written before the incident is still readable. Regression probe: the checker's store-then-retrieve cycle across two cycles.
- **Rollback:** re-apply the preserved pre-restore copy for code, and restore state only from a snapshot that includes up-to-date data. A second whole-tree restore on an already-damaged service is unsafe because it can overwrite evidence of what was lost.

## Failure modes and things teams stopped doing

- Teams stopped treating deployment as a file copy. The published patch-infrastructure account separates deployable code from deployment data specifically so that shipping code cannot wipe the data the service depends on. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped assuming a code rollback implies data recovery. Framework documentation makes flag/state persistence across rounds an explicit concept, which means a restored-but-empty store is still a failing service. [src-enowars-engine-readme-7933cf37]
- Teams stopped trusting an undocumented snapshot. A snapshot whose contents nobody has reviewed is not a rollback plan; the review step above exists because the archive and the state paths are usually written by different people at different times. [src-enowars-checker-tenets-bf4b0ac7]

## Evidence status

- **Status:** source-supported but untested — and partly inference
- **What we actually ran:** nothing. No archive was inspected and no restore was performed in this session.
- **Our adaptation vs the source:** the specific scenario "team restored a whole tree and destroyed checker data" is our construction (researcher inference) from the sourced practices of separating deployable code from deployment data and of persisting stored data across rounds. Neither cited source states that a team did this; the practice they describe is the countermeasure, not the narrative.

## Sources

- `src-maplebacon-faustctf-patcher-bf21013c` — keeping deployment data out of deployable code.
- `src-enowars-engine-readme-7933cf37` — flag/state persistence across rounds as a framework concept.
- `src-enowars-checker-tenets-bf4b0ac7` — what a service must guarantee about stored data.
- `src-d0gl0v3r-umcs2026-c85f0c19` — restore-versus-debug pressure during a live event.
