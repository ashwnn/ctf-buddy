# Patch upload handling without removing the feature the checker uses

**First useful action.** Write down the one legitimate upload the checker or the product performs, then
make the smallest change that removes the attacker's influence over path and type.

```bash
# record the legitimate workflow FIRST (this is your regression probe)
curl -sS -o <EVIDENCE_DIR>/upload-before.http -F 'file=@<LOCAL_TMP>/<LEGIT_NAME>.png' \
  'http://127.0.0.1:<PORT>/<UPLOAD_ROUTE>'
sha256sum <LOCAL_TMP>/<LEGIT_NAME>.png
```

Expected: a stored legitimate file with a retrievable URL. If this fails before you patch anything, the
service is already broken — fix the baseline first, or you will attribute a pre-existing fault to your
change.

## Symptoms

- `card-web-014-upload-landing-zone` proved client influence over the stored name, path, or type.
- The upload route is used by the checker (flags or user content may be stored through it).
- A previous "fix" removed the upload or restricted it so aggressively that the checker went red.

## Prerequisites and assumptions

- A proven, reproducible upload weakness and the exact code path that stores the file.
- One recorded legitimate upload, with its content hash and returned URL.
- An immediate rollback path (one file, one commit).
- Stack/version: framework-specific; the safe implementation uses the framework's own directory-scoped
  save helper where one exists (`src-flask-send-from-directory-24ec5c2a`).

## Diagnostic sequence

1. Re-run the legitimate upload and save the response. → Baseline.
2. Confirm the vulnerability still reproduces on the unpatched revision. → Otherwise the patch cannot be
   evaluated.
3. Identify the smallest change: usually the *name generation* line, or the directory resolution line,
   not the route.
4. Apply, restart only that service, then run the pair: exploit attempt must fail, legitimate upload must
   still succeed.
5. Restart the service without deleting its data and confirm previously uploaded legitimate files are
   still retrievable. → Catches patches that change the storage layout and orphan existing files.

If the legitimate upload fails but the exploit also fails, the patch is overbroad: revert and narrow it.
If old files break while new ones work, the patch changed the storage layout — revert and instead
constrain the path without moving existing data.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| legitimate upload `200` + retrievable URL | baseline intact | Safe to judge the patch. |
| exploit filename `../../../<UNIQUE_NAME>.txt` | no file outside the root | Path influence removed. |
| `sha256sum` of the retrieved legitimate file | equals the uploaded file's hash | Content integrity preserved; no re-encoding by the fix. |
| checker green after patch | intended | The feature the checker uses still functions. |
| checker red only after restart | layout change | The patch moved or renamed storage; old objects are unreachable. |

## State-changing actions

- **Impact:** upload handling is shared by legitimate users and the checker; a wrong change breaks
  content storage and may orphan existing files.
- **Preconditions:** reproducible weakness, recorded legitimate workflow, one-file rollback, permission
  to modify the service.
- **Health check before:** `<CHECKER_COMMAND> ... baseline` — expect green, plus one successful
  legitimate upload.
- **Apply:** one change at the storage point — server-generated name plus path confinement, or an
  explicit allowlist of extensions derived from the product's actual feature set.
- **Health check after:** `<CHECKER_COMMAND> ... cycle` — expect green; regression probe: the same
  legitimate upload by URL and a create-then-retrieve round trip across a service restart.
- **Rollback:** `git revert <PATCH_COMMIT>` and redeploy; keep the upload directory untouched. If old
  files are already orphaned, do not delete anything — restore the previous naming/lookup scheme so the
  objects become reachable again.

## Exploit → patch pair

- **Flaw:** the stored location or type of an uploaded artifact is decided by the client.
- **Reproduce on the isolated fixture:** `fixtures/d3-notehub-patch` (planned in
  `research/06-drills-and-validation.md`) or a small local upload fixture: submit a benign file with a
  traversal-bearing filename, then the same file with a normal name (not yet run here).
- **Narrow patch:** replace client-derived names with server-generated ones; resolve and verify the final
  path stays within the upload root; validate type server-side.
- **Legitimate functionality that must keep working:** upload, retrieval by the returned URL, and any
  per-file metadata (size, name shown to the user) the product exposes.
- **Verify:** the traversal attempt stores nothing outside the root **and** the legitimate file is
  retrievable with an identical hash.

## Failure modes and things teams stopped doing

- Disabling the upload route as the "fix". In an availability-scored event this is a functional
  regression; the checker exercises legitimate behaviour (`src-enowars-checker-tenets-bf4b0ac7`,
  `src-faust-attackdefense-beginners-e53569f0`).
- Blocking by extension list copied from the internet. Derive the list from the product's real feature
  set; an over-broad block is a regression, an under-broad one is not a fix.
- Changing where files are stored to "somewhere safer" mid-event. Existing files and checker-created
  content become unreachable; the patch should confine, not relocate.
- Rebuilding the whole service tree to apply a one-line change. That is how mutable state (uploads,
  databases) gets overwritten; keep mutable data out of the deploy path, as the Maple Bacon patching
  retrospective describes (`src-maplebacon-faustctf-patcher-bf21013c`).
- Judging the patch by the exploit alone. The pair is mandatory: exploit fails *and* legitimate upload
  succeeds.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. The commands above were not executed in this session.
- **Our adaptation vs the source:** the framework-safe save pattern is from
  `src-flask-send-from-directory-24ec5c2a`; the "functionality is part of the contract" rule is from
  `src-enowars-checker-tenets-bf4b0ac7` and `src-faust-attackdefense-beginners-e53569f0`; the "keep mutable data out of the
  deploy path" constraint is from `src-maplebacon-faustctf-patcher-bf21013c`. The specific patch shape (server-side
  naming plus confinement) is our synthesis and must be adapted to the service in front of you.

## Sources

- `src-flask-send-from-directory-24ec5c2a` — framework file-upload handling and directory-scoped saving.
- `src-enowars-checker-tenets-bf4b0ac7` — checker/service functionality must be preserved by any change.
- `src-faust-attackdefense-beginners-e53569f0` — organizer guidance that breaking legitimate behaviour harms the
  service score.
- `src-maplebacon-faustctf-patcher-bf21013c` — narrow deployment and rollback that does not disturb mutable state.
