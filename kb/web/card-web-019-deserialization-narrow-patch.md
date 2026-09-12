# Narrow a deserialization patch and keep the import workflow

**First useful action.** Before changing anything, import one legitimate object and record the stored
state it produces; that record is your regression probe.

```bash
curl -sS -i -X POST -H 'Content-Type: application/json' --data @<LEGIT_IMPORT_FILE> \
  'http://127.0.0.1:<PORT>/<IMPORT_ROUTE>' -o <EVIDENCE_DIR>/import-before.http
curl -sS -b <SESSION_JAR> 'http://127.0.0.1:<PORT>/<LIST_ROUTE>' \
  -o <EVIDENCE_DIR>/state-before.json
```

Expected: a successful import and a listing that shows the imported object. If the import already fails,
stop: you need a working baseline before you can claim your patch preserved anything.

## Symptoms

- `card-web-018-deserialization-http-path` proved the deserializer can construct types or run code.
- The import endpoint is part of the product's legitimate workflow, and possibly of the checker's.
- A previous "fix" broke imports or lost previously stored objects.

## Prerequisites and assumptions

- A working import baseline and the exact deserializer configuration line.
- The deserialization library's documented safe mode for your version (verify locally; do not assume an
  option name).
- One-command rollback.
- Stack/version: the safe option differs per library and release.

## Diagnostic sequence

1. Baseline the import and record the resulting stored state. → Regression probe.
2. Confirm the dangerous capability still reproduces. → Otherwise the patch is unnecessary.
3. Choose the smallest configuration change: disable type-name resolution / use the safe loader / bind
   the payload to a fixed schema class.
4. Apply, restart only the affected service, then verify three things in order: the manipulated payload
   fails, the legitimate import passes, and previously stored objects are still readable.
5. Restart the service and re-check the listing. → Detects serializer changes that break persisted data.

If previously stored objects become unreadable, your change altered the storage format. Revert and instead
restrict what can be *constructed*, without changing what is *stored*.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| import `200` + listing shows the object | baseline intact | Safe to judge the patch. |
| manipulated payload `400`/`403` | intended | The construction path is closed. |
| legitimate import `200` + listing shows the object | intended | Feature preserved. |
| listing empty after patch | data loss | You changed the storage format, not just the construction rules. |
| listing empty after *restart* only | persistence bug | The change interacts with restart/state; treat as a blocker. |

## State-changing actions

- **Impact:** the import path may be used by the checker to store and later retrieve data; a wrong change
  silently loses state.
- **Preconditions:** reproducible capability, recorded import baseline, committed pre-patch revision,
  permission to modify the service.
- **Health check before:** `<CHECKER_COMMAND> ... baseline` — expect green, plus one successful import.
- **Apply:** the single deserializer configuration or schema-binding change.
- **Health check after:** `<CHECKER_COMMAND> ... cycle` — expect green; regression probe: import a
  legitimate object and read it back after a restart.
- **Rollback:** `git revert <PATCH_COMMIT>` and redeploy, then re-import the baseline payload to confirm
  the previous behaviour is restored. Do not delete stored objects to "clean up" after a serializer
  change.

## Exploit → patch pair

- **Flaw:** the deserializer resolves types or code that the data should not be able to select.
- **Reproduce on the isolated fixture:** against a local fixture, submit a payload that selects a type not
  in the intended model and observe whether the runtime reports a constructed/unknown type (not yet run
  here). Keep this in a dedicated fixture — never against a shared host.
- **Narrow patch:** the published FAUST CTF 2024 Todo patch is the model: constrain the deserialization
  rather than removing the import feature (`src-faust-todo-patches-r06-abf8d3d1`).
- **Legitimate functionality that must keep working:** importing a genuine saved object, and reading back
  objects created before the patch.
- **Verify:** the manipulated payload fails, the legitimate import succeeds, and the pre-patch object is
  still readable after a restart.

## Failure modes and things teams stopped doing

- Deleting the import feature. The published FAUST patch shows the alternative: narrow the unsafe
  behaviour and keep the workflow (`src-czechcyberteam-faust2024-todolist-225eeec1`).
- Content-type or extension checks as the only barrier. They do not change what the deserializer will do
  with the bytes it receives.
- Changing the serialized format mid-event. Existing state becomes unreadable, which is a functional
  regression in an availability-scored event (`src-enowars-checker-tenets-bf4b0ac7`).
- Patching without a restart-and-retrieve step. Persistence failures are invisible until the service
  comes back.
- Applying the same patch to a second service without verifying it there. Services in the same event often
  share a language but not a version or a library default.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No import was performed and no patch was applied in this session.
- **Our adaptation vs the source:** this card is deliberately modelled on the published FAUST CTF 2024
  Todo exploit/patch pair (`src-faust-todo-service-r06-58bee3ce`, `src-faust-todo-exploits-r06-b0f65b05`,
  `src-faust-todo-patches-r06-abf8d3d1`) and the writeup's description of the same
  (`src-czechcyberteam-faust2024-todolist-225eeec1`). The specific patch text is not reproduced; only the shape
  (narrow the construction path, keep the workflow) is. The three-step verification order is our
  addition.

## Sources

- `src-faust-todo-patches-r06-abf8d3d1` — published narrow patch for an unsafe deserialization path.
- `src-faust-todo-service-r06-58bee3ce` — the service the exploit/patch pair applies to.
- `src-faust-todo-exploits-r06-b0f65b05` — the published exploit used to judge whether the patch closes the
  primitive.
- `src-czechcyberteam-faust2024-todolist-225eeec1` — team writeup describing the defect and the patch decision.
- `src-enowars-checker-tenets-bf4b0ac7` — functionality must be preserved by any change.
