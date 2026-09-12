# Treat untrusted deserialization as code execution, and patch it narrowly

**First useful action.** Find every place attacker-influenced bytes reach a deserializer, and write down which of them are reachable from the graded interface before changing any of them.

```bash
grep -rnE 'pickle\.loads?|yaml\.load|marshal\.load|unserialize|readObject|TypeNameHandling|BinaryFormatter|ObjectInputStream|loads?\(' \
  <SERVICE_DIR> | grep -vE 'json\.loads|\.safe_load' | head -n 40
```

Expected: a short list of deserialization sinks. If the list is empty, look for framework-specific helpers, template engines, and cache layers — an indirect `loads` inside a session or cache library is still a sink.

## Symptoms

- A route accepts uploaded, imported, cached, or session data that is serialized with a type-tagged or executable format.
- The service supports "import a recipe/config/plugin" or restores state from a client-supplied blob.
- A defensive change to the serializer broke retrieval of previously stored objects.

## Prerequisites and assumptions

- Source or configuration showing the serializer and the input boundary.
- A way to distinguish checker-required data from incidental data.
- Assumption: security depends on the format's semantics, not on content filtering. Byte-pattern or class-name deny lists are not a sandbox.

## Diagnostic sequence

1. Trace from request body/file/session to the deserialize call → branch A: attacker controls the bytes, so the sink is live; branch B: the data is server-generated and integrity-protected, so record it as lower risk.
2. Determine whether the format lets the payload select types (type tags, class names, reducers) → if yes, the sink is code execution; if the format is schema-fixed and non-executable, it is at most a parsing risk.
3. Identify the minimum data the graded flow actually needs from that format → this defines the patch target.
4. Apply the narrowest change that removes type selection or untrusted decoding while keeping the data model, then run the store-then-retrieve regression, because deserializer changes frequently break reading of old objects.

If the graded flow needs a format you cannot safely decode, isolate that one feature rather than rewriting the service: a failing checker costs more than one closed import path.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| the grep above | sink list with file:line | candidate attacker-controlled decode points |
| `grep -rnE 'safe_load\|allowlist\|ALLOWED_TYPES\|SerializationBinder' <SERVICE_DIR>` | existing restrictions | whether a sink is already constrained; absence is not proof of safety |
| `<SERVICE_HEALTH_REQUEST>` before/after | status and body | deserializer edits break stored data more often than fresh data |
| `git diff --stat` | changed files | a deserialization patch that touches many files has exceeded its scope |

## State-changing actions

- **Impact:** changing a serializer affects persisted objects, caches, and session state; the failure mode is "everything works until you read something written before the change".
- **Preconditions:** a baseline snapshot, the checker contract, and a stored object created before the change to test against.
- **Health check before:** store one object through the legitimate flow and confirm you can read it back.
- **Apply:** remove type-name-driven construction, or replace untrusted deserialization with a schema-fixed decode on the single boundary that matters; do not rewrite unrelated serialization.
- **Health check after:** the newly stored object reads back, and an object stored *before* the change still reads back. Regression probe: the checker's full store-then-retrieve cycle.
- **Rollback:** `git revert --no-edit <patch-commit>` and restore state from the snapshot if the patch wrote any. Rolling back is unsafe if new objects were written in the new format and cannot be read by the old code — restore state first.

## Exploit → patch pair

- **Flaw:** attacker-supplied serialized data selects a type or reducer that executes during deserialization.
- **Reproduce on the isolated fixture:** send a serialized payload to the import endpoint of `http://127.0.0.1:<PORT>` (`<LOCAL_FIXTURE>`) that instantiates a harmless marker class from the service's own code → expect the marker to be constructed, proving type selection.
- **Narrow patch:** constrain construction to an explicit set of expected data types, or move that one boundary to a schema-fixed format.
- **Legitimate functionality that must keep working:** the documented import/restore workflow used by the checker, and reading of objects stored earlier in the game.
- **Verify:** the marker payload is rejected or inert while the legitimate import still succeeds and old objects still read.

## Failure modes and things teams stopped doing

- Teams stopped assuming a "trusted internal" format is trusted. Published service sources for attack/defense events include import paths where the decode step itself is the vulnerability, which is why the boundary — not the value — is what must change. [src-enowars-cyberalchemist-readme-3cef120f]
- Teams stopped changing serializers mid-incident without a persistence test. Guidance around patching services that store flags warns that deserializer changes can break persisted objects, so old-state retrieval belongs in the verification. [src-enowars-buggy-readme-f85b8d0e]
- Teams stopped treating a filtered payload as a fixed payload. Filters that reject known-bad encodings are fragile; the durable fix is to stop letting untrusted bytes choose code paths. [src-maplebacon-ad-primer-23bd534f]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No deserialization sink was identified and no payload was constructed in this session. `<LOCAL_FIXTURE>` must be a team-created local copy, never a graded instance.
- **Our adaptation vs the source:** the sink-hunt grep and the persistence-first verification order are ours. The "deserialization as unintended execution path" framing comes from published service code for the cited events.

## Sources

- `src-enowars-cyberalchemist-readme-3cef120f` — service source where dynamic dispatch/deserialization was the vulnerable path.
- `src-enowars-buggy-readme-f85b8d0e` — service whose auth/state logic and stored data constrain how patches may be applied.
- `src-maplebacon-ad-primer-23bd534f` — A/D primer on patching versus filtering.
- `src-enowars-checker-tenets-bf4b0ac7` — requirement that services keep working, including across restarts.
