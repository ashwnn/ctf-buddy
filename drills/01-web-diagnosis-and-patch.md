# Drill 01 — Web vulnerability diagnosis and narrow patch

**Time:** 20-30 minutes. **Track:** web, attack/defend patching.
**Fixture:** `fixtures/p1-flask-compose` (nginx + Flask, deliberate path traversal).
**Synthetic data only.** Nothing here touches a real event host.

## Goal

Reproduce a real vulnerability in the fixture, find the vulnerable call in the
source, apply the single narrow fix through the plan/apply engine, and prove the
exploit stopped while the legitimate workflow still works.

## Setup

```bash
cd fixtures/p1-flask-compose
docker compose up -d --build
curl -sS http://127.0.0.1:8080/healthz        # expect {"status":"ok"}
cd ../..
```

## Tasks

1. **Reproduce the defect.** Request the canary that lives outside the download
   root:
   `curl -sS "http://127.0.0.1:8080/files?name=../../canary.txt"`
2. **Baseline the legitimate flow.**
   * `curl -sS "http://127.0.0.1:8080/files?name=welcome.txt"`
   * create a note: `curl -sS -X POST -H 'Content-Type: application/json' -d '{"title":"drill","body":"hello"}' http://127.0.0.1:8080/api/notes`
   * read it back with the returned id, then delete it and read again (expect 404).
3. **Find the vulnerable call.** Read `service/app.py` (for example with
   `./ctfctl files read fixtures/p1-flask-compose/service/app.py`) and name the
   exact line that trusts the client-supplied name.
4. **Plan, do not patch yet.**
   `./ctfctl plan --profile web-nginx-flask-compose --verbose`
   Read the diff, the verifiers, the exploit probe and the rollback text.
5. **Apply and watch the transaction.**
   `./ctfctl apply --plan latest --yes`
6. **Verify both sides.**
   * exploit: step 1 must no longer return the canary;
   * legitimate: step 2 must all still pass;
   * `./ctfctl verify --plan latest`
7. **Practice the undo.** Record the tx id from step 5, then
   `./ctfctl rollback --tx <tx-id> --yes` and confirm the exploit works again.

## Expected evidence

* The exploit response before the patch contains `FIXTURE_CANARY_...`; after the
  patch it is a 404 (or another refusal).
* The plan shows one auto action that changes one line, keeps the route and
  response options, and names the exploit probe.
* The apply output has `phase: COMMITTED`, a file pre/post hash, and every
  verifier `ok: true`.
* The rollback output has `phase: ROLLED_BACK` and restores the file.

## Success criteria

* You can explain why `send_from_directory` is the narrow fix and what it
  deliberately does **not** change (route, callers, response headers, storage).
* The exploit is dead and the tier-3 note round-trip still passes after the
  patch.
* Rollback restores the vulnerable baseline without touching the notes volume.

## Reset

```bash
cd fixtures/p1-flask-compose && ./reset.sh
```

Answers and expected values: `drills/answers.md`.
