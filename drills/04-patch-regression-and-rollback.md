# Drill 04 — Patch regression and rollback

**Time:** 20-30 minutes. **Track:** attack/defend operations.
**Fixture:** `fixtures/p1-flask-compose`.

## Goal

Practice the bad day: a patch is applied and then something breaks. Learn to read
the verification failure, understand why rollback may refuse, and restore the
service without destroying data.

## Setup

```bash
cd fixtures/p1-flask-compose
docker compose up -d --build
cd ../..
./ctfctl plan --profile web-nginx-flask-compose
./ctfctl apply --plan latest --yes
# record the tx id from the output
curl -sS "http://127.0.0.1:8080/files?name=../../canary.txt"   # must NOT return the canary
```

## Tasks

1. **Inject a regression.** Edit `fixtures/p1-flask-compose/service/app.py` and
   make the health route fail, for example by replacing its return with
   `raise RuntimeError("drill regression")`. Restart only the app:
   `docker compose -f fixtures/p1-flask-compose/compose.yaml restart web`
2. **Detect it.** Run `./ctfctl verify --plan latest`. Which verifier fails
   first, and what does it say?
3. **Try the undo.** Run `./ctfctl rollback --tx <tx-id> --yes`.
   It should refuse: the file changed after the transaction. Write down the
   conflict message. Why is refusing the safe behavior?
4. **Inspect, then recover deliberately.** Run `./ctfctl recover`, then restore
   the file with `git restore -- fixtures/p1-flask-compose/service/app.py`,
   restart the app, and confirm the legitimate workflow passes again.
5. **Back to baseline.** Confirm the original exploit works again (the fixture is
   deliberately vulnerable) and the health endpoint answers.

## Expected evidence

* `verify` output with at least one required check `ok: false` and a detail line
  naming the failed request or the missing guard.
* `rollback` refusal that names the modified file and the transaction.
* `recover` output that says what it will not do without a decision.
* After recovery: health 200, legitimate download 200, exploit returns the
  canary again (that is the restored baseline, not a victory).

## Success criteria

* You never force a rollback over a teammate's edit; you recover with knowledge
  of who changed what.
* The notes volume is untouched; only the app source and container restart.
* You can explain the difference between "rollback restores the pre-image" and
  "git restores the tracked original".

## Reset

```bash
cd fixtures/p1-flask-compose && ./reset.sh
```

Answers and expected values: `drills/answers.md`.
