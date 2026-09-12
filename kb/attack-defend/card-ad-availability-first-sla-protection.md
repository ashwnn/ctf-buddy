# Protect availability first: never trade a working service for an untested control

**First useful action.** Turn the service's legitimate happy path into a saved smoke test and start a low-rate availability watch before you change anything.

```bash
mkdir -p <WORKDIR>/health && \
printf '%s\n' '<EXACT_LEGITIMATE_REQUEST_LINE>' > <WORKDIR>/health/<SERVICE>.req && \
( while true; do
    printf '%s %s\n' "$(date -u +%H:%M:%S)" \
      "$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 5 '<HEALTH_URL>')"
    sleep <WATCH_INTERVAL_SECONDS>
  done ) | tee -a <WORKDIR>/health/<SERVICE>.log
```

Expected: a long run of identical status codes with stable latency. If the first lines are already `000` or `5xx`, you inherited a broken service — fix or restore that before any hardening, or every later measurement is meaningless.

## Symptoms

- A checker or scoreboard reports your service down/faulty/recovering while your terminal looks fine.
- A defensive control (filter, proxy, WAF, rate limit) was added and the score moved before any code was edited.
- The service answers from your laptop but only intermittently from anywhere else.

## Prerequisites and assumptions

- One known-good request that exercises the behaviour the game actually grades (store-then-retrieve, or the documented health endpoint).
- Stack-agnostic; the probe host must be one the organizer permits.
- Assumption: availability is scored in many A/D formats, but whether a failed check costs points immediately, after retries, or not at all is event-specific. Confirm before optimising for it.

## Diagnostic sequence

1. Issue the legitimate request once by hand and record status, body invariant, and state change → this is your baseline; if it already fails, stop and go to `card-ad-restore-patch-exploit-triage`.
2. Start the watch loop and let it run through one full cycle → branch A: stable, so you now have a reference for every later change; branch B: intermittent failures, so the cause is load, timing, or a dependency rather than your code.
3. Compare a failing window against process lifecycle (`systemctl show -p NRestarts -p ActiveEnterTimestamp <UNIT>`, or `docker ps --format '{{.Names}} {{.Status}}'`) → a restart at the same timestamp identifies a crash loop, not a network fault.

If branch B with restarts, go to `card-ad-rollback-by-commit` (self-inflicted) or `card-ad-unknown-rule-dry-run` (someone else's control). If branch A, keep the loop running while you patch.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl -s -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 5 '<HEALTH_URL>'` | `200 0.041` | legitimate path answers fast; anything else is a regression you caused or inherited |
| `awk '{print $2}' <WORKDIR>/health/<SERVICE>.log \| sort \| uniq -c` | counts per status code | `000` means refusal/timeout, not an application error |
| `systemctl show -p NRestarts -p ActiveEnterTimestamp <UNIT>` | restart counter and start time | a rising counter during your watch pins the problem on process lifecycle |

## State-changing actions

- **Impact:** the watch loop is read-only against the service but consumes a constant request budget and writes a growing log; an interval shorter than the real checker interval can itself look like load.
- **Preconditions:** an authorized probe URL plus a confirmed legitimate baseline response.
- **Health check before:** `curl -sS -o <WORKDIR>/health/before.txt -w '%{http_code}\n' '<HEALTH_URL>'` — expect the baseline code.
- **Apply:** start the loop with `<WATCH_INTERVAL_SECONDS>` comfortably larger than the service's own check interval so your probe cannot dominate its traffic.
- **Health check after:** `tail -n 20 <WORKDIR>/health/<SERVICE>.log` — expect an unchanged status column. Regression probe: re-run the saved request line from `<WORKDIR>/health/<SERVICE>.req` and confirm the body invariant still holds.
- **Rollback:** `pkill -f '<WORKDIR>/health'` then `pgrep -af curl` to prove no stray probes remain. The loop becomes unsafe if the organizer forbids self-chosen probe rates, or if its traffic competes with the real checker.

## Failure modes and things teams stopped doing

- Teams stopped bolting on generic filtering layers "to be safe". In a documented first-time A/D retrospective the team deployed a WAF before understanding the exploit, and it consumed all 8 GB of RAM on the target host — a self-inflicted outage that also removed the service's usefulness. Measure resource use before deploying any always-on component. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped leaving availability as an accident. The same retrospective describes spending significant effort simply keeping containers alive instead of analysing services. "Keep it up" is a task with an owner. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped trusting their own laptop as an availability signal: a capture on the wrong interface once produced false confidence, and a health probe that takes a different path from the checker has the same defect. [src-d0gl0v3r-umcs2026-c85f0c19]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No watch loop was started and no HTTP request was issued.
- **Our adaptation vs the source:** the availability-first ordering is ours, informed by organizer statements that the gameserver grades intended service behaviour plus the retrospective above. `<WATCH_INTERVAL_SECONDS>` is deliberately left to the team until the checker interval is known.

## Sources

- `src-faust-ad-beginners-779c0a5e` — organizer explanation of what the gameserver exercises and the cost of breaking legitimate behaviour.
- `src-ructfe-rules-95d7c601` — an event whose scoring is explicitly availability-sensitive.
- `src-faust-rules-2024-7fc6a296` — availability as a scored component alongside offense and defense.
- `src-enowars-checker-tenets-bf4b0ac7` — service/checker expectations that define what "available" means.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time team retrospective: WAF memory exhaustion, container babysitting, wrong-interface monitoring.
