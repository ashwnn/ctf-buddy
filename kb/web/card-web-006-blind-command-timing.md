# Confirm blind command execution with one bounded differential, then stop probing

**First useful action.** Once the shell sink is identified but the response carries no output,
prove execution with a single low-impact timing differential against your own instance.

```bash
# baseline latency for the same request, 5 samples
for i in 1 2 3 4 5; do curl -sS -o /dev/null -w '%{time_total}\n' \
  'http://127.0.0.1:<PORT>/<ROUTE>?<PARAM>=<BENIGN_VALUE>'; done
# one injection attempt that adds a short, bounded delay
curl -sS -o /dev/null -w '%{time_total}\n' \
  'http://127.0.0.1:<PORT>/<ROUTE>?<PARAM>=<BENIGN_VALUE>;<SHORT_SLEEP_COMMAND>'
```

Expected: the injected sample sits outside the baseline spread by a margin that repeats. If the
two distributions overlap, you have not proven anything — use a deterministic local artifact
(file created in a temp path you control on the team's own fixture) instead of a longer delay.

## Symptoms

- Source shows a command sink, but the HTTP response contains neither stdout nor stderr.
- Error handling swallows the utility's output and status.
- The utility's success is not externally visible (fire-and-forget job, async worker).

## Prerequisites and assumptions

- A proven or strongly-indicated command sink (`card-web-005-command-injection-trace`).
- A baseline latency distribution, not a single sample.
- Rules that permit even this bounded side effect against your own/team-owned instance only.
- Stack/version: stack-agnostic; timing resolution depends on the deployment.

## Diagnostic sequence

1. Take 5-10 baseline samples of the legitimate request. → You get a spread and a median.
2. Insert one bounded delay and repeat. → A clear, repeatable separation confirms execution.
3. Repeat the delay once more to rule out a cold cache. → Consistent separation = confirmed.
4. Immediately stop payload iteration. The primitive is proven; further probing only consumes the
   window and risks the checker's availability budget.
5. Decide: exploit it (offence) or patch it (defence). Both need the same sink location.

If step 2 shows no separation but the source is unambiguous, that is still a finding — report it
as "source-confirmed, execution-unconfirmed" and patch the sink anyway. Do not escalate delay
magnitudes to force a signal.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| 5 baseline samples | e.g. a tight band around a median | Your noise floor; any confirmation must exceed it. |
| 1 injected sample | value outside the band, reproduced once more | Command execution with a measurable side effect. |
| injected sample inside the band | — | Unproven; use a local filesystem artifact or stop. |
| Both requests timing out | the service is now unavailable | You have damaged availability. Stop and restore before anything else. |

## Exploit → patch pair

- **Flaw:** the same shell-composition defect as the non-blind case; the response simply does not
  carry the evidence.
- **Reproduce on the isolated fixture:** against an owned local fixture with the sink instrumented,
  send one bounded delay and compare to five baseline samples (not yet run here).
- **Narrow patch:** fix the composition at the sink (fixed executable plus argument vector, or a
  strict semantic allowlist). Do not add a timeout as the only change — a timeout bounds damage, it
  does not remove execution.
- **Legitimate functionality that must keep working:** the utility's normal operation, including
  its expected latency; a patch that adds a multi-second timeout can itself fail the checker.
- **Verify:** the injected request returns to the baseline latency **and** the legitimate request
  produces its normal result.

## Failure modes and things teams stopped doing

- Long sleeps. They damage the service you may also need to keep available and are indistinguishable
  from a hung request to a teammate watching the scoreboard.
- Treating a timing result as proof when the baseline was one sample. The PortSwigger material on
  blind command injection exists because the signal must be separated from normal latency
  (`src-portswigger-command-injection-7c72bc4a`).
- Confirming twice and continuing to probe afterwards. Once proven, additional payloads add no
  information and add risk.
- Judging a patch by "the delay is gone". Patches must be judged by the exploit failing *and* the
  legitimate flow passing (`src-enowars-checker-tenets-bf4b0ac7`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No timing samples were collected in this session.
- **Our adaptation vs the source:** `src-portswigger-command-injection-7c72bc4a` describes blind command
  injection and out-of-band confirmation. We replaced the generic out-of-band advice with a
  deliberately bounded local differential plus an explicit stop rule, because our event context is a
  scored service where the sleep itself is a self-inflicted availability risk.

## Sources

- `src-portswigger-command-injection-7c72bc4a` — blind command execution and confirmation techniques.
- `src-enowars-checker-tenets-bf4b0ac7` — the principle that a change must be judged against service/checker
  functionality, not only against the exploit.
