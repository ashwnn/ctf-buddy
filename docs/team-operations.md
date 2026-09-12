# Team operations: the first 30 minutes and the handoff rules

Written for an unspecified small team where one person may hold several roles.
Fill the blanks at kickoff; do not guess them.

## Roles (stack them when you are few)

| Role | Owns | First action |
|---|---|---|
| **Lead / timekeeper** | Clock, ticks, scoreboard, decisions | Start a timer; write the tick length on the board the moment it is known |
| **Service owner(s)** | One service each: patch, verify, keep legitimate flows working | Claim the service in the ownership sheet before touching it |
| **Recon** | Challenge triage in the first 15 minutes; flag board | Triage by category, not by curiosity |
| **Attack** | Opponent-side work, flag submission, exploit harnesses | Set up one reusable submission command with a mock endpoint first |
| **Observation** | Logs, captures, alert triage | Start bounded capture/log tail only after the checker pattern is understood |
| **Scribe** | Timeline, decisions, what broke and how it was restored | Keep a running line per change: time, service, who, what, verified |

Rule: one writer per service at a time. If you need another pair of eyes, the
service owner drives and the helper talks.

## First 5 / 15 / 30 minutes

**0-5 minutes: stabilize and see.**

1. Confirm connectivity and access. Do not change anything yet.
2. `ctfctl targets declare <host> --label '<service>'` for each team-owned host.
3. Run `ctfctl remote probe <host> --save` for every host. Read-only.
4. Write down: services, ports, stack guesses, who owns what.
5. Confirm the rules that change behavior: ticks, scoring, patch permission,
   network restrictions, decoy permission. Unknown rule means no mutation.

**5-15 minutes: understand the checker and the services.**

1. Observe legitimate traffic first (`ctfctl remote run <host> watch --seconds 60`).
2. Identify the checker contract for one service: which paths, which state
   transitions, does it write data.
3. Reproduce the legitimate workflow by hand. This becomes the health check you
   must not break.
4. Start one challenge per person from the scoreboard, highest confidence first.
5. Put the observation host on its own laptop, not the laptop with the exploit
   tooling, if devices allow.

**15-30 minutes: first patch, first flag, first handoff.**

1. Pick the service with the clearest observed vulnerability and the narrowest
   fix. Prefer a fix you can verify in under five minutes.
2. `ctfctl remote plan <host> --verbose`; read the diff; then `apply --plan ...
   --yes`. Verify immediately, including the legitimate workflow.
3. Record the plan id, transaction id and rollback command in the timeline.
4. Submit one flag through the mock/tested submission path before trusting it.
5. Write the first handoff line (template below) even if nothing broke.

If the environment resets: check the timeline for the last plan id and re-apply
the exact plan. Do not improvise a new fix under time pressure.

## Service ownership sheet (fill at kickoff)

| Service | Host:port | Owner | Backup owner | Legitimate workflow check | Last plan id | Last tx | Notes |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
| | | | | | | | |
| | | | | | | | |

Rules:

* The owner is the only person who edits the service source or config.
* The backup owner may observe and verify, not edit.
* Every applied change gets a timeline line and the tx id in this sheet.
* If the owner is stuck for more than 10 minutes, hand off explicitly: state,
  last action, rollback command, next step.

## Patch handoff template

Copy this into the team channel or notebook for every change:

```
time:        <UTC>
service:     <name>            host: <ip:port>
owner:       <who>
problem:     <one line, with evidence>
plan id:     <plan-id>         tx: <tx-id>
diff:        <one line summary; full diff is in the plan>
legitimate:  <the workflow you re-ran after the patch>
exploit:     <the probe that must now fail>
result:      <OK / REGRESSED / ROLLED BACK>
rollback:    ctfctl remote rollback <host> --tx <tx-id> --yes
next:        <exact next action or "watch for regressions">
```

## Emergency restore card

When a change breaks a service or the checker fails after an edit:

1. Stop editing. State out loud what you changed last.
2. `ctfctl remote rollback <host> --list` to find the tx id.
3. `ctfctl remote rollback <host> --tx <tx-id> --yes`.
   If it refuses because the file changed after the transaction, do **not**
   force it: that means a teammate edited the same file. Read `recover` output,
   decide with the owner, and restore deliberately.
4. `ctfctl remote verify <host> --plan <plan-id>` and re-run the legitimate
   workflow by hand.
5. Record the incident in the timeline: time, service, cause, fix, verification.
6. Only after it is green, re-take the point or re-attempt the attack.

Recovery assets, in order of preference:

* the engine's own `backups/` copy and transaction journal on the target
  (`~/.ctfctl/state/tx/<tx-id>/`);
* the plan's exact pre-state (`pre/` files in the same directory);
* Git, if the service source is under version control;
* the original service files from the environment image.

A file copy is not a consistent live-database backup. If a database is involved,
restore code/config first, then let the application recover its own data.

## Offline and one-device reality

* Assume one connected device per member and no shared server. Each member keeps
  a complete checkout of this repository and a built search index locally.
* Prefer `ctfctl remote probe` output saved into `state/` and shared as a file
  over whatever channel the rules allow, over relying on live shared access.
* Keep the knowledge base index built before the event (`ctfctl kb index`), so
  search works with no network and no teammate availability.
* Do not assume a shared jump box is allowed. If a shared server exists, it is a
  target like any other and needs a declaration; if it does not, everything here
  still works from individual laptops.
* Designate one person per service to avoid simultaneous edits; the single
  writer is enforced by ctfctl on the target, but humans should not rely on the
  tool to referee a disagreement.
