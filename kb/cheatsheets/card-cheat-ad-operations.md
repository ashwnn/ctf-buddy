# Attack/defence operations: the tick loop cheat sheet

**First useful action.** Write the tick loop on the wall before the first tick: *availability →
checker baseline → own traffic review → enemy traffic review → patch → attack → log*. Teams that
improvise lose the first three ticks to context switching.

```bash
# once, before the event: prove the happy path and save it
BASE='http://<TEAM_VM_IP>:<PORT>'
curl -sS -o /tmp/base.json -w 'baseline %{http_code} %{size_download}b\n' "$BASE/<KNOWN_ROUTE>"
# every tick: the same command must still print the same thing
```

Expected: the same status and a body of the same shape. A different size or a 5xx is your first task
of the tick, before any attack work.

## Symptoms

- The tick has started and everyone is doing something different.
- The checker reports the service down but the port answers locally.
- You have three candidate tasks and no owner for any of them.

## Prerequisites and assumptions

- One person who owns the board (what is being worked on, by whom) — even in a small team
  (`card-ad-small-team-role-stacking`, `card-ad-service-ownership-and-board`).
- An observation channel that is not your attack tooling: `ctfctl watch` for logs, `tshark` for
  captures, both bounded.
- Known rules: patch policy, flag lifetime, whether decoys/honeypots are allowed
  (see `docs/event-facts.md`).

## Diagnostic sequence

1. **Availability first.** Run the saved happy path for every owned service. Anything failing goes
   to the top of the queue (`card-ad-availability-first-sla-protection`).
2. **Checker vs attack traffic.** Filter your own traffic out of the capture, then look at what
   remains (`card-ad-diff-attack-vs-checker-traffic`, `card-ad-capture-inbound-traffic`).
3. **Flags.** Confirm where the flag lives and how long it is valid
   (`card-ad-flag-lifetime-and-attack-info`); hunt the read path others forget
   (`card-web-025-flag-read-path-priority`).
4. **Patch queue.** One owner per service; a patch without a two-check gate is not landed
   (`card-cheat-web-defense-patch`).
5. **Handover.** End of your shift, write: what changed, what is verified, what is suspected, what is
   next (`card-ad-handoff-under-pressure`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ctfctl watch --logs <PATH> --seconds 60` | bounded summary | what hit the service in the last minute |
| `ctfctl remote plan <TEAM_VM_IP> --verbose` | plan + diff | what the toolkit would change, and why |
| `ctfctl remote apply <TEAM_VM_IP> --plan <ID> --yes` | `COMMITTED` + verifier results | landed, with an automatic rollback on regression |
| `ctfctl remote rollback <TEAM_VM_IP> --list` | transaction list | you can always get back; know the id before you need it |
| `tshark -r tick.pcap -Y 'ip.src != <YOUR_IP>' -q -z conv,tcp` | the other teams and the checker | attack surface, not your own noise |
| `rg -n 'flag' /var/www /srv` | flag read paths | where the scorer reads from; protect that exact path |
| `docker compose ps` | per-service health | which owned service is actually up |

## State-changing actions (only if the card changes a host or service)

- **Impact:** every mutation on a scored host can cost points. Order: availability fix → narrow patch
  → review-only change (firewall/SSH) only with a console available.
- **Preconditions:** declared target, acknowledged event policy, reviewed diff, saved happy path.
- **Health check before:** the happy path, immediately before the change.
- **Apply:** one change at a time; never batch an unrelated hardening with a patch.
- **Health check after:** happy path again, plus the exploit probe must fail.
- **Rollback:** `ctfctl remote rollback <TEAM_VM_IP> --tx <TX> --yes`; the pre-image is stored before
  every replace.

## Failure modes and things teams stopped doing

- Two people editing the same service; ownership sheet exists for a reason
  (`card-ad-fail-edited-someone-elses-service`).
- Patching before understanding, then needing to roll back while the checker is failing
  (`card-ad-fail-patched-before-understanding`).
- Restoring "clean" state from a snapshot and destroying flags other teams had already planted
  (`card-ad-fail-restore-destroyed-live-state`).
- Sinking the whole tick into a WAF that exhausts memory and takes the service down
  (`card-ad-fail-waf-ram-exhaustion`).
- Standing on a port/interface that is not the one the checker uses
  (`card-ad-fail-wrong-interface-monitoring`).

## Evidence status

- **Status:** source-supported (rules and writeups from five events); the tick loop is our ordering.
- **What we actually ran:** the `ctfctl watch`/`plan`/`apply`/`rollback` commands in the Docker
  integration test and the real-SSH lab (see `docs/validation.md`).
- **Our adaptation vs the source:** the seven-stage loop and the "two-check gate" wording are ours;
  the sources describe the same priorities in prose.

## Sources

- `src-faust-ad-beginners-779c0a5e`, `src-faust-attackdefense-beginners-e53569f0` — what the game is
  and what loses it.
- `src-enowars-checker-tenets-bf4b0ac7` — checker behaviour and what it expects from a service.
- `src-enowars-general-docs-5c2a697e`, `src-saarctf-2024-readme-6dacbfcc` — tick model and rules.
- `src-ructfe-rules-95d7c601`, `src-faust-rules-2024-7fc6a296`, `src-saarctf-rules-a45fdf6b` — the
  written rules that bound what you may fire at whom.
- `src-maplebacon-ad-primer-23bd534f`, `src-d0gl0v3r-umcs2026-c85f0c19`,
  `src-czechcyberteam-faust2024-todolist-225eeec1` — first-person accounts of the loop.
