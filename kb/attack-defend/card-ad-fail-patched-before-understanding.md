# Failure story: patched before understanding, and paid for it twice

**First useful action.** Before any edit in response to an incident, write one sentence naming the exploited condition and the command that demonstrates it. If the sentence contains "probably" or "maybe", you are not ready to patch.

```bash
cat > <WORKDIR>/incident.md <<'EOF'
observed: <what changed - score, flag loss, alert, timestamp>
proven: <one request plus one observed effect>
hypothesised_root_cause: <one sentence>
demonstration: <exact command that shows the effect>
candidate_fix: <the single condition you would change>
EOF
grep -c 'proven:' <WORKDIR>/incident.md
```

Expected: a filled `proven` line backed by a command. If it is empty, the correct next action is investigation (see `card-ad-restore-patch-exploit-triage`), not a patch.

## Symptoms

- A score drop triggers an immediate, unrehearsed change to the service.
- The change is described as "hardening" rather than "fixing the condition at line N".
- No one can say whether the change addressed the attack or a symptom of it.

## Prerequisites and assumptions

- The service's health test and a captured or logged view of the suspicious traffic.
- A repository or snapshot so a change is reversible.
- Assumption: a defensive change that is not understood cannot be evaluated; it can only be hoped for.

## Diagnostic sequence

1. Write the incident block → branch A: `proven` names a request and an effect; branch B: only symptoms exist, so keep investigating and change nothing.
2. Establish whether the loss continues: compare the last two cycles of your own flag values and checker statuses → branch A: loss is ongoing, so an *understood* narrow fix is urgent; branch B: loss stopped, so you have time to understand before changing anything.
3. If you are under time pressure, choose the reversible intervention with the smallest blast radius: a narrow code fix, or a restart with the rollback command ready — never a new always-on component.
4. After any change, verify both halves: the attack effect stops *and* the legitimate flow still passes.

If you cannot complete step 4 in this tick, revert rather than leave an unverified change live; an unverified change during a live event is an unknown quantity for the rest of the game.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -c 'proven:' <WORKDIR>/incident.md` | 1 or 0 | whether you have evidence or a feeling |
| `git diff` before deploying | changed lines | if the change is bigger than the hypothesis, it is not a fix |
| health test + exploit test after | two results | the only acceptable evidence that the change was an improvement |
| `free -m`, `uptime` after the change | resource trend | whether the intervention cost more than it bought |

## State-changing actions

- **Impact:** any unrehearsed change to a graded service risks the availability component as well as the security one; combining several changes makes attribution impossible.
- **Preconditions:** a named exploited condition, a reversible single change, a rollback command already written.
- **Health check before:** legitimate smoke test passes and its response is saved.
- **Apply:** one change, one reason, one commit.
- **Health check after:** legitimate smoke test unchanged; the demonstrated effect no longer reproduces. Regression probe: the checker's store-then-retrieve cycle.
- **Rollback:** `git revert --no-edit <change>` plus redeploy. Rollback is unsafe if the change wrote state; restore state from the pre-change snapshot in that case.

## Failure modes and things teams stopped doing

- **The documented failure.** The same first-time UMCS 2026 retrospective that records the WAF memory exhaustion also states the team patched before understanding the exploit; the two are one story about acting before comprehension. The durable lesson is reproduce first, then change the smallest thing that removes the primitive. [src-d0gl0v3r-umcs2026-c85f0c19]
- **The practice that replaced it.** Working teams package a proven primitive before patching it, and when patching they keep the change behaviour-preserving so the checker keeps passing; a change nobody can evaluate is worse than the exposure it was meant to close. [src-ntt-enowars8-writeup-8b4ecb49]
- Teams stopped confusing "the attack stopped" with "the vulnerability is gone". A patch that blocks one payload leaves variants when the underlying construction is weak, so the follow-up check is traffic-based rather than assumption-based (`card-ad-find-patch-bypass-in-traffic`). [src-thomasweigold-saarctf2025-eaa12cba]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No incident block was filled and no patch was applied in this session.
- **Our adaptation vs the source:** the incident-block template is ours. The failure narrative and its consequences come from the cited first-time team retrospective; the "package then patch" contrast comes from the cited team write-up.

## Sources

- `src-d0gl0v3r-umcs2026-c85f0c19` — patched before understanding the exploit; WAF memory exhaustion.
- `src-ntt-enowars8-writeup-8b4ecb49` — proven exploit then precise defence as the working alternative.
- `src-thomasweigold-saarctf2025-eaa12cba` — weak construction whose fix replaces the mechanism, not a payload.
- `src-faust-ad-beginners-779c0a5e` — organizer framing that graded behaviour must keep working.
