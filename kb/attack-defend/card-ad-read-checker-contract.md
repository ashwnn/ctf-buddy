# Read the checker and extract its contract before broad patching

**First useful action.** Locate the checker or demo checker, list the flag-lifecycle functions in source order, and turn them into a short written contract of what must keep working.

```bash
grep -rnE 'putflag|getflag|havoc|check_|store|retrieve' <CHECKER_DIR> | head -n 40
```

Expected: a handful of function names with file and line numbers. Read those functions top to bottom and write down, for each: the endpoint or protocol message it uses, the state transition it expects, how long that state must persist, and any timeout it enforces. If the grep returns nothing, `<CHECKER_DIR>` is probably the wrong path — find the checker before you touch the service.

## Symptoms

- A vulnerability is reproduced but nobody knows which behaviour must remain intact.
- Someone proposes "disable that endpoint" or "block that parameter" as the patch.
- The service answers your probe correctly but the game still grades it faulty.

## Prerequisites and assumptions

- Checker source, a demo checker, or an organizer statement that checkers are hidden.
- Ability to run the checker against your own instance only.
- Assumption: checker semantics are framework-specific. MUST/SHOULD language in an infrastructure specification is a design requirement for *that* framework, not a rule for every event.

## Diagnostic sequence

1. List the checker's functions and read the flag-placement and flag-retrieval paths first → these define the minimum legitimate functionality your patch must preserve.
2. Read any "noise"/"havoc"/adversarial path → it tells you which inputs the grader will itself throw at your service; a patch that blocks those inputs can fail the check even though it hardened the service.
3. Record timeouts and retry expectations → branch A: the checker tolerates a restart inside the window, so deploy-restart is cheap; branch B: it does not, so a restart inside a check window costs you.
4. If the checker is hidden, infer the contract from baseline request/response traffic and mark it `inferred` rather than `known`.

If the checker exercises a feature you were about to remove, go to `card-ad-narrow-trust-boundary-patch` and find a narrower fix. If the contract is entirely inferred, go to `card-ad-unknown-rule-dry-run` and keep behaviour-changing edits local until it is confirmed.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -rnE 'putflag\|getflag\|havoc' <CHECKER_DIR>` | function names and locations | the order in which to read the checker; putflag/getflag define the flag lifecycle |
| `<CHECKER_RUNNER> <SELF_SERVICE_ADDRESS>` | per-check PASS/FAIL plus messages | the closest thing to ground truth you have; run it before and after every change |
| `grep -nE 'timeout\|sleep\|retry\|backoff' <CHECKER_DIR>/*.py` | numeric bounds | how much downtime a check window tolerates |

## State-changing actions

- **Impact:** running a checker against your own instance writes flag material and then reads it back, and may leave rows/files behind; it can also collide with a concurrently running organizer check.
- **Preconditions:** you are pointing at your own instance, not a peer's; you accept that leftover state will exist.
- **Health check before:** the saved legitimate smoke test from `card-ad-availability-first-sla-protection` — expect its baseline response.
- **Apply:** `PYTHONPATH=<CHECKER_DIR> python3 <CHECKER_RUNNER> <SELF_SERVICE_ADDRESS>` (adapt the invocation to the provided runner; the shape is framework-specific).
- **Health check after:** re-run the legitimate smoke test and then the checker — expect both to pass, and note whether any new state remains.
- **Rollback:** if the local checker run corrupted state you care about, restore the service state path from your baseline snapshot, never by re-running the checker; it is now unsafe to keep running checkers against an instance whose state you cannot restore.

## Failure modes and things teams stopped doing

- Teams stopped patching before understanding what the grader does. A first-time team retrospective records that they built a defensive control before understanding the exploit or the payload, and the control then damaged the host. Reading the checker first is the cheap version of "understand before you change". [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped assuming the intended vulnerability is the only one. An organizer who authored a service has described how a service can contain behaviour they did not intend; the checker contract tells you what must survive, not what is exploitable. [src-stoffregen-enowars9-acef75f7]
- Teams stopped treating a hidden checker as an excuse to guess. If the checker is not provided, derive the contract from observed traffic and label it as inferred so nobody later quotes a guess as a requirement. [src-saarctf-2024-readme-6dacbfcc]

## Exploit → patch pair

- **Flaw:** a patch that removes a feature the checker exercises (for example deleting a retrieval endpoint) "fixes" the vulnerability by breaking the graded behaviour.
- **Reproduce on the isolated fixture:** run the checker against your own local copy at `http://127.0.0.1:<PORT>` after applying a deliberately over-broad change to `<LOCAL_FIXTURE>` → expect the checker to report a functional failure, proving the contract is real.
- **Narrow patch:** revert the over-broad change and restrict it to the single condition that crosses the trust boundary, keeping the checker-visible endpoint.
- **Legitimate functionality that must keep working:** the exact store/retrieve path the checker uses, including retrieval of state written earlier in the game.
- **Verify:** `<CHECKER_RUNNER> http://127.0.0.1:<PORT>` → the deliberately exploitable test request now fails while the checker passes.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No checker was located or executed; `<CHECKER_DIR>` and `<CHECKER_RUNNER>` are placeholders because the artifact is event-provided.
- **Our adaptation vs the source:** saarCTF's repository demonstrates the "demo checker run against a local service instance" pattern; ENOWARS' specification supplies the MUST/SHOULD framing. The contract worksheet itself is ours.

## Sources

- `src-enowars-checker-tenets-bf4b0ac7` — service/checker requirements and patchability expectations.
- `src-faust-gameserver-readme-4e7460fe` — checker, flag, and tick semantics from a real gameserver.
- `src-saarctf-2024-readme-6dacbfcc` — demo checker/exploit workflow against a service instance.
- `src-stoffregen-enowars9-acef75f7` — service-author view of intended versus unintended vulnerability.
- `src-d0gl0v3r-umcs2026-c85f0c19` — patching before understanding, and its cost.
