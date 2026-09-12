# Suspect environment parity before rewriting a failing exploit

**First useful action.** Compare the container environment with the documented full system — processes,
privileged daemons, devices, and listeners — before touching the exploit.

```bash
ps -eo pid,cmd --sort=pid | head -n 40; ss -ltnp
```

Expected: the process list and the listening sockets of the environment you are running in. If a helper
daemon the challenge depends on is absent, or if something unrelated holds a port you need, you have
found an environment problem, not a vulnerability problem.

## Symptoms

- An official/demo exploit from the challenge documentation fails in your local container while the
  service itself appears to be present and healthy.
- The challenge README mentions host services, privileged operations, or VM-only components.
- A port bind fails with "address already in use" during a build or start step.

## Prerequisites and assumptions

- Access to both environments (or to documentation describing the full environment).
- Acceptance that this is a legitimate first hypothesis: the repository index records a real case where a
  demo exploit required the full VM because a helper daemon does not start inside Docker, and another
  where an unrelated host daemon occupied a port the service wanted.
- Rule awareness: you do not disable host services on infrastructure you do not own, and you do not
  change organizer systems to make a local test pass.

## Diagnostic sequence

1. List processes and listeners in the failing environment; compare against the documented environment.
2. Ask the discriminating question: is the *capability* the exploit needs present (a daemon, a device, a
   kernel feature, a mount, a privileged helper)? Capabilities, not file lists, decide exploit viability.
3. If a capability is missing → reproduce in the environment where it exists (the full VM/image the
   organizer provides), and record the mismatch as a known limitation of local testing.
4. If a capability is present but the port is taken by something else → identify the owner
   (`card-misc-host-port-conflict-triage`) before changing any service configuration.
5. Only if parity is confirmed and the capability exists should you revisit the exploit itself.

If parity cannot be achieved locally → keep the exploit written but mark it as unverified locally, and
give the live environment first priority for validating it. If parity explains the failure → document it
so the next teammate does not repeat the investigation, which is exactly the negative-knowledge rule this
repository follows.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ps -eo pid,cmd` | expected daemon absent | Missing capability: local test cannot succeed as written |
| `ss -ltnp` | unexpected listener on a needed port | Port conflict; identify the owner before editing service config |
| container inspect / mounts | missing device or mount | Sandbox difference, not an application defect |
| running the same exploit in the full VM | success | Parity was the issue; record the environment requirement |

## Failure modes and things teams stopped doing

- Rewriting a working exploit because the container lacked a daemon. The corpus records this trap
  directly: the demo exploit needed the full environment because a helper component does not start in
  Docker. The exploit was fine; the environment was not.
- Disabling unrelated host services to free a port. On shared or competition infrastructure that is an
  unauthorized state change; check the port's owner and change your own service's configuration instead.
- Treating "it works in the VM" as proof of everything. Parity cuts both ways: VM behavior may not match
  the graded service either, so validate where the checker runs.
- Leaving the mismatch undocumented. An unrecorded environment difference gets re-diagnosed by the next
  person, which is the single most expensive kind of repeated work in a timed event.

## Evidence status

- **Status:** source-supported but untested; this is negative knowledge captured from a challenge
  repository rather than a reproduction.
- **What we actually ran:** nothing. No container or VM was started in this session; the mismatch is
  reported by the saarCTF challenge repository as recorded in the repository index, and the diagnostic
  commands listed are standard inspection commands that were not executed here.
- **Our adaptation vs the source:** the source records the specific failure; the parity checklist and the
  capability-first framing are our generalization, and the port-owner branch links to a separate card.

## Sources

- `src-saarctf-2024-readme-6dacbfcc` — organizer-repository evidence that one demo exploit requires the full
  VM because a component does not start in Docker, plus a host-port-conflict example.
- `src-iproute2-ss-manpage-fc58f455` — socket inspection semantics used to identify listeners and owners.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time-team evidence that observing/validating in the wrong
  environment produces false confidence.
