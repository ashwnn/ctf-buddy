# Find the real owner of a port before blaming the service

**First useful action.** Ask the kernel who holds the port, instead of editing the service's
configuration to work around a bind failure.

```bash
ss -ltnp | grep -F ':<PORT>' || ss -lunp | grep -F ':<PORT>'
```

Expected: the listening socket with its owning process and PID where permissions allow. If the grep
returns nothing, the port is free (or the process list is not visible to you) — re-run with adequate
privileges before changing anything.

## Symptoms

- A challenge service or a local fixture fails to start with an address-in-use style error.
- The service starts but responds in a way that does not match its documented behavior.
- Two components in the same environment both want the same well-known port.

## Prerequisites and assumptions

- Linux with iproute2. Process-to-socket mapping needs appropriate privileges and visibility; the
  corpus notes that exact columns and the availability of process information vary by version and by
  what the kernel exposes to your user.
- A policy limit: on shared or organizer-owned infrastructure you do not stop unrelated daemons. You
  change your own service's configuration, or you move to the environment where nothing conflicts.

## Diagnostic sequence

1. Identify the owner of the port with `ss -ltnp` (TCP) or `ss -lunp` (UDP), including the PID and
   program name if visible.
2. Decide whether the owner is part of your service stack, part of the environment you do not control,
   or a leftover process from a previous run of your own work.
3. If it is your own leftover process (a crashed or orphaned service) → stop it cleanly and record the
   action. This is the common and benign case.
4. If it is an environment component you do not control → do not stop it. Either reconfigure your own
   service to a different endpoint for local testing, or reproduce in the environment the organizer
   provides. The repository index records a real example of a host component occupying the port a
   challenge component wanted.
5. Record the outcome with the command output, so the next person does not re-diagnose the same conflict.

If the port is free but the service still fails to bind → the error is not a conflict; look at
permissions, address family (IPv4/IPv6), or a configuration path.
If the owner is another instance of your own service → check whether a supervisor is restarting it
before killing anything, or you will race the supervisor forever.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ss -ltnp` | `LISTEN ... users:(("<proc>",pid=<PID>,...))` | Owner identified: decide whose process it is |
| `ss -ltnp` | no process info shown | Insufficient privileges or visibility: escalate or use another method |
| `ss -lunp` | UDP listener | The conflict is UDP, not TCP; a TCP-only check would have missed it |
| repeated owner change after each kill | restart by a supervisor | Stop killing; change the configuration instead |

## Failure modes and things teams stopped doing

- Disabling unrelated host services to free a port. The saarCTF case recorded in this corpus shows the
  conflict is real, but the correct response is to understand the owner, not to break someone else's
  component — and on competition infrastructure it may be an unauthorized change.
- Assuming "the service is broken" from a bind error. Address-in-use is an environment fact; the
  service code is usually innocent.
- Killing a supervisor-managed process in a loop. You will lose to the supervisor and add noise to the
  logs that someone else needs to read.
- Not recording the conflict. An undocumented port conflict is rediscovered by every teammate in turn.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing. No port conflict was produced or observed in this session; the
  `ss` syntax family was recorded as fixture-verified in the repository's 2026-09-11 build pass, but
  process mapping was not fully reproduced there either.
- **Our adaptation vs the source:** the source records the conflict example; the owner-classification
  branch, the supervisor-restart warning, and the explicit "do not disable environment components" rule
  are our additions.

## Sources

- `src-saarctf-2024-readme-6dacbfcc` — organizer-repository evidence of a host component conflicting with a
  challenge component's port.
- `src-iproute2-ss-manpage-fc58f455` — the documented socket-inspection tool, including the caveat that
  process display depends on permissions and that output columns vary by version.
