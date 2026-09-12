# Split a physical or hardware puzzle into device, transport, and service layers

**First useful action.** Draw three columns — physical/device state, network transport, application
service — and prove one layer at a time instead of debugging "the box".

```bash
ip -brief link; ip -brief addr; ss -ltnup
```

Expected: interface names and states, assigned addresses, and the local listening sockets. If an
interface you expect is missing or down, the problem is at the device/link layer and no amount of
application debugging will help.

## Symptoms

- The puzzle involves a physical device, a router, a cable, a sticker, or something you must plug in or
  configure, plus a software component.
- "It does not work" is the only symptom anyone can articulate.
- Two teammates are testing at the same time and neither knows what the other changed.

## Prerequisites and assumptions

- Authorized access to the hardware and the network segment. Repository rule 1 applies: only
  team-assigned or event-authorized targets, and the event name alone is not a scope.
- Documentation for the device (port list, default address, reset procedure) or a way to observe its
  state.
- A note taker. Physical puzzles have state that is invisible to teammates who are not in the room.

## Diagnostic sequence

1. Device layer: power, link status, indicator behavior, cabling, and any device-side configuration.
   Record the device's own state before touching the network.
2. Transport layer: does the address exist, is the route correct, is the port reachable from exactly the
   point the challenge intends? Test reachability with the simplest possible client first.
3. Service layer: only once transport is proven, talk the application protocol
   (`card-misc-unusual-protocol-no-dissector` if it is not a known one).
4. Reset behavior: physically reset the device when a test fails, so each test starts from a described
   state. Record the reset procedure alongside the result.
5. Write down which layer each failure belonged to. That single artifact prevents a second person from
   re-testing layers already excluded.

If the device layer fails → stop and fix or record that; nothing downstream is meaningful.
If the service layer fails but transport is confirmed → treat it as a normal application problem and use
the relevant protocol card. If failures are intermittent → suspect a race or a shared-state ordering
issue across layers and record the sequence and timing, not just the outcome.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ip -brief link` | `eth0  UP` | Link-layer state; DOWN/NO-CARRIER is a device-layer problem |
| `ip -brief addr` | address present/absent | Transport layer has an address to work with |
| `ss -ltnup` | listeners | A service is (or is not) actually running on this box |
| `nc -vz <HOST> <PORT>` | `succeeded`/`refused` | Reachability boundary between transport and service |
| device reset + repeat | same/different result | Reproducibility: distinguishes state from intermittent failure |

## Failure modes and things teams stopped doing

- Debugging the application while the link is down, or vice versa. The corpus records the layer-splitting
  lesson from a physical/router attack/defense challenge where the environment was unusual and
  event-specific; the transferable part is scoping the layers, not the specific hardware.
- Destructive firmware or configuration changes without a documented restore path. If you cannot undo
  it, do not do it during the event; a physical device may also be needed by the checker.
- Two analysts mutating device state concurrently. Serialize access to the hardware and log who changed
  what — the ownership discipline from the attack/defend operations research applies double here.
- Assuming the device is the challenge's weak point. It may be host-side configuration, a race, or a
  credential, and the device is merely where you notice the symptom.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing. No network or hardware was touched in this session; the layer-split
  method is a rewrite of repository draft MISC-001 and the `ss`/`ip` command shapes are standard
  (the `ss` family was recorded as fixture-verified in the repository's 2026-09-11 build pass).
- **Our adaptation vs the source:** we added the reset-and-record step, the serialization rule, and the
  "intermittent means race, record timing" branch, none of which the source index records.

## Sources

- `src-molteniluca-homerooter-ff20860b` — first-hand writeup of a physical/router-and-service attack/defense
  challenge; the origin of the scope-splitting lesson.
- `src-iproute2-ss-manpage-fc58f455` — the socket-inspection command semantics used to establish the service
  layer.
