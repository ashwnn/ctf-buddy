# Decide which exposure you may actually narrow, and prove it is not the scored path

**First useful action.** Before touching bind addresses, ports, or proxy rules, write down which listener
the checker and legitimate clients use — and treat every other listener as *review-only* until proven
private.

```bash
ss -ltnp
docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Ports}}\t{{.Status}}' 2>/dev/null
nginx -T 2>/dev/null | grep -nE 'listen|proxy_pass' | head -n 30
```

Expected: a list of listeners with their owners, and for each one a judgement: "front/legitimate",
"backend reached through the proxy only", or "unknown". If an upstream listener is bound to all interfaces
and the proxy is the only documented entry point, it *looks* narrowable — but the checker may contact it
directly, and that is unproven, so the change stays review-only.

## Symptoms

- A backend service listens on all interfaces while a reverse proxy is supposed to be the only entry point.
- A database or admin port is published on the host.
- The team wants to "reduce attack surface" mid-event.

## Prerequisites and assumptions

- Local access to the team's own VM/container and read access to its configuration.
- A recorded legitimate request through the front port, and the checker's own flow if it is known.
- Event permission to modify the service. Absent that permission, this card is a *review* card.
- Stack/version: container networking changes the answer; published ports vs host network mode behave
  differently (`src-docker-host-network-o9-6732393f`), and Docker-managed firewall rules interact with host
  firewall expectations (`src-docker-firewalls-o6-351180c6`).

## Diagnostic sequence

1. Enumerate listeners and map each to a process/container (`card-web-010-route-to-source-owner`).
2. Classify each listener: external entry point, internal backend, management, unknown. → Only "internal
   backend proven to be reached only via the proxy" is a candidate.
3. Look for evidence that it is *not* private: organizer documentation naming the port, the checker using
   it, a second service connecting from outside the host, or a published port in the container definition.
4. If any such evidence exists, stop. Record "review-only: port may be scored".
5. If changing it is permitted and safe, make one change (bind address or a single proxy directive), and
   verify through the *front* path the checker uses.

If the change causes the checker to fail, restore immediately and treat the front path as authoritative
(`card-web-009-exploit-availability-regression-pair`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ss -ltnp` | `0.0.0.0:<APP_PORT>` owned by the app | Directly reachable from the network; not automatically wrong. |
| `ss -ltnp` | `127.0.0.1:<APP_PORT>` | Already loopback-only; nothing to narrow. |
| `docker ps --format '{{.Ports}}'` | `0.0.0.0:<PORT>-><CPORT>` | Published container port; reachable regardless of host firewall expectations (`src-docker-firewalls-o6-351180c6`). |
| `docker inspect ... NetworkMode` | `host` | The container shares the host namespace; published-port logic does not apply (`src-docker-host-network-o9-6732393f`). |
| organizer documentation naming the port | explicit | Proof that it is intended; do not narrow it. |

## State-changing actions

- **Impact:** changing a bind address or proxy rule alters who can reach the application. A wrong change can
  fail the checker for the rest of the event.
- **Preconditions:** listener classification complete, no evidence the port is scored, the front path's
  legitimate request recorded, and one-command rollback prepared.
- **Health check before:** the front-path request returns its documented healthy response; the checker is
  green.
- **Apply:** one change only — either the backend bind address or a single proxy directive.
- **Health check after:** the front-path request returns the same status and body; regression probe: the
  checker's full flow, including any write and later retrieve.
- **Rollback:** restore the single changed unit/config file from its committed revision, reload only that
  service, re-verify the front path. If a container was recreated, keep its named volumes — never remove
  data volumes to "reset" the service.

## Exploit → patch pair

- **Flaw:** the card is defensive. The "flaw" is an exposure that is broader than the product's entry
  contract; the "pair" is proof that narrowing it does not break the legitimate workflow.
- **Reproduce on the isolated fixture:** `fixtures/d3-notehub-patch` (planned in
  `research/06-drills-and-validation.md`) with the application behind a proxy, checking that the legitimate
  front-path flow still works after a bind-address change (not yet run here).
- **Narrow patch:** bind the backend to the loopback/private address, or remove the published port, only
  when the checker contract is known not to require it.
- **Legitimate functionality that must keep working:** every front-path request, and any direct connection
  the checker itself makes.
- **Verify:** the front-path request and the checker are unchanged; the direct external connection is no
  longer accepted.

## Failure modes and things teams stopped doing

- Narrowing "obviously internal" ports without evidence. The discovery research classifies exactly this
  change as review-only and notes that the visibility of a scored endpoint is an organizer question, not a
  guess (`research/03-discovery-and-defense.md`).
- Enabling a firewall or a default-deny policy mid-event. The scope of the change is far larger than the
  exposure it fixes, and rollback is easy to get wrong.
- Filling the host with a defensive layer. The first-time UMCS 2026 retrospective records a WAF deployed
  before the exploit was understood that consumed the host's RAM — a defensive idea that became the
  outage (`src-d0gl0v3r-umcs2026-c85f0c19`).
- Assuming availability does not matter. Availability is scored in mature A/D formats, and organizer
  guidance treats breaking legitimate behaviour as harmful to the score
  (`src-enowars-checker-tenets-bf4b0ac7`, `src-faust-attackdefense-beginners-e53569f0`).
- Importing another event's rules about filtering, port blocking, or target scope. The `rules.yaml` schema
  in `research/01-event-and-team-operations.md` keeps those fields `UNKNOWN` deliberately.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No listener inventory was taken and no bind change was made in this
  session. `research/03-discovery-and-defense.md` states that none of its host/service mutations was
  executed on a disposable VM, so all of them are review-only.
- **Our adaptation vs the source:** the review-only classification and the "prove the front path" rule come
  from `research/03-discovery-and-defense.md`; the Docker networking caveats from
  `src-docker-firewalls-o6-351180c6` and `src-docker-host-network-o9-6732393f`; the availability contract from
  `src-enowars-checker-tenets-bf4b0ac7` and `src-faust-attackdefense-beginners-e53569f0`; the WAF failure story from
  `src-d0gl0v3r-umcs2026-c85f0c19`. The specific ports in the table are placeholders, not observations.

## Sources

- `src-enowars-checker-tenets-bf4b0ac7` — service/checker design: functionality and availability are part of the
  contract.
- `src-faust-attackdefense-beginners-e53569f0` — organizer guidance that breaking legitimate behaviour harms the
  service score.
- `src-docker-firewalls-o6-351180c6` — Docker-managed firewall/NAT behaviour and the UFW caveat for published ports.
- `src-docker-host-network-o9-6732393f` — host network mode semantics where publishing is irrelevant.
- `src-nginx-proxy-module-f3430c5a` — proxy-to-upstream relationships used to decide what "internal" means.
- `src-nginx-switches-o19-a2887699` — reading the effective configuration before changing it.
- `src-saarctf-2024-readme-6dacbfcc` — real A/D packaging where an environment/port detail decided whether an
  exploit path worked at all.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time A/D failure modes, including a defensive layer that became an
  outage.
