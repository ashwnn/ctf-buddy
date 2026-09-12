# Prove your capture point sees the graded traffic before you trust it

**First useful action.** Generate one request you control, then confirm that exact request appears in the chosen capture or log source — before analysing anything.

```bash
( sudo tcpdump -n -i <IFACE> -s0 -w <WORKDIR>/captures/<SERVICE>-probe.pcap 'host <TEAM_VM_IP> and port <PORT>' ) &
TPID=$!; sleep 2; curl -sS -o /dev/null '<HEALTH_URL>'; sleep 2; sudo kill -INT $TPID; \
  tcpdump -nr <WORKDIR>/captures/<SERVICE>-probe.pcap 2>/dev/null | wc -l
```

Expected: a non-zero packet count containing your probe. Zero means the sensor is in the wrong place — host versus container interface, a filtered bridge, a reverse proxy that terminates earlier, or a different network namespace. Fix the sensor; do not conclude "attacks are invisible".

## Symptoms

- You believe you are monitoring the service but nothing suspicious ever appears, even when the score says you are being hit.
- Traffic to the service works from outside, so you assume it must traverse the interface you captured.
- The service runs in a container while the capture runs on the host's VPN interface.

## Prerequisites and assumptions

- Permission to capture on your own interfaces, plus a disk budget and a rotation policy.
- Basic tooling: `tcpdump` and/or `tshark`. Neither was available in the environment this card was written in, so every command here is documentation-derived.
- Assumption: captures may contain flags and credentials. They stay team-private and are deleted or rotated according to event policy.

## Diagnostic sequence

1. Send a known request and look for it in the capture → branch A: present, so continue to continuous capture; branch B: absent, so the sensor is mis-placed (go to step 2).
2. If absent, enumerate the actual path: published host ports, container network/bridge, proxy in front of the app, and the interface the request really arrives on (`ip -br addr`, `docker network ls`) → capture on the layer that carries the traffic, or capture inside the container.
3. If absent at every layer, check whether the request is encrypted before it reaches you and whether the terminating proxy logs it → pivot to reverse-proxy or application logs.
4. Once the probe is visible, start a bounded rotating capture and re-verify that the probe still appears in the newest file.

If the probe is visible and suspicious traffic still never appears, go to `card-ad-diff-attack-vs-checker-traffic` and check your filters for over-narrow expressions. If the probe is not visible at any layer you can reach, record the visibility gap on the service board rather than assuming detection works.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tcpdump -n -i <IFACE> -s0 -w <FILE> '<BPF_FILTER>'` | silent start plus a growing file | capture is running; the BPF filter may already be too narrow |
| `tcpdump -nr <FILE> \| head` | packet lines with timestamps | confirms your probe crossed this interface |
| `ip -br addr` / `docker network ls` | interfaces and bridge names | where a container's traffic actually appears |
| `ss -ltnp` | publishing process and port | whether a proxy terminates the connection before the app sees it |

## State-changing actions

- **Impact:** capture writes files continuously and can fill the disk; an over-broad filter or an unfiltered capture on a busy interface is its own outage risk. Captured data may contain flags and peer credentials.
- **Preconditions:** confirmed visibility point, rotation plan, disk headroom, and a decision on which interfaces are inside the rules.
- **Health check before:** your own availability watch is flat and the legitimate smoke test passes.
- **Apply:** start a rotating capture bounded by file count or size (`-C <MB> -W <COUNT>`) on the proved interface only.
- **Health check after:** the probe request appears in the newest file; the service's own latency is unchanged; disk usage is stable. Regression probe: the graded store-then-retrieve cycle still passes while capture runs.
- **Rollback:** stop the capture and remove the files according to policy; then verify free disk. It is unsafe to keep a capture running if the disk is shared with the service or the files are copied outside the team.

## Failure modes and things teams stopped doing

- Teams stopped monitoring the layer they assumed. A first-time team retrospective reports listening on the host VPN interface while the vulnerable services ran inside Docker, so the important traffic never appeared; they moved the sensor once they mapped the real path. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped assuming a log source will exist. A write-up from an event where Apache access logs were available for payload recovery is useful precisely because log availability was event-specific; if you have no capture and no logs, your detection story is a guess. [src-vicevirus-ihack2024-12725f0d]
- Teams stopped treating "we saw nothing" as a finding. Absence of observed attacks after a wrong-interface capture is the canonical example of evidence created by an instrument rather than by reality. [src-d0gl0v3r-umcs2026-c85f0c19]

## Evidence status

- **Status:** version-sensitive / source-supported but untested
- **What we actually ran:** nothing. `tcpdump` was not available in this session, so the capture commands are documentation-derived; the visibility-probe idea is ours.
- **Our adaptation vs the source:** the "prove the sensor with a self-generated request first" rule is our addition. It is the cheapest generalisation of the wrong-interface failure documented by the cited team.

## Sources

- `src-d0gl0v3r-umcs2026-c85f0c19` — wrong-interface monitoring as a concrete, first-hand failure.
- `src-dttw-defcon2018-retro-83e7e6ea` — team retrospective in which traffic review mattered during the event.
- `src-maplebacon-ad-primer-23bd534f` — primer treatment of traffic analysis and attacker behaviour in A/D.
- `src-vicevirus-ihack2024-12725f0d` — log-based payload recovery whose availability depended on the event.
