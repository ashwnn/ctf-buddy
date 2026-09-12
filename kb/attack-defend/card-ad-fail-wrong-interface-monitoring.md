# Failure story: monitored the wrong interface and called the game quiet

**First useful action.** Before trusting any quiet capture, generate your own known request and check that it appears in the sensor you plan to rely on.

```bash
ip -br addr | tee <WORKDIR>/ifaces.txt; \
  ( sudo tcpdump -n -i <IFACE> -s0 -w <WORKDIR>/probe.pcap 'port <PORT>' ) & TPID=$!; \
  sleep 2; curl -sS -o /dev/null '<HEALTH_URL>'; sleep 2; sudo kill -INT $TPID; \
  tcpdump -nr <WORKDIR>/probe.pcap 2>/dev/null | wc -l
```

Expected: a non-zero count. A zero count with a working service means your telemetry is pointed at a layer the traffic never crosses, and every "we saw nothing" conclusion that follows is an artifact.

## Symptoms

- The score drops or flags are lost while your capture shows nothing unusual.
- The service runs in a container but the sensor runs on the host's remote-access interface.
- The team concludes that opponents are passive, or that the vulnerability is unexploitable.

## Prerequisites and assumptions

- Any capture capability at all, on an interface the rules permit.
- A service whose request path you can trace from client to process.
- Assumption: you may capture only on your own assigned interfaces; validating a sensor is a local action, not a peer-directed one.

## Diagnostic sequence

1. Send one known request and search for it in the newest capture → branch A: found, so the sensor is valid for that path; branch B: not found, so stop analysing and go to step 2.
2. Enumerate the path: published host port, container bridge or network, any reverse proxy, and the interface that receives the connection → the sensor belongs on the layer that carries graded traffic.
3. Re-test after moving the sensor; if a container is involved, confirm the container's network namespace rather than assuming host-level capture sees it.
4. Only when the probe is visible, re-examine the "quiet" period — the attacker may have been in your logs the whole time.

If the sensor still cannot see the traffic, record the gap explicitly on the board as `visibility: none` so nobody builds detection claims on it.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ip -br addr` | interface list with state | candidates for `<IFACE>`; a `veth`/bridge hints at container networking |
| `tcpdump -nr <FILE>` after the probe | packet lines | zero lines disproves the sensor, not the attack |
| `docker network ls` / published ports | bridge and mapping | the layer between host port and container process |
| `ss -ltnp` | publishing process | identifies a reverse proxy that terminates traffic before the app sees it |

## State-changing actions

- **Impact:** capture writes files and can fill a disk; captures can contain flags and credentials and must stay team-private.
- **Preconditions:** an interface you are permitted to capture, free disk, and a rotation limit.
- **Health check before:** the service's legitimate smoke test passes.
- **Apply:** capture with a rotation bound (`-C <MB> -W <COUNT>`) on the interface proven by the probe.
- **Health check after:** the probe still appears, service latency unchanged, disk stable. Regression probe: one checker cycle passes while capture runs.
- **Rollback:** stop capture, delete or archive per policy, and verify free disk. Do not leave an unbounded capture running on a host that also runs the service.

## Failure modes and things teams stopped doing

- **The documented failure.** In a first-time UMCS 2026 attack/defense retrospective, the team monitored the VPN interface on the host while the vulnerable services ran inside Docker. They later learned the relevant traffic was flowing through Docker's virtual networking, so their monitoring simply missed the activity they needed. The lesson recorded in that account is about mapping the real request path before relying on telemetry. [src-d0gl0v3r-umcs2026-c85f0c19]
- **The practice that replaced it.** Send one known request through the same path the checker uses and confirm the chosen capture point sees it; if it does not, move the sensor rather than assuming the attacker is invisible.
- Teams stopped treating "nothing in the capture" as evidence of no attack, because that conclusion is exactly what a mis-placed sensor produces. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped assuming a log source will exist at all. A team write-up that recovered attacker payloads from Apache access logs is useful precisely because whether logs exist and are complete is event-specific; without capture and without logs, detection is a guess. [src-vicevirus-ihack2024-12725f0d]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. `tcpdump` was unavailable in this session; the probe command is our construction and is documentation-derived.
- **Our adaptation vs the source:** the probe-the-sensor-first rule is our generalisation of the cited failure, not a procedure the source describes.

## Sources

- `src-d0gl0v3r-umcs2026-c85f0c19` — first-hand account of monitoring the wrong interface while services ran in containers.
- `src-vicevirus-ihack2024-12725f0d` — payload recovery from logs, whose availability was event-specific.
- `src-dttw-defcon2018-retro-83e7e6ea` — team retrospective in which traffic understanding drove decisions.
- `src-maplebacon-ad-primer-23bd534f` — primer framing of traffic analysis for defenders.
