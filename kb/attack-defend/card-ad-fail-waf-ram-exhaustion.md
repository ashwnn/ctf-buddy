# Failure story: installed a WAF that ate the whole machine's memory

**First useful action.** Before deploying any always-on defensive component, measure the host's free memory and the component's own growth, and write the removal command first.

```bash
free -m | tee <WORKDIR>/mem.before; \
  pgrep -af '<COMPONENT_PROCESS_NAME>' || echo 'component not running'; \
  while true; do printf '%s %s\n' "$(date -u +%H:%M:%S)" "$(awk '/VmRSS/{print $2}' /proc/<COMPONENT_PID>/status 2>/dev/null)"; sleep 10; done | tee -a <WORKDIR>/mem.watch
```

Expected: `VmRSS` for the component should reach a plateau. A value that climbs across sample after sample, while `free -m` shrinks, is the documented failure mode — remove the component before it takes the service with it.

## Symptoms

- The service becomes slow or unreachable after a defensive layer was added.
- Host memory usage climbs continuously with no corresponding application load.
- The team's explanation for the outage involves "the WAF blocking things", and blocking quality is being discussed instead of resource use.

## Prerequisites and assumptions

- Shell access to your own host and the ability to stop what you started.
- A written rule answer on whether the defensive layer is even permitted (`card-ad-unknown-rule-dry-run`).
- Assumption: a resource-heavy defensive layer is an availability risk, not automatically a protection.

## Diagnostic sequence

1. Establish free memory before the component starts → this is the only baseline that makes growth visible.
2. Watch the component's resident set over a few minutes → branch A: plateau, keep it while monitoring; branch B: monotonic growth, remove it now.
3. If removed, re-run the legitimate smoke test and compare against the earlier baseline → branch A: service recovers, so the incident is closed and the failed component is documented rather than redeployed; branch B: still degraded, so the component caused damage beyond memory (restart the service).
4. Ask whether the component was needed at all: was there a reproduced exploit whose specific condition it addressed, or was it a general "harden everything" measure?

If the growth branch repeats with a different component, stop deploying generic filters and go to `card-ad-narrow-trust-boundary-patch` for the actual condition.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `free -m` | memory table with available | the resource budget the service depends on |
| `awk '/VmRSS/{print $2}' /proc/<PID>/status` sampled | rising or flat number | unbounded growth in an inline proxy/filter |
| `systemctl show -p NRestarts <UNIT>` | restart counter | the service being killed by the out-of-memory killer shows up here |
| `dmesg \| tail -n 30` | kernel lines | an OOM-kill entry names the victim process |

## State-changing actions

- **Impact:** installing an inline defensive component changes graded traffic and consumes host resources shared with the service; removing it restores the previous traffic path but may leave stale state or configuration behind.
- **Preconditions:** permission to run the layer, a measured baseline, and the removal command prepared in advance.
- **Health check before:** free memory recorded and the legitimate smoke test passing.
- **Apply:** install on the narrowest scope with an explicit memory limit if the tool supports one; never install it on the same host that runs the graded service without a bounded ceiling.
- **Health check after:** service latency and status unchanged, component memory flat, disk and CPU stable. Regression probe: the checker's full cycle, not just a ping.
- **Rollback:** stop and disable the component, restore the previous traffic path, re-run the smoke test. Rollback is unsafe if the component modified request bodies or state; compare a captured request before and after removal.

## Failure modes and things teams stopped doing

- **The documented failure.** In a first-time UMCS 2026 attack/defense retrospective, the team says it implemented a WAF before understanding the exploit or the payload, and that the WAF ultimately consumed all 8 GB of RAM on the target machine. The reported lesson is to patch the root cause rather than reach for generic filtering, and to measure resource impact of any defensive control. [src-d0gl0v3r-umcs2026-c85f0c19]
- **The practice that replaced it.** Reproduce first; measure CPU/working set/latency before and after a defensive control; write the rollback command before deployment; treat a resource-heavy control as a service-outage risk.
- Teams stopped letting an emergency control become permanent. The same class of problem — an undocumented state-changing measure that outlives its justification — is why containment and patching are tracked as separate, individually reversible actions. [src-ructfe-rules-95d7c601]
- Teams stopped assuming a defensive layer is legal by default. One event restricted peer-traffic filtering outright, so a control that changes graded traffic can be a rules violation as well as a resource risk. [src-ructfe-rules-95d7c601]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No component was installed and no memory sampling was performed in this session.
- **Our adaptation vs the source:** the memory watchdog and the removal-first discipline are ours. The failure itself, including the 8 GB figure, is reported by the cited first-time team retrospective.

## Sources

- `src-d0gl0v3r-umcs2026-c85f0c19` — WAF deployed before understanding the exploit; 8 GB of RAM consumed.
- `src-ructfe-rules-95d7c601` — rules restricting filtering; availability-sensitive scoring.
- `src-ntt-enowars8-writeup-8b4ecb49` — the contrasting practice: precise defence instead of broad controls.
- `src-maplebacon-ad-primer-23bd534f` — A/D primer discussion of defensive approaches.
