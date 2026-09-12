# Bound flag lifetime and flag identifiers with your own evidence, not folklore

**First useful action.** Sample your own service's checker-visible flag once a minute into a timestamped log so the real refresh interval stops being a guess.

```bash
mkdir -p <WORKDIR> && while true; do
  printf '%s\t%s\n' "$(date -u +%H:%M:%S)" "$(<SELF_FLAG_READ_COMMAND>)"
  sleep 60
done | tee -a <WORKDIR>/flag-rotation.log
```

Expected: the same value repeated for a stable number of minutes and then a different value — the run length of identical values is your observed refresh interval. If the value never changes, your read command is hitting a cache or a static field and the observation means nothing.

## Symptoms

- An exploit retrieves useful material from one target and rejected/old material from another.
- You hold per-team or per-tick identifiers in your notes with no idea which cycle they belong to.
- Someone proposes "just resubmitting" a value captured several cycles ago.

## Prerequisites and assumptions

- A read path for *your own* service's flag-equivalent secret. Never a peer's.
- Organizer-provided submission interface, or an explicit statement that submission is manual.
- Assumption: whether per-team/per-tick identifiers are published at all is event-specific. Some games expose an attack-info style feed; others expect identifiers to be derived from service behaviour. Do not invent an endpoint.

## Diagnostic sequence

1. Run the rotation log for at least three or four suspected cycles → learn the refresh interval and whether refresh aligns to a wall-clock boundary.
2. Validate one freshly read value and one value from the previous cycle → branch A: the older value is accepted, so validity spans more than one cycle; branch B: it is rejected, so validity is short and fetch→submit must happen inside one cycle.
3. Check whether an identifier/attack-info interface is documented (`grep -inE 'attack.?info|flag.?id|retriev' <RULES_FILE>`) → if documented, parse it; if silent, derive identifiers from the service's own public behaviour and mark the derivation as an assumption.

If the older value is rejected (branch B), go to `card-ad-exploit-harness-then-thrower` and make fetch→submit one bounded step. If it is accepted (branch A), still expire your cache: stale-value traffic is wasted work and can look like an attack on your own infrastructure.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| value sampling with `sleep 60`, then `cut -f2 <WORKDIR>/flag-rotation.log \| uniq -c` | run lengths | observed refresh rate and the first hard lower bound on cycle length |
| `awk -F'\t' '$2!=p {print $1" changed"; p=$2}' <WORKDIR>/flag-rotation.log` | change timestamps | regular timing suggests a fixed clock; jitter suggests the value is event-driven |
| `grep -inE 'attack.?info\|flag.?id\|submit' <RULES_FILE>` | hits or silence | whether identifiers are published; silence means derive-and-label, not invent |

## Failure modes and things teams stopped doing

- Teams stopped resubmitting the same harvested value in a loop. Duplicate and expired-submission handling vary between frameworks, and reposting a stale value spends the window you needed for a fresh capture. [src-enowars-engine-readme-7933cf37]
- Teams stopped treating "flag" as "any string that looks flag-shaped". Established A/D documentation treats flag validity as a framework concept with a defined lifetime, which is exactly why lifetime must be measured rather than assumed. [src-enowars-engine-readme-7933cf37] [src-enowars-checker-tenets-bf4b0ac7]
- Teams stopped caching identifiers without provenance. A cached value untagged by service, cycle, and observation time makes a later failure indistinguishable from a broken exploit. [src-maplebacon-ad-primer-23bd534f]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No rotation log was produced in this session.
- **Our adaptation vs the source:** the freshness discipline is ours. ENOWARS/FAUST material establishes that validity windows exist and are framework-defined; the 60-second sampling cadence is our compromise between resolution and noise, not a source recommendation.

## Sources

- `src-enowars-engine-readme-7933cf37` — flag validity, rounds, and checker API concepts.
- `src-enowars-checker-tenets-bf4b0ac7` — what services and checkers are expected to guarantee about stored data.
- `src-maplebacon-ad-primer-23bd534f` — general A/D primer; attack-info style feeds are competition-dependent.
- `src-faust-rules-2024-7fc6a296` — a concrete, differently-sized flag-lifetime rule from a real event.
- `src-ructfe-rules-95d7c601` — a third lifetime, expressed in rounds rather than ticks.
