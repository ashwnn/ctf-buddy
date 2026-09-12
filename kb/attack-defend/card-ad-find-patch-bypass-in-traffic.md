# Look for the patch bypass in traffic before you patch a second time

**First useful action.** Freeze the original exploit signature and the deployment timestamp, then look at what changed in post-patch traffic instead of writing another patch immediately.

```bash
grep -n 'deployed\|patch' <WORKDIR>/service-board.md | tail -n 5 && \
  tshark -r <PCAP_AFTER_PATCH> -Y 'http.request' -T fields -e ip.src -e tcp.stream -e http.request.uri 2>/dev/null \
  | sort | uniq -c | sort -n | tail -n 25
```

Expected: a short list of post-patch request shapes that are still rare, ideally a variant of the original exploit. If post-patch traffic looks identical to pre-patch traffic while your score still drops, the cause may not be an attacker at all — consider a second vulnerable store, a state problem, or your own broken change.

## Symptoms

- The exploit no longer works against your own service, but the score keeps falling.
- An attacker's request is the same route with a different parameter, encoding, or ordering.
- Teammates are stacking defensive patches without knowing which one is load-bearing.

## Prerequisites and assumptions

- Captures or logs on both sides of the deployment, and the exact deployment time.
- The exact original exploit request, minimised and saved.
- Assumption: your patch was narrow enough that a bypass implies a second reachable path, not a rewrite of the whole feature.

## Diagnostic sequence

1. Confirm the original exploit really fails now → if it still succeeds, the patch is not deployed or not applied to the running copy (`card-ad-listener-to-process-owner`).
2. Compare post-patch requests to the original exploit → classify each difference as encoding (URL/base64/case), transport (GET vs POST, different content type), route (alternate endpoint reaching the same sink), or parameter aliasing.
3. Trace the surviving variant to the code path it actually reaches → branch A: same sink, so the fix was incomplete; branch B: different sink or a second vulnerability, which needs its own analysis before any patch.
4. Check the state you introduced: compare the service's own logs and state around the deployment for evidence the failure is self-inflicted.

If branch A, extend the patch along the same boundary. If branch B, treat it as a fresh vulnerability and run the full exploit→patch cycle rather than editing the old patch again.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `curl ... '<ORIGINAL_EXPLOIT>'` after patch | failure | the patch is live and effective against the known request |
| `sort \| uniq -c \| sort -n` over post-patch URIs | counts | rare shapes are candidates; a variant of the original URI is the strongest signal |
| `tshark -r <PCAP> -Y 'http.request' -T fields -e tcp.stream -e http.content_length` | stream and size | a body size matching the old payload with a new route is a bypass in progress |
| `git log --oneline -n 5` plus board timestamps | commits vs drop time | whether the score fell before or after your patch |

## Failure modes and things teams stopped doing

- Teams stopped stacking speculative patches. Each additional change multiplies regression risk; the documented guidance is to keep changes precise and behaviour-preserving, which is only possible when one diff is attributable to one observation. [src-ntt-enowars8-writeup-8b4ecb49]
- Teams stopped assuming their own change is innocent. A first-time retrospective's WAF reduced the host to an outage, showing that a falling score after a "defensive" action may be self-inflicted. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped treating one blocked payload as a solved vulnerability. Where an identity or token construction is weak, a patch that merely changes constants leaves a family of variants; the reference fix replaces the weak construction instead. [src-thomasweigold-saarctf2025-eaa12cba]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No captures were compared in this session.
- **Our adaptation vs the source:** the "classify the difference, then decide branch A or B" sequence is ours. The underlying principles (precise patches, self-inflicted failures, weak constructions with variants) come from the cited sources.

## Sources

- `src-ntt-enowars8-writeup-8b4ecb49` — precise defence that must not break graded behaviour.
- `src-d0gl0v3r-umcs2026-c85f0c19` — a defensive control that damaged the host.
- `src-thomasweigold-saarctf2025-eaa12cba` — patch example where the fix replaced weak construction rather than a value.
- `src-dttw-defcon2018-retro-83e7e6ea` — reviewing traffic to understand what opponents actually did.
- `src-maplebacon-ad-primer-23bd534f` — A/D primer on defending while attacks continue.
