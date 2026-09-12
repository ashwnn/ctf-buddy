# Diff attacker traffic against normal traffic instead of reading packets

**First useful action.** Group this cycle's conversations by route or message shape, then rank them by rarity — rare shapes are your reading list, not your verdict.

```bash
tshark -r <PCAP> -Y 'http.request' -T fields \
  -e ip.src -e tcp.stream -e http.request.method -e http.host -e http.request.uri \
  2>/dev/null | sort | uniq -c | sort -n | tail -n 40
```

Expected: a short tail of request shapes seen once or twice among high-count checker-like repeats. If sorting produces one giant uniform block instead, either the cycle contains no attacker traffic, or your extraction is collapsing the distinguishing fields — add body length or content type and look again.

## Symptoms

- Hundreds of requests per cycle make manual inspection impossible.
- You know attacks are happening (score movement) but not which conversation caused it.
- A filter you wrote earlier now hides the very traffic you need.

## Prerequisites and assumptions

- A capture or log covering at least one full cycle, plus a way to identify normal checker traffic.
- Working CLI tooling; note the local version, since option sets change between releases.
- Assumption: the checker may itself send unusual or malicious-looking input. Rarity ranks reading order; it does not establish intent.

## Diagnostic sequence

1. Count request shapes per cycle and separate high-frequency (checker-like) from low-frequency → branch A: a clear minority tail exists, read those first; branch B: everything is rare, which suggests the capture covers an unusual window or the service is genuinely varied.
2. For each rare shape, pull the response status and any state change → a 200 with a privileged side effect matters far more than a 404 probe.
3. Correlate the timestamp with score changes or checker failures → this converts "interesting" into "caused something".
4. Only then read the byte stream of the few conversations that survived steps 1–3.

If a rare conversation turns out to be a legitimate client or a new checker behaviour, record it as a baseline and remove it from future reading lists. If no rare traffic exists but score fell, go to `card-ad-replay-http-from-pcap` and compare against the previous cycle.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark ... -e http.request.uri \| sort \| uniq -c \| sort -n` | counts per URI | the rarity ranking; low counts are the reading list |
| `tshark -r <PCAP> -Y 'http.response.code >= 400' -T fields -e tcp.stream` | stream ids with error responses | scanning and failed exploitation, usually lower priority than successes |
| `tshark -r <PCAP> -Y 'http.request' -T fields -e tcp.stream -e http.content_length` | stream and body size | a body size that never appears in normal traffic is a strong signal of attack payloads |
| `grep '<TIMESTAMP_PREFIX>' <ACCESS_LOG>` | matching lines | the same question answered from logs when no capture is available |

## State-changing actions

- **Impact:** analysis is read-only; the risk is operational, not technical — a whitelist built from this analysis and then applied as a filter changes graded traffic.
- **Preconditions:** a written rule answer that filtering is permitted, and a demonstrated legitimate baseline for the traffic you intend to allow.
- **Health check before:** availability watch flat; legitimate smoke test passing.
- **Apply:** if and only if filtering is allowed, apply the narrowest rule that blocks the specific identified transaction, never a broad deny for a URI prefix.
- **Health check after:** legitimate smoke test unchanged and the checker still passes. Regression probe: the specific legitimate client behaviour that shares the blocked route.
- **Rollback:** remove the rule and restore the previous traffic pattern; it is unsafe to keep a filter whose blocked set you cannot describe precisely.

## Failure modes and things teams stopped doing

- Teams stopped using anomaly scores as proof. Attribution guidance in team retrospectives points at correlating traffic with actual effects, because unusual does not mean malicious and normal-looking does not mean safe. [src-dttw-defcon2018-retro-83e7e6ea]
- Teams stopped trusting a single sensor. The wrong-interface failure shows a "quiet" capture can be manufactured by the capture point rather than by the attacker's absence. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped assuming the checker looks normal. Service and checker design guidance expects checkers to exercise services with inputs a defender might call hostile, so a filter tuned on payload appearance is likely to fail the check it was meant to protect. [src-enowars-checker-tenets-bf4b0ac7]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. `tshark` was unavailable in this session; field names and the follow/statistics syntax are documentation-derived and version-sensitive.
- **Our adaptation vs the source:** the rarity-first reading order is our triage rule. The source material establishes that defenders review high-volume traffic and that checkers may look hostile; it does not prescribe a ranking method.

## Sources

- `src-dttw-defcon2018-retro-83e7e6ea` — team retrospective on service review and traffic during the event.
- `src-enowars-checker-tenets-bf4b0ac7` — checker behaviour assumptions, including hostile-looking inputs.
- `src-tshark-man-page-d914bcdd` — authoritative option/field reference; version-sensitive.
- `src-wireshark-follow-stream-00828e3e` — reconstructing a single conversation once it is on the reading list.
- `src-d0gl0v3r-umcs2026-c85f0c19` — why a quiet capture is not evidence.
