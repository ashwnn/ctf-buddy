# Normalise every clock before you correlate two artifacts

**First useful action.** Convert every timestamp you intend to compare into UTC epoch, write the source clock and its timezone next to it, and treat a match as an interval, not an instant.

```bash
tshark -r <CAPTURE.pcap> -t ud -T fields -e frame.number -e frame.time_epoch -e frame.time_utc | head
date -u +%Y-%m-%dT%H:%M:%SZ ; mactime -b <BODY_FILE> -d -z UTC > <OUTDIR>/timeline-utc.csv
```

Expected: capture timestamps in UTC epoch, the workstation's own UTC time, and a disk timeline reported in UTC. If `mactime` is invoked without a timezone, its output silently reflects the analysis host's local zone — that single mistake has produced wrong incident narratives in real investigations.

## Symptoms

- You must decide whether a file write preceded a network transfer.
- Two artifacts disagree by a suspicious number of seconds or hours.
- A teammate is about to state "the attacker did X at 14:03" from one log line.

## Prerequisites and assumptions

- At least two timestamp sources (capture + filesystem image, capture + application log, memory + log).
- Known timezone of each source host, or the ability to infer it from an anchor event.
- Stack/version: TShark `-t` modes for display time; The Sleuth Kit `mactime`; Zeek logs store UTC epoch in `ts`.

## Diagnostic sequence

1. Record each source's clock basis: capture files carry epoch seconds (UTC by definition); file MAC times carry the filesystem's UTC epoch but are *displayed* in local time by many tools; log lines carry whatever the application wrote. Branch: any source writes local time without a zone → treat it as UTC±unknown and say so.
2. Find one anchor event visible in two sources (a login, a DNS query that also appears in a web log, an uploaded file that also appears in a capture). Interpretation: the delta between the two timestamps is your measured clock offset. Branch: delta is a clean number of whole hours → timezone misconfiguration; delta is a few seconds → clock skew or logging latency.
3. Express every claim as "A at T1 (source S1) and B at T2 (source S2), offset measured as Δ" with Δ explicitly bounded. Branch: Δ ≥ the interval you care about → you cannot order the events; say that, or find a better anchor.
4. Build the merged timeline only from intervals: for each artefact record `{time, source, clock_basis, uncertainty}` and never drop the uncertainty column.
5. Re-run the timeline in UTC (`-z UTC` for `mactime`, `-t ud` for TShark) so the artifact you hand to a teammate is zone-unambiguous.

If the two artifacts cannot be made comparable, go to card-artifact-connection-correlation and fall back to provenance/volume evidence instead of timing. If one timestamp source is a capture that may have been truncated, go to card-wrong-dissector before trusting its first/last frame times.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <C> -t ud -T fields -e frame.time_epoch` | epoch seconds | Zone-free capture time |
| `tshark -r <C> -t ud -T fields -e frame.time_utc` | `YYYY-MM-DD HH:MM:SS.ffffff` UTC | Human-readable UTC without local conversion |
| `date -u +%Y-%m-%dT%H:%M:%SZ` | current UTC | Basis for "when did we observe this" notes |
| `mactime -b <BODY> -z UTC -d` | CSV timeline | Disk timeline without local-zone drift |
| `zeek-cut ts uid` on `conn.log` | epoch seconds | Zeek's zone-free equivalent for correlation |
| `awk` delta between two anchor timestamps | seconds of offset | The measured clock offset you must publish |

## State-changing actions (only if the card changes a host or service)

Not applicable — read-only, but note that *changing* any host clock during the event (even to "fix" a skew) invalidates every timestamp collected afterwards and can break checker authentication or TLS validity. Do not adjust clocks on team-owned hosts during play; record the offset instead.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. The transferable rule for service work: a patch deployed at time T defines which traffic is pre- or post-patch, so the deployment timestamp is evidence and belongs in the team log (see the patcher material, S004).

## Failure modes and things teams stopped doing

- **Correlating a local-time log with a UTC capture.** The classic off-by-N-hours narrative error; it usually shows up as "the attack happened before the upload". Rule now: normalise first, correlate second.
- **Reporting an instant from a single source.** Single-clock claims ignore skew and logging latency; the DEF CON retrospectives' evidence discipline (S007) supports publishing what was observed plus its uncertainty. Rule now: interval plus measured offset.
- **Editing clocks mid-event.** Changing a host clock to make two timelines "agree" destroys the ability to correlate anything afterwards and can break services. Rule now: never touch the clock; record the delta.
- **Ignoring sub-second ordering.** Millisecond-level ordering matters for "request then write" versus "write then request"; capture files with nanosecond resolution tempt over-precision. Rule now: state the resolution of each source and refuse to order events closer than that.

## Evidence status

- **Status:** documentation-derived for tool flags, operator-derived for the interval/uncertainty rule; untested locally.
- **What we actually ran:** nothing — no `tshark`, `mactime`, or Zeek binary here; the `date` example is illustrative only.
- **Our adaptation vs the source:** drafted card PCAP-00x treated correlation as a join problem; this version adds the clock-basis/uncertainty discipline and the explicit ban on clock changes during play, which no single source in our corpus states as a rule.

## Sources

- `src-tshark-man-page-d914bcdd` — `-t` display-time modes and `frame.time_epoch`/`frame.time_utc`.
- `src-zeek-file-analysis-4f12a413` — Zeek logs carry zone-free timestamps suitable for joins.
- `src-dttw-defcon2018-retro-83e7e6ea` — evidence discipline under time pressure.
- `src-maplebacon-faustctf-patcher-bf21013c` — patch-time bookkeeping as evidence (via the repo's research source table).
