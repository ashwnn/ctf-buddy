# Prove exfiltration with a baseline, a channel, and a shape — not one big packet

**First useful action.** Compute outbound volume per internal host and per minute, compare it to a baseline window from before the suspected activity, and only then name the channel that carries it.

```bash
tshark -r <CAPTURE.pcap> -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len -e udp.length > <OUTDIR>/flows.tsv
awk -F'\t' '$2=="<TEAM_VM_IP>" {b[$3]+=$4+$5} END {for (d in b) print b[d], d}' <OUTDIR>/flows.tsv | sort -rn | head
```

Expected: a short list of destinations ranked by bytes leaving `<TEAM_VM_IP>`. If nothing stands out against the baseline, you do not have an exfiltration finding yet — say so instead of dramatising a single upload.

## Symptoms

- Score drops, a flag store leaks, or the challenge asks "what did the attacker take".
- A capture shows a burst of outbound traffic to an address the team cannot explain.
- You need to quantify rather than characterise: how much, how long, in which direction.

## Prerequisites and assumptions

- Baseline capture or baseline statistics from a quiet period; otherwise use checker traffic as the reference and state that limitation.
- Capture has full payloads (check the snaplen, card-capture-hygiene) and low loss; a truncated capture understates volume and hides payloads.
- Stack/version: TShark 3.6+/4.x field names; `ip.src`-style filters in `-z io,stat` must be written without quotes.

## Diagnostic sequence

1. Volume: bytes out per internal host and per destination, plus a per-minute rate (`tshark -q -z io,stat,60,ip.src==<TEAM_VM_IP>`). Interpretation: exfiltration is a *sustained* deviation, not a spike caused by a backup or a checker retry.
2. Direction and shape: ratio of outbound to inbound bytes for the suspect pair, and whether transfer is bulk (high rate, few connections) or beaconing (regular small messages with low inter-arrival variance). Compute inter-arrival deltas per flow before claiming C2.
3. Channel: identify which protocol carries the bytes — HTTP POST bodies, DNS query/TXT volume (card-dns-tunneling-triage), ICMP payloads, TLS record sizes (`tls.record.length`), SMTP attachments, or an unknown binary protocol (card-unknown-protocol-triage).
4. Payload: try to recover at least one artefact from the channel (export objects, stream, carved bytes) — a recovered payload turns an inference into a finding.
5. Attribution boundary: state plainly whether the traffic left the competition network or only went to another in-game host (lateral movement looks identical in volume terms).

If the channel is unknown, go to card-unknown-protocol-triage. If the payload is opaque, go to card-unknown-payload-encoding. If the volume is explained by legitimate activity, record it as explained and stop.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `-T fields -e ip.src -e ip.dst -e tcp.len -e udp.length` | per-frame byte accounting | Base data for every volume claim |
| `tshark -q -z conv,ip` | per-pair totals both directions | Which pair dominates and in which direction |
| `tshark -q -z io,stat,60,ip.src==<TEAM_VM_IP>` | 60-second buckets | Sustained rate versus single burst |
| `-Y "http.request.method==\"POST\"" -T fields -e http.host -e http.content_length` | POST sizes | Upload channel candidates |
| `-Y "icmp.type==8" -T fields -e data.len` | echo payload sizes | Covert channel candidate |
| `awk` over `frame.time_epoch` per flow | inter-arrival deltas | Beaconing versus streaming |

## State-changing actions (only if the card changes a host or service)

Not applicable — read-only analysis of an existing capture. Do not "block" a suspected exfiltration path during the event unless the rules and service ownership model clearly allow it; blocking can break the checker and cost availability points.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. Where the exfiltration channel is a flaw in a team-owned service (for example an unauthenticated export endpoint), the fix belongs to the service-owner patch workflow with its own regression pair.

## Failure modes and things teams stopped doing

- **Calling the largest flow "the exfiltration".** Volume ranks candidates; you still need channel and payload. The A/D primer's caution about rarity/anomaly ranking applies here directly (S005).
- **Forgetting the checker in the baseline.** Checkers deliberately exercise the service and generate traffic that repeats every tick; FAUST's beginner material explains that this traffic is the definition of legitimate behaviour (AD1). Rule now: subtract the recurring pattern before calling anything anomalous.
- **Ignoring the direction that is not network.** USB mass-storage writes and removable media are exfiltration too; a capture-only mindset misses them (see the USB cards).
- **Claiming precise numbers from a truncated or lossy capture.** Under-sampled captures produce understated volumes; state capture quality before any number. Rule now: report capture parameters alongside volume.
- **Chasing volume while the evidence you need is host-side.** If a host image exists, the artefact and its timestamps are stronger evidence than byte counters (card-image-triage-memory-and-disk).

## Evidence status

- **Status:** documentation-derived for the measurements, operator-derived for the baseline/channel/shape bar; untested (no capture tooling or capture files here).
- **What we actually ran:** nothing. The card deliberately contains no example numbers, because inventing a representative capture would be false evidence.
- **Our adaptation vs the source:** drafted PCAP-family notes covered conversation ranking; this card adds the explicit three-part evidentiary bar and the capture-quality caveat, which is what distinguishes a reportable finding from a hunch.

## Sources

- `src-tshark-man-page-d914bcdd` — statistics options, field extraction used for the accounting.
- `src-faust-ad-beginners-779c0a5e` — legitimate/checker traffic as the baseline definition.
- `src-maplebacon-ad-primer-23bd534f` — anomaly ranking versus proof; traffic as defensive evidence.
- `src-dttw-defcon2018-retro-83e7e6ea` — triage discipline when many flows compete.
