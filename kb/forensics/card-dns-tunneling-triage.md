# Decide whether DNS is normal or a tunnel from four measurements

**First useful action.** Extract every query name once, then measure label length, uniqueness, record types, and response sizes — a tunnel shows up as a sustained pattern, not as a single odd-looking name.

```bash
tshark -r <CAPTURE.pcap> -Y "dns.flags.response==0" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type > <OUTDIR>/dns-queries.tsv
awk -F'\t' '{c[$3]++} END {for (k in c) print c[k], k}' <OUTDIR>/dns-queries.tsv | sort -rn | head -n 20
```

Expected: a small number of repeated short names if the capture is ordinary web traffic; a long tail of unique, long labels under one parent domain if something is tunnelling.

## Symptoms

- DNS traffic volume that seems high for the services in scope, or many queries that never receive a useful answer.
- Query names that look like encoded data (`<base32-looking-label>.<parent-domain>`).
- A challenge that hints at "exfiltration", "command and control", or "covert channel".

## Prerequisites and assumptions

- DNS is visible, i.e. classic UDP/TCP port 53. If the capture only shows TLS on 443/853 with no plaintext DNS, the names are unavailable — go to card-tls-keys-and-cleartext-shortcuts.
- A rough baseline: what the checkers and your own services normally resolve.
- Stack/version: TShark 3.6+ field names (`dns.qry.name`, `dns.qry.type`, `dns.flags.response`, `dns.resp.len`).

## Diagnostic sequence

1. Volume and uniqueness: count queries per parent domain and the ratio of unique names to total queries. Interpretation: a handful of names repeated thousands of times is caching/health traffic; thousands of *unique* names under one domain is the tunnel signature.
2. Label length and alphabet: compute the length distribution of the leftmost label and whether labels consist of base32/base64-safe characters. Interpretation: long, high-entropy labels carry payload; ordinary hostnames do not.
3. Record types and response sizes: TXT/NULL-heavy queries, or responses much larger than queries, indicate data flowing *in*; long queries with short answers indicate data flowing *out*.
4. Timing: are queries evenly spaced (beaconing) or bursty (bulk transfer)? Branch: regular spacing plus unique labels → automated tunnel; one burst of long names → a single upload attempt.
5. Only then decode: take the payload labels, strip the parent domain, and hand the strings to card-unknown-payload-encoding.

If the payload labels decode to structure you recognise (base32/hex/zlib), go to card-unknown-payload-encoding. If the queries are anomalous but the names are fully random-looking with no plausible encoding, re-check that you are not misreading ordinary CDN/anycast lookups.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <C> -Y "dns.flags.response==0" -T fields -e dns.qry.name` | query names | The raw material for every measurement below |
| `awk -F. '{print $(NF-1)"."$NF}'` | parent domains by count | Which domain is being hammered |
| `tshark -r <C> -Y "dns.qry.type==16" -T fields -e dns.qry.name -e dns.txt` | TXT query/answer pairs | Data-in channel; also the classic "flag in TXT record" challenge |
| `tshark -r <C> -q -z io,stat,10,"dns"` | DNS bytes per 10 s | Burst versus steady-rate shape |
| `head -n 1 <RUN>/dns.log \| tr '\t' '\n' \| nl` and `zeek-cut query qtype_name rcode` | Zeek DNS fields | Independent view with rcode/NXDOMAIN counts |

## State-changing actions (only if the card changes a host or service)

Not applicable — read-only analysis. Do not "block the tunnel" by changing DNS configuration during the event unless the rules and the service ownership model explicitly allow it; a defensive DNS change can break your own service's resolution and the checker's health probe.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. A real service-side fix (validating resolver input, restricting egress) belongs to the patch workflow, and only after you have proven the tunnel exists with the measurements above.

## Failure modes and things teams stopped doing

- **Calling any long domain name a tunnel.** Ordinary web traffic contains long subdomains (tracking, CDN sharding, random identifiers). Maple Bacon's primer warns against treating rarity alone as maliciousness (S005): rarity ranks candidates, it does not classify them. Rule now: require at least two of {sustained unique labels, oversized responses, encoded alphabet, off-baseline volume}.
- **Chasing volume without a baseline.** Without knowing what the checkers resolve, "high DNS traffic" is meaningless; the same primer recommends understanding normal traffic before anomaly hunting (S005). Rule now: capture a clean baseline window first.
- **Decoding labels before confirming the channel is a tunnel.** Time is wasted decoding legitimate tracking identifiers. Rule now: measurements first, decoding only for a channel that passed step 4.
- **Assuming DNS is the only covert channel.** The same four measurements apply to ICMP, HTTP POSTs, and unknown binary protocols; see card-exfil-detection, which is where this card's output belongs when the volume question is broader than DNS.
- Narrower replacement: baseline → volume/uniqueness → alphabet → response size → timing → decode.

## Evidence status

- **Status:** documentation-derived and version-sensitive; untested locally (no capture tooling in this environment).
- **What we actually ran:** nothing. No worked example with real numbers appears here because we did not run one; the card gives a measurement procedure, not fabricated statistics.
- **Our adaptation vs the source:** the brief's DNS bullet asked for "analysis and tunnelling"; this card converts it into four measurements with an explicit two-of-four bar and a stop rule before decoding (our inference, not a claim taken from any source).

## Sources

- `src-tshark-man-page-d914bcdd` — DNS field extraction and statistics options.
- `src-maplebacon-ad-primer-23bd534f` — rarity-versus-maliciousness caution and baseline-first traffic reading.
- `src-zeek-file-analysis-4f12a413` — companion log-driven analysis pattern used by the Zeek option in the table.
