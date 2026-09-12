# Give every recovered artifact a provenance row before analysing it

**First useful action.** For each extracted file, write one provenance row — hash, capture file, tool and version, stream/fuid/frame, UTC timestamp, endpoints, protocol — and refuse to build conclusions on artifacts without one.

```bash
sha256sum <OUTDIR>/http-objects/* | sort ; grep -w <FUID_OR_STREAM> <OUTDIR>/zeek-<RUN_TAG>/files.log
```

Expected: an artifact hash plus either a Zeek file row (fuid, conn_uids, hosts, size) or a Wireshark stream/frame reference. If neither exists because you carved raw bytes, mark the row `provenance: weak (byte offset only)`.

## Symptoms

- Several artifacts are on disk and nobody can say which tick, host pair, or protocol produced them.
- Two teammates extracted the same payload with different names and different sizes.
- An hour later you must justify which flow the flag-bearing file actually travelled in.

## Prerequisites and assumptions

- Protocol-aware extraction ran first (card-http-object-export or card-zeek-file-inventory) or Zeek logs are available.
- A single scratch directory per analysis run, and a team-visible notes file.
- Stack/version: Zeek 6.x+ for `conn_uids`/`fuid`; Wireshark/TShark for stream/frame references.

## Diagnostic sequence

1. Join Zeek rows: `files.log` fuid → `conn_uids` → `conn.log` uid → 5-tuple, duration, byte totals, `orig_bytes`/`resp_bytes`. Branch: the join resolves → you have strong provenance; no join → continue to step 2.
2. For Wireshark-side artifacts, record `tcp.stream`, `tcp.stream` direction, first and last `frame.number`, and `frame.time_epoch`. Branch: stream is unknown because the artifact was carved → record the byte offset inside the pcap and the carve tool version.
3. Compare hashes across artifacts → duplicate hashes collapse to one artifact with two provenance rows (that is a finding: the same file travelled twice).
4. Only after the row exists, start interpreting the artifact (type, strings, structure).

If provenance shows the artifact came from a protocol/flow you have not identified, go to card-unknown-protocol-triage. If it came from nowhere the capture explains, the capture itself is suspect — go to card-wrong-dissector.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -w <FUID> <RUN>/files.log` | one TSV row | File identity, size, hashes, MIME guess |
| `grep -w <CONN_UID> <RUN>/conn.log` | connection row(s) | Which host pair and duration carried it |
| `tshark -r <C> -Y "http.response && tcp.stream==<STREAM>" -T fields -e frame.number -e frame.time_epoch -e ip.src -e http.host` | frame list with UTC epoch | Wireshark-side provenance for the same artifact |
| `sort <prov.tsv> \| uniq -c` on hash column | repeated hashes | Same payload transferred more than once |

## State-changing actions (only if the card changes a host or service)

Not applicable — the card writes only notes files. Keep provenance rows free of live flags; reference the artifact by hash instead.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — provenance reconstruction does not modify services. Its output is what makes a later patch decision reviewable.

## Failure modes and things teams stopped doing

- **Filename collisions in export directories.** Two HTTP responses can share a name; exporters overwrite silently, so an artifact can vanish mid-analysis. Rule now: export into a run-tagged directory, then hash and rename by hash.
- **Forgetting which rotated capture file an artifact came from.** We recommend ring-buffer captures (card-capture-hygiene); that convenience is exactly what destroys provenance unless the artifact records the file name too. Rule now: provenance row includes capture file name *and* its hash.
- **Calling an artifact "the attacker's tool" from network presence alone.** Presence on the wire is not execution on a host; the A/D primers stress correlating traffic with service-side evidence rather than assuming effect (S005, S007). Rule now: state "transferred" unless a host-side artifact proves execution.
- Narrower replacement: hash → join → row → then interpret.

## Evidence status

- **Status:** source-supported but untested; the join logic is documented, the workflow is ours.
- **What we actually ran:** nothing — no Zeek/Wireshark binaries and no capture in this environment.
- **Our adaptation vs the source:** drafted card PCAP-006 described the fuid→conn join; this version adds the weak-provenance label for carved bytes and the capture-file-hash requirement, both needed because we recommend rotated captures.

## Sources

- `src-zeek-file-analysis-4f12a413` — fuid, conn_uids, and the file/connection metadata model.
- `src-wireshark-follow-stream-00828e3e` — stream-level identity for Wireshark-side artifacts.
- `src-maplebacon-ad-primer-23bd534f` — correlating traffic evidence with service effects.
- `src-dttw-defcon2018-retro-83e7e6ea` — evidence discipline when many flows compete for attention.
