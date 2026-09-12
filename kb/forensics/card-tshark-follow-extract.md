# Extract streams with TShark so the result is diffable and repeatable

**First useful action.** Stop hand-copying payloads: dump the stream with a one-line TShark command, save the command and the tool version next to the output file, and hash the result.

```bash
tshark --version ; tshark -r <CAPTURE.pcap> -q -z follow,tcp,raw,<STREAM> > <OUTDIR>/stream-<STREAM>.txt ; sha256sum <OUTDIR>/stream-<STREAM>.txt
```

Expected: a transcript file plus a version string and a hash. If the file is empty, the stream index or the mode name is wrong for your TShark release — check `tshark -z help` locally rather than trusting any online option list.

## Symptoms

- Several captures need the same extraction, or the same capture must be re-examined after a teammate's hypothesis changes.
- You need to diff "normal" versus "suspicious" traffic for the same flow.
- You must hand an artifact to another teammate or the team log with provable provenance.

## Prerequisites and assumptions

- `tshark` on PATH; capture readable; stream index known (card-pcap-follow-stream).
- A writable scratch directory outside the tracked repository tree.
- Stack/version: TShark 3.x/4.x; `-z follow` modes are `ascii`, `hex`, `raw`, and the available modes have changed historically.

## Diagnostic sequence

1. `tshark --version` → pin the exact release in your notes. Branch: two teammates on different releases may produce different transcripts for the same capture, so only compare transcripts produced by the same version.
2. `tshark -z follow,tcp,raw,<STREAM>` → branch: raw output intact → keep it as the byte-fidelity record; `ascii` is easier to read but re-encodes binary bytes.
3. Cross-check volume: sum `tcp.len` over the stream's frames and compare with the artifact size. Branch: mismatch means capture gaps or truncation — do not claim byte-exact reconstruction.
4. Hash and file the artifact next to the capture rather than inside the repository working tree.

If the raw stream contains a nested protocol you still cannot name, go to card-unknown-protocol-triage. If it looks like a known protocol that TShark keeps labelling `data`, go to card-wrong-dissector-encapsulation.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark --version` | `TShark (Wireshark) 4.x.y` | Version you must record beside every transcript |
| `tshark -r <C> -q -z follow,tcp,raw,<STREAM>` | compact transcript | Deterministic extraction for diffing and archiving |
| `tshark -r <C> -Y "tcp.stream==<STREAM>" -T fields -e tcp.len \| awk '{s+=$1} END {print s}'` | summed payload bytes | Cross-check against transcript size |
| `tshark -r <C> -Y "tcp.stream==<STREAM>" -T fields -e tcp.payload \| tr -d '\n' \| xxd -r -p > <OUTDIR>/stream.bin` | raw bytes on disk | Byte-exact payload for carving/entropy work |
| `tshark -z help` | `follow,tcp,<mode>,<stream>` list | Which modes your local build actually supports |

## State-changing actions (only if the card changes a host or service)

Not applicable — this card only writes files into team scratch space. Keep extracted payloads out of the tracked repository: they can contain flags and attacker tooling, which the repo's conventions forbid committing.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — extraction only.

## Failure modes and things teams stopped doing

- **Copy-pasting GUI output into notes.** An extraction without its command, version, and hash cannot be re-derived or defended later, which is exactly the evidence discipline the A/D retrospectives argue for (S007). Our rule: command + version + hash beside the artifact.
- **Grepping the whole capture with `strings` instead of reading one stream.** It is a last resort, and it destroys which endpoint said what; Maple Bacon's primer argues for reading the traffic rather than dumping bytes (S005). Our rule: extract with an explicit stream and mode first.
- **Assuming online option lists match the event laptop.** The TShark manual documents a large, evolving option set (S028), and older builds accept different `-z` modes. Our rule: verify with `tshark --version` and `tshark -z help` locally.
- **Comparing transcripts produced by different tool versions.** Silently different formatting makes real differences invisible. Our rule: record the version in the artifact name or note.
- Narrower rule: extract with an explicit stream/mode, record version, verify byte totals, then interpret.

## Evidence status

- **Status:** documentation-derived, untested (no `tshark` binary available in this environment; the repo's earlier research pass recorded the same).
- **What we actually ran:** nothing — the `sha256sum`, `awk`, and `xxd` steps are standard utilities but were not exercised here.
- **Our adaptation vs the source:** drafted card PCAP-003 asked for scriptable extraction with version pinning; this version adds the byte-total cross-check and an explicit rule about not storing payloads in the tracked repo.

## Sources

- `src-tshark-man-page-d914bcdd` — `-z follow` modes, `-T fields`, `-z help` behaviour.
- `src-wireshark-follow-stream-00828e3e` — what a followed stream does and does not represent.
- `src-maplebacon-ad-primer-23bd534f` — evidence-first traffic analysis.
- `src-dttw-defcon2018-retro-83e7e6ea` — time-pressured triage discipline.
