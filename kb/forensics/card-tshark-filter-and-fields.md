# Extract fields, not screenshots: keep display filters and capture filters straight

**First useful action.** Write one `-T fields` command per question you actually have, and check the field name exists in your build before concluding anything from its absence.

```bash
tshark -r <CAPTURE.pcap> -Y "<display-filter>" -T fields -E header=y -E separator=, -E occurrence=f -e frame.number -e frame.time_epoch -e ip.src -e tcp.stream -e <field.one> -e <field.two>
```

Expected: one CSV line per matching frame with only the columns you asked for. If a column is empty for every row, the field name is wrong for this release — confirm with `tshark -G fields | grep -w <field.one>` instead of assuming the protocol is absent.

## Symptoms

- You are scrolling `tshark -V` output or the GUI packet-detail tree looking for one value.
- A filter that works in the Wireshark GUI produces nothing on the command line (or vice versa).
- You need a candidate list to diff between captures, ticks, or teammate runs.

## Prerequisites and assumptions

- `tshark` available with the target protocol's dissector built in.
- You know whether you are reading a file or capturing live — the two paths accept different filter syntax.
- Stack/version: TShark 3.x/4.x; dissector field names are version-dependent and are the single most common source of "the traffic isn't there" errors.

## Diagnostic sequence

1. Decide read vs capture: reading a file → `-Y` display filter only (a `-f` capture filter is not applied to `-r` input); capturing live → `-f` BPF filter, optionally plus `-Y`.
2. Build the field list with `-T fields`, and set `-E occurrence=f` so multi-value fields do not flood the output; use `a` (all) only when you deliberately want every repeat.
3. Validate one row against the GUI/packet detail for the same frame number → branch: values match → template is trustworthy; values differ → you are reading the wrong field (common with similarly named fields such as `http.host` vs `http.request.full_uri`).
4. Save the template as a one-liner in the team notes keyed by question ("which clients POSTed what, per stream") rather than re-inventing filters under time pressure.

If the fields you need do not exist for any protocol, the traffic is not being dissected as you think — go to card-wrong-dissector-encapsulation. If the values you want are inside opaque payload bytes, go to card-unknown-payload-encoding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -G fields \| grep -w dns.qry.name` | one field definition line | The field exists in this build; absence means a different name or version |
| `tshark -r <C> -Y "http.request" -T fields -e http.host -e http.request.uri` | host, URI per request | Request inventory without reading payloads |
| `tshark -r <C> -Y "dns.flags.response==0" -T fields -e dns.qry.name -e dns.qry.type` | query name, type | DNS question inventory (feeds card-dns-tunneling-triage) |
| `tshark -r <C> -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name` | SNI values | Which hostnames a client asked for, even without keys |
| `tshark -r <C> -Y "usb.transfer_type==0x01" -T fields -e usb.capdata -e usbhid.data` | report bytes (one column often empty) | Which USB HID field name your release populates |
| `tshark -r <C> -d tcp.port==<PORT>,http -T fields -e http.request.uri` | decoded fields | Force a dissector hypothesis to test it |

## State-changing actions (only if the card changes a host or service)

Not applicable — read-only. Live-capture filter choices belong to card-capture-hygiene.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — no service is touched.

## Failure modes and things teams stopped doing

- **Grepping `-V` dumps.** It works once and then silently matches the wrong direction, the wrong frame, or a hex rendering. Maple Bacon's primer argues for reading traffic at the protocol level (S005); our extension of that into field templates is our own rule: one field, one meaning, one row per frame.
- **Using display-filter syntax as a BPF capture filter.** `-f` takes pcap syntax (`port 80`, `host <TEAM_VM_IP>`), not `tcp.port==80`; TShark errors, and a hurried operator may conclude the traffic does not exist (TShark manual, S028).
- **Assuming a missing field means missing traffic.** Field names move between releases; the USB writeups we hold show decoding that depends on the device's report layout and on which report-byte field the analyzer exposes (src-metactf-key-evidence-9f635ac3, src-snakectf-ordinary-keyboard-19216912). Our rule: verify the field name in the local build first.
- **Believing a template because it "looked right" on one frame.** Validate one row against packet detail before using it at scale.
- Narrower replacement: field name check → one validated row → then batch extraction.

## Evidence status

- **Status:** documentation-derived and version-sensitive; untested locally.
- **What we actually ran:** nothing — no `tshark` binary in this environment.
- **Our adaptation vs the source:** the TShark manual documents the option surface (S028); the judgment layer (validate one row, pin field names, keep templates question-shaped) is ours and is labelled as inference.

## Sources

- `src-tshark-man-page-d914bcdd` — `-Y`/`-f`/`-T fields`/`-E`/`-d`/`-G` semantics and the read-vs-capture distinction.
- `src-metactf-key-evidence-9f635ac3` — field-extraction USB decoding and its dependence on report layout.
- `src-snakectf-ordinary-keyboard-19216912` — standard decode assumptions failing on a non-standard device.
- `src-maplebacon-ad-primer-23bd534f` — protocol-level reading over raw dumps.
