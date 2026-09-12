# Decode USB HID keyboard reports as transitions, not as packets

**First useful action.** Filter interrupt transfers from the HID interface into a TSV, then reconstruct keystrokes from key-state *changes* rather than converting every packet into a character.

```bash
tshark -r <CAPTURE.pcap> -Y "usb.transfer_type==0x01 && usb.bInterfaceClass==0x03" -T fields -e frame.number -e usb.device_address -e usb.capdata -e usbhid.data > <OUTDIR>/hid.tsv ; head -n 5 <OUTDIR>/hid.tsv
```

Expected: rows where one of the two byte columns is populated (releases differ on which field name exists). If both are empty, your build uses a different field name — confirm locally with `tshark -G fields | grep -iE 'capdata|usbhid'` before trying anything clever.

## Symptoms

- The capture contains a USB device that identifies as a keyboard or keypad.
- Extracted report bytes repeat in long runs (typematic repeats) and naive decoding gives `aaaaaaa`-style text.
- A challenge description mentions keystrokes, typing, or "what did they type".

## Prerequisites and assumptions

- USB capture with the device's interrupt endpoint traffic and device/interface descriptors.
- A keymap for HID Usage Page 0x07 (keyboard/keypad) and the byte layout you read from the report descriptor.
- Stack/version: Wireshark/TShark 3.x/4.x; the HID report-bytes field was renamed over time, and USB class/transfer field names are version-sensitive too.

## Diagnostic sequence

1. Confirm the interface is HID (`usb.bInterfaceClass==0x03`) and that only keyboard-class devices are in view. Branch: several HID devices → key your decoding by `usb.device_address`, never by frame order.
2. Inspect one report's length and structure. Branch: 8 bytes with a leading modifier byte and six key slots → standard layout (continue); different length or a leading report-ID byte → card-usb-hid-report-descriptor.
3. Build a transition list: a report whose key bytes are zero means "no key held"; a report that repeats the previous key bytes is a typematic repeat and must not be emitted twice; a changed byte means a new key press.
4. Apply modifiers per report (`0x02`/`0x20` shift, plus Ctrl/Alt) and map usage codes to characters; keep a raw transcript beside the decoded text so a mis-map stays visible.
5. Re-read the decoded text for a second layer (Base32/hex/ROT) if it looks like encoded data rather than prose; snakeCTF's `ordinary-keyboard` stacks an encoding step after the HID decoding (src-snakectf-ordinary-keyboard-19216912).

If the decoded text stays nonsense after the layout is confirmed, go to card-usb-hid-report-descriptor — the framing, not the keymap, is usually wrong. If the descriptor is standard but the bytes are clearly not key reports, the device may be a composite/custom HID device: treat it as an unknown protocol (card-unknown-protocol-triage).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -Y "usb.transfer_type==0x01 && usb.bInterfaceClass==0x03"` | interrupt/HID frames | The candidate keystroke stream |
| `-e usb.capdata` and `-e usbhid.data` | hex report bytes (one column usually empty) | The payload to decode, whichever name this build populates |
| `-e usb.device_address` | per-device grouping | Separates keyboard from other HID traffic |
| `-e frame.time_epoch` | keystroke timing | Distinguishes human typing from scripted injection |
| `tshark -G fields \| grep -iE 'capdata\|usbhid'` | field name(s) | Local-build truth instead of an online recipe |

## State-changing actions (only if the card changes a host or service)

Not applicable — replaying the keystrokes against a live system is explicitly out of scope for this card; the deliverable is a decoded transcript treated as evidence.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. The relevant security judgment is that a USB HID device is trusted like a keyboard: the "patch" (device policy, port control, authorisation) lives with the endpoint-hardening workflow, not here.

## Failure modes and things teams stopped doing

- **One packet, one character.** Ignoring releases and typematic repeats produces duplicated or missing letters. MetaCTF's Flash CTF USB/HID challenge writeup decodes a specific keyboard report structure (src-metactf-key-evidence-9f635ac3); that structure carries state, not single keypress events, so our rule is transitions-only.
- **Guessing keyboard layouts.** US vs regional layouts differ mainly in shift symbols; if text is nonsense, the framing is the first suspect, not the layout. Rule now: verify report length/shape before touching the layout.
- **Using an online decoder.** Offline-readiness and data-handling rules forbid shipping challenge bytes to a third-party service. Rule now: local script, local keymap table.
- **Assuming a second keyboard is absent.** Composite captures can hold several devices; a mix of two interleaved streams decodes as garbage. Rule now: group by device address first.
- Narrower replacement: interface check → report shape check → transitions → keymap → optional second-layer decode.

## Evidence status

- **Status:** source-derived, untested (no `tshark` and no USB capture in this environment).
- **What we actually ran:** nothing — no decoding script was written or executed, so the card describes the method and references the keymap rather than embedding code as judged-correct.
- **Our adaptation vs the source:** drafted card PCAP-008 described filtering and mapping; this version adds device-address grouping and explicit release/repeat handling, which is where naive decoders fail.

## Sources

- `src-metactf-key-evidence-9f635ac3` — keyboard HID decoding from a capture; report-layout assumption and its limits (organizer-authored challenge writeup).
- `src-snakectf-ordinary-keyboard-19216912` — the non-standard-descriptor path and the post-HID encoding layer (organizer-authored writeup).
- `src-tshark-man-page-d914bcdd` — field-extraction mechanics used by the one-liner.
- Attribution limit: the USB HID specification (maintainer: USB-IF) is the authority for report layouts. The orchestrator reported a HID-specification record in `sources/verified-index.jsonl`, but that file was not readable in this worker session, so no source id is asserted for it here.
