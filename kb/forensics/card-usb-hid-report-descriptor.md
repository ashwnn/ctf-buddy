# When HID decoding is garbage, read the report descriptor instead of the keymap

**First useful action.** Find the device's report descriptor in the capture and derive the report layout from it; a decoder built from the descriptor cannot be "the wrong keyboard layout".

```bash
tshark -r <CAPTURE.pcap> -Y "usb.setup.bRequest==0x06" -T fields -e frame.number -e usb.device_address -e usb.setup.wValue -e usb.capdata | grep -i '2222\|0x22' ; tshark -r <CAPTURE.pcap> -Y "usb.control.Response==1" -T fields -e frame.number -e usb.capdata | head -n 5
```

Expected: one or more control transfers whose `wValue` high byte is `0x22` (report descriptor) with a byte blob attached. If nothing matches, the descriptor may sit in a setup/response pair your build labels differently — dump all control-transfer payloads for that device address and read them by hand.

## Symptoms

- Standard keyboard decoding produces structured-looking but wrong output, or output that changes shape mid-capture.
- The decoded "keystrokes" include characters no keyboard emits, or the report is not 8 bytes.
- The writeup community notes a challenge with a deliberately non-standard descriptor (snakeCTF 2024 Quals `ordinary-keyboard` did exactly this).

## Prerequisites and assumptions

- The capture includes the enumeration phase (device/configuration/report descriptors) or at least the HID interface's control transfers.
- You can read HID item encoding: a short item byte packs size in bits 0-1 (0/1/2/4 bytes), type in bits 2-3 (0 = Main, 1 = Global, 2 = Local), tag in bits 4-7; e.g. `0x05` = Global Usage Page, `0x09` = Local Usage, `0xA1` = Main Collection, `0x75` = Global Report Size, `0x95` = Global Report Count, `0x81` = Main Input, `0x85` = Global Report ID.
- Stack/version: Wireshark/TShark USB field names vary between releases; validate the filter names with `tshark -G fields`.

## Diagnostic sequence

1. Extract the descriptor blob and split it into items using the size/type/tag rules above. Interpretation: Global items set the *next* field's width and count; Local items bind usages; Main items (Input/Output/Feature) commit a field.
2. Reconstruct the report layout: walk the Input items in order, summing Report Size × Report Count bits, and note Constant padding and any Report ID prefix. Branch: layout matches `modifier(8) + reserved(8) + 6×8` → standard (card-usb-hid-keyboard-decode); anything else → build a custom decoder from *this* layout.
3. Check the usage range: a keyboard-like device normally declares Usage Page 0x07 with Logical Minimum 0 and Logical Maximum ≥ 0x65. Branch: a small logical maximum (e.g. 0x1F) means the device reports an *index* into a custom key set, not HID usage codes → decode indices, then decode the resulting alphabet downstream (snakeCTF's challenge added a Base32 layer after the custom keyboard, S037).
4. Handle multiple interfaces and Report IDs: key your decoder by (device address, interface, report ID). Branch: reports from two layouts are interleaved → split before decoding, never after.
5. Validate the decoder against the capture: every report must consume exactly the declared number of bytes; a byte-count mismatch means your layout is wrong.

If the descriptor parses cleanly but the values still look random, go to card-unknown-payload-encoding. If there is no descriptor anywhere in the capture, treat the device as an unknown binary protocol (card-unknown-protocol-triage) and derive framing from the byte lengths instead.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -Y "usb.setup.bRequest==0x06" -e usb.setup.wValue` | GET_DESCRIPTOR requests | `0x22xx` = report descriptor; `0x0100` = device descriptor |
| `-e usb.capdata` on control responses | raw descriptor bytes | The blob to parse item by item |
| `-e usb.device_address -e usb.interface_id` | device/interface split | Keeps two layouts from being mixed |
| byte-count check while decoding | expected vs observed report length | A wrong layout shows up immediately |
| `tshark -G fields \| grep -i 'usb.setup\|control.Response\|capdata\|usbhid'` | local field names | Prevents "the field does not exist, therefore no descriptor" mistakes |

## State-changing actions (only if the card changes a host or service)

Not applicable — descriptor parsing is offline analysis of a capture. Do not plug the challenge device into anything during the event unless the organizers say you may.

## Exploit → patch pair (web/service cards where applicable)

Not applicable in the forensics lane. The security lesson worth keeping: HID devices are trusted input authorities, and a device with a non-standard descriptor still behaves like a keyboard to the OS — that is an endpoint-hardening concern, not a patch to apply mid-event.

## Failure modes and things teams stopped doing

- **Swapping keyboard layouts and encodings on garbage output.** If the framing is wrong, the keymap cannot rescue it; snakeCTF's `ordinary-keyboard` exists precisely because standard decoders fail on a non-standard descriptor (S037). Rule now: descriptor first, keymap second, encoding third.
- **Assuming one report per keystroke.** Custom descriptors can pack several fields into one report, or split one action across reports. Rule now: derive the meaning of *fields*, then build events.
- **Ignoring Report IDs.** A leading report-ID byte shifts every subsequent field by one byte and is the most common cause of "almost correct" decoding. Rule now: check for a Report ID item before writing the parser.
- **Running a downloaded decoder script from a writeup.** Repo conventions treat downloaded content as data, and install hooks/scripts are forbidden; a copied decoder also has no provenance for the challenge's descriptor. Rule now: parse the descriptor ourselves, in our own few lines of code.

## Evidence status

- **Status:** source-derived for the failure mode, operator-derived for the parsing procedure; untested (no capture, no `tshark`, no decoder executed in this environment).
- **What we actually ran:** nothing.
- **Our adaptation vs the source:** drafted card PCAP-009 said "inspect the descriptor"; this version turns it into an item-walk procedure with a byte-count validation step, and adds the small-logical-maximum branch that indicates a custom key alphabet rather than HID usage codes.

## Sources

- `src-snakectf-ordinary-keyboard-19216912` — organizer writeup of a challenge built on a non-standard HID report descriptor, including the downstream Base32 step.
- `src-metactf-key-evidence-9f635ac3` — the conventional-descriptor path this card is the escape hatch from.
- `src-tshark-man-page-d914bcdd` — field extraction mechanics.
- Attribution limit: the USB HID specification (USB-IF) is the authority for item encoding and report layout. The orchestrator reported a HID-specification record in `sources/verified-index.jsonl`, but that file was not readable in this worker session, so no source id is asserted for it here.
