# Treat a non-standard HID report descriptor as the protocol specification

**First useful action.** Decode the device's HID report descriptor before attempting any keycode
decoding, and build the byte layout from it.

```bash
# capture in hand; list devices and interfaces first, then the descriptor
tshark -r <USB_PCAP> -Y "usb.idVendor" -T fields -e usb.src -e usb.dst -e usb.idVendor -e usb.idProduct | sort -u
```

Expected: one or more USB devices with vendor/product identifiers. If nothing appears, the capture may
not include the descriptor exchanges — check whether the capture started after device enumeration, and
say so, because that limitation constrains everything downstream.

## Symptoms

- A standard keyboard decoder over the capture produces garbage, repeated characters, or nothing.
- The device identifies as a HID keyboard but its reports do not match the common 8-byte layout.
- Some reports appear to carry multiple values, or the challenge mentions Base32/Base64-style encoding
  after decoding.

## Prerequisites and assumptions

- A USB capture that includes either enumeration (descriptor exchange) or enough consistent data to
  infer the layout empirically.
- A HID usage-table reference and a parser for report descriptors (or patience to read the item
  structure by hand).
- The organizer's own challenge writeup is the strongest reference here and it is explicit that the
  descriptor was deliberately non-standard — which is why standard decoders fail by design.

## Diagnostic sequence

1. Enumerate devices/interfaces from the capture. Confirm which interface belongs to the puzzle device
   rather than to a hub or a composite function.
2. Locate and decode the report descriptor. Extract report IDs, field widths, field counts, usage pages
   and usages, and logical ranges.
3. Build the decoder from those fields: bit/byte offset, width, and meaning for each field. Write the
   offsets in the notes — guessed offsets are what make later reasoning unverifiable.
4. Apply the decoder to the interrupt/bulk transfer payloads and check that decoded values are in the
   declared logical range. A value outside the declared range means the layout or the report ID is
   wrong.
5. Only after raw values are correct, map them to higher-level symbols, and only after that apply any
   further encoding stage the challenge uses.

If the descriptor is decodable → proceed with the values. If descriptors are absent from the capture →
infer the layout from repeated structure (which bytes change on each event, which are constant) and mark
the inference as unverified. If the decoded values are in range but nonsense → you may be reading the
wrong interface or report ID; re-check step 1 before touching the symbol mapping.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `tshark -r <PCAP> -Y "usb.idVendor" -T fields ...` | device/interface list | Which device and interface to decode |
| descriptor bytes with usage items | field definitions | The authoritative layout: widths, counts, ranges |
| report payload byte count | fixed size per report ID | Cross-check against the descriptor's total field bits |
| decoded value outside logical range | out-of-spec | Wrong report ID, offset, or endianness assumption |

## Failure modes and things teams stopped doing

- Swapping keyboard layouts and encodings when the framing is wrong. The organizer writeup behind this
  card records a deliberately non-standard descriptor that defeats stock decoders; the fix is reading
  the descriptor, not trying more key maps.
- Ignoring the descriptor because a "known" layout seemed to work for part of the capture. Partial
  agreement is how wrong decoders survive; check the declared ranges.
- Assuming all reports have the same length. Report IDs and variable fields produce different lengths;
  a parser that assumes a fixed size silently misaligns everything after the first exception.
- Decoding a second encoding stage before raw values are trusted. Higher-stage confidence cannot exceed
  the confidence of the bytes underneath it.

## Evidence status

- **Status:** source-supported but untested; the `tshark` field-shape example is our construction and
  cannot be verified without a local TShark installation (not available in the repository's build
  fixture either).
- **What we actually ran:** nothing. No capture was parsed in this session and no USB device was
  involved.
- **Our adaptation vs the source:** the descriptor-first rule comes from the organizer writeup we cite
  (via the repository index); field-by-field range checking, the report-ID caution, and the
  "capture started late" limitation are our additions.

## Sources

- `src-snakectf-ordinary-keyboard-19216912` — organizer writeup of a challenge built on a deliberately
  non-standard HID report descriptor, including a later encoding stage.
- `src-metactf-key-evidence-9f635ac3` — organizer writeup that assumes a particular USB keyboard
  report structure; the contrast that motivates descriptor-first decoding.
- `src-wireshark-follow-stream-00828e3e` — protocol reconstruction background for the capture side.
