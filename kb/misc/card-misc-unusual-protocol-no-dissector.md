# Reconstruct an unusual protocol when no dissector understands it

**First useful action.** Follow the raw stream and read the bytes, instead of assuming the capture is
encrypted because the dissector shows nothing useful.

```bash
tshark -r <PCAP> -q -z follow,tcp,raw,<STREAM_INDEX> | head -n 40
```

Expected: a raw hex transcript of both directions. If this errors, check the installed version's
supported follow types with the tool's own help; exact `-z` syntaxes differ across releases.

## Symptoms

- The capture has traffic to the interesting port but the dissector labels everything as generic TCP or
  data.
- Some messages decode partially, so the framing is probably known and the payload semantics are not.
- A challenge mentions a "custom", "legacy", or "unusual" protocol.

## Prerequisites and assumptions

- A capture and a candidate stream (identified by port, peer, or timing).
- `tshark` or Wireshark of a version recorded alongside the finding; the corpus notes that option sets
  and stream types vary across releases.
- The willingness to work at the byte level as a first-class method, not as a fallback.

## Diagnostic sequence

1. Identify candidate streams by volume and endpoints rather than reading packets sequentially
   (conversation/endpoint statistics are cheaper than scrolling).
2. Follow the stream in raw form. Look for framing: fixed-length records, length prefixes, delimiters,
   request/response alternation.
3. Write down the frame structure you believe you see, then test it: does it partition the *entire*
   stream without leftovers? Leftover bytes falsify the model cheaply.
4. Once framing holds, extract field candidates and look for structure in each: counters, lengths that
   match payload sizes, identifiers that repeat.
5. If a field looks like a name, path, or credential, treat it as text and check whether further
   decoding is justified (`card-crypto-classify-before-decoding`) rather than assuming obfuscation.

If framing holds and fields are readable → you have the protocol; document it and move to exploiting or
patching as the challenge requires. If framing does not hold → check whether it is a *framed* protocol
with a header you have not noticed (TLS-like, length-prefixed, or chunked), or whether the capture is
truncated. If the capture is truncated, record that limitation; many "unknown protocol" cases are
captures that end mid-message.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `-q -z follow,tcp,raw,<N>` | hex transcript | Byte-level ground truth for framing analysis |
| `-q -z follow,tcp,ascii,<N>` | readable transcript | Useful when the payload is text; hides binary framing |
| conversation/endpoint statistics | byte/packet counts per pair | Picks the streams worth reading |
| repeated length-prefixed blocks | consistent frame boundaries | Framing hypothesis confirmed |
| leftover/unparsable tail | model failure | The framing assumption is wrong, or the capture is truncated |

## Failure modes and things teams stopped doing

- Declaring "encrypted" because a dissector showed no protocol. Undecoded traffic is not evidence of
  encryption; entropy-like appearance and dissector failure are different observations.
- Reaching for advanced carving before reconstructing the conversation. The corpus's packet-analysis
  material is clear that following a stream is the basic tool, and export/carve workflows are for
  artifacts, not for understanding an exchange.
- Reading packets one by one through a large capture. This is the same inefficiency that conversation
  triage exists to avoid.
- Ignoring the tool version. `tshark` and Wireshark option sets change across releases; a command copied
  from an online example may not exist in your build. Record the version with the finding and check local
  help when a syntax fails.

## Evidence status

- **Status:** documentation-derived but untested in this session; explicitly version-sensitive.
- **What we actually ran:** nothing. `tshark`/`tcpdump` were not available in the repository's build
  fixture either, so no follow/stream command in this card has been executed anywhere in this project.
- **Our adaptation vs the source:** the framing-test step ("does it partition the whole stream?") and the
  truncated-capture branch are our additions; the follow-stream mechanics are documented tooling
  behavior from the sources below.

## Sources

- `src-wireshark-follow-stream-00828e3e` — documented stream-following behavior and the representations
  available for reading a conversation.
- `src-tshark-man-page-d914bcdd` — the CLI surface for scriptable stream extraction, with the version caveat
  recorded by the repository index.
- `src-zeek-file-analysis-4f12a413` — the contrast between extracting files from a capture and reconstructing
  the protocol that carried them.
