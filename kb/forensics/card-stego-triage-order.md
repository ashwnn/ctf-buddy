# Work steganography in a fixed order and stop when the evidence stops

**First useful action.** Identify the container and its structure before transforming pixels or samples: cheap structural checks eliminate most stego challenges in the first minutes.

```bash
file <ARTIFACT> ; exiftool <ARTIFACT> ; pngcheck -v <ARTIFACT> 2>/dev/null ; strings -a -n 6 <ARTIFACT> | head -n 40
```

Expected: a container type, its metadata, its internal structure, and any embedded text. If `pngcheck` reports a chunk after `IEND`, or the file size exceeds the sum of the declared structure, you are looking at appended data, not LSB steganography.

## Symptoms

- A challenge hands you an image/audio/PDF file with no further hint.
- A teammate is already running every stego tool they can remember, in no particular order.
- Extracted output looks like noise and the team keeps trying wider parameter sweeps.

## Prerequisites and assumptions

- Tools for structure first (`file`, `exiftool`, `pngcheck`, `strings`, `xxd`) and for content second (an LSB extractor for PNG/BMP, an audio analysis tool for WAV/MP3).
- Offline operation: do not upload challenge files to online decoders or stego services.
- Stack/version: `pngcheck` 2.x/3.x, `exiftool` 12.x, `zsteg` (Ruby gem) for PNG/BMP LSB; availability differs per event laptop.

## Diagnostic sequence

1. Container identity and metadata (`file`, `exiftool`) → branch: meaningful metadata (comment, author, coordinates, an odd tool name) → follow the hint before touching pixels.
2. Structural integrity (`pngcheck -v`, or a chunk/section walker for GIF/PDF/WAV) → branch: checksum errors or unexpected chunks → fix the structural reading first; trailing data after the end marker → carve that region and treat it as a nested artifact (card-carving-binwalk-foremost).
3. Text-level scan: `strings -a -n 6`, and look for base64/hex-looking runs inside text chunks or comments → branch: encoded-looking text → card-unknown-payload-encoding.
4. Only now content-level transforms, cheapest and most reversible first: LSB/bit-plane extraction for lossless formats, then parameter sweeps. Lossy formats (JPEG, MP3) rarely carry reliable LSB data — prefer structure-based hiding there (comment fields, appended data, thumbnails).
5. Require a domain check on every candidate output: readable text, flag-format match, a valid nested file signature, or a parseable structure. Anything else is a fail and gets recorded as a fail.

If a validated nested artifact appears, loop back to step 1 for that artifact. If two attempts in a row produce structureless output, stop and re-read the challenge text rather than widening the search (our stop rule, consistent with the corpus's stance that heuristic output is not proof, S035).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file <ARTIFACT>` | container type | Which structure checker and which transform family apply |
| `exiftool <ARTIFACT>` | metadata table | Hints, provenance, and sometimes the payload |
| `pngcheck -v <ARTIFACT>` | chunk list with lengths | Structural truth for PNG; reveals appended/odd chunks |
| `strings -a -n 6 <ARTIFACT> \| head` | visible text runs | Hints and encoded layers |
| `xxd <ARTIFACT> \| tail -n 20` | trailing bytes | Appended data after the end marker |
| bit-plane/LSB extractor output | candidate text/bytes | Hypothesis, not a result — validate against a domain check |

## State-changing actions (only if the card changes a host or service)

Not applicable — stego work is offline artefact analysis. The only operational rule is to keep candidate outputs out of the tracked repository when they may contain live flags or hostile content.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — steganography analysis does not modify a service, and this card makes no claim about a service-side flaw.

## Failure modes and things teams stopped doing

- **Tool roulette.** Running every stego tool with default settings produces plausible-looking noise; the CyberChef Magic source record makes the general point for heuristic transforms — suggestions are speculative and require independent validation (S035). Rule now: structure before content, and domain-check every output.
- **Small-parameter sweeps masquerading as analysis.** Widening bit offsets/planes because "it nearly worked" is the stego version of recursive decoding; the corpus's stop rule for layered decoding applies here unchanged.
- **Using online stego services.** Offline readiness and data-handling rules forbid it; a flag or a hint uploaded to a third party is a real incident during an event.
- **Assuming the answer is in the pixels.** Appended archives, metadata fields, and text chunks are far more common in challenge design than robust LSB encoding. Rule now: structural checks first, LSB later.
- **Forgetting provenance.** Every extracted candidate needs the artifact name, the transform, the exact parameters, and a hash; otherwise a found flag cannot be reported defensibly.

## Evidence status

- **Status:** operator-derived and unresolved; untested (no image fixtures, no stego tooling in this environment).
- **What we actually ran:** nothing.
- **Our adaptation vs the source:** the corpus explicitly declined to write a stego card in the first pass because no primary-source set had been collected, and this worker session still has no verified stego source. The card therefore encodes a *decision order and stop rule* rather than tool claims, and every tool name is marked as needing local confirmation. **Disclosed gap:** no verified primary source backs the tool-specific steps; treat them as team practice, not as sourced fact.

## Sources

- `src-cyberchef-magic-source-2a3dcc0a` — heuristic transforms produce speculative candidate chains, not proof; the validation obligation used in step 5.
- `src-wireshark-export-objects-4056c43f` — structure-aware extraction beats blind transformation when the container is a protocol stream.
- No maintainer documentation for stego tooling is cited: none was readable in this session.
