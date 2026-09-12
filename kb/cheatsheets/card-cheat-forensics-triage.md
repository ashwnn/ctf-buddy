# Forensics triage: image, memory, and file-artifact commands

**First useful action.** Identify what the artifact *is* before running any extraction tool: the file
type, the filesystem, and whether it is split, compressed, or encrypted. One `file`/`binwalk` pair
saves an hour of wrong tooling.

```bash
ART='<ARTIFACT>'          # disk image, memory dump, or unknown blob
file "$ART"
binwalk "$ART" 2>/dev/null | head -20
```

Expected: either a readable format (ext4, NTFS, ELF, PCAP, ZIP, XZ) or a list of embedded signatures.
A JPEG inside a PDF inside a ZIP is a normal forensic challenge, not a broken file.

## Symptoms

- A single binary artifact and no context ("what is this?").
- A memory dump and a question about a process, a key, or a connection.
- A disk image and a question about a deleted file or a command that ran.

## Prerequisites and assumptions

- `binwalk`, `foremost`, `sleuthkit` (`fls`/`icat`), `volatility3`, `zeek` for network-derived files.
- Read-only handling: copy the artifact first, never mount a scored image read-write.
- Stack/version: filesystem tools differ between distros; the sleuthkit commands below are stable.

## Diagnostic sequence

1. `file` + `binwalk` (above) → decide: filesystem image, memory dump, or file container.
2. Filesystem image → `fls -r -o <OFFSET> image` to list (including deleted entries), then
   `icat -o <OFFSET> image <INODE>` to read one file without mounting.
3. Memory dump → `vol -f dump.raw windows.info` / `linux.pslist`, then `*_filescan` or
   `*_cmdline`. Identify, then dump specific objects (`windows.dumpfiles --virtaddr …`).
4. Container (ZIP/PDF/office) → `binwalk -e` into a scratch directory, or `7z l` first to look before
   extracting.
5. Network-derived files → `zeek -r capture.pcap` and read `files.log`/`extract_files/`
   (`card-zeek-file-inventory`), rather than re-implementing reassembly.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file "$ART"` | `DOS/MBR boot sector`, `ELF 64-bit`, `Zip archive` | which tool family applies |
| `binwalk "$ART"` | signatures + offsets | embedded or appended content |
| `fls -r -o 2048 image.dd` | inode list, `*` marking deleted | deleted-but-recoverable files |
| `icat -o 2048 image.dd 1234 > out.bin` | file bytes | recover one inode without mounting |
| `vol -f dump.raw linux.pslist` | process table | what was running; pivot to `linux.bash` / `linux.proc` |
| `vol -f dump.raw windows.netscan` | socket table | connections at capture time (`card-artifact-connection-correlation`) |
| `binwalk -eM --directory scratch "$ART"` | extraction log | recursive carving; check the output tree, do not trust the count |
| `foremost -T -i "$ART" -o out/` | carved files | recovery when binwalk's extraction fails |
| `zeek -r capture.pcap` then `cat files.log` | file records | network-derived objects with hashes and MIME types |

## State-changing actions (only if the card changes a host or service)

None. Carving writes only into the directory you name; keep that directory inside the repository's
git-ignored `captures/` or `/tmp`, never next to an exhibit you might need to re-verify.

## Failure modes and things teams stopped doing

- Mounting an evidence image read-write and changing the mtime of every file you look at.
- Running the memory profile for Windows on a Linux dump (or the reverse) and concluding the dump is
  corrupt.
- Treating `binwalk` output as a file list: it is a signature list, and offsets are not sizes.
- Losing the offset when jumping between `fls` and `icat` (`-o` must be identical).

## Evidence status

- **Status:** source-supported, version-sensitive (volatility symbols and binwalk versions change).
- **What we actually ran:** nothing on a real exhibit; the drill assets are synthetic PCAPs, not disk
  images. The commands come from the manuals listed below.
- **Our adaptation vs the source:** the identify-then-extract ordering and the read-only handling rule
  are ours.

## Sources

- `src-sleuthkit-man-8143b04f` — `fls`/`icat` semantics and offsets.
- `src-binwalk-repo-c9f54f48`, `src-foremost-repo-1cac79f0` — carving and signature extraction.
- `src-volatility3-docs-8f56170f` — dump, process, and network plugins.
- `src-zeek-file-analysis-4f12a413`, `src-zeek-file-analysis-ad0bf877` — network file extraction.
- `src-metactf-key-evidence-9f635ac3` — a real challenge where identification decided the approach.
