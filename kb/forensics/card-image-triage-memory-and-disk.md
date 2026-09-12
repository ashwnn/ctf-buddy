# Triage a memory or disk image in a fixed order, on a hashed copy

**First useful action.** Hash the image and work on a copy; then run the OS-identification step before any plugin sweep, because every later command depends on knowing what you are looking at.

```bash
sha256sum <IMAGE> > <OUTDIR>/image.sha256 ; file <IMAGE>
vol -f <MEMORY_IMAGE> <OS>.info          # e.g. windows.info / linux.pslist style plugin names
mmls -o <OFFSET> <DISK_IMAGE>            # partition layout, then fsstat -o <OFFSET>
```

Expected: an OS/format identification plus either a partition table or a kernel/OS metadata dump. If `vol` rejects the plugin name, list the plugins it actually ships (`vol --help`, or the plugin directory) instead of assuming an online recipe applies.

## Symptoms

- The challenge hands you a `.raw`/`.mem`/`.vmem`/`.dd`/`.img` file with no explanation.
- You need process, command-line, or network-context evidence that a capture cannot provide.
- A teammate wants to mount the image directly from the evidence copy.

## Prerequisites and assumptions

- Read-only copy of the image, plus free space (recovery and timelines write more than the image size).
- Memory: Volatility 3 (plugin names are namespaced by OS, e.g. `windows.*`, `linux.*`); Volatility 2 users must translate the older `imageinfo`/`pslist` names. Disk: The Sleuth Kit (`mmls`, `fsstat`, `fls`, `icat`, `mactime`).
- Stack/version: Volatility 3.x with the matching symbol table availability, TSK 4.x; symbol/symbol-table issues are the most common first failure.

## Diagnostic sequence

1. `file <IMAGE>` and, for memory, the OS identification plugin. Branch: OS and version identified → continue; identification fails → try `strings -a -n 8 <IMAGE> | head` for OS banners, and record the uncertainty rather than guessing a plugin set.
2. For **memory**, walk outward: process list → parent/child tree → command lines → network connections → (only if a hypothesis needs it) loaded modules, injected regions, or shell history. Each step should answer a question; stop when the question is answered.
3. For **disk**, identify partitions (`mmls`), then the filesystem (`fsstat -o <OFFSET>`), then build a body file and timeline: `fls -r -m / -o <OFFSET> <IMAGE> > <OUTDIR>/body.txt` and `mactime -b <OUTDIR>/body.txt -d > <OUTDIR>/timeline.csv`. Interpretation: the timeline is what you correlate later (card-timeline-correlation).
4. Recover specific files by inode with `icat -o <OFFSET> <IMAGE> <INODE>` rather than by re-mounting, and hash what you recover; bulk recovery tools are a last resort because they scramble provenance.
5. Re-hash the image after the run to prove the evidence was not modified (this is the only "health check" a forensic workflow needs).

If recovered content is an executable or archive, go to card-carving-binwalk-foremost. If the task is really about a capture, go back to card-pcap-first-pass-triage — image triage is slower and should be justified.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `sha256sum <IMAGE>` before and after | identical digests | Evidence integrity; required for any claim about the image |
| `file <IMAGE>` | `data` or a format guess | Raw memory images are usually `data`; do not stop there |
| `vol -f <MEM> <OS>.info` | OS/version/build | Chooses the plugin family and confirms symbol support |
| `mmls <DISK>` | partition table | Partition start sectors for `-o` offsets |
| `fsstat -o <OFFSET> <DISK>` | filesystem type/params | Confirms the filesystem before listing files |
| `fls -r -m / -o <OFFSET> <DISK>` → `mactime -b … -d` | timeline CSV | Correlatable timeline, including deleted entries |
| `icat -o <OFFSET> <DISK> <INODE> > <FILE>` | recovered bytes | Targeted recovery with intact provenance |

## State-changing actions (only if the card changes a host or service)

- **Impact:** mounting an image or running recovery tools on the *analysis* host can alter the image (write-back) or leave a mount that later confuses tooling. Nothing here touches the CTF service.
- **Preconditions:** image hashed; enough scratch space; you know whether the platform supports read-only loop mounts.
- **Health check before:** `sha256sum <IMAGE>` recorded; `mount | grep <IMAGE>` shows the image is not already mounted.
- **Apply:** prefer inode-level tools (`icat`, `fls`) over mounting; if mounting is unavoidable, mount strictly read-only (`mount -o ro,loop,noexec`).
- **Health check after:** `mount | grep <IMAGE>` (systemd-based hosts may show the image under `/run/media/...`) and re-run `sha256sum <IMAGE>` — digest must be unchanged. Regression probe: `icat` of a known inode still returns the same bytes as before the mount.
- **Rollback:** `umount <MOUNT_POINT>` (or `umount -l` as a last resort), confirm with `mount | grep <IMAGE>`, and re-hash. Rollback is unsafe to skip if the digest changed: re-copy the pristine image before further analysis.

## Exploit → patch pair (web/service cards where applicable)

Not applicable — image triage does not modify a service. Where it feeds a patch decision, the artifact belongs to the service-owner workflow with its own regression tests.

## Failure modes and things teams stopped doing

- **Analysing the original image.** Recovery and mount operations write; the hashed copy is the only defensible working surface. This follows the same before/after discipline the A/D patcher material applies to service state (S004).
- **Plugin-name folklore.** Volatility 2 and Volatility 3 plugin names differ, so recipes copied from older writeups fail; the correct move is to enumerate the installed tool's plugin list. Rule now: identify the tool version before trusting any command from a writeup.
- **Deep-diving one artifact while the clock runs.** The DEF CON retrospectives describe service reasoning under hard time pressure (S008); image triage must be hypothesis-driven, not a full investigation. Rule now: each step answers a question or you move on.
- **Trying to mount a memory image.** Raw memory has no filesystem; teams lose time before realising it needs a memory framework. Rule now: `file` plus OS identification decides the tool family.
- **Over-claiming Windows artifact coverage.** Our corpus has no verified Windows registry/event-log sources yet, so this card deliberately stops at process/cmdline/network/timeline basics; see the missing-evidence note.

## Evidence status

- **Status:** source-supported for the workflow framing, operator-derived for the command order; untested (no Volatility, no Sleuth Kit, no images in this environment).
- **What we actually ran:** nothing — `sha256sum`, `file`, `mount` shapes were not exercised here either.
- **Our adaptation vs the source:** the corpus previously listed memory/disk forensics as a gap; this card closes it at the "first ten minutes" level only, and links out to the timeline card instead of duplicating timeline theory. **Disclosed gap:** no verified maintainer-documentation record for Volatility or The Sleuth Kit was readable in this session (the orchestrator reported such records in `sources/verified-index.jsonl`, which this worker could not read), so plugin/subcommand names must be confirmed against the installed tools.

## Sources

- `src-maplebacon-faustctf-patcher-bf21013c` — hash/snapshot-before-change discipline applied here to evidence copies (via the repo's research source table).
- `src-dttw-defcon2021-retro-14eb5491` — time-pressured service reasoning: depth must be justified by a question.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time-team resource/process mistakes worth avoiding during analysis.
