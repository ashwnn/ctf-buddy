# Read ELF headers before choosing architecture, tool, or address model

**First useful action.** Dump the ELF header and the program headers once, and write down class,
endianness, machine, type, and entry before touching any interactive tool.

```bash
readelf -h <ARTIFACT>; readelf -l <ARTIFACT> | head -n 40
```

Expected: an ELF header block and a program-header table with `LOAD` segments plus their virtual
addresses and permissions. If `readelf` reports `Not an ELF file`, branch to
`card-rev-tool-family-by-content-type`.

## Symptoms

- A writeup's addresses fail to line up with your debugger.
- You cannot decide between 32-bit and 64-bit register sets, or whether the base address is fixed.
- `objdump` output is ambiguous about whether the artifact is an executable or a shared object.

## Prerequisites and assumptions

- The artifact is ELF (confirmed by `file`). For other formats use the vendor tooling instead.
- `readelf` and `objdump` installed; the repository build pass confirmed both command shapes.
- Stack/version: output columns vary slightly across binutils releases, and the fields you need
  (class, machine, type, entry, segment permissions) are stable across those releases.

## Diagnostic sequence

1. `readelf -h <ARTIFACT>` → `Class` and `Data` fix register width and endianness. Getting this wrong
   invalidates every later instruction decode.
2. `readelf -h` → `Type`: `EXEC` (fixed load address) versus `DYN` (PIE/shared, load address
   randomized). This decides whether a hardcoded address is meaningful.
3. `readelf -l <ARTIFACT>` → segment permissions. A segment that is both writable and executable is
   worth a second look, but on its own it proves nothing about intent.
4. `readelf -d <ARTIFACT>` → dynamic entries, interpreter, and `NEEDED` libraries.
5. Only now select the tool and language: Ghidra for compiled code, gdb for controlled execution,
   neither for Office containers.

If the header says `DYN` → plan on base-relative addressing before quoting any absolute address.
If it says `EXEC` → addresses in the file are usable but confirm the loader's base anyway.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `readelf -h <ARTIFACT>` | `Class: ELF64`, `Data: 2's complement, little endian` | 64-bit little-endian: x86-64/AArch64 register widths apply |
| `readelf -h <ARTIFACT>` | `Type: DYN` | PIE/shared object: compute the runtime base first |
| `readelf -h <ARTIFACT>` | `Entry point address: 0x<ADDR>` | Where execution begins; not necessarily where the interesting logic lives |
| `readelf -l <ARTIFACT>` | `LOAD ... RWE` | Writable+executable segment: note it as a hypothesis, never as a verdict |
| `objdump -f <ARTIFACT>` | `file format elf64-x86-64` | Independent confirmation of architecture for the disassembler |

## Failure modes and things teams stopped doing

- Copying addresses out of a writeup for a different build. Anyone who has tried a fixed address on a
  `DYN` binary has watched a debugger land in unmapped memory; treat published addresses as
  build-specific until you confirm type and base.
- Trusting a single tool's format label. `file`, `readelf`, and `objdump` occasionally disagree on
  wording for unusual artifacts; the header fields are the tiebreaker.
- Reading program headers when section headers are the actual question (or the reverse). Sections
  describe linking; segments describe what the loader maps. Both matter for different hypotheses.
- Concluding "non-ELF means unsupported". A PE or a script is a different tool chain, not a dead end
  — see `card-rev-tool-family-by-content-type`.

## Evidence status

- **Status:** source-supported but untested in this session; version-sensitive in output wording.
- **What we actually ran:** nothing here. The repository's 2026-09-11 build pass recorded
  `readelf -h <ARTIFACT>` and `objdump -f <ARTIFACT>` as fixture-verified command shapes against
  `/bin/true`; that verification belongs to that pass, not to this worker session.
- **Our adaptation vs the source:** the repository draft REV-002 supplied the tool ordering; we added
  the PIE/`DYN`-versus-`EXEC` branch, the segment-permission caution, and the explicit statement that
  a writable+executable segment is a hypothesis and not a finding.

## Sources

- `src-ghidra-intro-guide-a55dff83` — the documented requirement to establish file type and processor
  before analysis begins.
- `src-gdb-memory-docs-c1468386` — GDB's own note that target architecture and build affect the
  formats, sizes, and features available; the reason header facts must be settled before debugging.
