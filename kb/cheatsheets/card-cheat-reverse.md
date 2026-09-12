# Reverse engineering: static first, dynamic second

**First useful action.** Get the file type, the imports, the strings, and the entry point before
opening a decompiler. Most challenge binaries announce what they are in the first four commands.

```bash
BIN='<BINARY>'
file "$BIN" && readelf -h "$BIN" | head -20
strings -n 6 "$BIN" | head -60
readelf -d "$BIN" 2>/dev/null | head -20      # dynamic: it links libc; static: it does not
```

Expected: architecture, whether it is PIE/stripped, the language runtime it links, and a handful of
strings that name the format, the checks, or the flag path.

## Symptoms

- A binary with no source and a question about the check it performs.
- A packed/obfuscated blob that refuses to disassemble usefully.
- A macro document, an OLE file, or a container of scripts.

## Prerequisites and assumptions

- `file`, `readelf`, `strings`, `nm`; optional `upx -d`, `ghidra`, `radare2`, `gdb`+`pwndbg`.
- Run untrusted binaries only in a disposable VM/container, never on the operator laptop.
- Stack/version: gdb/pwndbg command syntax is stable; decompiler output is version-sensitive.

## Diagnostic sequence

1. `file` + `readelf -h` → if `UPX` appears in strings, unpack first (`upx -d`) and re-run.
2. `strings -n 6` and `nm -D` → the function names and messages usually name the algorithm.
3. Locate the comparison or the win condition: in a decompiler, xref the "wrong/Correct" strings
   (`card-rev-ghidra-string-xref-pivot`) rather than reading `main` top to bottom.
4. Confirm anything dynamic in gdb at the decision point, not by stepping from `_start`:
   `gdb -q ./bin -ex 'b *0x<ADDRESS>' -ex run -ex 'x/8gx $rsp'`
   (`card-rev-gdb-state-snapshot-diff`, `card-rev-gdb-targeted-memory-inspection`).
5. For documents: `olevba`/`oleobj` before any decompiler (`card-rev-olevba-macro-triage`).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `file "$BIN"` | `ELF 64-bit LSB pie executable, x86-64` | architecture and PIE-ness |
| `readelf -h "$BIN"` | `Type: DYN (PIE)`, `Entry point 0x...` | where execution starts; DYN means addresses slide |
| `readelf -d "$BIN"` | `NEEDED libc.so.6` | dynamic; no `NEEDED` and big file means static |
| `strings -n 6 "$BIN" \| rg -i 'flag\|correct\|wrong\|key'` | candidate messages | anchors for xrefs |
| `nm -C "$BIN" \| head` | symbols (or `no symbols`) | stripped or not; C++ names demangled |
| `objdump -d --no-show-raw-insn "$BIN" \| less` | disassembly | fallback when no decompiler is available |
| `upx -d "$BIN" -o "$BIN.unpacked"` | `Unpacked 1 file` | packed with UPX; work on the unpacked copy |
| `gdb -q "$BIN" -ex 'set follow-fork-mode parent' -ex run` | gdb prompt | dynamic confirmation of the static reading |
| `olevba "$DOC"` | macro source + IOCs | Office document triage before anything else |

## State-changing actions (only if the card changes a host or service)

None: reverse engineering reads the artifact. The only rule with teeth is isolation — run the binary
in a VM with no network and no shared folders.

## Failure modes and things teams stopped doing

- Reading `main` top to bottom in a decompiler; the interesting function is almost never there.
- Patching the binary to skip a check before understanding what the check computes — the "solution"
  then fails the real validator (`card-rev-ghidra-decompiler-judgment`).
- Ignoring packaging: a "custom crypto" routine that is a known library after `upx -d`.
- Treating compiler-generated noise as deliberate obfuscation.

## Evidence status

- **Status:** source-supported; commands are generic toolchain usage.
- **What we actually ran:** nothing in this repository (no reverse fixtures shipped). The cards in
  `kb/reverse/` record what the source teams did.
- **Our adaptation vs the source:** the four-command identification block is ours.

## Sources

- `src-gdb-memory-docs-c1468386` — examining memory at a chosen breakpoint.
- `src-pwndbg-docs-0ce3ac51` — context/step workflow over bare gdb.
- `src-ghidra-intro-guide-a55dff83` — decompiler workflow and string xrefs.
- `src-radare2-book-eda5089b` — `rabin2`/`r2` alternative toolchain.
- `src-upx-repo-06fd2cb3` — unpacking.
- `src-oletools-olevba-30832d42`, `src-oletools-oleobj-7dbd4193` — macro/embedded-object triage.
- `src-sysv-amd64-abi-6cb16e19` — calling convention when reading disassembly by hand.
