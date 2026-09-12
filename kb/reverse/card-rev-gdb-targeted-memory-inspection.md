# Inspect exactly the memory you need with GDB's x command

**First useful action.** Stop at the point you care about and dump a bounded region in a deliberately
chosen size and format instead of dumping memory broadly.

```bash
gdb -q <LOCAL_FIXTURE_BINARY> -ex 'set pagination off' -ex 'break <FUNC_OR_LINE>' -ex run
# then, at the stop point:
(gdb) x/16gx <ADDRESS_OR_EXPRESSION>
```

Expected: sixteen 8-byte words starting at the given address, which should contain the buffer,
pointer, or structure you broke for. If GDB reports an invalid address, the expression is wrong —
check the register/symbol and the stop point rather than widening the dump.

## Symptoms

- You need to know whether a decoded value is still present after a parsing step.
- A pointer gives you the address of data, and you need the bytes at that address, not the pointer.
- You are reasoning about a structure but cannot tell where the field boundary lies.

## Prerequisites and assumptions

- You can run the artifact inside an isolated fixture (`<LOCAL_FIXTURE_BINARY>`), never on shared or
  organizer infrastructure and never on an artifact you have not decided is safe to execute.
- GDB installed. Stack/version: available formats, sizes, and features depend on the target
  architecture and the local GDB build, so confirm format letters on your own machine once.
- A stop point: function name, source line, or address from the analyzer.

## Diagnostic sequence

1. Break at the boundary you are testing (before parsing, after parsing, at the comparison) and run
   with controlled input so the state is reproducible.
2. `x/<count><format><unit> <expr>` with an explicit format: `x` hex, `s` string, `i` instructions,
   `g` giant (8-byte), `w` word (4-byte), `b` byte. Choose the unit that matches the data model.
3. Dump the same region twice, before and after the step under test, and compare. A change proves the
   step touched that memory; a lack of change falsifies your hypothesis cheaply.
4. For a pointer value, dump both the pointer word (`x/gx $rsp+0x10`) and the target
   (`x/32bx *0x<ADDR>` after reading the value) — mixing these up is the most common mistake.
5. Keep each dump bounded (16-64 units). Record the exact command and its output for the findings note
   so a teammate can reproduce it without re-deriving the address.

If the dump shows a readable string where you expected binary → you are at the wrong address, or the
data was already decoded. If the dump is unreadable/unmapped → the value was a length, a tag, or an
offset rather than an address.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `x/16gx <ADDR>` | 16 eight-byte words | Good default for pointers and 64-bit structure fields |
| `x/32bx <ADDR>` | 32 individual bytes | Byte-level layout: boundaries, padding, magic bytes |
| `x/s <ADDR>` | a quoted string | Confirms a char buffer; stop at the first NUL, so it can hide trailing data |
| `x/8i $pc` | 8 instructions | Confirms you are at the instruction you think you are |
| `x/4gx $rsp` | stack words | Stack locals/arguments; useful before and after a call |

## Failure modes and things teams stopped doing

- Dumping thousands of bytes and scrolling. A wide dump answers nothing; the discriminating question
  is "did this specific location change after this specific step".
- Trusting `x/s` for a buffer that may contain embedded NULs or trailing payload — use a byte dump
  when the challenge is about raw bytes.
- Assuming the same command works unchanged on a different architecture. GDB's own documentation
  notes that formats, sizes, and features depend on the target and build; verify once per target.
- Debugging on a shared or live service. A debugger changes timing and state; anything you learn there
  may not describe the checker-visible service, and repository rule 1 keeps execution inside
  authorized fixtures.

## Evidence status

- **Status:** source-supported but untested in this session.
- **What we actually ran:** nothing. No debugger was started by this worker and no binary was executed;
  the syntax is drawn from GDB's documented memory-examination syntax, and the specific example
  command line is our construction (the repository draft REV-005 phrased it as a pattern, not a
  literal invocation).
- **Our adaptation vs the source:** the before/after comparison rule and the
  pointer-versus-target confusion warning are our operational additions; the format/size semantics
  come from GDB's own documentation on examining memory.

## Sources

- `src-gdb-memory-docs-c1468386` — GDB's documented memory-examination syntax and its warning that
  target architecture and build affect available formats and sizes.
- `src-ghidra-intro-guide-a55dff83` — obtaining addresses and function boundaries to break on.
