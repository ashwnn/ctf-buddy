# Prove parser behavior with a before/after memory snapshot, not with inference

**First useful action.** Take one bounded dump before the parser call and one after, on identical
input, and let the difference tell you what the parser actually produced.

```bash
# inside an isolated fixture copy of the artifact
gdb -q <LOCAL_FIXTURE_BINARY> \
  -ex 'set pagination off' -ex 'break <PARSE_ENTRY>' -ex run \
  -ex 'x/32bx <BUFFER_ADDR>' -ex 'continue' \
  -ex 'x/32bx <BUFFER_ADDR>' -ex 'quit'
```

Expected: two byte dumps of the same region, one at the input state and one after the call returns.
If the two dumps are identical, the function under test is not the one transforming that region —
re-check the breakpoint and the address.

## Symptoms

- A challenge binary claims to validate or transform input, and you cannot tell what the in-memory
  representation really is.
- You suspect an off-by-one, a truncation, or an endianness conversion but have no proof.
- A structure field's meaning is ambiguous and the decompiler cannot settle it.

## Prerequisites and assumptions

- A locally runnable fixture with byte-identical input each run (fixed seed, no timestamps, no
  randomization) so that the two snapshots are comparable.
- The buffer address or a symbol expression that survives to that point; with PIE, use the
  symbol/expression rather than a hardcoded absolute address.
- Execution stays inside the isolated fixture. This card never runs against a live or shared service.

## Diagnostic sequence

1. Freeze the input: same bytes, same arguments, same environment. Without this, a difference proves
   nothing.
2. Break at the boundary before the transformation; dump the input region in bytes (`x/32bx`) and in
   the unit your model claims (`x/8gx`).
3. Continue and break again after the call; dump the same region with the same command.
4. Compare field by field. Truncation, padding, byte swaps, and terminator placement all become
   visible here in a way pseudocode usually hides.
5. Immediately test the highest-value prediction: craft one input that should change exactly one field,
   and check that only that field changed. A snapshot difference is evidence; a prediction that
   survives is proof.

If the region never changes → the mutation happens elsewhere (a copy, a second buffer, or a library
call). If the region changes but not in the layout you predicted → your structure model is wrong, and
you should rebuild it from the parser code in `card-rev-ghidra-decompiler-judgment` before proceeding.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `x/32bx <BUFFER_ADDR>` | 32 hex bytes | Byte-level ground truth for layout and padding |
| `x/8gx <BUFFER_ADDR>` | 8 eight-byte words | Pointer/field alignment view of the same region |
| `x/2s <BUFFER_ADDR>` | two C strings | Reveals where the first NUL sits, often the real boundary |
| `info registers` at the stop point | register values | Cross-check the address expression used in the dumps |
| `continue` × N | repeated stops | Turns a single observation into a small sequence you can reason about |

## Failure modes and things teams stopped doing

- Comparing dumps across runs with different inputs. Any difference is then explained by the input, not
  by the parser; teams waste hours on this in live-service work too, which is why the attack/defend
  retrospectives insist on a controlled reproduction before patching.
- Reading a matched structure only through the decompiler's type view. Structured types are a
  reconstruction; the byte dump is the observation.
- Debugging on the target service "because it is the same binary". Different loader, environment,
  and concurrency change behavior; lesson recorded by the first-time UMCS 2026 retrospective, which
  patched before understanding the exploit and damaged its own availability.
- Chasing the whole structure. The card stops at the field on the flag path; unrelated layout details
  do not earn their time in a timed event.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session — no debugger, no fixture execution. The `x`
  command semantics are documentation-derived from GDB; the two-snapshot workflow is our extension of
  the repository draft REV-005, and the single-field prediction test is our addition.
- **Our adaptation vs the source:** the "prediction that survives is proof" gate is a researcher
  judgment, not a documented GDB procedure. It exists to keep the difference between observation and
  conclusion explicit.

## Sources

- `src-gdb-memory-docs-c1468386` — the memory-examination foundation this technique is built on.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-hand failure story: patching before understanding, and
  monitoring/observing the wrong layer; the reason this card demands a controlled, reproducible
  fixture instead of live-service inference.
- `src-dttw-defcon2021-retro-14eb5491` — evidence that binary service work is done under time
  pressure, which motivates the deliberately narrow scope of this card.
