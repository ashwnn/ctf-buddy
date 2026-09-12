# Judge decompiler output instead of believing it

**First useful action.** For the one comparison you care about, confirm the decompiler's rendering
against the disassembly listing before you build anything on top of it.

```bash
objdump -d --no-show-raw-insn <ARTIFACT> | grep -n -A6 -B6 "<SYMBOL_OR_ADDRESS>"
```

Expected: the real instruction sequence around the decision — `cmp`, `test`, `jcc`, `call` — which
either matches the pseudocode's logic or exposes where it does not. If the symbol is stripped and the
address is unknown, obtain it from the analyzer's listing view of the same function.

## Symptoms

- Decompiler pseudocode shows a type or structure field that contradicts how the data was parsed.
- Two nearby branches look identical in pseudocode but behavior differs at runtime in a fixture.
- You need to choose between "the check is one `cmp`" and "there is a helper that validates".

## Prerequisites and assumptions

- An analyzer project with analysis complete, plus `objdump` for the independent listing.
- Your knowledge of the decompiler is second-hand: the guidance here is documentation-derived, and
  the specific heuristics that make decompilation lossy are tool- and build-dependent.
- Stack/version: decompiler output quality changes between Ghidra releases and with compiler
  optimization level; record the analyzer version alongside any finding.

## Diagnostic sequence

1. Identify the single decision you are testing (a comparison, a length check, an authorization test).
   Broad function-level "understanding" is not a testable goal.
2. Read the decompiler view around that decision → record the pseudo-C as a hypothesis, not a fact.
3. Open the disassembly listing at the same address → look for the actual condition: register
   comparison, signed/unsigned variant, width truncation, fallthrough order.
4. If they agree, keep the pseudocode as a working model, and name variables only for values whose
   role you proved (`req_user`, `session_user`, `path`, `token`); mark unproven ones with a prefix
   such as `maybe_`.
5. If they disagree, the listing wins and the pseudocode was wrong — re-derive the model, then re-test
   in a fixture before quoting either version.

If the decision is inside a big switch/state machine → prefer the caller-visible behavior in a fixture
over reading the whole function. If the discrepancy is a structure layout → check the parser code that
fills the structure before trusting either view.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `objdump -d <ARTIFACT>` | `cmp $0x2,%eax` / `je  <ADDR>` | The actual condition and its width; the authoritative answer |
| `objdump -d <ARTIFACT>` | `call <libc-function>@plt` | A library call: the semantics live outside this binary |
| `readelf -r <ARTIFACT>` | relocation entries | Which call targets are resolved at load time (relates to PLT stubs) |
| Decompiler view, same function | C-like condition | A hypothesis to be confirmed above, not a source of truth |

## Failure modes and things teams stopped doing

- Writing a writeup-quality exploit from pseudocode without a fixture test. The repository's own
  CryptoHack note generalizes: an automated tool's plausible-looking output is a lead, not proof.
- Renaming every variable aggressively and then reasoning from the new names. A wrong name
  (`is_admin` for a length) silently manufactures a vulnerability theory; the disassembly does not
  lie about which register is compared.
- Reversing library code because it appears in the call graph. `strcmp`, `malloc`, and TLS helpers are
  not your challenge; note them and move on.
- Treating an unrecognized structure field as a mystery to solve before testing behavior. Fixture
  behavior is usually cheaper evidence than a full structure recovery pass.

## Evidence status

- **Status:** source-supported but untested; version-sensitive (decompiler quality varies by release).
- **What we actually ran:** nothing. No Ghidra session and no `objdump` run happened in this worker
  session. The listing-versus-decompiler distinction is documentation-derived; the tiebreak rule
  ("listing wins") is explicitly our inference.
- **Our adaptation vs the source:** the repository draft REV-004 recommended renaming variables around
  trust boundaries. We kept that, removed the implied trust in decompiler output, and added the
  disassembly-confirmation gate and the fixture-behavior shortcut.

## Sources

- `src-ghidra-intro-guide-a55dff83` — the documented existence of both a disassembly listing and a
  decompiler view, and the strings/xref navigation that gets you to a function quickly.
- `src-cyberchef-magic-source-2a3dcc0a` — used by analogy only: heuristic automation produces plausible
  candidates, and the repository's own note stresses that Magic output is not proof. The same
  discipline is applied here to heuristic pseudocode.
