# Reverse a service binary when no source is provided

**First useful action.** Capture the service's legitimate behavior (one request in, one response out,
with state before and after) before you try to understand a single function.

```bash
# against your own assigned instance or an isolated fixture only
printf '<LEGITIMATE_REQUEST>' | timeout 5 nc 127.0.0.1 <PORT> | tee <ANALYSIS_DIR>/baseline.out
```

Expected: a deterministic response you can re-run later as a regression test. If the request hangs or
returns nothing, the protocol or port assumption is wrong — capture with the packet tooling first
(`card-misc-unusual-protocol-no-dissector`) rather than guessing a second payload.

## Symptoms

- The service is delivered as a binary or container image with no readable source tree.
- A checker or scan shows the port is alive but the request format is unclear.
- The team is split between "reverse it fully" and "attack it blind".

## Prerequisites and assumptions

- The service is an explicitly team-assigned asset, or a local copy of it. Nothing in this card is run
  against another team or organizer infrastructure.
- A disassembler/decompiler and a way to talk to the service locally.
- The rules are unknown or unresolved for anything beyond local testing — the repository's operating
  doctrine keeps cross-team action in dry-run mode until the organizer confirms it.

## Diagnostic sequence

1. Record baseline behavior: one legitimate request, its response, and the service's state change.
   This is both your first understanding and your patch regression test.
2. Map the process: which binary, which port, which arguments, which files it touches. `ss -ltnp` plus
   an inspection of the process's command line and working directory is enough to start.
3. Identify the input path in the binary: strings and xrefs from whatever the protocol visibly uses
   (`card-rev-ghidra-string-xref-pivot`) instead of reversing from the entry point.
4. Only reverse the functions on that input path. Anything else is deferred until the path is closed.
5. Decide ownership and record it: in a live event one person owns this service's state, and the binary
   analysis notes must be handed over in a form someone else can continue from.

If a checker or demo checker source is available → read it before reversing further; the checker
defines the legitimate behaviors you must not break. If no checker exists → infer the contract from
baseline traffic and write down that it is inferred, not known.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ss -ltnp` | `LISTEN ... users:(("<proc>",pid=<PID>,...))` | Maps the port to the owning process (needs privilege for full detail) |
| `printf '<REQUEST>' \| nc 127.0.0.1 <PORT>` | deterministic response | Baseline behavior; becomes the regression probe |
| `strings -a -n 8 <BINARY>` | protocol tokens, error text | Input-path anchors for the disassembler |
| `systemctl status <UNIT>` / container inspect | runtime wrapper | Tells you whether a supervisor restarts the service after a change |

## Failure modes and things teams stopped doing

- Full reverse-engineering before any behavior capture. The team retrospectives in this corpus
  repeatedly point at sequencing mistakes: the UMCS 2026 first-time team patched before understanding
  and damaged its own availability, and the attack/defend operations notes make a known-good baseline
  a precondition for every later step.
- Attacking or scanning opponents while the service is still unowned and unbaselined. The repository's
  rule gate keeps cross-team execution disabled until the organizer confirms scope and automation.
- Treating the binary as a black box forever. Behavior capture without any static analysis leaves you
  unable to patch; static analysis without behavior capture leaves you unable to prove anything.
- Spreading one binary across three analysts with no owner. The RuCTFE-era operations lesson recorded
  in this corpus is that unclear ownership produces duplicate work and failed handoffs — worse in a
  binary-only service where the whole team wants to look at once.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing. No service was contacted and no binary analyzed in this session;
  the `ss` command shape is repository build-pass verified, the rest is source-supported workflow.
- **Our adaptation vs the source:** the repository's AD-003 (port-to-process mapping) and the
  attack/defend retrospectives supply the baseline-first discipline; combining them into a binary-only
  service workflow is our adaptation. The card deliberately does not promise that full reversal is
  needed — the stop condition is "the input path is understood and a regression test exists".

## Sources

- `src-dttw-defcon2021-retro-14eb5491` — first-hand evidence of binary-only service work under
  finals conditions; used for the workflow shape, not for scoring or infrastructure assumptions.
- `src-d0gl0v3r-umcs2026-c85f0c19` — first-time-team failure story about patching before understanding and
  observing the wrong layer.
- `src-duchyoftaco-misec-ructfe2019-332d8e5b` — ownership and context-switching failures that this card's ownership
  rule answers.
- `src-enowars-checker-tenets-bf4b0ac7` — organizer-side description of what a service must keep
  doing, used to define the "do not break this" contract.
