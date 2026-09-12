# Classify a command sink before writing any payload

**First useful action.** For each process invocation, record three facts: is there a shell, is the argument
a string or a vector, and what does the invoked program do with a single argument.

```bash
rg -n --no-config -B3 -A6 -e 'subprocess|os\.system|os\.popen|exec\(|spawn|child_process|system\(' \
  <SERVICE_SRC>/ | head -n 120
```

Expected: a short list with visible argument construction. Three useful classes appear:
(1) shell string built from request data — directly injectable; (2) argument vector with no shell — injection
has to happen inside the invoked program's own option parsing; (3) a fixed command whose *environment* or
*config file* is request-influenced — a different fix (input validation on the file content, not the
command).

## Symptoms

- The service wraps a CLI tool and passes user input as an argument.
- The invoked tool accepts options that can read files, write files, or follow includes.
- Output is transformed before being returned, so a direct injection is not obviously visible.

## Prerequisites and assumptions

- Read access to the source, and one legitimate request that exercises the wrapped tool.
- Knowledge of which runtime is in play (Python, Node, PHP, Java, shell scripts).
- Stack/version: shell behaviour and the wrapped program's option parsing are both version-sensitive.

## Diagnostic sequence

1. Classify each sink into the three classes above. → Most of the work.
2. For class 1, find the exact composition and the boundaries of the user value. → This is the patch site.
3. For class 2, read the wrapped program's options for the ones that read files, write files, or load
   configuration. → The finding is "an argument can be abused", and the fix is an allowlist of accepted
   argument *values*, not escaping.
4. For class 3, determine whether the request influences a config file, an environment variable, or a
   template the tool loads. → The fix belongs where that content is written, not at the command.
5. Confirm on your own instance with a benign argument that changes the tool's behaviour. → Interpretation,
   not harm.

If the classification is class 1 and you need to determine whether execution happens at all, go to
`card-web-006-blind-command-timing`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `subprocess.run("cmd " + x, shell=True)` | string plus shell | Class 1; separators are meaningful. |
| `subprocess.run(["cmd", x])` | vector, no shell | Class 2; inspect the tool's option semantics. |
| `subprocess.run(["cmd", "-f", path])` with request-derived `path` | file argument | Class 2/3; the argument is a path, so confinement applies. |
| `os.environ` mutated from a request value | environment influence | Class 3; check what the child process reads from the environment. |
| wrapped tool's `--help` output mentioning `--config`/`--output` | option surface | Candidate for class 2 abuse; keep to the tool's documented behaviour. |

## Exploit → patch pair

- **Flaw:** request data influences command structure (class 1), the invoked program's option semantics
  (class 2), or the content the program consumes (class 3).
- **Reproduce on the isolated fixture:** against a local fixture, pass a benign argument that changes the
  wrapped tool's observable behaviour (for example an extra option it accepts) and record the change (not
  yet run here).
- **Narrow patch:** for class 1, fixed executable plus argument vector; for class 2, allowlist the accepted
  argument values and validate any path argument against a fixed directory; for class 3, validate the
  content that reaches the program.
- **Legitimate functionality that must keep working:** the wrapped tool still produces the same output for
  the legitimate inputs the product and the checker use.
- **Verify:** the abusive argument no longer changes behaviour **and** the legitimate call returns the same
  result.

## Failure modes and things teams stopped doing

- Assuming a non-shell invocation is automatically safe. Class 2 abuse (option injection, path arguments,
  config loading) is common and is *not* a shell-injection bug, so it needs a different fix.
- Copying the wrapped tool's `--help` into a card. A card must encode a decision rule; the tool's options
  belong on the tool's own documentation, which is also version-specific
  (`src-c4tbuts4d-stayhomectf2022-61868263` is indexed as a corpus of multi-language services whose wrappers differ).
- Ignoring environment and config influence because "the command is constant". The command being constant
  does not make its inputs safe.
- Debugging the application layer when the failure is at the device or transport layer — the home_r00ter
  writeup explicitly splits device, transport, and service layers (`src-molteniluca-homerooter-ff20860b`).
- Reporting a class-2 finding as RCE. In a scored event, overstating severity misroutes the team's
  attention and its patch budget (`src-enowars-checker-tenets-bf4b0ac7` keeps the focus on function-preserving fixes).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No sink was classified and no argument was sent in this session.
- **Our adaptation vs the source:** the shell/OS-dependence of command injection is from
  `src-portswigger-command-injection-7c72bc4a`; the layered-diagnosis habit from `src-molteniluca-homerooter-ff20860b`;
  the cross-language service breadth from `src-c4tbuts4d-stayhomectf2022-61868263`; the environment-mismatch caution
  (an exploit that fails in a container because a dependency does not start there) from
  `src-saarctf-2024-readme-6dacbfcc`. The three-class taxonomy is our synthesis for deciding *which* fix
  applies, and it is explicitly a judgment framework rather than a sourced claim.

## Sources

- `src-portswigger-command-injection-7c72bc4a` — command-injection mechanics and OS/shell dependence.
- `src-molteniluca-homerooter-ff20860b` — layer separation across device, transport, and service.
- `src-c4tbuts4d-stayhomectf2022-61868263` — multi-language A/D service corpus.
- `src-saarctf-2024-readme-6dacbfcc` — environment mismatch between container and full VM for an exploit path.
