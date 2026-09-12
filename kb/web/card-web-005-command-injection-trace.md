# Trace command injection from the request value to the exact shell boundary

**First useful action.** Find the one call that turns request data into a process invocation, and
decide whether an argument vector or a shell string is being built there.

```bash
rg -n --no-config -e 'subprocess|os\.system|os\.popen|shell=True|exec\(|spawn|child_process' \
  -e 'system\(|popen\(|`|Runtime\.getRuntime' <SERVICE_SRC>/
```

Expected: a handful of call sites. Read the two or three that are reachable from a route. If the
call passes an argument list with no shell, metacharacters alone do **not** prove injection — the
bug would have to live in what the invoked program does with a single argument.

## Symptoms

- A route runs a system utility: `ping`, `nslookup`, `convert`, `ffmpeg`, `tar`, `zip`, `mail`,
  `whois`, or a service-specific CLI.
- The request supplies a hostname, filename, format, or "options" string.
- Timing, output, or an error message changes when the parameter contains shell metacharacters.

## Prerequisites and assumptions

- The route and parameter are reachable without privileged access, or you have source only.
- One baseline request that succeeds, so you can distinguish injection from a broken feature.
- Stack/version: separator and quoting rules depend on the OS and shell; Windows `cmd.exe` and
  POSIX shells differ, and a non-shell `execvp` behaves differently again.

## Diagnostic sequence

1. Grep the sinks (command above). → You get candidate process-invocation sites.
2. For each, read how the argument is assembled: literal + concatenation, f-string/interpolation,
   or a list. → Concatenated string reaching a shell = genuine boundary; list = only second-order.
3. Identify which request key feeds it and whether any validation sits between.
   → Validation that is a *positive allowlist of characters or a fixed enum* is a real control;
   a denylist of one or two characters is not.
4. Confirm on your own instance with a benign marker that changes command *structure* but does not
   harm the host (for example an extra harmless argument). → Output or exit-code change confirms
   interpretation, not injection.
5. Only for a proven shell boundary, determine what the process can do and what the flag-reading
   path looks like; then move to the patch.

If the sink is a shell string but the response never contains command output, go to
`card-web-006-blind-command-timing`. If the sink is a list/argv call, treat the finding as
"argument-level abuse inside the invoked program" and go to
`card-web-029-command-sink-taxonomy`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'shell=True' <SERVICE_SRC>` | one or more hits | A shell is in the path; separators become meaningful. |
| `rg -n 'subprocess\.(run\|check_output\|Popen)\(\s*\[|execFile\(' <SERVICE_SRC>` | list-style call | No shell; keep looking for string-built commands elsewhere. |
| `rg -n 'f"\|\.format(\|%s" *%' <SERVICE_SRC>` near a sink | interpolation into a command | Candidate injection point; read the surrounding validation. |
| `curl 'http://127.0.0.1:<PORT>/<ROUTE>?<PARAM>=<BENIGN_MARKER>'` | changed output/exit code vs baseline | Confirms the value reaches the utility's argument parsing. |

## Exploit → patch pair

- **Flaw:** request data is interpolated into a command string that a shell then parses, so shell
  metacharacters change the command.
- **Reproduce on the isolated fixture:** against an owned local fixture, send a value that adds one
  harmless extra argument and observe the utility's changed behaviour; only on a host you own
  (not yet run here).
- **Narrow patch:** replace string composition with a fixed executable plus an argument **vector**
  (`subprocess.run([<BINARY>, <ARG1>, <ARG2>])` with no shell), or, where the tool must be invoked
  through a shell, restrict the parameter to a strict semantic allowlist (a literal enum, or a
  validated hostname/regex) *before* composition.
- **Legitimate functionality that must keep working:** the intended operation still runs with the
  same output for valid inputs, and its exit code and response schema are unchanged for the
  checker.
- **Verify:** the metacharacter probe no longer changes behaviour **and** the legitimate request
  still returns the same result as the pre-patch baseline.

## Failure modes and things teams stopped doing

- Escaping or blacklisting one separator. Separators are environment-specific; the injectable
  surface is the composition, not the character (`src-portswigger-command-injection-7c72bc4a`).
- Assuming "it is a `subprocess` call, therefore safe". The question is whether a shell is involved
  and how the argument vector is built, not which library is used
  (`src-portswigger-command-injection-7c72bc4a`).
- Patching the route by removing the feature. A removed feature is a checker-visible regression;
  the narrow change is at the sink (see `card-web-029-command-sink-taxonomy`).
- On a hybrid physical/service challenge, debugging only the application while the failure is
  really at the device or transport layer. The home_r00ter writeup splits device, transport, and
  service layers explicitly for exactly this reason (`src-molteniluca-homerooter-ff20860b`).

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. The grep pattern was not executed against a service in this
  session, and no payload was sent anywhere.
- **Our adaptation vs the source:** `src-portswigger-command-injection-7c72bc4a` supplies the class,
  the blind-execution concept, and the OS/shell dependence. `src-molteniluca-homerooter-ff20860b` supplies
  the layered-diagnosis habit for hardware-plus-service challenges. Our addition is the explicit
  "list vs string" gate before any payload is attempted, which keeps the team from reporting a
  non-vulnerability.

## Sources

- `src-portswigger-command-injection-7c72bc4a` — command-injection mechanics, blind variants, and the
  warning that separators depend on the target OS/shell.
- `src-molteniluca-homerooter-ff20860b` — layer separation across device, transport, and application in a
  hybrid service challenge.
