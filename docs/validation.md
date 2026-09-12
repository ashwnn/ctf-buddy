# Validation record

Actual commands, actual results, and an explicit list of what was **not** run.
"Our checks" means the repository's own test suite; it is not proof that an
unseen organizer checker passes.

## Environment

| Item | Value |
|---|---|
| Operator OS (dev) | Windows 11 (10.0.26200), Python 3.14.7, SQLite 3.50.4 |
| Operator OS (intended) | Arch Linux laptop (owner's machine); Linux-first, stdlib only |
| SSH client | OpenSSH_for_Windows_9.5p2 (for argv checks); real remote runs pending on Arch |
| Docker | Not available on the dev machine; container integration module skipped |
| Network | None used during the suite; offline checks enforce it (see below) |

## Commands and results

### Full test suite

```bash
python tests/run_tests.py
```

Result (2026-09-12): **108 passed, 0 failed, 1 module skipped, 72.9 s**,
exit code 0.

Module coverage, all green unless noted:

| Module | Tests | What it proves |
|---|---|---|
| `t_engine` | 20 | Apply/rollback, stale plans, interrupted transactions, conflicting rollback, single-writer lock, failed syntax validation, functional regression -> automatic rollback, repeated apply, metadata preservation, line endings |
| `t_profiles` | 14 | Closed action registry, allowlisted argv, detection predicates, shipped profiles valid |
| `t_safety` | 13 | Offline commands open no socket, no free-form command strings, inert rendering, no secrets in reports |
| `t_kbindex` | 11 | Punctuation-safe FTS queries, deleted documents, missing FTS5 fallback, deterministic rebuild |
| `t_decoy` | 11 | Rules gate, port safety, resource bounds, inert responses, lifecycle start/status/stop |
| `t_discover` | 9 | Non-root gaps, redaction, unknown listeners never become stack claims |
| `t_files` | 9 | Depth/entry caps, absolute-path refusal, secret-name refusal, binary refusal, redaction, truncation |
| `t_remote` | 21 | Host injection refusal, ssh argv construction, bundle contents, fingerprint change, probe parsing (ss/netstat/proc), declaration gate before ssh, two-pass plan, policy gate, `--yes` gate, apply mirroring, read-only allowlist, unreachable-host message |
| `t_integration_docker` | 0 run | **SKIPPED**: `docker is not available (daemon not running or CLI missing)` |

### Offline guarantee

`tests/t_safety.py::test_offline_commands_never_open_a_socket` monkeypatches
`socket.connect`/`connect_ex`/`create_connection` and runs doctor, index, search,
discover and plan. No non-loopback connection was attempted.

### Decoy lifecycle (Windows hang fix)

Before the fix, `t_decoy.test_start_status_stop_lifecycle` hung indefinitely on
Windows: the liveness check used `os.kill(pid, 0)` after SIGTERM, which blocked
in this environment. After the fix the same module runs in 42.7 s with all 11
tests green. The POSIX liveness path is unchanged.

### Doctor

```bash
python tools/ctfctl.py doctor
```

Reports FTS5 available, 114 cards / 277 primary sources / 50 teams, index
integrity OK, 2 tested profiles, 2 fixtures, `remote over ssh yes`; warns about
the platform (Windows: read-only, no host mutation), missing optional tools, and
0 drill documents. Performs no network access.

## What was validated functionally

* **Search**: ranked and literal search over the shipped corpus, including
  punctuation queries (`../`, `$_GET`, `403`, `ss -lntup`) and deleted documents.
* **Patch engine**: on fixture-shaped services, apply -> legitimate workflow
  still works -> exploit probe stops working -> rollback restores byte-identical
  files, with metadata (mode/ownership where restorable) and without rewriting
  line endings.
* **Authorization**: undeclared targets cannot be planned into mutations;
  declared + policy-ack targets can; stale plans and conflicting rollbacks are
  refused.
* **Remote transport (fake)**: all command construction, gating, parsing,
  mirroring and error handling listed in the `t_remote` row above.

## What was NOT run (explicit)

| Not run | Why | How to validate |
|---|---|---|
| Real SSH end-to-end (`remote probe` to a live host) | No SSH server reachable from the dev machine | Run once from the Arch laptop against the practice VM; record host class, date, `probe`/`plan` output shape, and any parser mismatch |
| Docker container integration (`t_integration_docker`) | Docker daemon unavailable here | `python tests/run_tests.py integration_docker` on a Docker-capable machine |
| Compose profiles against the real event stack | No event stack available yet | `remote plan --verbose` then `apply` on the declared box; run the legitimate workflow and the profile's exploit probe before and after |
| Host firewall / SSH config changes | Not implemented by policy (review-only) | Operator decision; container tests cannot validate host networking, so never count them as proof |
| Privileged discovery completeness | Dev machine is not Linux | `discover` on the target as root vs unprivileged, compare gaps |
| Windows host mutation | Unsupported by design | N/A |

## Honesty rules applied

* A TCP connect or HTTP 200 is treated as liveness only; tier-2/3 verifiers run
  real HTTP workflows and check application state.
* Functional verifiers are labeled as our checks, not as organizer acceptance.
* Secret-looking values are redacted before anything reaches `state/` or stdout,
  including probe output, plans, audit records and error messages.
* No test result above is inferred. The Docker module reports a skip, not a pass.
