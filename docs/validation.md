# Validation record

Actual commands, actual results, and an explicit list of what was **not** run.
"Our checks" means the repository's own test suite; it is not proof that an
unseen organizer checker passes.

## Environment

| Item | Value |
|---|---|
| Operator OS (dev) | Windows 11 (10.0.26200), Python 3.14.7, SQLite 3.50.4 |
| Operator OS (intended) | Arch Linux laptop (owner's machine); Linux-first, stdlib only |
| SSH client | OpenSSH_for_Windows_9.5p2 |
| Docker | Docker Desktop 29.7.2 engine; fixture images built locally |
| Real SSH target | throwaway Alpine 3.20 container, sshd on 127.0.0.1:2222 (removed after the run) |
| Network | The suite itself uses no network; the lab run used Docker image pulls and one SSH loopback connection |

## Full test suite

```bash
python tests/run_tests.py
```

Result (2026-09-12): **132 passed, 0 failed, 0 modules skipped, 83.2 s**,
exit code 0. Docker was available, so the container integration module ran
instead of skipping.

| Module | Tests | What it proves |
|---|---|---|
| `t_engine` | 20 | Apply/rollback, stale plans, interrupted transactions, conflicting rollback, single-writer lock, failed syntax validation, functional regression -> automatic rollback, repeated apply, metadata preservation, line endings |
| `t_remote` | 22 | Host injection refusal, ssh argv construction, bundle contents, fingerprint change, probe parsing (ss/netstat/proc), declaration gate before ssh, two-pass plan, policy gate, `--yes` gate, apply mirroring, flag absorption for `remote run`, read-only allowlist, unreachable-host message |
| `t_profiles` | 14 | Closed action registry, allowlisted argv, detection predicates, shipped profiles valid |
| `t_safety` | 13 | Offline commands open no socket, no free-form command strings, inert rendering, no secrets in reports |
| `t_decoy` | 11 | Rules gate, port safety, resource bounds, inert responses, lifecycle start/status/stop |
| `t_kbindex` | 12 | Punctuation-safe FTS queries, deleted documents, missing FTS5 fallback, deterministic rebuild, operator-local text indexing |
| `t_files` | 10 | Depth/entry caps, absolute-path rules (POSIX paths verbatim on Windows), secret-name refusal, binary refusal, redaction, truncation |
| `t_discover` | 9 | Non-root gaps, redaction, unknown listeners never become stack claims |
| `t_template` | 7 | Submission allowlist, dry-run default, dedup, rate window, mock accept/reject over loopback |
| `t_release` | 6 | Release contents, manifest verification, tamper detection, deterministic archive, source-licence mirror |
| `t_drills` | 5 | Synthetic PCAP validity/determinism, transcript ground truth, drill sheet section contract |
| `t_integration_docker` | 3 | Both shipped profiles end to end against the Compose fixtures |

### Offline guarantee

`tests/t_safety.py::test_offline_commands_never_open_a_socket` monkeypatches
`socket.connect`/`connect_ex`/`create_connection` and runs doctor, index, search,
discover and plan. No non-loopback connection was attempted.

## Container integration (Docker)

```bash
python tests/run_tests.py integration_docker
```

Result: **3 passed, 0 failed, 15.7 s** once Docker Desktop was running.

* `test_p1_discover_plan_apply_rollback`: discover -> plan -> apply -> the
  traversal exploit stops returning the canary -> the legitimate download and
  create/read/delete workflow keep working -> rollback restores the vulnerable
  state.
* `test_p2_discover_plan_apply_rollback`: the same for the PHP/Apache fixture.
* `test_fixture_containers_stay_inside_their_project`: no fixture reaches
  outside its Compose project.

## Real SSH end-to-end (lab, removed after the run)

A throwaway `alpine:3.20` container ran `sshd` on `127.0.0.1:2222` with
`python3` and (for the mutation test) a privileged Docker-in-Docker daemon with
the `p1` fixture deployed at `/opt/p1-flask-compose`. The operator-side sequence
was exactly the documented workflow:

```bash
ctfctl targets declare 127.0.0.1 --label "ssh lab container" --ack-policy
ctfctl remote probe 127.0.0.1 --user root --port 2222 --identity <key> --save --keep-raw
ctfctl remote files 127.0.0.1 ... list /etc --depth 1 --limit 8
ctfctl remote files 127.0.0.1 ... read /etc/os-release
ctfctl remote files 127.0.0.1 ... find /etc --name '*.conf' --limit 5
ctfctl remote plan 127.0.0.1 ... --verbose
ctfctl remote apply 127.0.0.1 ... --plan sha256:128a... --yes --json
ctfctl remote rollback 127.0.0.1 ... --tx tx-20260912T042626Z-2651 --yes --json
ctfctl remote recover 127.0.0.1 ...
ctfctl remote run 127.0.0.1 ... doctor --quick --json
```

Verified outcomes:

* **probe**: real Alpine output parsed (hostname, os-release, listeners on 22,
  uid, python3); unprivileged/missing-tool gaps reported honestly; raw kept only
  on request and redacted.
* **files**: list/read/find over real SSH; secret-name and binary refusals held;
  POSIX absolute paths work from a Windows operator (a bug found here: 
  `os.path.isabs("/etc")` is False on Windows; fixed and covered by
  `t_files.test_validate_path_keeps_posix_paths_verbatim`).
* **plan**: detected `web-nginx-flask-compose`, mirrored authorization from the
  local declaration, produced the exact one-line diff, verifiers, exploit probe
  and rollback text. A deliberately mismatched project (`p1-web`, no Flask in
  the image name) correctly produced **no match** rather than a guess.
* **apply**: `phase: COMMITTED`, tx `tx-20260912T042626Z-2651`, file pre/post
  hashes recorded, service restarted, all verifiers `ok: true`, including the
  tier-3 create/read/delete workflow and the negative probe
  `GET /files?name=../../canary.txt -> 404`.
* **independent check**: `wget` from inside the lab before/after confirmed the
  canary was reachable before, gone after, and the legitimate download stayed
  200 throughout.
* **rollback**: `phase: ROLLED_BACK`, file restored, service restarted, legitimate
  workflow still green, canary reachable again.
* **host-key check**: recreating the container changed its host key and SSH
  refused the connection until the stale entry was removed. Default strict
  checking is on; ctfctl does not disable it.
* **cleanup**: container removed, the test host key removed from
  `known_hosts`, and the test declaration removed from `state/`.

Not exercised in the lab: an `apply` that triggers the automatic
rollback-on-verification-failure path (that path is covered by `t_engine` and by
the fixture integration test), and privileged host firewall/SSH changes (not
implemented by policy).

## Release packaging and offline rehearsal

```bash
python tools/package_release.py --rehearse --json
python tools/package_release.py --check dist/ctf-buddy-0.1.0.tar.gz
```

* The builder assembles `dist/ctf-buddy-0.1.0.tar.gz` (195 files, ~520 KiB)
  plus `MANIFEST.sha256`, `SOURCE-LICENSES.jsonl` (one record per source with
  licence and reuse status) and `CHECKSUMS.sha256`.
* The rehearsal extracts the archive to a temporary directory and runs the full
  suite from there. Recorded result: **132 passed, 0 failed, 0 modules skipped,
  83.0 s** from `dist/ctf-buddy-0.1.0.tar.gz` (sha256
  `927d6f4988190603248c41f32c142b3f3d5b52994a1c6c636fb29d337526fe40`, 200
  files); see also `docs/progress.md`.
* `--check` verifies every manifest hash against the archive and reports
  unlisted files; tamper detection is covered by `t_release`.
* The archive contains no binaries, no runtime state, no captures, no generated
  index and no local source snapshots. Determinism is covered by
  `t_release.test_release_is_deterministic` (`SOURCE_DATE_EPOCH` or the HEAD
  commit date is used as the timestamp).

## What was NOT run (explicit)

| Not run | Why | How to validate |
|---|---|---|
| The real event stack against real organizer rules | No event environment exists yet | `remote probe`, then `remote plan --verbose`; run the legitimate workflow and the profile's exploit probe before and after |
| Host firewall / SSH config changes | Not implemented by policy (review-only) | Operator decision; container tests cannot validate host networking, so never count them as proof |
| Privileged discovery completeness on the event host | Lab was a container, not the event VM | `discover` on the target as root vs unprivileged, compare gaps |
| Windows host mutation | Unsupported by design | N/A |
| Long-running observation under real attack traffic | Lab had no adversary | `watch` on the declared host once ticks start |

## Honesty rules applied

* A TCP connect or HTTP 200 is treated as liveness only; tier-2/3 verifiers run
  real HTTP workflows and check application state.
* Functional verifiers are labeled as our checks, not as organizer acceptance.
* Secret-looking values are redacted before anything reaches `state/` or stdout,
  including probe output, plans, audit records and error messages.
* No test result above is inferred. Where something was not run, it says so.
