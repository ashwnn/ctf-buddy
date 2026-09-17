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
| Docker | Docker Desktop 29.7.2 engine; fixture images built locally; daemon not running for the 2026-09-16 local run (see not-run table) |
| CI | GitHub-hosted runners (ubuntu-latest, windows-latest); workflow run 35191029558 |
| Real SSH target | throwaway Alpine 3.20 container, sshd on 127.0.0.1:2222 (removed after the run) |
| Network | The suite itself uses no network; the lab run used Docker image pulls and one SSH loopback connection |

## Full test suite

```bash
python tests/run_tests.py
```

Result (2026-09-16, latest): **216 passed, 0 failed, 2 modules skipped**, exit
code 0, on Windows 11 with Python 3.14.7. No Docker daemon was running locally,
so `t_integration_docker` and `t_integration_lockdown` skipped with a recorded
reason; the ubuntu CI jobs ran both (see "Continuous integration"). The module
counts below sum to 220, the count exercised on ubuntu.

| Module | Tests | What it proves |
|---|---|---|
| `t_engine` | 22 | Apply/rollback, stale plans, interrupted transactions, conflicting rollback, single-writer lock (including reclaiming a lock left by a dead process), failed syntax validation, functional regression -> automatic rollback, repeated apply, metadata preservation, line endings |
| `t_remote` | 22 | Host injection refusal, ssh argv construction, bundle contents, fingerprint change, probe parsing (ss/netstat/proc), declaration gate before ssh, two-pass plan, policy gate, `--yes` gate, apply mirroring, flag absorption for `remote run`, read-only allowlist, unreachable-host message |
| `t_remote_ops` | 14 | `remote auto` read-only default + report files + `--yes` gate + graceful degradation without python3; honeypot gates and argument forwarding; `collect` refusing unvalidated paths; lockdown reading the operator address from the ssh session; the access-recheck auto-rollback after an ssh/firewall change |
| `t_lockdown` | 13 | Additive ruleset rendering, `/0` and operator-excluding allowlists refused, effect/rollback argv shape, nft effect allowlist, sshd `Match`/empty-config refusal, key-required validation, idempotent second render, review-only plan shape, verifier pruning, and the `file_create` apply/rollback/conflict paths |
| `t_honeypot` | 7 | Busy/privileged/invalid ports refused, listener cap, HTTP lure logging with `decoy=true`, banner mode speaking first, per-port stop |
| `t_integration_lockdown` | 1 | End-to-end lockdown inside a disposable container: create + load + verify + rollback of the nftables file, sshd config restore, effect dispatch and rollback effect, honeypot serving and logging (`nft`/`sshd` stubbed) |
| `t_profiles` | 14 | Closed action registry, allowlisted argv, detection predicates, shipped profiles valid |
| `t_safety` | 13 | Offline commands open no socket, no free-form command strings, inert rendering, no secrets in reports |
| `t_decoy` | 11 | Rules gate, port safety, resource bounds, inert responses, lifecycle start/status/stop |
| `t_kbindex` | 13 | Punctuation-safe FTS queries, deleted documents, missing FTS5 fallback, deterministic rebuild, row-parity verify, cheatsheet tag listing, operator-local text indexing |
| `t_kb_cli` | 15 | `kb show`, `kb open` and `kb export` at the CLI boundary: printed path for `$EDITOR`, export contents, no implicit browser launch |
| `t_cli_plan_alias` | 14 | Documented `--plan` examples parse on the real CLI and resolve the right plan id (remote apply/verify, top-level apply); fake ssh runner, no sockets |
| `t_integrate` | 12 | Corpus integration: merge skips, conflicts, problems report, idempotence, dry runs |
| `t_watch` | 9 | Bounded `watch`/observe line and time budgets, dry-run capture plan, no socket or tcpdump start |
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

## Continuous integration (GitHub-hosted, our check)

`.github/workflows/tests.yml` runs `python tests/run_tests.py` on a matrix of
ubuntu-latest and windows-latest with Python 3.9 and 3.x. Workflow run
**35191029558** is all green on every job:

| Runner | Result | Notes |
|---|---|---|
| ubuntu-latest | 220 passed, 0 failed, 0 skipped | Docker available; both container modules ran |
| windows-latest | 216 passed, 0 failed, 2 modules skipped | The runner's Docker was in Windows-container mode; the fixture images need Linux containers |

Commit shas cited in this document predating 2026-09-17 refer to the
pre-normalization history; the rewrite changed authorship only and every tree
is byte-identical.

These are GitHub-hosted runners and the results are our checks. They do not
prove that an organizer checker passes or that the event environment behaves
the same.

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
python tools/package_release.py --check dist/ctf-buddy-0.2.0.tar.gz
```

* Recorded rehearsal (2026-09-16, commit `8f689e3`; commits after it contain
  only documentation changes): exit 0, version 0.2.0, 219 files archived;
  `dist/ctf-buddy-0.2.0.tar.gz` is 612,577 bytes with sha256
  `df03917b71a49aa8300331140a2ee4ab1b47b39c29829971a45604bd337bee40`, alongside
  `CHECKSUMS.sha256` (259 B), `MANIFEST.sha256` (23,105 B), `RELEASE-NOTES.md`
  (1,655 B) and `SOURCE-LICENSES.jsonl` (36,778 B, one record per source with
  licence and reuse status).
* The rehearsal extracts the archive to a temporary directory and runs the full
  suite from there. It ran on Windows with Python 3.14.7, so the Docker-backed
  integration modules were skipped locally, as in the suite run above.
* `--check` verified the archive against its manifest: OK, 219 files checked.
  A second independent build of the same tree was byte-identical. Tamper
  detection is covered by `t_release`.
* The archive contains no binaries, no runtime state, no captures, no generated
  index and no local source snapshots. Determinism is covered by
  `t_release.test_release_is_deterministic` (`SOURCE_DATE_EPOCH` or the HEAD
  commit date is used as the timestamp).

## What was NOT run (explicit)

| Not run | Why | How to validate |
|---|---|---|
| Docker-backed integration modules on the local Windows host (2026-09-16 run) | No Docker daemon was running | Start Docker Desktop and run `python tests/run_tests.py integration_docker`; the ubuntu CI jobs already ran both modules |
| The real event stack against real organizer rules | No event environment exists yet | `remote probe`, then `remote plan --verbose`; run the legitimate workflow and the profile's exploit probe before and after |
| A real nftables load and its host effect | `nft` is stubbed in the container test (real packages need network), including the ubuntu CI run | On the declared host: `remote lockdown`, read the diff, then `nft list table inet ctfctl_lockdown` and a real reconnect check while the console is open |
| A real `sshd -t`/`-T` run and a post-hardening reconnect | Same reason: `sshd` is stubbed in the container | On the declared host, after `--approve-review --yes`: open a *second* SSH session and re-run `sshd -T \| grep -i passwordauth` |
| `remote honeypot` / `remote lockdown` over a real SSH session | Fake-transport tests only; the stubbed container lockdown ran on ubuntu CI, but neither was exercised over real SSH | Run both against a throwaway lab host before the event and record the result here |
| Honeypots under adversarial traffic | Only loopback requests were made | Start a listener once ticks begin and read `honeypot logs`/`collect` |
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
