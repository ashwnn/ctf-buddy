# Consolidation plan: reference tooling into ctf-buddy

Date: 2026-09-17. Branch: `feat/rj-ctf-consolidation`.

This is the keep/port/reject/defer decision record for consolidating behaviour
observed in two reference repositories into this repository's own `ctfctl`
surface. No code is copied: neither reference repository has a repository
LICENSE, so reuse rights are unclear. Their described behaviour is reimplemented
independently behind narrow tests, and upstream defects are recorded in the
follow-up list below instead of vendored fixes.

## Scope and repository boundaries

| Repository | Revision (inspected 2026-09-17) | Reuse status | Role |
|---|---|---|---|
| `XavierElChantiry/rj-ctf-2026` | `f8d38db0` (tree dated 2026-09-16) | no LICENSE file at the repository root | behaviour reference for A/D submission and triage tooling; README "Borrowed ideas" credits ashwnn/ctf-buddy |
| `DoAnythingForNow/ctf` | `71bc0d93` (tree dated 2026-09-02) | no repository LICENSE; README says none was chosen, userscripts carry per-file MIT notices | behaviour reference for offline, per-domain stdlib tooling |
| `ctf-buddy` (this repository) | branch `feat/rj-ctf-consolidation` | project license governs | the only place consolidation lands |

Event context stays context: the theme "Relentless Pursuit: Innovate.
Anticipate. Defend." is not scoring evidence, and 2026-10-03 appears in team
materials but not in an organiser publication we could verify. See
`docs/event-facts.md` for the fact classes.

## Keep matrix (already shipped here, never duplicated)

| Component | Where | Why it stays the single implementation |
|---|---|---|
| Knowledge base and FTS index | `kb/`, `tools/ctfctl` | offline corpus with source-linked evidence |
| Drills | `drills/` | event-time practice with separate answers |
| Release packaging | `tools/package_release.py` | reproducible archive with rehearsal and check |
| Target declaration | `state/targets.json` | authorization scope for any remote work |
| Guarded remote ops | discovery, probe, plan, apply, verify, rollback | declared targets, plans, rollback records |
| Patch verification | `tools/ctfctl` engine | every mutation is proven or rolled back |
| Rollback journal | `state/` | the recovery path for a failed apply |
| File locking | `apply.WriterLock` | concurrent runs cannot interleave state writes |
| Bounded observation | `observe.py` | logs and capture inside line and size budgets |
| Doctor capability report | `ctfctl doctor` | honest platform support reporting |

A port that would duplicate any row above is rejected by this plan.

## Port matrix (adapted intent, independent implementation)

These seven slices are the branch scope. Every source below was inspected
2026-09-17 at `f8d38db0` (Xavier) or `71bc0d93` (DoAnythingForNow).

| Our capability | Adapted intent from | How ours differs |
|---|---|---|
| Submit outcome reliability (`submit.py`: pending, accepted, rejected-final, retryable; migration; locking; dry-run isolation) | seen-set before submission, no retry after failure, acceptance not persisted (`ctf_ad/attack/runner.py` lines 94-100); bounded retry/backoff (`ctf_ad/attack/submitters.py`); TCP submit with dry-run default and no flag retention (`attack-defense/flag_submit.py`) | outcomes persist across runs; retry only for retryable classes; dry-run records nothing and mutates no state; mirrors the locking pattern of `apply.WriterLock` (standalone implementation, no repository imports) |
| `ctfctl challenge init` (isolated workspaces under `work/<id>/`) | per-challenge scratch layout in both references; no single upstream module | one workspace per challenge id, no shared scratch, refuses to overwrite an existing workspace |
| `ctfctl artifact scan` (streaming sha256, bounded strings, flag regex, bounded base64/hex pass, optional ZIP/TAR member inspection) | `ctf_toolkit/common/flagscan.py` lines 85-102; `forensics/archive_walker.py` bomb and encrypted-member guards | never `extractall`; members checked for containment; depth 3, 2000 members, 50 MiB per member, 250 MiB total, 200:1 ratio; scanned content is never executed |
| `ctfctl decode` (base64, base32, hex, binary, URL, ROT13, gzip, zlib; printable filter) | `ctf_toolkit/common/decode_chain.py`; `crypto/identify_encoding.py` and `crypto/encoding_chain.py` | depth 4 cap kept, output always bounded, every step reported so the operator sees the chain |
| `ctfctl crypto caesar, xor-single, xor-crib, vigenere` | `ctf_toolkit/red/crypto_solve.py`; `crypto/xor_solver.py` and `crypto/classical_analysis.py` | same primitives as explicit subcommands; no auto-solve chain, no network use |
| `ctfctl logs triage` (access and SSH log signatures) | `ctf_toolkit/blue/log_triage.py`; `forensics/log_timeline.py` | local files only, bounded lines per file, each signature stated with its match evidence |
| `ctfctl pcap triage` | `ctf_toolkit/blue/pcap_triage.py`; `forensics/pcap_inventory.py` | optional `tshark` only; no Scapy dependency and no custom TCP reassembly |

## Reject matrix (observed upstream, refused here)

All rejections were inspected 2026-09-17 at `f8d38db0` unless noted.

| Rejected | Where | Reason |
|---|---|---|
| `ctf_defense/03_firewall_lockdown.sh` (broad firewall flush/drop) | Xavier | a blanket firewall change can break the checker and the operator session; our only firewall action stays the review-only, additive nftables table in `docs/support-matrix.md` |
| `ctf_defense/02_backup_git.sh` (git-init backup with destructive rollback commands) | Xavier | rollback by destructive commands is neither bounded nor tested; the rollback journal and bounded backups replace it |
| `ctf_defense/07_chroot_jail.sh` (chroot jail) | Xavier | broad host mutation on an unknown service with no tested profile and no validation path |
| Unrestricted archive extraction (`extractall`) | Xavier `ctf_toolkit/common/flagscan.py` lines 85-102 | untrusted input; zip-slip and archive-bomb exposure; replaced by bounded member validation in `ctfctl artifact scan` |
| Web probe / active scanning in the new path | Xavier `ctf_toolkit/red/web_probe.py` | scanning needs a declared target; the existing scoped remote probe is the only sanctioned path |
| Custom TCP reassembly | Xavier `ctf_toolkit/blue/pcap_triage.py` | correctness and maintenance risk; `tshark` owns reassembly and stays optional |

## Defer matrix (real, not this branch)

| Deferred | Trigger to revisit |
|---|---|
| Full `ctf_ad` integration | after every port slice lands and a local scrimmage shows the loop fits our flow |
| Scoreboard integration | when the organiser API or format is known and the team commits to polling it during ticks |
| FAUST-specific configuration | only if the event publishes FAUST-style rules (see `docs/event-facts.md` V3 and A4) |
| Extra honeypots beyond the shipped decoy/honeypot | after the existing honeypot survives a full rehearsal |
| Dashboards | when there is data worth charting and a named person reads it during ticks |
| Autonomous exploit execution | explicit rules permission plus a reviewed action allowlist; not assumed for this event |
| More A/D service profiles | a third tested profile with its own patch and verify path |

## Upstream follow-up list

Recorded here for the team; not yet filed against the upstream repositories.

1. Xavier `ctf_ad/attack/runner.py` lines 94-100: a flag is marked seen before
   submission, a failed submission is never retried, and acceptance is not
   persisted. Inspected 2026-09-17 at `f8d38db0`. Our submit slice is the
   independent fix: durable outcome states with retry only for retryable
   failures.
2. Xavier `ctf_toolkit/common/flagscan.py` lines 85-102: archive extraction via
   `extractall` into a temp dir with no path, size, or depth validation.
   Inspected 2026-09-17 at `f8d38db0`. Our `artifact scan` validates every
   member and enforces the bounds in the port matrix.
3. Licensing: neither repository has a repository LICENSE. Xavier `f8d38db0`
   has no LICENSE file; DoAnythingForNow `71bc0d93` README states no license was
   chosen, with MIT per-file notices on userscripts only. Inspected 2026-09-17.
   No code is copied from either repository.

## Verification expectations

| Level | Command | Expected result |
|---|---|---|
| Per slice | focused stdlib tests for the slice module | new tests pass; each bound (depth, member count, sizes, ratio) has at least one negative test |
| Full suite | `python tests/run_tests.py` | green before the slice is recorded in `docs/progress.md`; skipped modules reported with their skip reason, never counted as passes |
| Release rehearsal | `python tools/package_release.py --rehearse --json` | exit 0, archive `--check` verified, suite inside the archive green; run after the final slice from a clean tree |

No slice is done on inspection alone, and no claim here is proof that an unseen
organiser checker passes. Tests that were not run are reported as not run
(`docs/validation.md`).
