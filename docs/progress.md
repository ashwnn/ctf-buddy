# Progress log

Append-only. Newest entries at the top. One line per verified slice; details go
in `docs/validation.md` and `docs/remote-mode.md`.

## 2026-09-12 (later) — Docker integration, real SSH lab, drills, release, template

**Container fixtures validated.** Docker Desktop was started; the container
integration module then passed 3/3 (15.7 s): both shipped profiles run
discover -> plan -> apply -> exploit stops working -> legitimate workflow keeps
working -> rollback restores the vulnerable state.

**Real SSH end-to-end validated.** A throwaway Alpine container ran sshd and
python3; for the mutation test it also ran a privileged Docker-in-Docker daemon
with the p1 fixture at `/opt/p1-flask-compose`. Over a real SSH connection the
documented workflow ran: declare -> probe -> files list/read/find -> plan
(detected the profile, exact diff) -> apply (`COMMITTED`, all verifiers green,
negative probe 404) -> independent wget confirmation -> rollback
(`ROLLED_BACK`, canary reachable again) -> recover/run. Host-key checking
correctly refused a recreated container. The lab and its test declaration were
removed afterward.

**Bugs found and fixed by the real runs:**

* `validate_path` rejected POSIX paths on Windows (`os.path.isabs("/etc")` is
  False there); remote file exploration was broken from a Windows operator.
  Fixed, POSIX paths are kept verbatim, covered by a new `t_files` test.
* `remote run <host> --user ... <subcommand>` swallowed the connection flags
  via argparse REMAINDER; they are now absorbed before dispatch, covered by a
  new `t_remote` CLI test.
* Plan rendering showed `host ? / ?`; it now uses the recorded host fingerprint
  and prints copy-pasteable `next:` apply/verify commands.
* `fixtures/p1-flask-compose/README.md` documented the path-segment route and a
  `ctfctl run` command that does not exist; both corrected to the query-string
  route and the real profile commands.

**Drills added** (`drills/`): web diagnosis and narrow patch, PCAP-to-request
reconstruction (with a deterministic stdlib PCAP generator), unknown-VM
inventory, patch regression and rollback, optional decoy detection. Each sheet
has Goal/Setup/Tasks/Expected evidence/Success criteria/Reset; answers are
separate in `drills/answers.md`. Covered by `t_drills` (5 tests).

**Release packaging added** (`tools/package_release.py`): builds
`dist/ctf-buddy-<version>.tar.gz` plus `MANIFEST.sha256`,
`SOURCE-LICENSES.jsonl`, `CHECKSUMS.sha256`, `RELEASE-NOTES.md`; `--check`
verifies an archive against its manifest; `--rehearse` extracts it and runs the
full suite from the extracted tree. Archives are deterministic, contain no
binaries and exclude state/captures/index/source snapshots. Covered by
`t_release` (6 tests).

**Bounded competition automation template added**
(`templates/competition-automation/`): mock-endpoint only, `dry_run` by default,
endpoint allowlist, flag regex, sha256 dedup, rate window, bounded retries.
Covered by `t_template` (7 tests).

**Opt-in local text indexing added.** Markdown dropped into the git-ignored
`sources/local/` is now indexed and searchable with no manifest requirement
(`kbindex.load_sources`), and the release builder explicitly excludes it, so
operator notes never enter a distributable archive. Covered by a new `t_kbindex`
test.

**Verification:** `python tests/run_tests.py` -> **132 passed, 0 failed, 0
modules skipped** (83.2 s) with Docker available.

**Release rehearsal:** `python tools/package_release.py --rehearse` built
`dist/ctf-buddy-0.1.0.tar.gz` (sha256
`927d6f4988190603248c41f32c142b3f3d5b52994a1c6c636fb29d337526fe40`, 200 files)
and ran the full suite from the extracted archive: **132 passed, 0 failed, 0
modules skipped, 83.0 s**. The archive was then rebuilt with this line included
and verified with `--check`.

## 2026-09-12 — remote mode, docs, baseline fixes

**Added: remote operation over SSH (`tools/ctfctl/remote.py`, `files.py`, CLI).**

* `ctfctl targets declare|list` — declares team-owned hosts; `--ack-policy` opens
  the mutation gate. Stored in git-ignored `state/targets.json` / `state/policy.json`.
* `ctfctl remote probe <host>` — fixed POSIX shell probe over ssh; no remote
  python needed; bounded output; redaction; honest gaps (unprivileged, missing
  tools, absent systemd).
* `ctfctl remote install <host>` — idempotent upload of `tools/ctfctl/*.py` +
  `profiles/*.json` to `~/.ctfctl` with a content fingerprint marker.
* `ctfctl remote files <host> list|read|find <path>` — bounded read-only FS
  exploration; absolute paths only; secret names metadata-only; binary refused;
  output redacted. Same code runs locally as `ctfctl files ...`.
* `ctfctl remote plan|apply|verify|rollback|recover|run` — proxies the existing
  engine on the target; two-pass plan mirrors exact target paths for
  authorization; mutations require declaration + policy ack + `--yes`; `run`
  allowlists read-only subcommands only.
* `doctor` now reports `remote-over-ssh` and lists `ssh` in capability groups.

**Fixed (before the feature, to get a green baseline):**

* Decoy stop hung on Windows: `_pid_alive` now uses `GetExitCodeProcess` instead
  of the destructive/blocking `os.kill(pid, 0)`; stop waits up to 5 s for the
  socket to be released. `tests/t_safety.py` decoy test now runs inside its
  throwaway repo copy.
* `files` depth logic was separator-dependent (wrong on Windows) and recursion
  ignored the remaining depth; remote upload paths used `os.path.join` (would
  send `state\targets.json` to Linux). All three fixed with tests.

**Verification:** `python tests/run_tests.py` -> 108 passed, 0 failed, 1 module
skipped (Docker unavailable). New modules: `t_remote.py` (21 tests),
`t_files.py` (9 tests). Full command and environment in `docs/validation.md`.

**Docs:** `README.md` (quickstart, exact commands), `docs/remote-mode.md`
(workflow, safety model, troubleshooting), `docs/support-matrix.md`,
`docs/team-operations.md` (first 5/15/30, ownership sheet, patch handoff,
emergency restore), `docs/validation.md`.

**Corpus/current inventory (from `ctfctl doctor`):** 114 cards in manifest,
277 primary sources, 50 teams/organizers, 2 tested profiles, 2 fixtures.

## Known gaps (next actions)

1. **Event-specific validation** still has to happen against the real box and
   the real rules (checker contract, tick length, patch permission). The lab
   proves the machinery; the event proves the configuration.
2. **Host firewall / SSH hardening is not automated** (review-only by policy).
   Container tests never validate host networking; do not read them as proof.
3. **Long-running observation under real attack traffic** is untested: the lab
   had no adversary. Start `ctfctl watch` once ticks begin and keep captures
   bounded.
4. Optional polish: a browser UI over the index (deliberately deferred until the
   CLI and remote workflows were complete).

## Open organizer questions (from `docs/event-facts.md`)

Unchanged: scoring model, tick length, flag lifetime, checker contract, target
ranges, reset policy, patch/network/AI rules, decoys, and how "one connected
device" is interpreted. Until answered, remote mutations stay gated and the
toolkit stays on the conservative side.
