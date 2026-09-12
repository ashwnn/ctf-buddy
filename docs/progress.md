# Progress log

Append-only. Newest entries at the top. One line per verified slice; details go
in `docs/validation.md` and `docs/remote-mode.md`.

## 2026-09-12 (final) — one-command recon, honeypots, gated lockdown, cheat sheets

**`ctfctl remote auto <ip>` added.** One read-only pass over a declared host:
probe -> install/discover -> plan (two-pass, authorization mirrored) -> bounded
file recon of `/var/www`, `/srv`, `/opt`, `/home` -> `state/reports/auto-<host>-<stamp>.{json,md}`
with identity, listeners, containers, firewall posture, detected stacks, plan
actions, evidence gaps and suggested unused honeypot ports. Read-only by default;
`--apply` and `--honeypot-port` each additionally require `--yes` and reuse the
gated paths below. A target without `python3` still yields the probe report plus a
recorded gap.

**Honeypots added** (`tools/ctfctl/honeypot.py`, `decoy.py` banner mode, CLI
`honeypot` and `remote honeypot`). Up to four listeners per host, `http` lure or
`banner` mode (ssh/smtp/ftp/telnet presets or custom text), every event marked
`decoy=true`, 4 MiB log budget per listener, 8 concurrent connections, and a
hard refusal to bind a port that is already in use or a privileged port without
`--allow-privileged`. Start/stop over ssh require declaration + acknowledged
policy + `--yes`; `status`/`logs`/`collect` are read-only, and `collect` only ever
reads paths this toolkit created (validated before they reach an ssh argv).

**Review-only lockdown added** (`firewall.nft_lockdown_table`,
`sshd.harden_authenticated_keys`, `ctfctl lockdown plan`, `remote lockdown`).
The firewall action creates `/etc/ctfctl-lockdown.nft` containing one **additive**
table that drops non-allowlisted inbound traffic; it never flushes the ruleset and
never edits another table, so Docker NAT rules survive. The allowlist is the team
ranges plus the operator's own address (read from the target's `$SSH_CONNECTION`)
plus every port the probe saw listening; `0.0.0.0/0` and an allowlist that
excludes the operator are refused, as is an empty one. The sshd action appends
key-only directives, refuses a `Match` block or an empty config, requires a
non-empty `authorized_keys`, and validates with `sshd -t` **and** `sshd -T`
(drop-ins included). Both are `review-only` (`--approve-review --yes`); rollback
restores the pre-image and runs `nft delete table inet ctfctl_lockdown`.

**New engine capability: `file_create`.** Actions may create a file, with a
rollback that deletes it -- and refuses to delete it if a teammate edited it
afterwards. Rollback effects now prefer an action-supplied `rollback_argv`
(loading a firewall table is not its own inverse; deleting it is). New verifiers
`nft.table` and `sshd.option`, and the nft effect allowlist accepts exactly two
argv shapes.

**Access-preserving guard.** After any apply whose plan touches sshd or firewall
paths, `remote apply` opens a *fresh* SSH connection from the operator. If that
fails, it reports the failure, attempts a rollback of the transaction, and prints
the console recovery path. The unit suite covers the failing-reconnect path.

**Nine cheat sheets added** (`kb/cheatsheets/`, 123 cards now, all indexed):
web triage, web defence patch loop, PCAP one-liners, forensics triage, reverse
engineering, crypto triage, A/D tick loop, vuln-box recon/lockdown/honeypot, and
unknown-artifact triage. New command `ctfctl kb cheat [topic]` lists them or
searches within the tag.

**Bugs found and fixed:**

* A stale lock (exclusive-create fallback, e.g. a crashed run on Windows) blocked
  every future mutation forever. `WriterLock` now reclaims a lock only when the
  recorded pid is dead *and* the file is older than 120 s, and never touches a
  live one.
* The first container run of the lockdown proved the plan was adding a
  `tcp.connect 127.0.0.1:22` readiness check on hosts where nothing listens on 22,
  so a correct lockdown was auto-rolled back. Verifiers are now pruned to checks
  that describe the host.
* `nft delete table ...` was rejected by the effect allowlist (list-vs-tuple
  comparison), which would have made every firewall rollback refuse its own
  inverse.
* `sshd.harden_authenticated_keys` was not idempotent (it re-appended its block on
  a second render) and `VerifyResult` was constructed with a `command` argument
  that does not exist; both fixed and covered.

**Verification:** `python tests/run_tests.py` -> **168 passed, 0 failed, 0 modules
skipped** (104.3 s) with Docker available. New modules: `t_lockdown` (13),
`t_honeypot` (7), `t_remote_ops` (12), `t_integration_lockdown` (1); `t_engine`
and `t_kbindex` gained lock-reclaim and cheat-sheet tests. Details and the
explicit not-run list are in `docs/validation.md`.

**Docs:** `docs/decoy.md` (new), `docs/remote-mode.md` (auto/lockdown/honeypot
sections), `docs/support-matrix.md` (new rows, the two review-only exceptions,
stubbed-container honesty), `docs/event-facts.md` (U15/U16), `docs/team-operations.md`,
`docs/card-template.md` (cheat-sheet adaptation), `README.md`. `doctor` now
reports the cheat-sheet count and the honeypot/lockdown capability lines.

**Release:** version bumped to 0.2.0; `python tools/package_release.py --json` built
`dist/ctf-buddy-0.2.0.tar.gz` (215 files, deterministic, sha256
`246c7a12e76cf1aefa3f8b1e1011285940790ee75e3c2fb2d98147ebfc261263`), `--check`
verified it against its manifest, and `--rehearse` extracted it and ran the whole
suite from the extracted tree: **168 passed, 0 failed, 0 modules skipped, 103.0 s**.

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
