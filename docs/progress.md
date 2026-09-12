# Progress log

Append-only. Newest entries at the top. One line per verified slice; details go
in `docs/validation.md` and `docs/remote-mode.md`.

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

1. **Real SSH end-to-end run is not validated.** All remote tests use a fake
   `SSH_RUNNER`; the developer machine has no reachable SSH server. Run the
   workflow once from the Arch laptop against the practice VM and record host
   class + date + result in `docs/validation.md`.
2. **Drills are still 0** (`doctor` warns). The brief asks for web vuln diagnosis
   + narrow patch, PCAP-to-request reconstruction, unknown VM inventory, patch
   regression/rollback, optional decoy detection. `docs/team-operations.md` is
   not a drill sheet; the sheets belong in `drills/`.
3. **Docker integration module has never run here** (`t_integration_docker` skip).
   Run it on a machine with Docker to validate the Compose fixtures end to end.
4. **Validation of one real legitimate-workflow + exploit pair on the remote
   profile** against the actual event stack, recorded before relying on apply.
5. `ctfctl remote plan --show <id>` could print a saved plan without re-planning;
   not needed yet because plans are pulled locally when made.

## Open organizer questions (from `docs/event-facts.md`)

Unchanged: scoring model, tick length, flag lifetime, checker contract, target
ranges, reset policy, patch/network/AI rules, decoys, and how "one connected
device" is interpreted. Until answered, remote mutations stay gated and the
toolkit stays on the conservative side.
