# Remote mode: pointing ctfctl at your vuln box by IP

This is the workflow for operating on the team's own host (the "vuln box") from
an operator laptop. The transport is OpenSSH; the mutation engine is the same
one used locally, uploaded to the target so there is exactly one implementation
of backup, verification and rollback.

## Prerequisites

* An SSH client on the laptop (`ssh` in `$PATH`). Arch: `pacman -S openssh`.
* Reachability and an authentication path to the host: your key/agent, or an
  interactive password prompt when you run from a terminal.
* `python3` on the target for `plan`, `apply`, `verify`, `rollback`, `recover`
  and `files`. `remote probe` needs only a POSIX shell.
* The target declared as team-owned (below) and the event policy acknowledged
  before any mutation.

No password is stored, no key is copied, and no SSH server configuration is
changed. Host-key verification keeps `ssh`'s normal behavior: if you want
`known_hosts` entries or a jump host, configure them in `~/.ssh/config` and
ctfctl will use them.

## Step 1: declare the target

```bash
ctfctl targets declare 10.10.5.3 --label "our vuln box" --ack-policy
```

* `--ack-policy` says you have read the event rules and confirmed that patching
  your own services is allowed. Without it, read-only remote work still runs;
  every mutation is refused.
* Re-running updates the record instead of duplicating it.
* `ctfctl targets list` shows what is declared and whether the policy is
  acknowledged. Stored in `state/targets.json` and `state/policy.json`, both
  git-ignored.

The declaration is the only thing that unlocks SSH at all. An undeclared host
fails with the exact command to fix it, before any connection is made.

## Step 2: read-only probe

```bash
ctfctl remote probe 10.10.5.3           # human summary
ctfctl remote probe 10.10.5.3 --save    # also state/remote/<host>/probe-latest.json
ctfctl remote probe 10.10.5.3 --keep-raw  # redacted raw sections, for debugging
```

The probe is a fixed POSIX shell script sent over stdin. It collects, with
bounded output and per-command timeouts:

* identity: user, uid, hostname, kernel, distribution, init system, python3;
* TCP/UDP listeners with process attribution where the kernel allows it;
* running systemd services and timers;
* containers (docker/podman) and bounded compose-file search;
* web roots, nginx/apache/php versions;
* firewall state (nft/iptables/ufw/firewalld) as raw bounded output;
* cron entries and timers; disk, memory, uptime, CPU count; python3 presence.

Honest gaps are part of the report: unprivileged probes say that listener
attribution may be incomplete; missing `ss`/`netstat` falls back to
`/proc/net/tcp`; absent tools are reported as absent, never as "empty".

Every string that reaches `state/` or stdout is passed through control-character
escaping and secret redaction. The raw probe is not saved unless you ask.

## Step 3: explore the filesystem

```bash
ctfctl remote files 10.10.5.3 list /var/www --depth 2 --limit 200
ctfctl remote files 10.10.5.3 read /var/www/app/app.py --max-bytes 65536
ctfctl remote files 10.10.5.3 find /opt --name "*.py"
```

* Absolute paths only. Relative paths are refused before any SSH call, with the
  reason visible.
* `list`: bounded depth (max 4) and entries (max 2000), sorted, symlinks shown
  but not followed for recursion.
* `find`: filename glob only (no content search), bounded depth and matches,
  directory symlinks never followed.
* `read`: bounded head of one file (max 1 MiB), binary files are reported as
  binary and their bytes are never printed, secret-looking names (`id_rsa`,
  `*.pem`, `.env`, `shadow`, `credentials*`, histories, ...) return metadata
  only, and text output is redacted for `password=`, bearer tokens, private key
  blocks and flag-like strings.
* The corresponding local commands (`ctfctl files ...`) work the same way on the
  laptop, which is what the tests exercise.

These paths are not a free-form shell. There is no `remote exec`.

## Step 4: plan

```bash
ctfctl remote plan 10.10.5.3 --verbose
ctfctl remote plan 10.10.5.3 --profile web-php-apache-compose
```

What happens:

1. The toolkit is uploaded to `~/.ctfctl` on the target if its fingerprint
   changed. The bundle contains `tools/ctfctl/*.py` and `profiles/*.json`; it
   never includes `kb/`, `tests/`, `sources/` or runtime state.
2. A first read-only plan pass runs with no authorization, purely to learn the
   candidate target paths.
3. If the host is declared and the policy is acknowledged, a generated
   `state/targets.json`/`state/policy.json` is written on the target declaring
   exactly those paths, and the plan runs a second time with authorization
   recorded. The plan file is saved on the target and pulled back to
   `state/remote/<host>/`.
4. You get the exact diff, verifiers, risks and rollback description. Read it.
   `--verbose` prints full diffs; without it diffs are truncated at 80 lines per
   action.

If no shipped profile matches, the command exits 1 and says so. That is a normal
outcome for an unfamiliar service: the probe and file evidence are the
deliverable, and no mutation is proposed.

## Step 5: apply, verify, roll back

```bash
ctfctl remote apply 10.10.5.3 --plan <plan-id> --yes
ctfctl remote verify 10.10.5.3 --plan <plan-id>
ctfctl remote rollback 10.10.5.3 --list
ctfctl remote rollback 10.10.5.3 --tx <tx-id> --yes
ctfctl remote recover 10.10.5.3
```

* `apply` requires an explicit plan id (or `latest` for the most recent pull)
  **and** `--yes`. `--dry-run` validates without writing.
* The remote engine re-checks that the plan is not stale, takes the single-writer
  lock, records the before state, makes a bounded backup, applies the exact diff,
  validates syntax, replaces atomically, runs health checks, and rolls back
  automatically if the service regresses. Everything is journaled under
  `~/.ctfctl/state/tx/` and audited in `~/.ctfctl/state/audit.jsonl`.
* `verify` runs the plan's checks and reports degradation without changing
  anything.
* `rollback --list` shows change batches; `rollback --tx <id> --yes` refuses if
  the file changed after the transaction (a teammate patched it meanwhile).
* `recover` inspects interrupted transactions. It never guesses: it tells you
  which files are in which state and what to do next.

## One-command pass: `remote auto`

```bash
ctfctl remote auto 10.10.5.3                    # read-only: probe, discover, plan, report
ctfctl remote auto 10.10.5.3 --apply --yes      # also apply the first matching tested-auto plan
ctfctl remote auto 10.10.5.3 --honeypot-port 8080 --yes
```

`auto` runs the whole read-only pipeline for one IP and writes two files under
`state/reports/`: a JSON record and a Markdown handover (`auto-<host>-<stamp>.md`)
listing identity, listeners, containers, firewall posture, detected stacks, the
exact plan actions, evidence gaps, and suggested unused ports for a honeypot.

It is **read-only unless you pass `--apply` and/or `--honeypot-port`, each of
which also requires `--yes`**. `--apply` uses the same gated apply path as
`remote apply` (including the automatic rollback on verification failure and the
operator-side reconnect check for access-affecting changes); `--honeypot-port`
uses the same gated path as `remote honeypot`. If the target has no `python3`,
the probe evidence and the report still happen, and the missing piece is
recorded as a gap — nothing is guessed.

## Review-only lockdown: `remote lockdown`

```bash
ctfctl remote lockdown 10.10.5.3 --allow-cidr 10.10.0.0/16
```

This pulls a plan that contains up to two actions:

* **`firewall.nft_lockdown_table`** — creates `/etc/ctfctl-lockdown.nft`, one
  *additive* nftables table (`table inet ctfctl_lockdown`) whose input chain drops
  anything not allowlisted. It never flushes the ruleset and never edits another
  table, so Docker NAT rules and anything the image shipped keep working. The
  allowlist is built from: the team ranges you name, **your own SSH source
  address (read from the target's `$SSH_CONNECTION`, always included)**, and
  every port the probe already saw listening, plus port 22 by default.
* **`sshd.harden_authenticated_keys`** — appends `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`, `PermitRootLogin prohibit-password` to
  `/etc/ssh/sshd_config`. It refuses if the file contains a `Match` block (an
  appended line would land inside it), refuses if the effective config
  (`sshd -T`, drop-ins included) does not report the hardened values, and
  refuses if no non-empty `authorized_keys` entry exists for the account that
  must keep access.

Both actions are `review-only`: `apply` needs `--approve-review --yes`, and the
plan shows the exact diff. Rollback restores `sshd_config` from the pre-image
and runs `nft delete table inet ctfctl_lockdown` (deleting the table is the
inverse of loading it; re-loading the file is not).

**Before applying, have the out-of-band console open.** The toolkit adds your
SSH address to the allowlist and re-checks your connection *after* the change
(auto-rolling back if a fresh SSH connection fails), but a firewall typo can
still end your session; the console is the recovery path. Container tests do not
validate host firewall or SSH behaviour, and `docs/support-matrix.md` says so.

## Honeypots

```bash
ctfctl remote honeypot 10.10.5.3 start --honeypot-port 8080 --yes
ctfctl remote honeypot 10.10.5.3 status
ctfctl remote honeypot 10.10.5.3 logs --lines 100
ctfctl remote honeypot 10.10.5.3 collect      # bounded copy into captures/
ctfctl remote honeypot 10.10.5.3 stop --all --yes
```

Start/stop are mutations (declaration + policy ack + `--yes`); the other three
are read-only. The listener refuses any port that is already in use and any port
below 1024 unless `--allow-privileged` is given. See `docs/decoy.md` for modes,
event format and bounds.

## Escape hatch for other read-only commands

```bash
ctfctl remote run 10.10.5.3 doctor --json
ctfctl remote run 10.10.5.3 discover --json
ctfctl remote run 10.10.5.3 watch --seconds 60 --iface eth0
```

`remote run` accepts only: doctor, discover, plan, verify, watch, files,
profiles, kb, recover. Anything that can mutate is not on the list.

## Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| `target ... is not declared` | Run `ctfctl targets declare <host> --label '...'` first |
| `ssh could not connect` | Address, route, port, key or agent. Nothing is retried automatically |
| `Permission denied (publickey,password)` | No usable key and no terminal for a prompt. Check `ssh` manually first |
| `python3 is not installed on <host>` | Probe still works; install python3 or run the toolkit locally on the target |
| `toolkit upload ... failed` | The target needs `base64` and `tar`; check the stderr tail in the error |
| plan exits 1 with no match | No shipped profile fits. Capture the probe and extend a profile deliberately |
| `the event policy is not acknowledged` | Re-run `targets declare ... --ack-policy` after reading the rules |
| Apply refuses a stale plan | The file changed after planning. Re-run `remote plan` |

## Limits

* This layer is transport plus the existing engine. It will not do blanket
  hardening: no package upgrades, no firewall flushes, no mass password rotation,
  no deleting unknown services. Two narrow, review-only exceptions exist and are
  documented above: an additive nftables allowlist table and an sshd key-only
  hardening action. Both require `--approve-review --yes`, both are reversible,
  and neither runs as part of any profile or of `remote auto --apply` unless you
  apply that plan explicitly.
* Profiles marked anything other than `tested-auto` never apply automatically.
  `docs/support-matrix.md` lists exactly what can apply and what cannot.
* The unit suite tests the full flow against a fake SSH transport. A real
  end-to-end SSH run must be done by the operator; record it in
  `docs/validation.md` with the date, the host class and the result.
