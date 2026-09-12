# Support matrix

What this toolkit will do automatically, what it will only propose, and what it
deliberately never does. If a row says "plan-only", `apply` refuses it by
construction.

| Status | Meaning |
|---|---|
| **tested-auto** | Covered by the disposable fixture matrix; `apply` may run it non-interactively after review |
| **plan-only** | Detection and evidence only; the plan lists a recommendation, `apply` refuses |
| **review-only** | A concrete action exists but needs `--approve-review` and an operator reading the diff |
| **not-automated** | No action is generated. Operator territory, documented, may be added later behind tests |
| **unsupported** | Honestly unavailable on the stated platform; no pretending |

## Platform and command surface

| Capability | Linux (operator) | Windows/macOS (operator) | Notes |
|---|---|---|---|
| Knowledge-base search / literal search | Supported | Supported | stdlib FTS5 with literal fallback |
| Local read-only discovery | Supported | Read-only, partial | Windows reports unsupported/read-only gaps |
| Remote probe over SSH | Supported | Supported | Target must be declared; probe needs only a POSIX shell |
| Remote files exploration | Supported | Supported | Target needs python3; absolute paths, caps, redaction |
| Remote plan | Supported | Supported | Two-pass plan; authorization mirrored from the local declaration |
| Remote apply/verify/rollback/recover | Supported | Supported | Target needs python3; only tested-auto profiles apply |
| Local host mutation (`ctfctl apply`) | Supported | Unsupported | Linux-only by design; refuse with a clear message elsewhere |
| `watch` (bounded logs/capture) | Supported | Logs only | Capture needs tcpdump on the host being watched |
| Decoy / honeypot | Supported | Local loopback only | Off until rules acknowledged and an unused port is named; never binds a busy port |
| Remote honeypot (`remote honeypot`) | Supported | Supported | Declaration + policy ack + `--yes` to start/stop; status/logs/collect are read-only |
| Remote lockdown (`remote lockdown`) | Supported (review-only) | Supported (plan only) | Additive nftables table + sshd key-only; needs `--approve-review --yes`, always keeps the operator's SSH address, and wants a console open |
| One-command recon (`remote auto`) | Supported | Supported | Read-only by default; `--apply`/`--honeypot-port` additionally require `--yes` |

## Shipped stack profiles

| Profile | Detects | Automatic action | Review-only action | Exploit probe | Validation |
|---|---|---|---|---|---|
| `web-nginx-flask-compose` | nginx reverse proxy + Flask service in one Compose project | Insert a `send_from_directory` containment guard | Bind published port to loopback | Traversal probe must stop returning the outside-root canary | Fixture `fixtures/p1-flask-compose`; legitimate workflow and exploit pair in `tests/t_engine.py` |
| `web-php-apache-compose` | PHP/Apache service in one Compose project with a download route | Insert a `realpath()` containment guard before the read | Bind published port to loopback | Traversal probe must stop returning the outside-root canary | Fixture `fixtures/p2-php-compose`; legitimate create/read/delete workflow + exploit probe |

Container integration tests run only when a Docker daemon is available; the
suite reports a skip with the reason otherwise (see `docs/validation.md`).

## Detection is broader than mutation

The plan stage collects evidence for far more than it will change: listeners,
services, containers, web roots, config files, permissions. A finding that has
no tested action becomes a recommendation in the plan, not an automatic change.
That is intentional: an unknown rule must not block read-only preparation, and a
known finding must not turn into an unreviewed mutation.

## Never automated (by policy, not by lack of code)

These are explicitly refused by design. They may be deliberate operator actions
later, after dependencies and scoring rules are understood, but the toolkit will
not do them for you:

* blanket package upgrades;
* rotating all passwords or keys;
* flushing firewall rules or replacing another table (`flush ruleset` is never
  generated, and the lockdown table is added, not substituted);
* a default-deny firewall with no allowlist — the action refuses an empty
  allowlist and refuses `0.0.0.0/0`, and always requires the operator's own
  source address;
* disabling "unknown" services;
* deleting suspicious files;
* changing database bind addresses;
* recursive permission changes;
* broad WAF blocks or IP autobans (including autobans driven by honeypot hits);
* bind-mounting an upstream/backend port to loopback without proof that the
  organizer checker does not contact it directly (always review-only).

## SSH and firewall changes

The SSH path is transport; `remote run` remains read-only. Two narrow actions are
the only firewall/SSH code in the toolkit, and both are **review-only** and
reversible:

| Action | Changes | Refuses when | Rollback |
|---|---|---|---|
| `firewall.nft_lockdown_table` | creates `/etc/ctfctl-lockdown.nft` and loads the one additive table `inet ctfctl_lockdown` | no allowlist, a `/0` entry, an allowlist that excludes the operator, a path outside `/etc`, `nft -c -f` rejects the ruleset, `nft` is missing | `nft delete table inet ctfctl_lockdown` plus deletion of the created file |
| `sshd.harden_authenticated_keys` | appends key-only directives to a real `sshd_config` | a `Match` block, an empty config, no usable `authorized_keys` entry, `sshd -t`/`sshd -T` rejects the candidate, `sshd` is missing | restore the pre-image and restart the service |

Both keep the ability to reconnect by construction (the operator's SSH source
address is in the allowlist; the sshd action never changes ports or auth keys),
and `remote apply` opens a *fresh* SSH connection after any access-affecting
change, auto-rolling back if it fails. The out-of-band console is still expected
to be open: a firewall typo can end the session before the reconnect check runs.

Container tests exercise the engine paths (file create/replace/delete, effect
dispatch, rollback) with **stubbed** `nft`/`sshd` binaries, because installing the
real packages needs network access. They do **not** validate that a real
ruleset loads on a real host, nor host firewall or SSH reachability. Do not read
them as such.

## Resource and output bounds

| Control | Bound |
|---|---|
| Probe section output | per-command `timeout 10`, per-section `head`, total capped by the ssh layer |
| Directory listing | depth <= 4, entries <= 2000 (default 200) |
| Filename search | depth <= 4, matches <= 2000 (default 200) |
| File read | 1 MiB hard cap (default 64 KiB), binary refused, secret names metadata-only |
| Remote command output | 512 KiB default, 1 MiB for the probe |
| Remote upload | ~250 KiB bundle, 240 s timeout |
| Decoy | request body bounded (64 KiB), 8 response slots, 4 MiB log budget, 10 s timeout |
| Honeypot | at most 4 listeners, 8 concurrent connections each, 512-byte banner read, 4 MiB log budget per listener |
| Remote honeypot collect | 4 MiB per log file, only paths this toolkit created, local copy under `captures/` |
| Remote auto report | bounded probe/discover/plan payloads; report written under `state/reports/` |
| Observation | 1800 s / 5000 lines / 512 KiB events per run |
