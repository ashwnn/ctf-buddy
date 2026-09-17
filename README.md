# ctf-buddy

Offline-first preparation toolkit for a first-time CTF team. It does two jobs:

1. **Find the answer fast.** A curated, source-linked knowledge base (123 cards
   from 100 canonical sources, 277 provenance records, 50 identifiable teams
   and maintainers) with ranked
   full-text search, literal code search, nine copy-paste **cheat sheets**
   (`ctfctl kb cheat`) and a usable `rg`/Markdown fallback.
2. **Operate on your vuln box by IP.** One command for the read-only pass
   (`ctfctl remote auto <ip>`: probe, discovery, plan, report), then reviewed and
   reversible changes over SSH: narrow patches with backup, health checks and
   rollback; an additive nftables lockdown; sshd key-only hardening; and
   honeypot listeners that log attacker traffic.

Ordinary use needs no Internet, no API keys and no cloud service. Only
`ctfctl prep-online` may touch the network, and only before the event.

## Authorization (read this first)

Tools and drills here run only against:

* local practice fixtures in `fixtures/`, and
* hosts a teammate has explicitly declared in `state/targets.json`.

The event name is **not** an authorization scope. Do not point anything here at
organizer infrastructure, opponent systems or public hosts. Remote mutations are
refused until the target is declared and the event policy is acknowledged; the
read-only probe also requires the declaration, with the exact command in the
error message.

Never commit real flags, credentials, packet captures, machine inventories or
private keys. `state/`, `captures/`, `backups/`, `index/` and `sources/raw/` are
git-ignored for that reason.

## Requirements

* Python 3.9+ with the standard library (that is the whole toolkit).
* A Linux laptop is the supported operator platform. Windows and macOS run the
  read-only and local parts; host mutation is Linux-only by design.
* For remote mode: an OpenSSH client (`ssh`) on the laptop, and a target that is
  reachable over SSH. `remote probe` needs only a POSIX shell on the target;
  `plan`/`apply`/`files` additionally need `python3` on the target.
* Optional tools (`rg`, `tcpdump`, `tshark`, `docker`, `curl`) enable extra
  features; `ctfctl doctor` reports exactly what is missing and what still works.

## Quickstart

From a checkout (Arch/other Linux):

```bash
./ctfctl doctor                 # offline capability report
./ctfctl kb index               # build the local search index (once)
./ctfctl kb search "command injection bypass WAF"
./ctfctl kb literal "../.."     # literal code/error-string search, punctuation safe
./ctfctl kb show card-web-003   # or: ./ctfctl kb open card-web-003
./ctfctl kb cheat               # all quick-reference sheets
./ctfctl kb cheat pcap          # just the topic you need, right now
```

Your own notes can join the search without joining the corpus: drop Markdown into
`sources/local/` (git-ignored, excluded from release archives), run
`./ctfctl kb index`, and your text is searchable locally. Snapshots that a
licence permits can live in `sources/text/` and are matched to their source
record; unknown licence means metadata only.

On Windows, use `python tools\ctfctl.py <command>` instead of `./ctfctl`.

### Your vuln box by IP

```bash
# 1. Declare the host as team-owned. --ack-policy also acknowledges the event
#    policy, which is required before any mutation. Read the rules first.
./ctfctl targets declare 10.10.5.3 --label "our vuln box" --ack-policy

# 2. One read-only pass: probe + discovery + plan + a written report.
#    Nothing is changed, and no flag/credential is ever copied back.
./ctfctl remote auto 10.10.5.3
#    -> state/reports/auto-10.10.5.3-<stamp>.md (+ .json)

# 2b. Or step by step. Read-only inventory; no remote python needed.
./ctfctl remote probe 10.10.5.3 --save

# 3. Explore the filesystem: bounded, redacted, absolute paths only.
./ctfctl remote files 10.10.5.3 list /var/www --depth 2
./ctfctl remote files 10.10.5.3 read /var/www/app/app.py
./ctfctl remote files 10.10.5.3 find /opt --name "*.py"

# 4. Detect the stack and review the exact plan (diffs, checks, rollback).
./ctfctl remote plan 10.10.5.3 --verbose

# 5. Apply the reviewed plan. The remote engine keeps a backup, runs health
#    checks and rolls back automatically if the service regresses.
./ctfctl remote apply 10.10.5.3 --plan <plan-id> --yes

# 6. Verify, and roll back deliberately if needed.
./ctfctl remote verify 10.10.5.3 --plan <plan-id>
./ctfctl remote rollback 10.10.5.3 --list
./ctfctl remote rollback 10.10.5.3 --tx <tx-id> --yes
```

### Defend and distract (all review-only or explicitly confirmed)

```bash
# The whole defensive pass in one command: patch, honeypot, then lockdown.
# Order matters: the honeypot port is added to the allowlist it would otherwise
# be dropped by. Needs the console open and the allowlist read out loud first.
./ctfctl remote auto 10.10.5.3 \
  --apply --honeypot-port 8080 --lockdown --allow-cidr 10.10.0.0/16 \
  --approve-review --yes

# Additive nftables allowlist + sshd key-only hardening. Creates ONE table and
# never flushes anything; your own SSH address is always in the allowlist.
./ctfctl remote lockdown 10.10.5.3 --allow-cidr 10.10.0.0/16
# read the diff, open the console, then:
./ctfctl remote apply 10.10.5.3 --plan <plan-id> --approve-review --yes

# Honeypots on ports the probe showed as unused (http lure or protocol banner).
./ctfctl remote honeypot 10.10.5.3 start --honeypot-port 8080 --yes
./ctfctl remote honeypot 10.10.5.3 start --honeypot-port 2222 --mode banner --banner ssh --yes
./ctfctl remote honeypot 10.10.5.3 logs
./ctfctl remote honeypot 10.10.5.3 collect     # bounded copy into captures/
./ctfctl remote honeypot 10.10.5.3 stop --all --yes
```

Details, bounds and failure modes: `docs/remote-mode.md`, `docs/decoy.md`,
`docs/support-matrix.md`.

`remote run <host> <subcommand>` proxies only read-only subcommands (doctor,
discover, plan, verify, watch, files, profiles, kb, recover). Mutations must go
through `remote apply` or `remote rollback`.

### Local fixtures and practice

```bash
# Flask behind nginx, and PHP/Apache, as disposable Compose fixtures.
cd fixtures/p1-flask-compose && docker compose up -d && cd ../..
./ctfctl discover --json                  # read-only inventory of this machine
./ctfctl plan --profile web-php-apache-compose --verbose
./ctfctl apply --plan latest --yes --dry-run
./ctfctl watch --logs /var/log/nginx/access.log --seconds 60
./ctfctl decoy status                     # decoys stay off until rules are acknowledged
```

### Drills and rehearsal

```bash
# Five short drills with separate answers: web diagnosis and patch, PCAP
# reconstruction, unknown-VM inventory, patch regression and rollback, decoy.
ls drills/
python drills/assets/make-synthetic-pcap.py captures/drill02.pcap --json

# Package and rehearse a release from the archive itself.
python tools/package_release.py --rehearse --json
python tools/package_release.py --check dist/ctf-buddy-0.2.0.tar.gz
```

The optional flag-submission template is in `templates/competition-automation/`;
it is disabled by default, mock-endpoint only, and refuses any host that is not
explicitly allowlisted.

## What is supported where

| Capability | Status |
|---|---|
| Knowledge-base search (ranked + literal) | Supported, offline, any platform |
| Read-only host discovery (local) | Supported; partial without root; Windows is read-only |
| Remote probe over SSH | Supported; needs a declared target; no remote python required |
| Remote files exploration | Supported; absolute paths, byte/entry caps, secret names refused |
| Remote plan | Both shipped profiles and plan-only recommendations |
| Remote apply / verify / rollback | Only profiles marked `tested-auto` (the two shipped ones) |
| One-command recon (`remote auto`) | Supported; read-only by default, report under `state/reports/` |
| Observation (`watch`) | Local bounded logs/capture; remote via `remote run <host> watch` |
| Decoy / honeypot | Local and remote; off until an unused port is named; never binds a busy port |
| SSH/firewall lockdown | **Review-only**, two narrow reversible actions (additive nftables table, sshd key-only) with `--approve-review --yes`; see `docs/support-matrix.md` |
| Package upgrades, mass password rotation, firewall flushes, autobans | **Not automated.** Refused by design |

## Layout

```
ctfctl                  thin bash wrapper (python3 -m ctfctl)
tools/ctfctl/           the toolkit (stdlib only)
tools/package_release.py  documented release builder with checksums and licences
kb/                     source-linked cards (incl. kb/cheatsheets/); kb/manifest.jsonl is the index of record
sources/                source provenance and verification records
profiles/               explicit supported stack profiles (YAML-ish JSON)
fixtures/               disposable practice services
tests/                  stdlib test suite (python tests/run_tests.py)
drills/                 participant drill sheets, answers separate
templates/              reusable templates kept away from runtime state
docs/                   event facts, operations, validation and progress
research/               research notes that informed the build (read-only reference)
dist/                   built releases (git-ignored)
```

Read next: `docs/remote-mode.md` for the SSH workflow in detail, `docs/decoy.md`
for honeypots and decoys, `docs/team-operations.md` for the first 30 minutes,
`docs/support-matrix.md` for what is automated and what is deliberately not, and
`docs/validation.md` for exactly which checks were run and which were not.

## Honest limitations

* Container fixtures are validated only when Docker is available; the test suite
  skips the container integration module with a clear reason when it is not.
* Remote mode is tested against a fake SSH transport in the unit suite. A real
  end-to-end run needs a reachable host and is recorded in `docs/validation.md`.
* The lockdown/honeypot container test stubs `nft` and `sshd` (the real packages
  would need network access). It proves the engine and the listener, not that a
  real ruleset loads on a real host; see `docs/support-matrix.md`.
* Our functional checks are *our* checks. They do not prove that an unseen
  organizer checker passes; see `docs/validation.md`.
