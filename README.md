# ctf-buddy

Offline-first preparation toolkit for a first-time CTF team. It does two jobs:

1. **Find the answer fast.** A curated, source-linked knowledge base (114 cards
   from 277 primary sources, 50 identifiable teams and maintainers) with ranked
   local search, literal code search and a usable `rg`/Markdown fallback.
2. **Operate on your vuln box by IP.** Point it at the host your team owns, get a
   read-only inventory, explore the filesystem, then plan and apply tested,
   narrow protective patches with backup, health checks and rollback over SSH.

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
```

On Windows, use `python tools\ctfctl.py <command>` instead of `./ctfctl`.

### Your vuln box by IP

```bash
# 1. Declare the host as team-owned. --ack-policy also acknowledges the event
#    policy, which is required before any mutation. Read the rules first.
./ctfctl targets declare 10.10.5.3 --label "our vuln box" --ack-policy

# 2. Read-only inventory. No remote python needed, nothing is changed.
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

## What is supported where

| Capability | Status |
|---|---|
| Knowledge-base search (ranked + literal) | Supported, offline, any platform |
| Read-only host discovery (local) | Supported; partial without root; Windows is read-only |
| Remote probe over SSH | Supported; needs a declared target; no remote python required |
| Remote files exploration | Supported; absolute paths, byte/entry caps, secret names refused |
| Remote plan | Both shipped profiles and plan-only recommendations |
| Remote apply / verify / rollback | Only profiles marked `tested-auto` (the two shipped ones) |
| Observation (`watch`) | Local bounded logs/capture; remote via `remote run <host> watch` |
| Decoy | Local only, disabled by default, requires explicit unused port + ack |
| SSH/firewall hardening, package upgrades, mass password rotation | **Not automated.** Review-only by design; see `docs/support-matrix.md` |

## Layout

```
ctfctl                  thin bash wrapper (python3 -m ctfctl)
tools/ctfctl/           the toolkit (stdlib only)
kb/                     source-linked cards; kb/manifest.jsonl is the index of record
sources/                source provenance and verification records
profiles/               explicit supported stack profiles (YAML-ish JSON)
fixtures/               disposable practice services
tests/                  stdlib test suite (python tests/run_tests.py)
drills/                 participant drill sheets (see docs/team-operations.md)
docs/                   event facts, operations, validation and progress
research/               research notes that informed the build (read-only reference)
```

Read next: `docs/remote-mode.md` for the SSH workflow in detail,
`docs/team-operations.md` for the first 30 minutes, `docs/support-matrix.md` for
what is automated and what is deliberately not, and `docs/validation.md` for
exactly which checks were run and which were not.

## Honest limitations

* Container fixtures are validated only when Docker is available; the test suite
  skips the container integration module with a clear reason when it is not.
* Remote mode is tested against a fake SSH transport in the unit suite. A real
  end-to-end run needs a reachable host and is recorded in `docs/validation.md`.
* Our functional checks are *our* checks. They do not prove that an unseen
  organizer checker passes; see `docs/validation.md`.
