# Vuln box: recon, lockdown, honeypot from one IP

**First useful action.** Declare the host, then run the read-only pass. Everything else (patch,
lockdown, honeypot) is a decision you make after reading the report, never before.

```bash
HOST='<TEAM_VM_IP>'                     # a host your team owns, declared by a teammate
./ctfctl targets declare "$HOST" --label "our vuln box" --ack-policy
./ctfctl remote auto "$HOST"            # probe + discovery + plan + report; changes nothing
```

Expected: `state/reports/auto-<host>-<stamp>.md` listing listeners, containers, firewall posture,
detected stacks, suggested unused ports, and every evidence gap. Read it before the next command.

## Symptoms

- You have an IP and ten minutes before the first tick.
- The box is a fresh image with an unknown stack and an unknown network posture.
- Attackers are already probing and you want a honeypot that is not a scored service.

## Prerequisites and assumptions

- The host is declared in `state/targets.json` by a teammate and reachable over SSH
  (`ctfctl targets declare ... --ack-policy`). The event name is not an authorization scope.
- `remote probe` needs only a POSIX shell on the target; `auto`, `plan`, `apply` and `honeypot` also
  need `python3` there.
- An out-of-band console (VNC/serial/provider console) before any firewall or SSH change.
- Rules check: confirm the event permits host firewalls, SSH changes, and honeypots.

## Diagnostic sequence

1. `remote auto <HOST>` (read-only) → read the report. Note every service that *must* stay reachable.
2. `remote files <HOST> list /var/www --depth 2` and `remote files <HOST> read <path>` for the app
   roots the report named → bounded, redacted, absolute paths only.
3. `remote plan <HOST> --verbose` → for a recognised stack, read the exact diff and the exploit probe.
4. `remote apply <HOST> --plan <ID> --yes` → apply only after the exploit probe and the legitimate
   workflow are understood. The engine backs up, verifies, and auto-rolls back on regression.
5. Lockdown last, with the allowlist from the report: `remote lockdown <HOST> --allow-cidr <TEAM_NET>`
   → review-only plan, needs `--approve-review --yes`, and it always keeps your own SSH address.
6. Honeypot only on a port the report shows as unused: `remote honeypot <HOST> start --port <FREE>
   --yes`; collect events with `remote honeypot <HOST> collect`.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ctfctl remote probe "$HOST" --save` | os, listeners, containers, firewall, tools | the read-only baseline; works with no remote python |
| `ctfctl remote auto "$HOST"` | report paths + suggestions | the whole read-only pipeline in one command |
| `ctfctl remote plan "$HOST" --verbose` | diff + verifiers + exploit probe | exactly what would change |
| `ctfctl remote apply "$HOST" --plan lt --yes` | `COMMITTED`, verifier table | landed with a rollback record |
| `ctfctl remote lockdown "$HOST" --allow-cidr 10.0.0.0/8` | review-only plan | additive nftables drops + sshd key-only |
| `ctfctl remote honeypot "$HOST" start --port 8080 --yes` | listener pid + log path | a decoy that logs `decoy=true` events |
| `ctfctl remote honeypot "$HOST" logs` | recent decoy events | who is probing, with user agents |
| `ctfctl remote rollback "$HOST" --list` | transactions | the way back for every change |

Manual equivalents when you must work without the toolkit on the box:

```bash
ss -lntup                                    # listeners and owning processes
nft list ruleset | head -40                  # current firewall (read-only)
nft -f /etc/ctfctl-lockdown.nft              # load the additive lockdown table
nft delete table inet ctfctl_lockdown        # remove it (this is the rollback)
sshd -T | grep -Ei 'passwordauth|permitrootlogin'   # effective sshd policy
nsenter -t 1 -n ss -lntup                    # listeners in the host netns from a container
```

## State-changing actions (only if the card changes a host or service)

- **Impact:** the lockdown adds a drop-only nftables chain (existing rules untouched) and turns off
  sshd password auth; a honeypot adds listeners on unused ports. All three are reversible.
- **Preconditions:** declared target, acknowledged policy, verified allowlist (team + checker +
  your own SSH address), a free port for the honeypot, and a console.
- **Health check before:** the report's listener list, plus one SSH login you have just proven works.
- **Apply:** `remote lockdown ... --approve-review --yes` then `remote apply` for the plan; the
  operator-side reconnect check runs after any change that can cut SSH.
- **Health check after:** `remote probe` again; compare listeners and confirm the checker's ports are
  still reachable. `nft list table inet ctfctl_lockdown` must show the table.
- **Rollback:** `remote rollback <HOST> --tx <TX> --yes` (restores `sshd_config` and deletes the nft
  table). If SSH is gone, use the console: `nft delete table inet ctfctl_lockdown` and restore the
  pre-image under `state/tx/<TX>/pre/`.

## Failure modes and things teams stopped doing

- Default-deny firewalls with no allowlist: the classic self-inflicted zero. The toolkit refuses to
  build one and always includes the operator's own CIDR.
- IPv6 forgotten: an `inet` table drops IPv6 traffic unless an IPv6 range is allowed.
- Honeypots on a port the checker uses — worse than no honeypot.
- Editing `sshd_config` without a known-good key; check `authorized_keys` first (the action refuses
  without one) and keep the console.
- Treating a container test as proof that *host* firewall/SSH changes are safe: it is not
  (`docs/support-matrix.md`).

## Evidence status

- **Status:** reproduced locally in a disposable container (ruleset load/delete, file create/rollback)
  as recorded in `docs/validation.md`; the host-networking effect of a real firewall is *our* check,
  not an organizer check.
- **What we actually ran:** `remote auto` and `remote honeypot` against the SSH lab and local
  fixtures; see `docs/validation.md` for the exact commands.
- **Our adaptation vs the source:** the additive-table design (never flush) and the mandatory operator
  CIDR are ours; Docker's documentation is the source for why flush is dangerous with containers.

## Sources

- `src-docker-firewalls-o6-351180c6` — why flushing the ruleset breaks container networking.
- `src-docker-host-network-o9-6732393f` — host vs bridge networking and published ports.
- `src-iproute2-ss-manpage-fc58f455` — listener/connection inspection.
- `src-nmap-reference-r06-45db80c0` — what an attacker's scan sees (why exposure matters).
- `src-enowars-checker-tenets-bf4b0ac7` — the checker must always be able to reach the service.
- `src-faust-todo-patches-r06-abf8d3d1` — narrow, reversible patches in practice.
