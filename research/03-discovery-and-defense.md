# Minimal Linux-First Discovery and Defensive Automation for Unknown Team-Owned CTF VMs

**Research date:** 2026-09-11  
**Target:** Raymond James CTF 2026 preparation  
**Artifact:** `research/03-discovery-and-defense.md`

## 1. Executive design

The correct design is not a universal hardening script. It is a conservative evidence-driven transaction tool for team-owned Linux CTF VMs:

1. **Discover first.** Build a provenance-bearing graph from listeners -> processes -> init/service manager -> reverse proxy/container -> source/config -> datastore/scheduled jobs.
2. **Plan narrowly.** A proposed mutation must name the exact condition it addresses, the evidence supporting that condition, the files/runtime objects it will touch, the verifier, and the inverse operation.
3. **Default to review-only.** Unknown services, host firewall changes, SSH changes, stateful container recreation, database changes, and ambiguous source patches are never silently applied.
4. **Verify functionality, not just liveness.** `systemctl is-active`, a listening socket, `HTTP 200`, `pg_isready`, or `PING` are necessary signals, not proof that the scored service still satisfies the organizer checker.
5. **Rollback only what this transaction changed.** Never restore an entire application tree, database volume, firewall ruleset, or mutable upload directory to an old snapshot just because a patch failed.
6. **Fail closed on stale evidence.** Teammate edits, process replacement, config changes, boot changes, changed Compose topology, and new application data invalidate assumptions rather than being overwritten.
7. **Unattended host mutation requires disposable-VM proof.** This research did not execute any candidate host mutation on a disposable VM. Therefore, **as delivered, all service/host mutations below are review-only**. Some are identified as candidates for later unattended use once their exact profile passes the test matrix in Section 12.

This matches the event brief's operational priority: rapidly enumerate an unknown service, find the vulnerable code path, patch it without breaking it, preserve availability, and monitor attacks. It also reflects real attack-defend scoring systems in which gameservers/checkers store and retrieve flags through legitimate service functionality; availability is part of the contract, not an optional hardening concern [A1][A2][A3].

### Non-goals

The tool must not, by default:

- install packages or run `apt`, `dnf`, `yum`, `apk`, or distribution upgrades;
- rotate all passwords or SSH keys;
- disable unknown services merely because they look unusual;
- impose a default-deny firewall;
- rewrite sysctls globally;
- kill listeners it cannot attribute;
- mass-`chmod` an application tree;
- edit database contents;
- delete cron jobs or timers it does not understand;
- run `docker system prune`, log cleanup, or database cleanup under disk pressure;
- dump environment variables, complete Compose configs, application configs, or command lines into the audit log.

The recommended implementation is a small Python 3 CLI using the standard library for orchestration, timeout control, hashing, JSON state, locks, and atomic file replacement. External commands remain providers, not dependencies assumed to exist.

Suggested interface:

```text
ctfguard discover [--json report.json]
ctfguard plan [--profile auto|nginx-flask|compose-web-db]
ctfguard apply PLAN_ID          # refuses review-only actions unless explicitly approved
ctfguard verify TX_ID
ctfguard rollback TX_ID
ctfguard status
```

`discover` and `plan` are read-only. `apply` is transactional and revalidates every prerequisite immediately before mutation.

---

## 2. Version and distribution assumptions

Do not infer capability from distro name alone. Feature-gate on the commands and versions actually present.

| Area | What can safely be assumed | What must be detected |
|---|---|---|
| Init/service manager | `/proc` exists on normal Linux systems. | PID 1 may be systemd, another init, or a container shim. Do not call `systemctl` until detected. |
| systemd | `systemd-run --on-active=` exists in systemd releases from v218 onward [O4]. | Installed version, whether transient units are permitted, whether the service manager is actually PID 1, and whether the relevant unit has a working `ExecReload`. |
| OpenSSH | `sshd -t` validates server configuration and `sshd -T` prints effective configuration in supported OpenSSH implementations [O5]. | Actual daemon binary/path, config path, `Include`/`Match` behavior, service unit name (`ssh.service`, `sshd.service`, custom unit, or no systemd unit), authentication method, address family, and reload semantics. |
| Ubuntu firewall | Ubuntu documents UFW as its default firewall frontend; UFW is initially disabled and manages IPv4/IPv6 rules [O16]. | Whether UFW is active, whether raw nftables/iptables rules coexist, and whether Docker bypasses the path being changed. |
| RHEL firewall | RHEL 9 documents firewalld and nftables, with firewalld maintaining distinct runtime and permanent configuration [O17]. | Active zone/interface mapping, runtime/permanent divergence, backend, Docker interaction. |
| nftables | `nft -c` can check a ruleset/batch without applying it; batches loaded with `nft -f` have transaction semantics [O13][O14]. | Installed version, actual active tables/chains, ownership of the ruleset, and whether another manager generates it. |
| iptables | `iptables-restore --test` exists in current iptables and `--wait` coordinates the xtables lock [O15]. | Whether the host uses legacy iptables or the nft compatibility backend, whether `--test` is supported by the installed version, and the separate IPv4/IPv6 state. |
| Docker | Docker may create NAT/filtering rules for bridge networking; host networking shares the host network namespace [O6][O7][O9]. | Engine version, firewall backend, network mode per container, published host addresses, rootless mode, and daemon permissions. |
| Compose | Current Compose Specification is the supported model; old `docker-compose` binaries still exist in older systems [O10][O11]. | `docker compose` vs `docker-compose`, project labels, config-file location, profiles, and interpolation behavior. Full `docker compose config` can surface interpolated values, so do not persist it [O12]. |
| Nginx | `nginx -t` validates configuration; `-T` also dumps it and was added in Nginx 1.9.2 [O19]. | Binary/config path from `nginx -V`, include graph, privileges needed to read referenced files, and secret-bearing directives. |
| Apache HTTP Server | `apachectl configtest`/`-t` tests syntax; `apachectl -S` can show virtual-host interpretation [O20]. | Actual binary/layout, loaded modules, proxy module use, distro config paths. |
| Flask | `send_from_directory()` is the safe helper for serving user-selected paths from a fixed directory; Flask 2.0 renamed a keyword parameter from `filename` to `path` [O21]. | Installed Flask version and exact route semantics. The synthetic diff below uses positional arguments to avoid relying on the renamed keyword. |

### On-host fingerprint probe

The runner should collect versions without failing if a command is missing:

```sh
cat /etc/os-release 2>/dev/null || true
uname -srmo
ps -p 1 -o pid=,comm=,args=

for x in systemctl systemd-run ss sshd nft iptables ip6tables ufw firewall-cmd docker nginx apachectl httpd; do
  command -v "$x" 2>/dev/null || true
done

systemctl --version 2>/dev/null | head -n 1 || true
systemd-run --version 2>/dev/null | head -n 1 || true
ss -V 2>&1 | head -n 1 || true
sshd -V 2>&1 | head -n 1 || true
nft --version 2>/dev/null || true
iptables --version 2>/dev/null || true
ip6tables --version 2>/dev/null || true
ufw --version 2>/dev/null | head -n 1 || true
firewall-cmd --version 2>/dev/null || true
docker version --format '{{.Client.Version}}|{{.Server.Version}}|{{.Server.APIVersion}}' 2>/dev/null || true
docker compose version 2>/dev/null || docker-compose version 2>/dev/null || true
nginx -v 2>&1 || true
apachectl -v 2>/dev/null || httpd -v 2>/dev/null || true
```

The execution engine, not the shell, should impose hard deadlines and output caps. If the GNU `timeout` command exists, it can be an extra guard, but the design must not depend on it.

---

## 3. Evidence model

Discovery should produce a graph, not a flat inventory.

Recommended node types:

- `Listener {proto, family, local_addr, local_port, inode}`
- `Process {pid, uid, exe, cwd, argv_hint, cgroup}`
- `Service {manager, unit, main_pid, fragment, dropins, working_dir, exec_start}`
- `ProxyRoute {frontend, server_name, path, upstream}`
- `Container {id, name, image, network_mode, compose_project, compose_service}`
- `Mount {source, destination, rw, type}`
- `SourceRoot {path, provenance}`
- `Database {engine_hint, endpoint, storage_hint}`
- `Schedule {manager, owner, expression_or_timer, target}`
- `File {path, sha256, mode, uid, gid, mtime_ns, size, xattrs_present}`
- `ResourceState {filesystem_free, inode_free, mem_available, load}`

Every edge records `source`, `timestamp`, and `confidence`. Examples:

```text
Listener :443 --kernel socket inode--> Process nginx      [high]
Process nginx --cgroup--> Service nginx.service            [high]
Nginx server /api --proxy_pass--> 127.0.0.1:8000           [high if parsed]
Listener 127.0.0.1:8000 --inode--> Process gunicorn        [high]
Process gunicorn --cwd/cmdline--> SourceRoot /srv/app       [medium]
Docker container --compose label--> compose service web     [high]
Compose service web --bind mount--> /opt/challenge/app      [high]
```

Confidence vocabulary:

- **High:** kernel/runtime identity, explicit unit property, explicit parsed proxy directive, explicit Compose label/mount.
- **Medium:** command-line/cwd inference, image-name database detection, source route inferred from module name.
- **Low:** port-number-only inference, process-name-only inference, filesystem-name heuristics.

No mutation may rely solely on low-confidence evidence.

---

## 4. Discovery matrix

Commands below are read-only with respect to the target service. `$PID`, `$UNIT`, `$CID`, `$PORT`, `$ROOT`, and similar placeholders are substituted only from validated discovery values. The runner applies its own 1-5 second watchdog and output cap even where the command has no built-in timeout.

| Observation | Exact read-only command/API | Privilege | Timeout / cost | Redaction needs | Interpretation | Confidence limits / fallback |
|---|---|---:|---|---|---|---|
| OS, kernel, PID 1 | `cat /etc/os-release 2>/dev/null; uname -srmo; ps -p 1 -o pid=,comm=,args=` | none | <1 s | none normally | Establish distro metadata, kernel, and init candidate. | `/etc/os-release` can be absent in stripped images. PID 1 name does not prove all systemd APIs work. Fallback: `readlink -f /proc/1/exe`. |
| Active listening TCP/UDP sockets | `ss -H -lntup` | root gives best process attribution | <1 s typical | redact remote/team-only addresses if exporting corpus | Primary listener inventory including PID/program where permitted. | Non-root may omit process owners. Fallback: `ss -H -lntu`; if `ss` absent, parse `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` and correlate socket inodes through readable `/proc/*/fd`. |
| Listener address-family split | `ss -H -4 -lntu; ss -H -6 -lntu` | none | <1 s | none | Avoid assuming `[::]:PORT` is equivalent to an IPv4 listener. | Actual remote reachability still requires remote testing. Kernel/app `IPV6_V6ONLY` behavior matters. |
| Socket -> process identity | `readlink -f /proc/$PID/exe; readlink -f /proc/$PID/cwd; cat /proc/$PID/cgroup` | same UID or root for full visibility | <1 s/PID | paths may reveal usernames/project names | Maps runtime PID to binary, working tree hint, container/systemd cgroup. | `/proc/$PID/cmdline` and cwd can be intentionally misleading or inaccessible. PID can race; re-check start time before planning. |
| Process command hint | `tr '\0' ' ' < /proc/$PID/cmdline; printf '\n'` | same UID/root | <1 s/PID | **high**: argv can contain passwords/tokens; never persist raw | Helpful for module names, bind addresses, config paths. | Process can rewrite argv; treat as medium confidence and redact before state write. Fallback: `ps -p "$PID" -o comm=` only. |
| Process parent/tree | `ps -o pid=,ppid=,user=,comm= -p "$PID"; ps -o pid=,ppid=,user=,comm= -p "$PPID"` | none for visible processes | <1 s | usernames | Distinguishes supervisor/init/container shim relationships. | Parent may have exited/reparented; use with cgroup evidence. |
| PID -> systemd unit | `systemctl status "$PID" --no-pager 2>/dev/null` then `systemctl show "$UNIT" --no-pager -p Id -p MainPID -p ControlGroup -p FragmentPath -p DropInPaths -p WorkingDirectory -p User -p Group -p ExecStart` | none often sufficient; config read permissions vary | 1-2 s | `ExecStart` may contain secrets; redact args | Gives authoritative unit, source file, drop-ins, work dir, execution user. | Only when systemd is active. Never query/store `Environment=` by default. Fallback: cgroup path + `/proc`. [O2] |
| Local unit overrides | `systemd-delta --type=extended "$UNIT" 2>/dev/null` | none/root depending files | 1-2 s | config lines may carry secrets | Reveals local drop-ins/overrides that make package defaults unreliable. | systemd-only; output can include file content, so parser should retain paths/directives only where possible. [O3] |
| Service logs, bounded | `journalctl -u "$UNIT" --since '-10 min' -n 200 --no-pager -o short-iso` | journal membership/root may be needed | <=2 s, capped 200 lines | **high**: requests, tokens, flags, cookies may appear | Identifies errors around startup/reload and functional probes. | Logs are attacker-controlled input in many services and not authoritative configuration. Never feed raw lines into mutation logic. [O1] |
| Candidate source root | `readlink -f /proc/$PID/cwd`; systemd `WorkingDirectory`; known bind mounts; then `git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null` | same UID/root | <1 s | path only | Source root supported by runtime provenance. | CWD is not necessarily code root. Require a second signal before automated source patching. |
| Source tree dirty state | `git -C "$ROOT" status --porcelain=v1 --untracked-files=no 2>/dev/null` | read access | <=2 s | file paths may be sensitive | Detects teammate edits before planning/apply. | No Git repository is normal. Dirty tree does not imply maliciousness. Do not auto-reset. |
| Nginx binary/config/version | `nginx -V 2>&1` | none | <1 s | compile paths only | Finds version, configure arguments, config prefix/path. | Binary may not be the running binary; compare `/proc/$PID/exe`. [O19] |
| Nginx syntax | `nginx -t` or `nginx -t -c "$CONF"` | same access as running config, often root | 1-3 s | error text can contain paths | Pre/post config validity check. | This can fail merely because unprivileged operator cannot read cert/key files. It is not a functional test. [O19] |
| Nginx proxy/upstream graph | `nginx -T 2>&1` parsed **in-memory only** for `listen`, `server_name`, `location`, `proxy_pass`, `fastcgi_pass`, `uwsgi_pass`, and `upstream/server` | often root | <=3 s, output capped | **very high**: full config may include credentials/keys/headers; raw output must never be persisted | Explicit frontend -> upstream relationships. | `-T` exists from Nginx 1.9.2. If unsupported or secret-safe parser unavailable, inspect only discovered include files individually or mark proxy mapping incomplete. [O18][O19] |
| Apache vhosts | `apachectl -S 2>&1` or `httpd -S 2>&1` | often none | 1-3 s | paths/hostnames | Maps listener/vhost config files. | Does not fully enumerate all proxy directives. Fallback: parse only referenced config files for `ProxyPass`, `ProxyPassMatch`, `SetHandler`. [O20] |
| Docker engine presence/version | `docker version --format '{{.Client.Version}}|{{.Server.Version}}|{{.Server.APIVersion}}'` | docker socket access | <=2 s | none | Confirms daemon access and API version. | Membership in `docker` group is effectively privileged; absence of permission is not absence of Docker. [O6] |
| Container listeners/published ports | `docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'` | docker socket access | <=2 s | image names may expose internal project name | Maps published host ports to containers without dumping env/command. | Host-network containers may show no `Ports` and still own host listeners. Correlate with cgroups/PIDs. |
| Container network mode + Compose provenance | `docker inspect -f '{{.Id}}|{{.Name}}|net={{.HostConfig.NetworkMode}}|project={{index .Config.Labels "com.docker.compose.project"}}|service={{index .Config.Labels "com.docker.compose.service"}}|workdir={{index .Config.Labels "com.docker.compose.project.working_dir"}}|files={{index .Config.Labels "com.docker.compose.project.config_files"}}' "$CID"` | docker socket | <=2 s/container | local paths; no arbitrary labels | Distinguishes bridge/host/container network modes and maps back to Compose project files. | Labels may be absent for non-Compose containers. Do not dump all labels because arbitrary labels can contain secrets. [O8][O9] |
| Container bind mounts/volumes | `docker inspect -f '{{range .Mounts}}{{.Type}}|{{.Source}}|{{.Destination}}|rw={{.RW}}{{println}}{{end}}' "$CID"` | docker socket | <=2 s/container | host paths | Critical for source/config location and mutable-state boundaries. | A named volume path may be implementation-specific; never edit DB data directly. |
| Docker network membership | `docker network inspect "$NET" --format '{{json .IPAM.Config}}|{{json .Containers}}'` | docker socket | <=2 s/network | container IP/MACs | Resolves internal addresses and service adjacency. | Output is runtime state, not evidence that a port is intended/scored. [O8] |
| Compose validity without value dump | `docker compose -f "$COMPOSE" config -q` | read project files | <=3 s | errors may include paths | Syntax/model validation before/after a candidate edit. | Compose resolves references/interpolation. Never persist full `docker compose config` output. For inventory use `config --services`, `--images`, `--networks`. [O11][O12] |
| Compose inventory | `docker compose -f "$COMPOSE" config --services; docker compose -f "$COMPOSE" config --images; docker compose -f "$COMPOSE" config --networks` | read project files | <=3 s | image/project names | Identifies services, images, networks without dumping env values. | Older `docker-compose` may differ. Feature-gate command spelling/version. |
| PostgreSQL liveness hint | `pg_isready -h 127.0.0.1 -p "$PORT" -t 1` | none if TCP reachable | ~1 s | none unless host is sensitive | Tells whether PostgreSQL is accepting/rejecting/not responding. | It is **not** application correctness. Wrong user/db parameters can still cause server log noise. [O22] |
| MySQL/MariaDB liveness hint | `mysqladmin --connect-timeout=1 -h 127.0.0.1 -P "$PORT" ping` or `mariadb-admin --connect-timeout=1 ... ping` | none | ~1 s | do not place password on command line | Confirms daemon reachability. | MySQL `mysqladmin ping` may return success when access is denied because the server answered. Treat only as liveness. [O23] |
| Redis liveness hint | `redis-cli -h 127.0.0.1 -p "$PORT" -t 1 PING` | none | ~1 s | do not pass auth secret in argv | `PONG` shows protocol responsiveness. | Authenticated Redis may return `NOAUTH`; neither result proves app semantics. [O24] |
| systemd timers | `systemctl list-timers --all --no-pager --no-legend` | none | <=2 s | unit names | Finds timer-driven maintenance/persistence. | Only systemd timers. Inspect target unit via safe `systemctl show`; do not disable automatically. |
| Current user's cron | `crontab -l 2>/dev/null` | current user | <1 s | **medium/high**: command lines can include secrets | User-level scheduled jobs. | Does not enumerate other users. Parse/redact before storing. |
| System cron inventory | `find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f -printf '%p\n' 2>/dev/null; sed -n '1,200p' /etc/crontab 2>/dev/null` | read access/root for full view | <=2 s | crontab lines can contain secrets | Enumerates distro-level scheduled job files. | Cron spool paths differ: Debian-family commonly `/var/spool/cron/crontabs`, RHEL-family commonly `/var/spool/cron`. Inventory paths first; do not assume. |
| `at` jobs | `atq 2>/dev/null` | current user/root for all | <1 s | job IDs/users | Detects pending one-shot jobs. | `atd` may be absent. Job bodies require separate access and may hold secrets. |
| File metadata for an exact config/source target | `stat -Lc '%n|%F|%a|%u|%g|%s|%Y|%i' -- "$PATH"` | read metadata | <1 s | path | Captures precondition and rollback metadata. | GNU `stat` format differs on BusyBox/BSD; fallback to Python `os.stat()`, preferred in the implementation. |
| Writable-file risk in a scoped service root | `find "$ROOT" -xdev \( -type f -o -type d \) \( -perm -0002 -o -perm -0020 \) -print 2>/dev/null | head -n 200` | read/search dirs | <=2 s hard timeout | paths | Finds group/world writable objects for review. | Group writable may be legitimate. Do not recursively chmod. `find` can be expensive; scope to proven service root and cap output/time. |
| Mount type/options | `findmnt -T "$PATH" -no TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null` | none | <1 s | mount paths | Detects bind mounts, read-only mounts, network filesystems, overlayfs. | If `findmnt` absent, parse `/proc/self/mountinfo`. Network FS weakens `flock` assumptions. |
| Disk block pressure | `df -P "$ROOT" /var /tmp 2>/dev/null` | none | <1 s | paths | Refuse mutation if backup/temp cannot be safely created. | Multiple paths may be same filesystem. No cleanup of service data is implied. |
| Inode pressure | `df -Pi "$ROOT" /var /tmp 2>/dev/null` | none | <1 s | paths | Detects ENOSPC caused by inode exhaustion. | `-i`/`-P` syntax may vary; Python `statvfs()` is preferred. |
| Memory/load pressure | `awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree|Dirty|Writeback):/ {print}' /proc/meminfo; cat /proc/loadavg` | none | <1 s | none | Avoid expensive rebuild/restart when host is already under pressure. | Not a performance diagnosis; cgroup limits may dominate. |
| Bounded process pressure view | `ps -eo pid,ppid,user,%cpu,%mem,rss,etime,comm --sort=-%mem 2>/dev/null | head -n 25` | none | <1 s | usernames | Finds obvious memory consumers without command-line secrets. | Sorting options vary in BusyBox. Fallback: parse `/proc/*/status` for relevant service PIDs only. |

### Missing-tool strategy

The orchestrator should classify each probe as `supported`, `permission_denied`, `not_installed`, `timed_out`, or `failed`. A missing convenience tool reduces confidence; it does not trigger package installation.

Preferred fallbacks:

- `ss` -> `/proc/net/*` + socket-inode correlation through `/proc/*/fd`.
- `lsof` is optional, not required.
- `systemctl` -> `/proc`, cgroups, process tree, init scripts/supervisor-specific detection.
- `findmnt` -> `/proc/self/mountinfo`.
- GNU `stat`, `df`, `flock` -> Python `os.stat`, `os.statvfs`, and `fcntl.flock`.
- `docker compose` -> test `docker-compose`; if neither exists, Docker container discovery still works.
- database clients absent -> do not install them; perform a bounded TCP handshake only when a protocol-safe implementation exists, otherwise report unknown.
- `nginx`/`apachectl` command absent but process present -> use `/proc/$PID/exe` and inspect only explicitly referenced config paths; do not guess distribution defaults as authoritative.

---

## 5. Listener -> service -> source mapping algorithm

The high-value discovery path should be deterministic and fast:

1. Read all IPv4/IPv6 listeners.
2. Where permissions allow, map socket inode/PID.
3. Re-open `/proc/$PID/stat` and capture process start time so PID reuse can be detected later.
4. Capture executable, cwd, cgroup, parent, and a **redacted** argv hint.
5. If systemd is active, map PID/cgroup to the unit and collect only safe unit properties.
6. If the process is Nginx/Apache, extract proxy/upstream mappings and recurse into the local upstream listener.
7. If the PID belongs to a Docker cgroup, map it to the container, network mode, Compose labels, ports, and mounts.
8. Derive source roots only from strong relationships: systemd `WorkingDirectory`, an executable/script path, explicit Compose bind mount, or multiple agreeing medium-confidence signals.
9. Hash only the exact source/config files considered as patch targets. Do not hash entire large trees during the opening minutes.
10. Record unknown edges rather than inventing them.

Example output:

```text
0.0.0.0:80/tcp
  -> pid 742 /usr/sbin/nginx
  -> nginx.service
  -> /etc/nginx/nginx.conf + /etc/nginx/sites-enabled/challenge
  -> server_name _ ; location / -> proxy_pass http://127.0.0.1:8000
  -> 127.0.0.1:8000/tcp
     -> pid 811 /usr/bin/python3
     -> challenge.service
     -> WorkingDirectory=/srv/challenge
     -> ExecStart=/usr/bin/gunicorn --bind 127.0.0.1:8000 app:app
     -> source candidate /srv/challenge/app.py
```

This path is much more useful than a generic `nmap localhost` result because it creates a patchable evidence chain.

---

## 6. Reverse proxies, Docker, databases, and state boundaries

### Reverse proxy interpretation

For Nginx, `proxy_pass`, `fastcgi_pass`, and `uwsgi_pass` provide explicit upstream edges [O18]. For Apache, `ProxyPass`, `ProxyPassMatch`, and proxy handlers are equivalent evidence [O20]. The discovery layer should distinguish:

- externally reachable listener;
- proxy virtual host/path;
- local or container upstream;
- upstream process/service;
- source root.

Do not infer that an upstream port is safe to close merely because it is behind a proxy. The organizer checker could intentionally contact the upstream directly. Exposure reduction is a mutation only after the intended ingress contract is established.

### Docker and host networking

Docker changes firewall reasoning materially:

- Published bridge-network ports use Docker-managed NAT/filtering. Docker documentation warns that Docker-created rules should not be casually modified [O6][O7].
- A published port without a host IP can bind broadly; current Compose documentation describes an omitted host IP as all interfaces and warns that published ports may bypass host firewall expectations [O10].
- Docker's `host` network mode shares the host network namespace; port publishing is unnecessary/ignored and host firewall changes act directly on the container's traffic [O9][O10].
- Docker's user policy hook such as `DOCKER-USER` applies to the iptables backend, not as a universal abstraction for every Docker/firewall version [O7].
- Current Docker documentation includes nftables firewall support, while older deployments may use iptables-nft or legacy iptables. Detect, do not assume [O6].
- Docker's interaction with UFW is specifically documented as problematic for published container ports [O6]. Therefore `ufw status` alone is not a trustworthy exposure map.

### Mutable-state boundary

Before any edit/rebuild, classify mounts and paths:

- **Static/replaceable:** application source, Nginx/Apache config, systemd drop-in created by the tool.
- **Mutable/application-owned:** uploads, SQLite DB, cache with required state, generated assets if users can modify them.
- **Database-owned:** Postgres/MySQL data directories, Docker named volumes, Redis persistence files.
- **Unknown:** anything without provenance.

Only static/replaceable files are candidates for source/config rollback. Mutable and database-owned paths are explicitly excluded from whole-tree restore.

This directly incorporates a practical lesson from Maple Bacon's FAUST patch deployment retrospective: version control made patch rollback easier, but mutable service data had to be kept out of the source deployment workflow to avoid overwriting live state [A2]. The safe generalization is the separation of code/config from mutable data, not their exact privileged Git deployment mechanism.

---

## 7. Mutation decision matrix

**Eligibility notation**

- **AUTO-CANDIDATE AFTER PROOF:** narrow enough to automate only after its exact profile passes the disposable-VM matrix in Section 12.
- **REVIEW-ONLY:** requires operator approval even after detection; the checker contract or blast radius is too uncertain for generic unattended use.
- **AUTO-ROLLBACK-ONLY:** never an automatic forward hardening change; the tool may automatically reverse its *own* exact change if the transaction has not been externally modified and the rollback path has been proven.

**Current status:** because no candidate was executed on a disposable VM during this research, none of the service/host forward mutations below is presently eligible for unattended application.

| Detected condition | Narrow action | Prerequisite evidence | Expected benefit | Potential checker breakage | Verification | Rollback | Eligibility |
|---|---|---|---|---|---|---|---|
| Exact synthetic-style Flask route passes attacker-controlled path to `send_file(os.path.join(FIXED_ROOT, name))` | Replace only that call with positional `send_from_directory(FIXED_ROOT, name, ...)`; preserve route/auth/response options | Exact AST/call-shape match; Flask installed/version recorded; fixed root proven; source file is static; clean or acknowledged Git state | Blocks path escape while preserving intended fixed-root download behavior [O21] | Route may intentionally allow other paths; framework wrapper behavior may differ | Framework/unit tests if present; syntax/import test; public ingress GET for known allowed file; traversal negative test; ephemeral create/read/delete if service supports it | Atomic restore of the one source file only if current hash still equals tool's post-patch hash | **AUTO-CANDIDATE AFTER PROOF** for exact profile; otherwise review-only |
| Nginx proxies all observed public traffic to Gunicorn on `0.0.0.0:8000` on same host | Change only Gunicorn bind to `127.0.0.1:8000` | Explicit Nginx `proxy_pass` to loopback/host; systemd unit owns Gunicorn; no evidence port 8000 is a scored/public endpoint; functional contract for public path exists | Removes direct upstream exposure | **High** if checker contacts port 8000 directly | `systemd` state + listener address + request through Nginx with correct Host/SNI + app-level functional probe | Restore exact unit/drop-in/source configuration, daemon-reload if applicable, reload/restart service, reverify | **REVIEW-ONLY** unless organizer/service contract proves upstream is private |
| Compose DB service publishes `5432`/`3306` on all host interfaces but app uses Compose-internal service DNS | Remove the DB `ports:` publication, leaving internal network connectivity; alternatively bind host publication to loopback only if host tooling needs it | Explicit Compose project; app and DB share network; DB is not identified as scored external service; named volume/data mount classified; config validates | Reduces direct DB exposure | **High** if checker expects DB port or another service accesses it via host publication | `compose config -q`; DB liveness from app network; application write/read path through public service; confirm host port change | Restore only Compose file if unchanged since patch; recreate affected service without deleting volumes; verify data sentinel persists | **REVIEW-ONLY**; stateful recreation is too risky generically |
| Exact secret file referenced by a service is world-readable/writable and runtime user/group is known | Remove only unnecessary world permission bit; do not recursively chmod | Exact reference to file; `stat` + ACL/xattr inventory; service UID/GID proven; app does not need broader writer; metadata backup available | Prevents trivial local tampering/disclosure | Service may use helper process under another account | Pre/post config check; service functional probe; access check as runtime UID where safe | Restore exact mode/ACL/xattrs if target hash/inode relationship is unchanged | **AUTO-CANDIDATE AFTER PROOF** for exact file profile; otherwise review-only |
| Source/config file is group/world writable but purpose/owner ambiguous | No automatic mutation; raise finding with path and provenance | Scoped service root only | Avoids unsafe blanket permission changes | Potentially severe if service writes it legitimately | N/A | N/A | **REVIEW-ONLY** |
| Unknown listener has no source/service attribution | No mutation; increase discovery, capture bounded logs/traffic if allowed | Listener inventory | Prevents killing a scored or management service | Killing it could cause immediate SLA loss | N/A | N/A | **REVIEW-ONLY** |
| Firewall is absent/disabled | **Do not** enable a default policy | None | Avoids self-lockout and checker breakage | Very high | N/A | N/A | **REVIEW-ONLY / no generic proposal** |
| One clearly unwanted exposure is identified and native firewall manager/backend is proven | Propose one exact runtime rule scoped to family, interface/address, protocol and port; schedule inverse first | Intended ingress contract; current firewall ownership; Docker path; IPv4/IPv6; separate fresh management path; timed rollback proven | Narrows one attack path | High if endpoint is scored or Docker bypass changes path | Remote fresh SSH + public service functional probe over every required address family; local rule counter observation if supported | Timed inverse rule, not whole-ruleset restore | **REVIEW-ONLY**; forward unattended host firewall change forbidden until disposable proof |
| SSH effective config has a suspicious/weak setting | Report setting and exact origin; do not generically rewrite | `sshd -T`, include/match provenance, management auth path | Operator can make informed targeted change | Extremely high: loss of management | `sshd -t`; effective-config recheck; **new** SSH connection from separate process/host using intended auth; public service test | Timed restore/reload created before change | **REVIEW-ONLY** |
| Tool itself created a static config/source mutation and verify fails | Restore only its exact pre-image if target still equals recorded post-image | Transaction ID; post-hash matches; rollback artifact intact | Rapid failure recovery | Low relative to leaving failed patch, but rollback may also be stale | Re-run same verifier after rollback | This is the rollback | **AUTO-ROLLBACK-ONLY after rollback engine proof** |
| Tool state/temp files consume space | Remove only abandoned tool-owned temp files whose transaction is closed/invalid | Ownership + state directory provenance | Recovers tool working space | None to service | Recheck `statvfs` | Not needed | Tool-internal auto is reasonable after unit tests; not a service mutation |
| Filesystem has insufficient blocks/inodes for safe backup/temp/atomic replace | Refuse forward mutation; optionally prune only tool-owned stale temp | `statvfs`, estimated copy size | Prevents partial corruption/ENOSPC | None from refusal | Recheck capacity | N/A | **Automatic refusal**, not mutation |
| Scheduled job/timer looks suspicious but provenance is unknown | Report only; capture owner, unit/file, target | Timer/cron inventory | Avoids destroying intended maintenance/checker support | Potentially high | N/A | N/A | **REVIEW-ONLY** |
| Container source exists only in immutable image layer | Do not `docker exec sed -i`; identify image/build context or bind-mounted source | Container inspect, image/project provenance | Avoids ephemeral untracked patch | Direct in-container edits disappear on recreate and are hard to rollback | N/A | N/A | **REVIEW-ONLY** until reproducible deployment path exists |

---

## 8. Two narrow stack profiles to implement first

These profiles maximize useful coverage without pretending to understand every Linux service.

### Profile A: host-native Nginx -> systemd -> Gunicorn/Flask

**Why first:** It exercises the entire high-value chain: public listener -> reverse proxy -> loopback/upstream listener -> process -> systemd unit -> working directory -> Python source. It also has strong native validators (`nginx -t`, Python compile/import checks, systemd properties) and a realistic narrow web vulnerability class.

#### Detection contract

Require all of the following before the profile activates:

1. Running Nginx PID owns or is tied to a public listener.
2. An Nginx config parse yields a local `proxy_pass` upstream.
3. That upstream listener maps to a Python/Gunicorn process.
4. Systemd maps the process to a unit with a stable `WorkingDirectory` or explicit module/script path.
5. Source root is independently confirmed by working directory, ExecStart/module, or Git root.

If any edge is missing, fall back to generic discovery and no profile mutation.

#### Synthetic fixture: bind exposure proposal

Before:

```ini
# /etc/systemd/system/challenge.service
[Service]
WorkingDirectory=/srv/challenge
ExecStart=/usr/bin/gunicorn --bind 0.0.0.0:8000 app:app
User=challenge
```

```nginx
server {
    listen 80;
    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

Representative diff:

```diff
 [Service]
 WorkingDirectory=/srv/challenge
-ExecStart=/usr/bin/gunicorn --bind 0.0.0.0:8000 app:app
+ExecStart=/usr/bin/gunicorn --bind 127.0.0.1:8000 app:app
 User=challenge
```

This is **review-only** because the checker may intentionally access port 8000. It is not justified merely because Nginx exists.

#### Synthetic fixture: narrow Flask path traversal patch

Before:

```python
from flask import Flask, send_file
import os

app = Flask(__name__)
UPLOAD_DIR = "/srv/challenge/uploads"

@app.get("/files/<path:name>")
def get_file(name):
    return send_file(os.path.join(UPLOAD_DIR, name), as_attachment=True)
```

Representative diff:

```diff
-from flask import Flask, send_file
-import os
+from flask import Flask, send_from_directory
 
 app = Flask(__name__)
 UPLOAD_DIR = "/srv/challenge/uploads"
 
 @app.get("/files/<path:name>")
 def get_file(name):
-    return send_file(os.path.join(UPLOAD_DIR, name), as_attachment=True)
+    return send_from_directory(UPLOAD_DIR, name, as_attachment=True)
```

Flask documents `send_from_directory()` as the helper intended to safely serve a client-selected path from a trusted directory [O21]. This should still be generated only for an exact syntactic/semantic match. It is not a generic search-and-replace across Python code.

Functional verifier for the synthetic fixture:

1. compile/import the app without executing development server side effects where feasible;
2. valid file `GET /files/<known-sentinel>` returns expected bytes through the Nginx/public ingress;
3. traversal input such as a percent-encoded `../` route does **not** return a file outside `UPLOAD_DIR`;
4. unrelated known route still returns expected status/schema;
5. if the route supports user-created files, create a unique sentinel through the application's normal API, read it, then delete it.

### Profile B: Docker Compose web application + PostgreSQL

**Why second:** It covers the most important container-specific hazards: published ports, Docker-created firewall rules, host networking, project provenance, bind mounts versus named volumes, and preserving mutable database state during a patch.

#### Detection contract

Require:

1. container has Compose project/service labels;
2. project config path is readable;
3. `docker compose config -q` succeeds;
4. web and DB services/network relationship is explicit;
5. DB storage is classified as named volume/bind mount and excluded from source rollback;
6. network mode is known and not blindly assumed to be bridge.

#### Synthetic fixture

Before:

```yaml
services:
  web:
    build: ./web
    ports:
      - "8080:8080"
    environment:
      DATABASE_HOST: db
    depends_on:
      - db

  db:
    image: postgres:16
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata: {}
```

Candidate A, if the database is proven internal-only:

```diff
   db:
     image: postgres:16
-    ports:
-      - "5432:5432"
     volumes:
       - pgdata:/var/lib/postgresql/data
```

No `expose:` entry is required for normal inter-container connectivity on a shared Compose network. Candidate B, if team-local host tooling must still reach it:

```diff
   db:
     image: postgres:16
     ports:
-      - "5432:5432"
+      - "127.0.0.1:5432:5432"
```

Both are **review-only** until it is proven that `5432` is not itself a scored endpoint. The fact that the `web` container uses `db` as its hostname is not enough to infer the organizer contract.

Verification should include:

- `docker compose config -q`;
- unchanged named-volume identity;
- DB accepts connections from the application network;
- public web ingress still performs an application-level read/write operation that actually reaches the database;
- the unique sentinel survives any required container recreation;
- no volume removal command is used.

---

## 9. Plan / apply / verify / rollback semantics

### 9.1 Plan

A plan is immutable content-addressed JSON containing:

```json
{
  "plan_id": "sha256:...",
  "created_at": "...",
  "boot_id": "...",
  "host_fingerprint": {"kernel": "...", "init": "..."},
  "profile": "nginx-flask",
  "evidence": ["...normalized/redacted observations..."],
  "preconditions": [
    {"path": "/srv/challenge/app.py", "sha256": "...", "mode": 420, "uid": 1001, "gid": 1001, "mtime_ns": 0},
    {"unit": "challenge.service", "main_pid": 811, "process_start_ticks": 123456}
  ],
  "actions": ["exact typed actions"],
  "verifiers": ["..."],
  "rollback": ["exact inverses"],
  "eligibility": "review-only"
}
```

Do not store raw secrets in the plan.

### 9.2 Single-writer locking

Use an advisory exclusive lock:

- root/system mode: `/run/ctfguard/lock`;
- non-root mode: `$XDG_RUNTIME_DIR/ctfguard.lock` or a mode-0700 runtime directory.

Python `fcntl.flock(fd, LOCK_EX | LOCK_NB)` is preferred over depending on the `flock(1)` binary [O25]. The lock prevents two `ctfguard` writers; it **does not** prevent teammate editors or service processes from changing files. That is why stale-plan checks are mandatory.

If the underlying filesystem is a network filesystem where flock semantics are uncertain, mutation is review-only or refused.

### 9.3 Stale-plan detection

Immediately after acquiring the writer lock and before any mutation, re-run all relevant preconditions:

- host boot ID (`/proc/sys/kernel/random/boot_id`);
- file SHA-256, size, inode, mtime, mode, uid/gid;
- symlink target and parent directory identity;
- service MainPID and process start time;
- listener tuple;
- Nginx/Apache proxy edge relevant to the action;
- Compose config digest/project identity;
- volume identity for stateful services;
- active firewall manager/backend for network actions.

Any mismatch makes the plan **stale**. The tool aborts and produces a new discovery/plan instead of applying an old patch over teammate work.

### 9.4 Apply

For each action:

1. preflight disk blocks/inodes and permissions;
2. create a transaction directory mode `0700`;
3. save rollback material only for exact static files/runtime objects being changed;
4. preserve original metadata needed for restoration;
5. write candidate file into the **same directory/filesystem** as the target;
6. validate candidate where possible before replacement;
7. `fsync` candidate;
8. atomically replace one file using `rename(2)`/Python `os.replace()` [O26];
9. `fsync` parent directory where supported;
10. run the minimal reload/restart command required by that profile;
11. run verifiers;
12. commit transaction only after verifiers pass.

A same-filesystem rename gives a strong atomic boundary for **one pathname**, not a multi-file application deployment [O26]. Multi-file changes, systemd daemon reload, service restart, Compose recreation, firewall changes, and application/database state are separate failure boundaries and require compensating rollback.

### 9.5 Metadata restoration

For every file mutation capture, as supported:

- uid/gid;
- mode;
- atime/mtime if materially important;
- SELinux context / security xattrs where present;
- ACLs where present;
- other xattr names and values only inside the root-only rollback artifact, never the normal audit record.

Do not assume `install(1)` or a basic copy preserves every xattr/ACL. If the engine cannot faithfully preserve metadata required by the target, the action becomes review-only/refused.

### 9.6 Secret-safe audit state

Normal audit state should contain **metadata and hashes**, not secret-bearing raw config:

```text
transaction id
actor uid
boot id
profile/action id
normalized endpoint/service identifiers
pre/post SHA-256
size/inode/mtime/mode/uid/gid
validator exit status
functional-probe status and response hash/schema, not response body
rollback status
```

Never persist by default:

- environment variable values;
- `Authorization`, `Cookie`, session tokens;
- DB passwords/DSNs with credentials;
- TLS private keys;
- full Nginx/Apache/Compose dumps;
- complete process command lines;
- CTF flags or request/response bodies that may contain them.

If a secret-bearing static file must be backed up for rollback, place the exact pre-image only in the transaction directory (`0700` directory, `0600` file), keep it outside normal logs, and delete it after the operator-defined retention window. Do not store hashes of low-entropy secrets as a substitute for redaction; they can still be guessable.

### 9.7 Interrupted execution

Persist a small transaction journal with fsync'd phases:

```text
PLANNED -> PREPARED -> FILE_REPLACED -> SERVICE_APPLIED -> VERIFYING -> COMMITTED
                                                     \-> ROLLING_BACK -> ROLLED_BACK
```

At next startup, if an unfinished transaction is found:

- if no target replacement occurred: remove only tool-owned temporary files;
- if replacement occurred and target still matches the tool's recorded post-hash: run verifier; on failure, rollback if eligible;
- if the target no longer matches the tool's post-hash: mark `CONFLICTED` and **do not rollback over teammate/application edits**;
- if service state changed independently, rediscover and require review.

### 9.8 Never overwrite fresh application data

Rollback is file/object-specific. It must never execute commands equivalent to:

```text
git reset --hard <old>
rsync --delete old-tree/ live-tree/
docker compose down -v
rm -rf uploads/
restore database volume snapshot
```

unless the mutable state itself was explicitly the intended test fixture and the operator approved it. In a real CTF VM, those operations can destroy newly submitted checker state, user data, flags, or teammate changes.

---

## 10. Verification: liveness is not the service contract

Attack-defend games commonly use checkers/gameservers that exercise legitimate service behavior, including flag placement and later retrieval [A1][A3][A4]. Consequently:

```text
process running
    < TCP port accepts
        < protocol speaks
            < endpoint returns expected shape
                < legitimate state transition works
                    < write/read/delete or equivalent workflow works through intended ingress
```

Each level is stronger than the previous one; none guarantees compatibility with an unpublished Raymond James checker.

### Verification tiers

| Tier | Test | What it proves | What it does not prove |
|---|---|---|---|
| 0 | process/unit active, expected listener exists | basic local runtime | reachability or semantics |
| 1 | TCP/TLS/protocol handshake | protocol endpoint responds | application workflow |
| 2 | known read-only public request via intended ingress | routing, Host/SNI, handler, response schema | write path/persistence |
| 3 | unique ephemeral create -> read -> optional update -> delete using normal application interface | meaningful application path, often DB/storage and auth | exact organizer checker assumptions |
| 4 | organizer-provided checker/service contract, if actually available | closest observable scored behavior | hidden checks may still exist |

A mutation profile should define the highest safe tier it can run. If only Tier 0/1 is available, automatic source/network mutation is not justified.

### Functional test rules

- Enter through the same public listener/hostname/TLS path that legitimate clients are expected to use, not only `localhost` or the upstream port.
- Preserve expected `Host` header and SNI when relevant.
- Use a collision-resistant sentinel such as `ctfguard-<txid>`.
- Prefer a dedicated test record or endpoint if the service exposes one.
- Clean up only the record the verifier itself created.
- Never search for, overwrite, or delete values that look like flags.
- Compare status, headers, JSON schema/protocol fields, and sentinel round-trip; avoid logging secret response bodies.
- If auth is required and no disposable test account/API token exists, the verifier must stop at the strongest non-destructive tier rather than invent credentials.
- A database's own `PING`/`pg_isready` is useful supporting evidence but does not substitute for application-level DB use [O22][O23][O24].

---

## 11. SSH, firewall, IPv4/IPv6, Docker, and recovery

### 11.1 SSH changes

SSH is a management dependency. Generic unattended SSH hardening is out of scope.

For any operator-approved SSH config edit:

1. identify the actual running `sshd` PID/binary and effective config source;
2. parse `Include` and `Match` implications; do not assume one `/etc/ssh/sshd_config` file contains the effective policy [O5];
3. save exact pre-image/metadata of only the file being edited;
4. run `sshd -t -f <config>` before reload;
5. when evaluating behavior, use `sshd -T` and, if `Match` rules matter, the implementation's connection-parameter evaluation form rather than assuming global output represents every client;
6. arm an independent timed rollback **before** reload;
7. reload only the detected service using its native mechanism; do not assume `ssh.service` vs `sshd.service`;
8. establish a **new** SSH connection from a separate process/host using the intended authentication method;
9. only then cancel the rollback.

The fact that the existing SSH session survives a reload does not prove that a new session can authenticate.

### 11.2 Timed rollback independent of the management session

On a proven systemd host with systemd >=218, a transient timer is an appropriate mechanism because it is owned by the service manager, not the SSH shell [O4]. A transaction can prepare a root-only rollback script and arm it before the network change:

```sh
systemd-run \
  --unit="ctfguard-rollback-$TXID" \
  --on-active=120s \
  /bin/sh "/run/ctfguard/tx/$TXID/rollback.sh"
```

Then verify the timer exists with `systemctl list-timers`/`systemctl status` before proceeding.

The rollback script must contain narrow inverse operations with stale guards. It must not restore an entire firewall ruleset or overwrite a config that changed after the tool's apply.

Possible fallback: `at`/`atd`, but only if its daemon, persistence, privilege behavior, and cancellation path have been proven on the target profile in a disposable VM. If no independent rollback executor is proven, an SSH/firewall forward change is **ineligible for unattended apply**.

### 11.3 Firewall backend rules

First identify who owns firewall state:

```sh
nft list ruleset 2>/dev/null
iptables --version 2>/dev/null
ip6tables --version 2>/dev/null
ufw status verbose 2>/dev/null
firewall-cmd --state 2>/dev/null
firewall-cmd --get-active-zones 2>/dev/null
```

These are inspection commands; raw firewall output is not normally secret but can expose internal topology.

Rules:

- **nftables:** candidate rulesets can be syntax/semantic checked with `nft -c -f FILE`; `nft -f FILE` uses a netlink batch transaction, but that does not make a badly designed policy safe [O13][O14].
- **iptables:** IPv4 and IPv6 are separate command paths. A change to `iptables` alone is not an IPv6 policy. Current `iptables-restore --test` can parse/check without commit, but feature-gate against the installed version [O15].
- **firewalld:** understand runtime vs permanent state. For a CTF experiment, a runtime-only candidate is safer to reverse than silently persisting policy, but it can still break the checker immediately [O17].
- **UFW:** `--dry-run` exists for proposed commands, but enabling/reloading UFW is broader than inserting one known-safe service rule and Docker-published ports may bypass expected UFW processing [O16][O6]. Do not auto-enable it.
- Do not mix managers just because their CLIs exist. A generated nft ruleset may be overwritten by firewalld/UFW or conflict with Docker.

### 11.4 Docker firewall interaction

Before any host firewall plan, enumerate:

- bridge vs host network mode per container;
- published address/port mappings;
- current Docker firewall backend/version;
- whether the candidate service is reached through host `INPUT`, forwarding/NAT, or host namespace directly;
- IPv4 and IPv6 publication.

Docker documents that bridge networking and port publication create firewall/NAT behavior, while host mode shares the host network namespace [O6][O7][O9]. A rule that appears correct in the host's `INPUT` chain can therefore fail to control a published container path.

### 11.5 IPv4/IPv6 rules

The automation must model address families separately:

- collect `ss -4` and `ss -6` listeners;
- test management and service ingress over every family that is actually in use;
- for raw iptables, snapshot/check both `iptables` and `ip6tables` state;
- for nftables, preserve the host's existing family model instead of rewriting everything into an `inet` table;
- for UFW, confirm its IPv6 configuration rather than assuming it;
- inspect Compose/Docker host bindings, including explicit IPv6 addresses [O10].

Do not infer that `[::]:22` accepts IPv4 simply because some Linux defaults use v4-mapped sockets. Treat observed/tested IPv4 and IPv6 reachability as separate evidence.

### 11.6 Remote recovery criterion

A network mutation cannot be considered verified solely from inside the modified VM. At minimum, network changes require a fresh connection test from another team-controlled process/host outside the target network namespace. Ideally the team has a lightweight verifier on a second laptop/VM capable of:

```text
TCP connect -> TLS/SNI if needed -> application probe -> fresh SSH login test if management changed
```

If no external verifier exists, firewall/SSH changes remain review-only even if local tests pass.

---

## 12. Disposable-VM test matrix

A host/service mutation becomes unattended-eligible only for an **exact profile/action pair** after it passes relevant rows below. Passing one profile does not authorize the same action on arbitrary stacks.

| Test | Fixture / fault injection | Expected behavior | Failure meaning / eligibility impact |
|---|---|---|---|
| Repeated discovery | Run `discover` 20 times on unchanged fixture | Same normalized graph except volatile PIDs/timestamps; no mutations | Drift/noise in stable identifiers must be fixed before stale-plan logic can be trusted. |
| Repeated apply | Apply same already-satisfied narrow patch twice | Second run is no-op or refuses because plan already consumed; no duplicate lines/rules | Non-idempotent action cannot be unattended. |
| Unknown stack | Listener owned by unsupported binary/custom supervisor | Inventory listener/process; classify unsupported; no mutation | Any guessed patch is disqualifying. |
| Missing root | Run as ordinary user without sudo/docker/journal permissions | Produce partial graph with explicit permission gaps; no privilege escalation attempt | Silent assumptions based on missing data are disqualifying. |
| Missing tools | Remove `ss`, `findmnt`, Compose plugin one at a time | Use documented fallback or mark probe unsupported; never install package | Unbounded/incorrect fallback blocks unattended use. |
| Full data filesystem | Fill target FS to leave insufficient space | Plan/apply refuses before backup/temp; service remains unchanged | Any partial write under ENOSPC disqualifies atomic mutation. |
| Inode exhaustion | Exhaust free inodes with small fixture files | Same refusal semantics as full disk | Failure to distinguish inode ENOSPC disqualifies. |
| Config changed after plan | Modify target after `plan` before `apply` | Apply rejects as stale and creates no mutation | Overwriting teammate edit is disqualifying. |
| Process restarted after plan | Replace PID/restart service | PID start-time/unit/listener precondition invalidates plan | PID-only identity is insufficient. |
| Teammate edit after apply before verify | Modify patched file after service apply | Tool detects post-hash conflict; does not auto-rollback over edit | Blind rollback is disqualifying. |
| Teammate edit during rollback timer window | Edit target after tool apply, before timed rollback | Rollback stale guard refuses file overwrite and records conflict | Timed rollback must not erase fresh edits. |
| Partial file-action failure | Kill tool after temp fsync, before rename | Target remains old; orphan temp cleaned later | If target becomes truncated/partial, design fails. |
| Partial service-action failure | Kill tool after atomic replace, before reload/verify | Startup finds unfinished tx, checks current hash, verifies or rolls back exactly | Blindly resuming without state comparison is disqualifying. |
| Validator failure | Make Nginx/Compose/source validator fail | Candidate not activated, or immediate narrow rollback if replacement already occurred | Service must remain on known pre-image. |
| Functional test failure | Patch passes syntax and listener checks but breaks API roundtrip | Transaction fails; rollback only own static mutation; mutable data preserved | Demonstrates why liveness cannot be commit criterion. |
| Mutable data changed during patch | Write a new upload/DB row between apply and rollback | Rollback preserves new data; only code/config reverts | Any whole-tree/volume restore is disqualifying. |
| Symlink swap | Replace target/parent with symlink between plan/apply | Precondition/open strategy rejects; no write outside intended target | Path-race vulnerability disqualifies unattended file edits. |
| Metadata-rich target | Add ACL, xattr/SELinux label where supported | Patch + rollback preserve required metadata | Metadata loss blocks unattended use on those filesystems. |
| NFS/network filesystem | Put target/lock on network FS | Tool marks locking/atomicity assumptions unsupported unless explicitly tested | Local-FS assumptions cannot be generalized. |
| IPv4-only service | Fixture listens only on v4 | Discovery and verification do not invent v6 reachability | False family inference blocks firewall automation. |
| IPv6-only service | Fixture listens only on v6 | Discovery/remote verifier use v6 path correctly | IPv4-only rule logic blocks firewall automation. |
| Dual-stack SSH | Management available on v4/v6 | Candidate network change tests required family paths separately | Existing session alone is insufficient. |
| Docker bridge | Published container service with Docker-managed NAT | Graph maps host publish -> container; firewall tests observe actual packet path | Host `INPUT`-only assumption blocks unattended firewall use. |
| Docker host mode | Container uses `network_mode: host` | Container is mapped to host listeners even without `Ports` output | Port-publication-only logic is disqualifying. |
| Compose stateful DB | Named volume + container recreation | Sentinel survives candidate recreate/rollback; volume ID unchanged | Any volume deletion/data loss disqualifies. |
| Docker/UFW interaction | UFW enabled + published Docker port | Discovery reports policy/exposure mismatch; no claim that UFW alone protects it | Incorrect security assertion blocks firewall profile. |
| iptables nft vs legacy | Test both implementations where available | Backend identified; commands/rules not mixed incorrectly | Backend ambiguity blocks unattended firewall mutation. |
| firewalld runtime/permanent | Runtime rule fixture | Tool can distinguish/reverse runtime rule without silently persisting it | Persistence confusion blocks unattended use. |
| SSH syntax failure | Deliberately malformed candidate config | `sshd -t` prevents reload | Reloading invalid config is disqualifying. |
| SSH auth regression | Candidate allows syntax but breaks intended auth | Fresh external login fails; independent timer restores old config | If recovery depends on lost SSH session, SSH automation is disqualified. |
| Firewall lockout | Candidate rule blocks management | Independent timer restores connectivity without current shell | If rollback executor does not fire, firewall automation is disqualified. |
| Reboot during transaction | Reboot at each journal phase in fixture | Behavior is defined: either old state, exact new state pending verify, or conflict; no destructive guessing | Undefined recovery blocks unattended use. |
| High load / low memory | CPU/memory pressure fixture | Runner respects deadlines, avoids expensive scans/rebuild, can abort cleanly | Watchdog failure risks availability and blocks unattended use. |

### Unattended eligibility gate

For a given `profile + action + distro/container/firewall combination`, all of the following must be true:

```text
exact detector passes
+ exact validator passes
+ rollback has been fault-tested
+ stale-plan tests pass
+ metadata tests pass
+ functional Tier 3 (or organizer-provided checker) passes
+ IPv4/IPv6 behavior tested where applicable
+ Docker/firewall backend behavior tested where applicable
+ fresh remote management recovery tested for SSH/firewall changes
= unattended candidate
```

If any required dimension is untested, status is `review-only`.

---

## 13. Minimal implementation order

A practical build sequence for the CTF repository:

### Phase 1: read-only core

Implement:

- `/proc` + `ss` listener/process graph;
- systemd unit mapping;
- resource pressure and filesystem metadata;
- Docker/Compose read-only mapping;
- Nginx upstream parser;
- systemd timer/cron inventory;
- JSON normalized report with redaction and confidence.

This alone is high-value during the first minutes of an unknown VM and cannot break the service.

### Phase 2: profile-specific planning

Implement two planners only:

1. `nginx-systemd-flask`
2. `compose-web-postgres`

The planner emits candidate diffs, exact preconditions, validators, verifiers, and rollback steps but does not automatically apply them.

### Phase 3: transaction engine

Implement:

- `flock`/`fcntl` single writer;
- content-addressed plans;
- stale-plan revalidation;
- same-directory atomic replacement;
- metadata capture/restore;
- transaction journal;
- conflict-aware rollback;
- no rollback of mutable paths.

### Phase 4: disposable fixtures and fault injection

Build local VMs/containers for the test matrix. Only then change individual actions from `review-only` to `auto-candidate`.

### Phase 5: optional remote verifier

A teammate laptop or isolated control VM can run fresh TCP/TLS/application/SSH checks. This is the prerequisite for considering any network-access mutation unattended.

---

## 14. Recommended operator output

The tool should optimize for rapid human decisions, not verbose scanner output:

```text
PUBLIC 0.0.0.0:80/tcp
  nginx.service (pid 742)
  /etc/nginx/sites-enabled/challenge
  / -> 127.0.0.1:8000
    challenge.service (pid 811, user challenge)
    /srv/challenge [git dirty: no]
    Flask 3.x hint

PUBLIC 0.0.0.0:5432/tcp
  docker: project=scoreboard service=db image=postgres:16
  network=scoreboard_default
  volume=scoreboard_pgdata -> /var/lib/postgresql/data [MUTABLE]
  web connects to db:5432 internally
  candidate: remove/loopback DB host publish
  status: REVIEW-ONLY
  reason: checker contract for 5432 unknown

WARNINGS
  Docker-published ports present; UFW status alone is not an exposure model.
  IPv6 listener set differs from IPv4 listener set.
  /var has 3% free inodes: forward mutation disabled.

SAFE NEXT ACTION
  inspect /srv/challenge route handlers; generate plan only
```

This is preferable to a one-shot `secure everything` mode because it preserves the two scarce resources in attack-defend: **service availability and operator attention**.

---

## 15. Findings that should remain explicitly unresolved for Raymond James

The supplied prep brief establishes that attack/defend is important and that teams should be able to patch services without breaking availability, but it does not define the 2026 organizer checker, exact scored ports, flag lifecycle, allowed host-level firewall behavior, persistence rules, or whether service source/configuration may be reset between rounds. Therefore this design intentionally does **not** assume:

- which listener is scored;
- whether direct backend/database ports are intentionally part of the service;
- whether the checker performs read-only, write/read, authentication, or persistence tests;
- whether host firewall modification is allowed;
- whether Docker/systemd is present;
- whether root/sudo is granted;
- whether the service is reset/redeployed during the event.

Those questions should be answered from organizer material when available and encoded as profile constraints, not guessed by the automation.

---

## 16. Sources

Retrieval date for time-sensitive documentation: **2026-09-11**.

### Official operating-system / service / framework documentation

- **[O1] systemd `journalctl` manual** - structured journal filtering and unit selection.  
  https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
- **[O2] systemd D-Bus interface** - manager/unit properties such as `MainPID`, control groups, and execution metadata.  
  https://wiki.freedesktop.org/www/Software/systemd/dbus/
- **[O3] systemd `systemd-delta` manual** - finding overridden/extended unit configuration.  
  https://www.freedesktop.org/software/systemd/man/latest/systemd-delta.html
- **[O4] systemd `systemd-run` manual** - transient services/timers; `--on-active=` is documented as available since systemd v218.  
  https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html
- **[O5] OpenSSH `sshd_config(5)` / `sshd(8)`** - effective server configuration, include/match behavior, configuration testing.  
  https://man.openbsd.org/sshd_config  
  https://man.openbsd.org/sshd
- **[O6] Docker Engine packet filtering and firewalls** - Docker-created firewall rules, backend interactions, UFW caveat.  
  https://docs.docker.com/engine/network/packet-filtering-firewalls/
- **[O7] Docker with iptables** - Docker chains and `DOCKER-USER` behavior under the iptables backend.  
  https://docs.docker.com/engine/network/firewall-iptables/
- **[O8] Docker port publishing / network inspect** - host publication behavior and runtime network inspection.  
  https://docs.docker.com/engine/network/port-publishing/  
  https://docs.docker.com/reference/cli/docker/network/inspect/
- **[O9] Docker host network driver** - host namespace semantics and ignored/unnecessary port publication.  
  https://docs.docker.com/engine/network/drivers/host/
- **[O10] Docker Compose service/network reference** - `network_mode`, `ports`, host bindings, bridge behavior.  
  https://docs.docker.com/reference/compose-file/services/  
  https://docs.docker.com/compose/how-tos/networking/
- **[O11] Docker Compose `config` reference** - validation and model inspection.  
  https://docs.docker.com/reference/cli/docker/compose/config/
- **[O12] Docker Compose trust model** - file references/interpolation can expose host-file contents through Compose processing/output.  
  https://docs.docker.com/compose/trust-model/
- **[O13] nftables manual** - command/check modes and ruleset operations.  
  https://netfilter.org/projects/nftables/manpage.html
- **[O14] nftables atomic rule replacement** - batch/transaction behavior.  
  https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
- **[O15] `iptables-restore(8)`** - `--test` and `--wait` behavior in current iptables.  
  https://man7.org/linux/man-pages/man8/iptables-restore.8.html
- **[O16] Ubuntu Server firewall documentation** - UFW as Ubuntu's default frontend, IPv4/IPv6, dry-run, disabled-by-default behavior.  
  https://ubuntu.com/server/docs/how-to/security/firewalls/  
  https://documentation.ubuntu.com/security/security-features/network/firewall/
- **[O17] Red Hat Enterprise Linux 9 firewall documentation** - firewalld/nftables choice and firewalld runtime vs permanent state.  
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/configuring_firewalls_and_packet_filters/index
- **[O18] Nginx `ngx_http_proxy_module`** - `proxy_pass` semantics.  
  https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- **[O19] Nginx command-line switches** - `-t`, `-T`, version behavior.  
  https://nginx.org/en/docs/switches.html
- **[O20] Apache HTTP Server `mod_proxy` and `apachectl`** - proxy mapping and config testing.  
  https://httpd.apache.org/docs/2.4/mod/mod_proxy.html  
  https://httpd.apache.org/docs/current/programs/apachectl.html
- **[O21] Flask API / file-upload pattern** - safe directory file serving and filename handling.  
  https://flask.palletsprojects.com/en/stable/api/  
  https://flask.palletsprojects.com/en/stable/patterns/fileuploads/
- **[O22] PostgreSQL `pg_isready`** - connection-status semantics and exit codes.  
  https://www.postgresql.org/docs/current/app-pg-isready.html
- **[O23] MySQL `mysqladmin`** - administrative `ping` semantics.  
  https://dev.mysql.com/doc/refman/8.4/en/mysqladmin.html
- **[O24] Redis `PING` / `redis-cli`** - protocol liveness behavior.  
  https://redis.io/docs/latest/commands/ping/  
  https://redis.io/docs/latest/develop/tools/cli/
- **[O25] Linux `flock(2)` / `flock(1)`** - advisory file locking and caveats.  
  https://man7.org/linux/man-pages/man2/flock.2.html  
  https://man7.org/linux/man-pages/man1/flock.1.html
- **[O26] Linux `rename(2)`** - same-filesystem pathname replacement atomicity.  
  https://man7.org/linux/man-pages/man2/rename.2.html
- **[O27] Linux `/proc/PID/cmdline`** - process command-line limitations.  
  https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html

### Original attack-defend organizers / team retrospectives

- **[A1] FAUST CTF 2025 - Attack/Defense for Beginners** - gameserver stores/retrieves flags using legitimate service functionality; availability matters.  
  https://2025.faustctf.net/information/attackdefense-for-beginners/
- **[A2] Maple Bacon - FAUST CTF patcher retrospective (2024)** - versioned patch deployment and the operational need to exclude mutable data from code rollout/rollback.  
  https://maplebacon.org/2024/09/faustctf-patcher/
- **[A3] NTT Security Japan - ENOWARS 8 Attack & Defense writeup** - defensive patching must remain pinpoint because organizers repeatedly test service functionality.  
  https://jp.security.ntt/insights_resources/tech_blog/enowars-8-writeup-attack-and-defense/
- **[A4] ENOWARS documentation - general Attack/Defense play** - service/checker availability model and team operations.  
  https://enowars.github.io/docs/play/general/
- **[A5] FAUST CTF gameserver repository** - public gameserver implementation/checker model.  
  https://github.com/fausecteam/ctf-gameserver
- **[A6] SaarCTF 2025 services/checkers repository** - examples of per-service checkers that place/retrieve flags.  
  https://github.com/saarsec/saarctf-2025

---

## Bottom line

Build a **read-only graph builder first**, then a **profile-specific planner**, then a **transaction engine**, and only after disposable-VM fault testing promote individual exact actions to unattended mode. The most useful first profiles are host-native `Nginx -> systemd -> Flask/Gunicorn` and `Docker Compose web -> PostgreSQL`. Keep SSH, firewall, unknown-service shutdown, recursive permission hardening, and stateful database/container mutations review-only unless their exact environment and recovery path have been proven.
