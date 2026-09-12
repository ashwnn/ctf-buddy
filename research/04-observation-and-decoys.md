# 04 - Observation and Optional Decoys for a Small Attack-Defend Team

Research date: 2026-09-11

## Executive recommendation

Use passive, bounded observation by default:

1. Preserve and query the logs the scored service already produces.
2. Run a small rotating packet-capture ring on the CTF-facing interface only, if packet capture is permitted and the host gives the team sufficient privilege.
3. Do not insert a new reverse proxy in front of a scored service only for visibility.
4. Do not expose an extra decoy listener unless the event rules or an organizer explicitly permit extra ports/services.
5. If a decoy is permitted, prefer the single-purpose unprivileged HTTP decoy in this document over a general honeypot.
6. If an established honeypot is desired, OpenCanary is the first option to evaluate. Cowrie is not a default because it is heavier operationally and some emulated commands can make real outbound connections to attacker-supplied destinations unless separately contained.

This fits the attached Raymond James prep brief, which treats attack-defend service availability, incoming-attack monitoring, `tcpdump`, `journalctl`, web/server logs and fast scripting as important. The brief also says Internet access may be unavailable, so anything optional must be staged offline before the event.

Important rule gate: the supplied brief does not establish that Raymond James permits decoys, honeypots, extra listening ports, extra devices, traffic interception, or modification of the scored network path. Treat all deception as OFF until organizers confirm it is allowed.

## What each mechanism actually does

| Mechanism | Creates bait? | Detects interaction by itself? | Main value | Main limitation / risk |
|---|---:|---:|---|---|
| Existing service logs | No | Yes, for events the service already logs | Lowest-risk request/error/auth visibility | May omit payloads, scans, dropped packets or exploit context |
| Rotating packet capture | No | Yes, at packet level | Independent evidence of connections, timing, protocol metadata and some plaintext request data | Privilege needed; encrypted payload remains opaque; plaintext capture can contain secrets |
| Fake endpoint in an existing app or proxy | Yes | Only if access logging/telemetry is enabled | High-signal path that legitimate users should not request | Code/config change can break a scored service |
| Canary file | Yes | No | Bait for local/file-system enumeration | Merely placing a file creates no alert |
| Canary file plus audit/access instrumentation | Yes | Yes | Can identify reads/opens of a bait file | audit rules usually need privilege; backups/indexers can trigger it |
| Standalone HTTP decoy | Yes | Yes | Cheap, explicit interaction signal isolated from the scored app | Extra port may be disallowed or collide with a checker/service |
| Reverse proxy inserted in front of a real service | Not necessarily | Yes | Central request logging and normalization | Adds a new failure point and can alter HTTP behavior |
| OpenCanary | Yes | Yes | Multiple low-interaction protocol decoys | More dependencies and protocol surface than needed for a small team |
| Cowrie | Yes | Yes | Rich SSH/Telnet credential and command interaction | Larger state/log footprint; richer emulation; outbound behavior must be contained |

The distinction matters:

- A fake endpoint or file is only bait. Without logging, audit, application telemetry or another detector, it does not tell you it was touched.
- Passive packet capture detects network interaction but does not create deception.
- A standalone decoy both creates bait and records interaction.
- A reverse proxy observes a real service by becoming part of its request path. That is operationally different from a separate decoy and is much more likely to affect checker behavior.

## Comparison

### 1. Native logs plus rotating packet capture

Recommendation: default.

Detection value:

- Existing service logs give request, application, authentication, error and process context with almost no new attack surface.
- `journalctl` can correlate service restarts, crashes, OOM events, permission failures and unit output.
- Packet capture gives an independent timeline of TCP/UDP activity and can show SYNs, resets, protocol negotiation and some plaintext request material even when the application fails before writing a log entry.
- The two together are more useful than either alone because they let the team distinguish "packet reached host" from "application accepted/processed request."

Limits:

- TLS/SSH payloads are encrypted.
- A small snap length may omit exploit payloads.
- Full packets can expose HTTP cookies, Authorization headers, tokens or challenge flags. The bounded profile below intentionally uses a short snap length, strict file permissions and a small ring.
- Packet capture can drop traffic under load. A dropped packet is not proof no event happened.
- Native logs are stack-specific. Do not assume nginx, Apache, systemd or Docker paths until discovery identifies them.

Dependencies:

- `journalctl` only where systemd-journald is used.
- `tcpdump` for the packet ring.
- No Internet required after packages are present.

Privilege:

- Reading some logs may require membership in `systemd-journal`, `adm`, a container group, or root.
- Linux live packet capture normally requires root or packet-capture capabilities. Do not globally `setcap` Python or unrelated interpreters.
- The profile below runs `tcpdump` as a dedicated unprivileged user with only `CAP_NET_RAW` granted by the unit.

Resource controls:

- PCAP ring: eight 8,000,000-byte files, about 64 MB maximum plus filesystem metadata and the currently open file.
- Snap length: 192 bytes.
- CPU quota: 20 percent of one CPU.
- Memory limit: 128 MB.
- No promiscuous mode.
- Capture only the selected CTF-facing interface, never `any` by default.

Removal:

- Stop/disable the unit.
- Remove the unit file, capture directory and dedicated user if desired.
- Verify no packet-capture process remains.

### 2. Minimal unprivileged HTTP decoy

Recommendation: preferred deception option, but only after organizer approval.

Design:

- One Python 3 standard-library process.
- High unprivileged TCP port, default example `18080`.
- Bind to the exact CTF-facing IP, not `0.0.0.0`, after checking collisions.
- No proxying.
- No DNS resolution.
- No callbacks.
- No file serving.
- No command execution.
- No credential validation.
- No body logging.
- Authorization and Cookie values are intentionally discarded.
- Host names, URLs and callback-looking strings are inert data only.
- Static 404 response for all valid requests.
- JSONL event log with size rotation.
- Single request worker, two-second socket timeout, bounded request-line/header/body parsing.
- cgroup CPU/memory/task limits and filesystem sandboxing under systemd.

Detection value:

- Any remote interaction with a port that has no legitimate purpose is a useful signal.
- Method, target, source address, user agent and basic metadata are enough to distinguish simple scans from targeted enumeration.
- Because the listener never forwards anywhere, hitting it cannot become a path to the scored service or real credentials.

Limits:

- A scan of every port may trigger it, so a hit is not proof of compromise.
- A checker or organizer scanner may also touch it.
- Single-threaded handling deliberately favors resource safety over fidelity and can drop or delay concurrent interactions.
- If extra ports are prohibited, do not use it.

Dependencies:

- Python 3 only.
- No pip packages.
- No network access.
- The included code was syntax-checked and locally exercised with a request containing an Authorization header and an attacker-looking callback URL. The secret value was not written to the JSON log and the callback remained inert.

Privilege:

- None for ports 1024-65535.
- Root is only needed if installing it as a system service or creating a dedicated service account.

Removal:

- Stop/disable service.
- Verify listener is gone.
- Delete unit, script, logs and service account.

### 3. OpenCanary

Recommendation: first established honeypot to evaluate if a general decoy is explicitly permitted.

Verified current state on 2026-09-11:

- Latest PyPI release found: `opencanary 0.9.9`, released 2026-07-22.
- Requires Python 3.10 or newer.
- Official project metadata classifies it as Production/Stable.
- Core is Python/Twisted and supports multiple fake network services.
- License: BSD 3-Clause.
- Official documentation describes low resource requirements and Raspberry Pi deployment, but does not provide a numeric RAM/CPU budget. Use external cgroup limits rather than assuming a number.
- Source includes `device.listen_addr`, allowing services to bind to a selected address.
- The current dependency set includes Twisted, cryptography, requests, Jinja2, redis, GitPython and others even if only one protocol is enabled.
- Current docs support file logging and multiple remote alert sinks. For this CTF profile, remote sinks must remain disabled.
- Optional port-scan functionality depends on iptables rather than nftables and is not useful for this minimal profile.

CTF-safe profile:

- Use one protocol only.
- Prefer a high unprivileged port.
- Set `device.listen_addr` to the exact team VM CTF address.
- Set all `*.enabled` values false, then enable only the chosen service.
- Disable portscan.
- Use local file logging only.
- Do not configure SMTP, Slack, Teams, Webhook, JSON TCP or any other remote sink.
- Do not reuse real credentials in banners, forms or configuration.
- Put it behind the same systemd CPU/memory/task constraints as the tiny decoy.

Offline staging:

On a preparation machine matching the event VM architecture and Python environment:

```bash
mkdir -p vendor/opencanary
python3 -m pip wheel --wheel-dir vendor/opencanary 'opencanary==0.9.9'
```

Offline:

```bash
python3 -m venv ./venv-opencanary
./venv-opencanary/bin/pip install \
  --no-index \
  --find-links ./vendor/opencanary \
  'opencanary==0.9.9'
```

Do not assume wheels built for a different architecture or Python ABI will work.

Useful interaction fields in the official examples include source/destination host and port, `logtype`, node ID and protocol-specific data. Be careful: some protocol modules intentionally log attempted usernames/passwords. Treat those strings as hostile evidence, not credentials to reuse.

Removal:

- Stop daemon.
- Remove the virtual environment, config and log directory.
- Confirm its port is absent from `ss -ltnup`.

### 4. Cowrie

Recommendation: comparison-only for this small-team profile unless SSH/Telnet deception is specifically useful and outbound networking is separately prevented.

Verified current state on 2026-09-11:

- Latest PyPI release found: `cowrie 3.0.13`, released 2026-08-24.
- Requires Python 3.10 or newer and less than Python 4.
- License expression: BSD-3-Clause.
- Official install docs strongly recommend a dedicated non-root user and note that Cowrie refuses to start as root.
- Docker quick start normally maps host port 2222 to Cowrie SSH port 2222.
- JSON output includes timestamp, event ID, sensor, session, source IP and connection protocol/ports.
- Cowrie stores JSON/debug logs, TTY session logs and attacker-transferred files.
- Current project dependencies include Twisted Conch, cryptography, bcrypt and related packages.
- The project is actively maintained; releases were published in August 2026.

Why it is not the default here:

- Cowrie is intentionally interactive and therefore has more parser/emulation surface than a simple decoy.
- It can record credentials and commands, creating more sensitive hostile content to handle.
- It can store uploaded/downloaded artifacts, increasing disk-management work.
- Cowrie emulates commands such as `wget`, `curl`, `ftpget` and `tftp`. Recent project fixes and issues explicitly discuss real outbound connections to attacker-specified targets. That violates this design's requirement that attacker-supplied callbacks/destinations remain inert unless the process is separately prevented from making outbound connections.
- Its richer behavior is valuable when SSH/Telnet adversary interaction is the actual research target, but it is unnecessary overhead for basic attack-defend awareness.

If used at all:

- Keep proxy mode off.
- Disable optional remote output plugins.
- Use only SSH or Telnet, not both unless justified.
- Bind a high port unless rules explicitly permit otherwise.
- Place it in a separate namespace/container or equivalent egress-controlled environment where accepted client sockets still work but arbitrary outbound `connect()` attempts cannot reach the network.
- Cap `download_limit_size`, session timeout, CPU, memory, tasks and disk.
- Never put real files, keys, passwords, tokens or reachable backend credentials into its fake filesystem.

Offline staging:

```bash
mkdir -p vendor/cowrie
python3 -m pip wheel --wheel-dir vendor/cowrie 'cowrie==3.0.13'
```

Offline:

```bash
python3 -m venv ./venv-cowrie
./venv-cowrie/bin/pip install \
  --no-index \
  --find-links ./vendor/cowrie \
  'cowrie==3.0.13'
```

The package itself is small, but transitive native/cryptographic dependencies mean the wheelhouse must be prepared for the target platform in advance.

## Default bounded observation profile

This profile adds no new network listener.

### Preflight

Identify the CTF-facing interface. Do not assume `eth0`.

```bash
ip -br addr
ip route
ss -H -ltnup
```

Record the baseline:

```bash
date -Is
ss -H -ltnup
ps -eo pid,user,comm,%cpu,%mem --sort=-%cpu | head -30
df -h
df -i
```

If systemd is present:

```bash
systemctl --failed --no-pager
journalctl -n 100 --no-pager
```

For a known scored service:

```bash
systemctl status SERVICE --no-pager
journalctl -u SERVICE --since '-5 min' --no-pager -o short-iso-precise
```

For a known container:

```bash
docker logs --since 5m --timestamps CONTAINER 2>&1 | tail -200
```

Do not turn on application debug logging during the event unless you have measured the overhead and know it does not expose secrets or flood disk.

### Safer hostile-string viewing

Treat request paths, user agents, usernames, headers and payload fragments as hostile terminal input.

Preferred:

```bash
journalctl -u SERVICE --since '-5 min' -o json --no-pager | jq -c .
```

For plain text logs:

```bash
sed -n '1,200l' /path/to/log
```

Avoid rendering attacker strings as HTML and avoid `jq -r` for hostile values. The decoy below uses JSON escaping and never logs request bodies or Authorization/Cookie values.

### Packet-capture user

If you have root and systemd:

```bash
sudo useradd \
  --system \
  --no-create-home \
  --shell /usr/sbin/nologin \
  ctfobs 2>/dev/null || true

sudo install -d -m 0700 -o ctfobs -g ctfobs /var/log/ctf-observe/pcap
```

### Packet-capture service

Before installing, replace `CTF_IFACE` with the actual external team interface.

`/etc/systemd/system/ctf-pcap.service`:

```ini
[Unit]
Description=CTF bounded packet capture ring
After=network.target

[Service]
Type=simple
User=ctfobs
Group=ctfobs

# Do not use "any". Do not capture promiscuously.
ExecStart=/usr/bin/tcpdump \
  -i CTF_IFACE \
  -p \
  -nn \
  -s 192 \
  -B 1024 \
  -C 8 \
  -W 8 \
  -w /var/log/ctf-observe/pcap/ring.pcap \
  tcp or udp

AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ReadWritePaths=/var/log/ctf-observe/pcap

CPUQuota=20%
MemoryHigh=96M
MemoryMax=128M
TasksMax=16
LimitNOFILE=64
Nice=10
UMask=0077

Restart=no

[Install]
WantedBy=multi-user.target
```

Validate unit syntax before starting:

```bash
sudo systemd-analyze verify /etc/systemd/system/ctf-pcap.service
```

Start:

```bash
sudo systemctl daemon-reload
sudo systemctl start ctf-pcap
```

Status:

```bash
systemctl status ctf-pcap --no-pager
systemctl show ctf-pcap \
  -p MainPID \
  -p MemoryCurrent \
  -p MemoryMax \
  -p CPUUsageNSec \
  -p TasksCurrent
sudo ls -lh /var/log/ctf-observe/pcap
```

Read metadata only by default:

```bash
sudo tcpdump -nn -tttt -r /var/log/ctf-observe/pcap/ring.pcap -c 50
```

Do not use `-A` or `-X` reflexively because application payloads may contain flags, credentials, tokens or terminal control data.

Stop:

```bash
sudo systemctl stop ctf-pcap
```

Cleanup:

```bash
sudo systemctl disable ctf-pcap 2>/dev/null || true
sudo rm -f /etc/systemd/system/ctf-pcap.service
sudo systemctl daemon-reload
sudo rm -rf /var/log/ctf-observe
sudo userdel ctfobs 2>/dev/null || true
```

No-root fallback:

- Use readable application logs and `journalctl --user` where applicable.
- If `tcpdump` lacks sufficient capability, skip live capture.
- Do not modify global capabilities or firewall policy simply to force packet capture to work.

## Opt-in standalone HTTP decoy

Use this only after organizer approval.

### Port and bind checks

Pick a high port that is not already used by a scored or administrative service.

Example:

```bash
DECOY_PORT=18080
ss -H -ltnup
ss -H -ltn "( sport = :${DECOY_PORT} )"
```

If the second command prints anything, stop. Do not steal, redirect or replace that port.

Choose the exact CTF-facing address:

```bash
ip -br addr
```

Use the specific address, for example `10.20.30.15`, rather than `0.0.0.0`.

### Decoy implementation

`/opt/ctf-decoy/decoy_http.py`:

```python
#!/usr/bin/env python3
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import socket
import socketserver
from datetime import datetime, timezone

MAX_REQUEST_LINE = 4096
MAX_HEADER_BYTES = 8192
MAX_HEADERS = 64
MAX_BODY = 4096
SOCKET_TIMEOUT = 2.0


def clipped_text(raw: bytes, limit: int) -> str:
    return raw[:limit].decode("utf-8", errors="replace")


def emit(logger: logging.Logger, **fields) -> None:
    fields.setdefault("ts", datetime.now(timezone.utc).isoformat())
    logger.info(json.dumps(fields, ensure_ascii=True, separators=(",", ":")))


class BoundedTCPServer(socketserver.TCPServer):
    allow_reuse_address = False
    request_queue_size = 16


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn: socket.socket = self.request
        conn.settimeout(SOCKET_TIMEOUT)

        src_ip, src_port = self.client_address[:2]
        event = {
            "event": "http_decoy",
            "src_ip": src_ip,
            "src_port": src_port,
            "status": "observed",
        }
        status = 404

        try:
            rfile = conn.makefile("rb")
            line = rfile.readline(MAX_REQUEST_LINE + 1)

            if not line:
                event["status"] = "empty"
                status = 400
            elif len(line) > MAX_REQUEST_LINE or not line.endswith(b"\n"):
                event["status"] = "request_line_too_long"
                status = 414
            else:
                parts = line.rstrip(b"\r\n").split(b" ", 2)
                if len(parts) != 3:
                    event["status"] = "malformed_request_line"
                    status = 400
                else:
                    method, target, version = parts
                    event["method"] = clipped_text(method, 16)
                    event["target"] = clipped_text(target, 2048)
                    event["version"] = clipped_text(version, 16)

                    header_bytes = 0
                    header_count = 0
                    headers = {}

                    while True:
                        remaining = MAX_HEADER_BYTES - header_bytes
                        if remaining <= 0:
                            raise ValueError("headers_too_large")

                        hline = rfile.readline(remaining + 1)
                        if not hline:
                            break

                        header_bytes += len(hline)
                        if header_bytes > MAX_HEADER_BYTES:
                            raise ValueError("headers_too_large")

                        if hline in (b"\r\n", b"\n"):
                            break

                        header_count += 1
                        if header_count > MAX_HEADERS:
                            raise ValueError("too_many_headers")

                        if b":" not in hline:
                            raise ValueError("malformed_header")

                        name, value = hline.split(b":", 1)
                        name_s = clipped_text(name.strip().lower(), 64)
                        value_s = clipped_text(value.strip(), 512)
                        headers[name_s] = value_s

                    event["header_count"] = header_count
                    event["user_agent"] = headers.get("user-agent", "")[:256]
                    event["host"] = headers.get("host", "")[:256]
                    event["has_authorization"] = "authorization" in headers
                    event["has_cookie"] = "cookie" in headers

                    # Host names and URLs are logged only as inert strings.
                    # Authorization/Cookie values are never logged.
                    content_length_raw = headers.get("content-length", "0")
                    try:
                        content_length = int(content_length_raw)
                    except ValueError:
                        raise ValueError("invalid_content_length")

                    if content_length < 0:
                        raise ValueError("invalid_content_length")

                    event["content_length"] = content_length

                    if content_length > MAX_BODY:
                        event["status"] = "body_too_large"
                        status = 413
                    else:
                        body = rfile.read(content_length) if content_length else b""
                        event["body_bytes_read"] = len(body)

                        # The body is intentionally discarded.
                        event["status"] = "observed"
                        status = 404

        except socket.timeout:
            event["status"] = "timeout"
            status = 408
        except (OSError, ValueError) as exc:
            event["status"] = str(exc)[:80]
            status = 400
        finally:
            emit(self.server.logger, **event)

            reason = {
                400: b"Bad Request",
                404: b"Not Found",
                408: b"Request Timeout",
                413: b"Payload Too Large",
                414: b"URI Too Long",
            }.get(status, b"Not Found")

            body = b"not found\n"
            response = (
                b"HTTP/1.1 " + str(status).encode() + b" " + reason + b"\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Cache-Control: no-store\r\n"
                b"Connection: close\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )

            try:
                conn.sendall(response)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded, non-proxying HTTP decoy"
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--log", default="./decoy-http.jsonl")
    args = parser.parse_args()

    if not (1024 <= args.port <= 65535):
        parser.error(
            "port must be 1024..65535 so the decoy does not need bind privileges"
        )

    logger = logging.getLogger("ctf-http-decoy")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        args.log,
        maxBytes=2_000_000,
        backupCount=4,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    with BoundedTCPServer((args.bind, args.port), Handler) as server:
        server.logger = logger
        emit(logger, event="decoy_start", bind=args.bind, port=args.port)

        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            emit(logger, event="decoy_stop")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Properties:

| Limit | Value | Purpose |
|---|---:|---|
| Request line | 4096 bytes | Prevent unbounded request-target parsing |
| All headers combined | 8192 bytes | Bound memory and parser work |
| Header count | 64 | Bound field processing |
| Stored individual header value | 512 bytes | Bound per-field storage |
| Stored user-agent/host | 256 bytes each | Keep event records small |
| Body accepted | 4096 bytes | Prevent large POST bodies |
| Body logged | 0 bytes | Avoid collecting secrets or hostile payloads |
| Socket timeout | 2 seconds | Bound slow-client hold time |
| Listen backlog | 16 | Bound queued connections |
| Workers | 1 | Bound process/thread count |
| Log files | 5 total, about 10 MB | 2 MB current plus 4 rotations |

### Service account and install

Replace `10.20.30.15` with the actual CTF-facing address.

```bash
sudo useradd \
  --system \
  --no-create-home \
  --shell /usr/sbin/nologin \
  ctfdecoy 2>/dev/null || true

sudo install -d -m 0755 /opt/ctf-decoy
sudo install -d -m 0700 -o ctfdecoy -g ctfdecoy /var/log/ctf-decoy
sudo install -m 0755 ./decoy_http.py /opt/ctf-decoy/decoy_http.py
```

`/etc/systemd/system/ctf-http-decoy.service`:

```ini
[Unit]
Description=CTF bounded HTTP decoy
After=network.target

[Service]
Type=simple
User=ctfdecoy
Group=ctfdecoy

ExecStart=/usr/bin/python3 \
  /opt/ctf-decoy/decoy_http.py \
  --bind 10.20.30.15 \
  --port 18080 \
  --log /var/log/ctf-decoy/http.jsonl

NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ReadWritePaths=/var/log/ctf-decoy

# The decoy never needs to initiate a network connection.
# Verify this directive on the event OS before relying on it.
SystemCallFilter=~connect

CPUQuota=10%
MemoryHigh=48M
MemoryMax=64M
TasksMax=8
LimitNOFILE=64
UMask=0077

Restart=no

[Install]
WantedBy=multi-user.target
```

Validate:

```bash
sudo systemd-analyze verify /etc/systemd/system/ctf-http-decoy.service
```

If the target systemd/kernel cannot apply `SystemCallFilter=~connect`, remove only that hardening line after confirming the Python implementation still contains no outbound-connect code. Do not weaken the rest of the service to make a decoy work.

### Start

Final collision check:

```bash
ss -H -ltn "( sport = :18080 )"
```

If empty:

```bash
sudo systemctl daemon-reload
sudo systemctl start ctf-http-decoy
```

### Status

```bash
systemctl status ctf-http-decoy --no-pager
systemctl show ctf-http-decoy \
  -p MainPID \
  -p MemoryCurrent \
  -p MemoryMax \
  -p CPUUsageNSec \
  -p TasksCurrent

ss -H -ltnp "( sport = :18080 )"
sudo sed -n '1,80l' /var/log/ctf-decoy/http.jsonl
```

### Stop

```bash
sudo systemctl stop ctf-http-decoy
ss -H -ltnp "( sport = :18080 )"
```

The second command must print no decoy listener.

### Cleanup

```bash
sudo systemctl disable ctf-http-decoy 2>/dev/null || true
sudo rm -f /etc/systemd/system/ctf-http-decoy.service
sudo systemctl daemon-reload

sudo rm -rf /opt/ctf-decoy
sudo rm -rf /var/log/ctf-decoy
sudo userdel ctfdecoy 2>/dev/null || true
```

### Synthetic event

Request:

```text
GET /admin?callback=http://203.0.113.50/collect HTTP/1.1
Host: 10.20.30.15:18080
User-Agent: recon-client
Authorization: Bearer DO-NOT-STORE
```

Synthetic log:

```json
{"event":"http_decoy","src_ip":"10.20.30.44","src_port":51512,"status":"observed","method":"GET","target":"/admin?callback=http://203.0.113.50/collect","version":"HTTP/1.1","header_count":3,"user_agent":"recon-client","host":"10.20.30.15:18080","has_authorization":true,"has_cookie":false,"content_length":0,"body_bytes_read":0,"ts":"2026-09-11T22:10:00+00:00"}
```

Interpretation:

- The callback URL is only a string in `target`.
- No DNS lookup occurs.
- No connection to `203.0.113.50` occurs.
- The Authorization value is not stored.
- This is evidence that something touched the decoy, not proof that the source is malicious.

## File canary profile

A file canary is useful only if access is instrumented.

### Bait only

Example:

```bash
install -m 0444 /dev/null /srv/example/.ops-backup.json
```

That creates bait but no detector. Do not infer access from the file's existence. Do not rely on `atime` as a robust alerting mechanism.

### Bait plus Linux audit

If auditd is already present and the team has permission to add a rule, use a narrow syscall path rule rather than a broad directory watch.

Example for 64-bit processes:

```bash
sudo auditctl \
  -a always,exit \
  -F arch=b64 \
  -F path=/srv/example/.ops-backup.json \
  -F perm=r \
  -F key=ctf_canary_read
```

If 32-bit processes are relevant on an x86_64 host, add the corresponding `arch=b32` rule.

Query:

```bash
sudo ausearch -k ctf_canary_read -ts recent
```

Cleanup by deleting the exact rule:

```bash
sudo auditctl \
  -d always,exit \
  -F arch=b64 \
  -F path=/srv/example/.ops-backup.json \
  -F perm=r \
  -F key=ctf_canary_read
```

Cautions:

- This requires privilege.
- Auditing a hot path can generate noise; keep it to one or a few bait files.
- Backups, antivirus, indexers, integrity scanners or your own teammate can trigger it.
- The bait file must contain no real secret, working key or credential.
- A file served through HTTP may be better detected by the existing web access log than by filesystem auditing.

If auditd is not already available, do not install it mid-CTF solely for a canary unless you have tested the operational impact.

## Reverse proxy guidance

Do not insert a new proxy solely to gain visibility during a live scored service.

Potential checker/service breakage includes:

- altered source IP handling,
- changed `Host` or forwarding headers,
- request-body buffering,
- chunked encoding differences,
- WebSocket or upgrade handling,
- TLS termination changes,
- timeout changes,
- connection reuse differences,
- maximum-body/header limits,
- path normalization,
- upload behavior,
- streaming behavior,
- new restart/reload failure modes.

Lower-risk alternative:

- If the service already uses nginx, Apache, HAProxy, Caddy or another reverse proxy, use its existing access/error logs first.
- If a decoy path is desired, add it only to an already-tested existing proxy/app configuration and only if rules permit it. A synthetic path such as `/internal/healthz-old` should return static content and must never proxy to a real backend.
- Validate config before reload and have a one-command rollback.
- Never introduce a new proxy layer in front of a working scored service merely to inspect requests.

## False positives and response policy

No automatic banning is part of this profile.

Reason:

- Attack-defend checkers may originate from unexpected addresses.
- Organizer infrastructure may scan.
- Teammates may probe the service.
- NAT can cause multiple actors to share a source address.
- A single SYN, malformed request or decoy hit does not prove exploitation.

Suggested triage:

| Evidence | Initial confidence | Action |
|---|---|---|
| One SYN or closed-port probe | Low | Record only |
| Broad port scan | Low to medium | Correlate with service logs and team activity |
| One HTTP decoy hit | Medium | Check source, timing and adjacent real-service traffic |
| Repeated decoy requests with targeted paths | Medium to high | Prioritize manual review |
| Canary file access by unexpected process/user | High after local-noise exclusion | Investigate process tree and nearby logs |
| Exploit-looking request plus application error/restart | High | Review real service immediately |
| Decoy hit from known checker/organizer address | Low for maliciousness | Suppress only in analyst view, preserve raw event |

If blocking is permitted by event rules, require a human decision based on multiple signals. Do not automatically firewall an address from one decoy event.

## Local validation drill

Run this before the event on a disposable VM or representative service host.

Set:

```bash
REAL_URL='http://127.0.0.1:8080/health'
DECOY_URL='http://127.0.0.1:18080/admin'
```

### 1. Baseline the real service

```bash
curl -fsS --max-time 2 "$REAL_URL"
ss -H -ltnup
```

Save the output.

### 2. Start observation

Start the bounded PCAP unit on the correct lab interface:

```bash
sudo systemctl start ctf-pcap
systemctl is-active ctf-pcap
```

### 3. Start the decoy locally

For the first test, bind it only to loopback:

```bash
sudo systemctl start ctf-http-decoy
systemctl is-active ctf-http-decoy
```

If the installed unit is configured for a non-loopback address, use a separate lab copy of the unit or run the script directly as your user on `127.0.0.1`.

### 4. Prove interaction creates an event

```bash
curl -i \
  --max-time 2 \
  -H 'User-Agent: validation-client' \
  -H 'Authorization: Bearer SHOULD-NOT-APPEAR' \
  'http://127.0.0.1:18080/admin?callback=http://203.0.113.50/x'
```

Expected:

- HTTP 404.
- One JSON event.
- `has_authorization` is true.
- The Authorization value is absent.
- Callback URL appears only as inert target text.

Check safely:

```bash
sudo sed -n '1,120l' /var/log/ctf-decoy/http.jsonl
sudo grep -F 'SHOULD-NOT-APPEAR' /var/log/ctf-decoy/http.jsonl && echo FAIL || echo PASS
```

### 5. Prove parser/resource bounds

Oversized body:

```bash
head -c 8192 /dev/zero | \
  curl -i \
    --max-time 3 \
    -X POST \
    --data-binary @- \
    'http://127.0.0.1:18080/upload'
```

Expected: HTTP 413 and no body bytes written to the event log.

Concurrent request pressure:

```bash
seq 1 100 | \
  xargs -n1 -P20 -I{} \
  curl -sS --max-time 3 -o /dev/null \
  'http://127.0.0.1:18080/probe?id={}' || true
```

Inspect cgroup use:

```bash
systemctl show ctf-http-decoy \
  -p MemoryCurrent \
  -p MemoryMax \
  -p CPUUsageNSec \
  -p TasksCurrent \
  -p TasksMax
```

Pass condition:

- Unit remains under configured memory/task ceilings or is cleanly killed by the cgroup rather than consuming the host.
- Real scored/test service remains healthy.

### 6. Prove the real service still works

```bash
curl -fsS --max-time 2 "$REAL_URL"
```

Compare with baseline. Any behavior change is a failure.

### 7. Prove capture contains the interaction

```bash
sudo ls -lh /var/log/ctf-observe/pcap
sudo tcpdump -nn -tttt -r /var/log/ctf-observe/pcap/ring.pcap -c 30
```

You should see loopback or lab-interface traffic only if the capture unit is attached to that interface. Do not weaken the capture configuration just to make the drill pass.

### 8. Stop the decoy and prove listener removal

```bash
sudo systemctl stop ctf-http-decoy
ss -H -ltnp "( sport = :18080 )"
```

Pass condition: no listener is returned.

### 9. Verify the real service again

```bash
curl -fsS --max-time 2 "$REAL_URL"
```

### 10. Stop observation and check disk bound

```bash
sudo systemctl stop ctf-pcap
du -sh /var/log/ctf-observe/pcap
```

Pass condition: packet capture is bounded to roughly the configured ring size, not unbounded growth.

## Go/no-go checklist for the event

Default observation can start only if:

- Correct CTF interface identified.
- Native service ownership/log locations understood.
- Packet capture is allowed.
- Capture unit passes local validation.
- Ring directory has sufficient free disk.
- No secret-bearing long-term capture is being created.

Decoy can start only if all are true:

- Organizer rules explicitly allow extra decoy services/ports.
- Selected port is unused.
- Exact bind address is known.
- No route to a real backend exists.
- No real credentials/keys/secrets are present.
- No callbacks, webhooks or external notification sinks are configured.
- Parser/resource limits are in place.
- Service has been locally validated.
- One-command stop and cleanup are known.
- Teammates know the port is a decoy.

If any item is unknown, run observation only.

## Sources and verification notes

All time-sensitive project/version claims below were checked on 2026-09-11.

### Attached event brief

- `raymond-james-ctf-2026-prep.md`
- Relevant supplied points: hybrid mini-Jeopardy plus live attack-defend; monitor incoming attacks; useful tools include `tcpdump`, `journalctl`, `ss`, `lsof`, `systemctl`, firewall tools and web/server logs; Internet may be limited/unavailable.
- The brief does not supply official 2026 organizer rules authorizing decoys or extra listening services.

### tcpdump / libpcap

- tcpdump manual: https://man7.org/linux/man-pages/man1/tcpdump.1.html
- Key verified behavior:
  - `-W` with `-C` limits file count and overwrites the ring.
  - `-Z user` can relinquish privileges after opening capture devices.
  - capture expressions limit stored packets.
- Note: `tcpdump.org` was blocked by robots in the research environment, so the current upstream manual was read through the man7 mirror.

### systemd upstream

- Execution/sandboxing source documentation:
  - https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml
- Resource-control source documentation:
  - https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml
- Relevant verified controls:
  - `NoNewPrivileges=`
  - `CapabilityBoundingSet=`
  - `ProtectSystem=`
  - `ProtectHome=`
  - `CPUQuota=`
  - `MemoryHigh=`
  - `MemoryMax=`
  - `TasksMax=`
- Current rendered-manual mirror used for easier reading:
  - https://man7.org/linux/man-pages/man5/systemd.exec.5.html
  - https://man7.org/linux/man-pages/man5/systemd.resource-control.5.html

### Linux audit

- auditctl manual:
  - https://man7.org/linux/man-pages/man8/auditctl.8.html
- audit rules manual:
  - https://man7.org/linux/man-pages/man7/audit.rules.7.html
- Verified:
  - syscall/path/permission filtering is supported.
  - legacy `-w` watch syntax is deprecated in favor of syscall-form rules.
  - `perm` can select read/write/execute/attribute access classes.

### OpenCanary

- Repository:
  - https://github.com/thinkst/opencanary
- README:
  - https://github.com/thinkst/opencanary/blob/master/README.md
- Current package metadata:
  - https://pypi.org/project/opencanary/
- Current build/dependency metadata:
  - https://github.com/thinkst/opencanary/blob/master/pyproject.toml
- Default/example configuration:
  - https://github.com/thinkst/opencanary/blob/master/opencanary/data/settings.json
  - https://github.com/thinkst/opencanary/blob/master/data/.opencanary.conf
- Logging documentation:
  - https://github.com/thinkst/opencanary/blob/master/docs/starting/configuration.rst
- Service/module bind behavior:
  - https://github.com/thinkst/opencanary/blob/master/opencanary/modules/mysql.py
  - https://github.com/thinkst/opencanary/blob/master/opencanary/modules/ftp.py
- License:
  - https://github.com/thinkst/opencanary/blob/master/LICENSE
- Verified version:
  - 0.9.9, released 2026-07-22.
- Verified license:
  - BSD 3-Clause.
- Verified Python floor:
  - Python >= 3.10.
- Resource note:
  - official docs describe very low resource requirements but provide no fixed RAM/CPU number.

### Cowrie

- Repository:
  - https://github.com/cowrie/cowrie
- Installation:
  - https://github.com/cowrie/cowrie/blob/main/INSTALL.rst
- Stable output event reference:
  - https://docs.cowrie.org/en/stable/OUTPUT.html
- Docker documentation:
  - https://docs.cowrie.org/en/stable/docker/README.html
- Current package metadata:
  - https://pypi.org/project/cowrie/
- Dependency file:
  - https://github.com/cowrie/cowrie/blob/main/requirements.txt
- License:
  - https://github.com/cowrie/cowrie/blob/main/LICENSE.rst
- Release history:
  - https://github.com/cowrie/cowrie/releases
- Verified version:
  - 3.0.13, released 2026-08-24.
- Verified license:
  - BSD-3-Clause.
- Verified Python range:
  - Python >= 3.10, < 4.
- Outbound-risk evidence:
  - Current project issues/release notes discuss real outbound transfers from emulated `wget`, `curl`, `ftpget` and `tftp` behavior and fixes around rate limits, SSRF-style target validation and download-size limits.
  - https://github.com/cowrie/cowrie/issues/40393
  - https://github.com/cowrie/cowrie/issues/40394
  - https://github.com/cowrie/cowrie/releases

## Bottom line

For a first-time small attack-defend team, visibility is more valuable than deception complexity.

Use:

- real service logs,
- bounded PCAP,
- explicit manual triage,
- no automatic bans.

Only if the rules permit it, add one high-port, non-proxying, non-callback HTTP decoy that cannot reach a backend and can be removed instantly.

OpenCanary is the only established honeypot here that is plausibly worth carrying as an optional pre-staged tool. Cowrie is technically capable and well maintained, but its richer SSH/Telnet interaction model creates more operational and containment work than this event-prep profile needs.
