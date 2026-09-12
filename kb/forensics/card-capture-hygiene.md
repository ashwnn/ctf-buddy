# Take a bounded, rotated, timestamped capture instead of an unbounded one

**First useful action.** Start the capture with an explicit size bound, file rotation, and a capture filter — an unbounded `tcpdump` on a vulnbox is a slow denial of service against your own service.

```bash
df -h <CAPTURE_DIR> ; pgrep -a tcpdump
tcpdump -i <IFACE> -nn -s0 -U -Z <UNPRIV_USER> -C 128 -W 8 -w <CAPTURE_DIR>/<SERVICE>-<UTCSTAMP>.pcap '<BPF_FILTER>'
```

Expected: a file that grows and rotates; `tcpdump -r <CAPTURE_DIR>/<SERVICE>-<UTCSTAMP>.pcap -c 5` prints real frames. If nothing is written, either the interface name is wrong, the capture filter matches nothing, or the process lost privileges — check the `tcpdump` stderr first, not the analyzer.

## Symptoms

- You are about to capture on an interface for the first time during the event.
- A previous capture died or the disk filled and a service went down.
- Nobody can tell which capture file covers which tick or service.

## Prerequisites and assumptions

- Team-owned host, organizer rules permitting packet capture, and enough free space for `-C` × `-W` megabytes plus slack.
- Capture privilege (root/CAP_NET_RAW) or a setuid/setcap `tcpdump`; the BPF filter is a **capture** filter (pcap syntax), not a Wireshark display filter.
- Stack/version: `tcpdump` 4.9+; `-C`/`-W`/`-Z`/`-U` are stable, and the output format is classic pcap (not pcapng), so name files `.pcap`.

## Diagnostic sequence

1. `ip -br link` (or `ip a`) → confirm the interface that actually carries service traffic. Branch: on a container host, also check veth/bridge interfaces; capturing only the management NIC is the classic wrong-interface mistake (src-d0gl0v3r-umcs2026-c85f0c19).
2. `df -h <CAPTURE_DIR>` → confirm free space ≥ `-C`×`-W` + slack; branch: under 1 GB free → lower `-C`/`-W` or move the directory to a scratch volume.
3. `tcpdump -i <IFACE> -nn -c 20 '<BPF_FILTER>'` → dry-run visibility check before writing files; branch: zero packets → the filter or interface is wrong even though the capture command "worked".
4. Start the bounded capture; after 30 s confirm `ls -l` growth, then join it to a tick label (file name plus a note in the team log).

If the capture shows the service on a port you did not expect, go to card-pcap-first-pass-triage. If it shows nothing at all while the service is clearly serving, go to card-wrong-dissector-encapsulation (interface/encapsulation check).

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ip -br link` | interface list with state | Which NIC actually carries traffic |
| `tcpdump -i <IFACE> -nn -c 20 '<BPF>'` | live frame count | Filter/interface sanity before committing disk |
| `tcpdump -D` | numbered device list | Valid `<IFACE>` values; `any` is a Linux-only pseudo-interface |
| `pgrep -a tcpdump` | other capture processes | A forgotten capture is already consuming disk |
| `tcpdump -r <FILE> -nn -c 5` | frame headers | The file is readable and contains real packets |
| `capinfos <FILE>` | duration, snaplen, encapsulation | Whether the capture is complete enough for byte-level work |

## State-changing actions (only if the card changes a host or service)

- **Impact:** a long-running process writes to local disk on the service host; if the disk fills, the service (and the checker's health probe) fails. Captured payloads contain other teams' exploit traffic and possibly live flags.
- **Preconditions:** proven team ownership of the host; rules permit capture; free space measured; interface and filter validated with a dry run.
- **Health check before:** `df -h <CAPTURE_DIR>` and `ss -ltnp` — record baseline disk and listeners.
- **Apply:** start `tcpdump` with `-C` (rotate at N MB per file), `-W` (keep N files), `-s0` (full payload), `-U` (write immediately so a crash still yields data), `-Z <UNPRIV_USER>` (drop privileges after opening the interface).
- **Health check after:** `ls -l <CAPTURE_DIR>` shows rotation; `tcpdump -r` reads the newest file; the legitimate service workflow (one real request from a teammate client) still succeeds **and** appears in the capture — that is the regression probe.
- **Rollback:** `pkill -INT -f 'tcpdump .*<SERVICE>'`, confirm with `pgrep -a tcpdump`, then delete or archive the files per event policy. Before rollback, check whether an incident investigation needs them; detection of an unsafe rollback is "no capture exists for the tick in question".

## Exploit → patch pair (web/service cards where applicable)

- **Flaw:** the capture command has no size bound, so a busy service fills the volume and the service dies.
- **Reproduce on the isolated fixture:** against `<LOCAL_FIXTURE>` (a 127.0.0.1 service you own, e.g. `http://127.0.0.1:<PORT>`), generate loopback traffic and run `tcpdump -i lo -s0 -w /tmp/fixture.pcap` with no `-C`/`-W` → the file grows without limit.
- **Narrow patch:** add `-C 128 -W 8` (and keep `-s0 -U`); nothing else about the capture changes.
- **Legitimate functionality that must keep working:** the fixture request still appears byte-for-byte in the newest rotated file and `tcpdump -r` reads it.
- **Verify:** `tcpdump -i lo -nn -C 128 -W 8 -w /tmp/fixture.pcap 'tcp port <PORT>'` → rotation occurs, older files are pruned, and the fixture request is still reconstructable. (Untested here: no `tcpdump` in this environment.)

## Failure modes and things teams stopped doing

- **Capturing on the wrong interface.** D0GL0V3R's UMCS 2026 first-time A/D writeup records monitoring the wrong interface and reasoning from a blind spot (src-d0gl0v3r-umcs2026-c85f0c19). Rule now: prove visibility with a 20-packet dry run on the interface you will actually write from.
- **Unbounded captures on the vulnbox.** The same retrospective records a defensive tool (a WAF) consuming all available RAM (src-d0gl0v3r-umcs2026-c85f0c19). Rule now: every monitoring process must have a hard resource bound.
- **Treating the capture file as throwaway.** Maple Bacon's A/D primer treats traffic as defensive evidence and the FAUST beginner material makes service behaviour the definition of healthy (src-maplebacon-ad-primer-23bd534f, src-faust-ad-beginners-779c0a5e). Our rule: the file name carries service + UTC timestamp, and the team log carries the tick.
- **Pipe-capturing to your laptop over a shared path.** Thomas Weigold's SaarCTF 2025 writeup pipes remote capture into local Wireshark over SSH (src-thomasweigold-saarctf2025-eaa12cba); useful, but it competes with your own control channel. Rule now: if the interface also carries your SSH session, filter it out or use the ring-buffer file and copy it back.

## Evidence status

- **Status:** source-supported but untested (no `tcpdump`/Wireshark binary in this environment; the repo's earlier research pass recorded the same gap).
- **What we actually ran:** nothing. `ss -ltnp`, `df -h`, `pgrep -a`/`pkill -a` syntax are standard Linux utilities but were not executed here either.
- **Our adaptation vs the source:** the remote-capture pipeline in S012 is presented there as a convenience; we turn the same idea into a bounded-file default with an explicit disk-impact and rollback section, because a first-time team's most likely own-goal is filling the service host.

## Sources

- `src-thomasweigold-saarctf2025-eaa12cba` — source-reported remote capture pipeline (`ssh … tcpdump … | wireshark -k -i -`) and its caveats.
- `src-d0gl0v3r-umcs2026-c85f0c19` — wrong-interface monitoring and resource-exhaustion failure stories.
- `src-maplebacon-ad-primer-23bd534f` — traffic analysis as a per-tick defensive activity.
- `src-faust-ad-beginners-779c0a5e` — availability matters; breaking your own service is a scoring problem.
