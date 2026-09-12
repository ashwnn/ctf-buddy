# Stream a remote capture only as a bounded, eyes-on session

**First useful action.** Prefer a bounded file capture on the remote host and copy it back; use the live SSH-to-Wireshark pipe only for a short interactive hypothesis test with a filter that excludes your own SSH channel.

```bash
ssh <USER>@<TEAM_VM_IP> 'timeout 60 tcpdump -n -i <IFACE> -U -s0 -w - "not port 22" ' | wireshark -k -i -
```

Expected: local Wireshark shows live frames from the remote interface for at most 60 seconds. If the window stays empty, either no matching traffic occurred, the interface is wrong, or the local Wireshark cannot read from stdin in this build — the timeout ends the experiment either way.

## Symptoms

- You need to see traffic *while* you trigger an action on the service (does my request reach the app? does the checker pattern differ?).
- Writing captures on the service host is undesirable (disk pressure) or forbidden by event rules.
- A teammate wants a live view but the remote box has no GUI.

## Prerequisites and assumptions

- Team-owned host, SSH access, `tcpdump` installed and permitted to capture, and organizer rules that allow capture on that path.
- Local Wireshark that can read a pcap stream from stdin (`-k -i -`), and enough bandwidth that the pipe does not disturb the service.
- Stack/version: `tcpdump` 4.9+, Wireshark 3.6+; behaviour of `timeout` differs slightly between GNU coreutils and busybox.

## Diagnostic sequence

1. Confirm the interface remotely: `ssh <USER>@<TEAM_VM_IP> 'ip -br link'` → branch: several interfaces → capture the one carrying service traffic, not `any`, unless you confirmed `any` shows the service.
2. Run a bounded version first (`timeout 60`) with `not port 22` → branch: frames appear → use it interactively; still empty → the flow may be container-local or on another host (the UMCS wrong-interface failure mode).
3. Record what you saw in the team log with a UTC window; a live-only view leaves no artifact, so nothing may be claimed later without a file.
4. For anything you may need to justify later, immediately switch to the file-based path (card-capture-hygiene) and copy the capture back with a hash.

If the live view shows traffic your local Wireshark cannot dissect, go to card-unknown-protocol-triage. If it shows nothing while your own test request clearly succeeds, the pipeline is wrong — verify the remote interface and that the request took the path you think.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ssh <U>@<H> 'ip -br link'` | interface list | Remote interfaces available for `-i` |
| `ssh <U>@<H> 'timeout 60 tcpdump -n -i <IFACE> -U -s0 -w - "not port 22"'` | binary pcap on stdout | Bounded live feed without remote disk use |
| `... \| wireshark -k -i -` | local capture window | Interactive inspection of that feed |
| `ssh <U>@<H> 'tcpdump -D'` | device list | Valid interface identifiers on that host |
| `ssh <U>@<H> 'pgrep -a tcpdump'` | process list | A previous live capture is still running |

## State-changing actions (only if the card changes a host or service)

- **Impact:** spawns a privileged capture process on the service host and moves its traffic over your SSH connection; a forgotten run keeps consuming CPU, disk, or bandwidth. Live traffic includes live flags and other teams' exploits.
- **Preconditions:** proven team ownership; rules allow capture; interface identified; `not port 22` filter understood (it also hides traffic you may want, e.g. tunnelled service ports).
- **Health check before:** `ssh <U>@<H> 'timeout 5 tcpdump -n -i <IFACE> -c 3'` returns a few frames and the service responds to a normal request.
- **Apply:** run the bounded pipeline (with `timeout`), keeping the capture filter as narrow as the question allows.
- **Health check after:** the service still answers a normal request and the SSH session stays responsive; regression probe: run the legitimate service workflow (checker-like request) and confirm it appears in the live view.
- **Rollback:** nothing to undo locally — the pipe ends with the client; remotely confirm `pgrep -a tcpdump` is empty. Rollback is unsafe to skip on a host whose disk or CPU budget you do not know.

## Exploit → patch pair (web/service cards where applicable)

Not applicable as a security patch; the safety-relevant comparison is an operational one. **Mistake:** an unbounded piped capture on a shared interface. **Reproduce on the isolated fixture:** against `<LOCAL_FIXTURE>` (127.0.0.1 service), run the pipeline with no `timeout` and no `not port 22`-style exclusion while generating traffic → the pipe grows without bound and the SSH channel is captured into itself. **Narrow fix:** add `timeout <SECONDS>` and exclude the control channel. **Legitimate functionality that must keep working:** the fixture request is still visible live. **Verify:** the same request appears while the process exits by itself.

## Failure modes and things teams stopped doing

- **Running a live capture with no end time.** Thomas Weigold's SaarCTF 2025 writeup shows the pipeline as a convenience for hands-on analysis (S012); the same technique without a bound is how teams fill a disk or capture themselves. Rule now: every remote pipeline gets a `timeout` and a filter.
- **Capturing over the channel you are watching through.** Without excluding the SSH port, the capture includes its own transport, which grows traffic and can look like an attack. Rule now: exclude the control channel or use the file path.
- **Believing the live view is the whole story.** A first-time A/D team documented monitoring the wrong interface and reasoning from a blind spot (D0GL0V3R, UMCS 2026, TR3). Rule now: prove one known request appears before trusting an empty or partial view.
- **Treating a live view as evidence.** Live-only inspection leaves no artifact; FAUST's beginner material and the A/D primers both push teams toward reproducible records rather than one-off glances (AD1, S005). Rule now: convert anything worth remembering into a capture file immediately.

## Evidence status

- **Status:** source-reported, untested locally (no `tcpdump` or Wireshark in this environment; the repo's earlier research pass also found both absent).
- **What we actually ran:** nothing.
- **Our adaptation vs the source:** S012 presents the ssh-pipe as a way to get a live Wireshark view; we demote it to a bounded, interactive-only tool with a mandatory timeout and an explicit rollback check, and make the file-based capture the default for anything evidential.

## Sources

- `src-thomasweigold-saarctf2025-eaa12cba` — source-reported `ssh … tcpdump … | wireshark -k -i -` pipeline and its unfiltered variant.
- `src-d0gl0v3r-umcs2026-c85f0c19` — wrong-interface monitoring failure story.
- `src-maplebacon-ad-primer-23bd534f` — traffic observation as a defensive habit.
- `src-faust-ad-beginners-779c0a5e` — availability first; defensive tools must not break the service.
