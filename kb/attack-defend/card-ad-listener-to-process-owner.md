# Map a listening port to the process, then to the source tree

**First useful action.** Start at the socket and walk outward — socket → PID → command line → working directory → executable → unit or container — instead of searching the filesystem for the service.

```bash
ss -ltnp | grep -E ':<PORT>\b' && \
for p in $(ss -ltnpH 'sport = :<PORT>' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
  printf 'PID=%s ' "$p"; tr '\0' ' ' < /proc/$p/cmdline; echo; \
  printf '  cwd=%s exe=%s\n' "$(readlink /proc/$p/cwd)" "$(readlink /proc/$p/exe)"; \
done
```

Expected: one or more PIDs with an interpreter or binary path and a working directory that contains the service source. If the loop prints nothing, `ss` could not resolve the owner — see the branch below rather than grepping the whole filesystem.

## Symptoms

- A checker or scan shows a port, but nobody knows which directory or unit serves it.
- Several services run on one host and it is unclear which of them is graded.
- A file edit appears to have no effect, suggesting you are patching a different copy than the one running.

## Prerequisites and assumptions

- Shell access to your own authorized instance; socket ownership display may require elevated privileges.
- Linux-first. On containers or namespaces the host view can differ from the in-container view.
- Assumption: process metadata is visible. This fails where the service runs in a container, under a different user, or inside a network namespace you cannot see into.

## Diagnostic sequence

1. `ss -ltnp` filtered to the port → branch A: PID and program name shown, so read `/proc/<PID>/cwd` and `/proc/<PID>/exe` and stop; branch B: no process column, so continue.
2. For branch B, check container/systemd ownership: `systemctl status <UNIT>` and `docker ps --no-trunc` (or the platform equivalent) → the mapping is usually in the unit file's `ExecStart` or the container's image/command.
3. Confirm by behaviour, not by path: hit the port with a known request and simultaneously watch the candidate process ("strace -f -p <PID>"-style tracing or the access log) → the process that reacts is the owner, regardless of what the file tree suggests.
4. Compare `readlink /proc/<PID>/root` with your own root → if it differs, you are looking at a container that mounts a different filesystem; edit through the container's own mount, not the host copy.

If you find the owner and its source directory, continue to `card-ad-baseline-snapshot-before-edit`. If you cannot see any owner, treat the platform as a container/namespace problem and ask the organizer how the instance is run before making changes.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `ss -ltnp` | `LISTEN 0 128 0.0.0.0:8080 users:(("python3",pid=431,...))` | the port is owned by that program; without privilege the `users:` column may be absent |
| `tr '\0' ' ' < /proc/<PID>/cmdline` | full argv on one line | reveals the interpreter, config flag, and entrypoint script |
| `readlink /proc/<PID>/cwd` / `exe` | absolute paths | the running copy's directory; often *not* the directory you edited |
| `readlink /proc/<PID>/root` | a filesystem root or `/` | a different root means a container: host edits may be invisible to the process |

## Failure modes and things teams stopped doing

- Teams stopped grepping the whole filesystem for a service name. The socket-to-process walk answers the same question in seconds and also reveals which *copy* of the code is live, which a filesystem-wide search cannot. [src-iproute2-ss-manpage-fc58f455]
- Teams stopped assuming that seeing a port means seeing the traffic. A first-time retrospective describes monitoring the host's VPN interface while the graded services ran inside Docker, so the capture missed what mattered; the same confusion between host and container view produces wrong port-to-process answers. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped assuming the host view is complete. A service repository documents that a full-VM run and a container run can differ because a host-side dependency does not start in the container — evidence that "which process is really serving this port" is not always answerable from one view. [src-saarctf-2024-readme-6dacbfcc]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. `ss -ltnp` is documented syntax from the iproute2 manual, but no process-to-port mapping was performed in this session.
- **Our adaptation vs the source:** the chain order (socket first, filesystem last) is ours and is deliberately the inverse of the naive approach. Container/namespace fallbacks are flagged as operator practice rather than quoted from the sources.

## Sources

- `src-iproute2-ss-manpage-fc58f455` — authoritative description of `ss` socket/process reporting and its limitations.
- `src-faust-gameserver-readme-4e7460fe` — how a gameserver's services relate to checkers and ports.
- `src-d0gl0v3r-umcs2026-c85f0c19` — wrong-layer monitoring as a concrete failure.
- `src-saarctf-2024-readme-6dacbfcc` — container-versus-full-VM behavioural difference.
