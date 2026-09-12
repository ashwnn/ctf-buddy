# Baseline the service: file list, listeners, process tree, then a code-only snapshot

**First useful action.** Capture the cheapest possible baseline — file inventory, listeners, process tree — and put *code and configuration only* under version control before anyone edits anything.

```bash
mkdir -p <WORKDIR>/baseline/<SERVICE> && cd <SERVICE_DIR> && \
  find . -type f -printf '%P\n' | sort > <WORKDIR>/baseline/<SERVICE>/files.txt && \
  ss -ltnp > <WORKDIR>/baseline/<SERVICE>/listen.txt 2>&1 && \
  ps -eo pid,ppid,user,etimes,args --forest > <WORKDIR>/baseline/<SERVICE>/ps.txt && \
  git init -q 2>/dev/null; git add -A && \
  git -c user.name=team -c user.email=team@<LOCAL_FIXTURE> commit -qm 'baseline before edits' && \
  git log --oneline -n 1
```

Expected: a commit hash printed and three baseline files on disk. If `git status` immediately lists unrelated churn (databases, uploads, caches), do not commit again — go to `card-ad-untrack-mutable-state` first and untrack those paths.

## Symptoms

- You receive a VM, container, source tree, or binary and nobody knows what changed since it was handed over.
- Two teammates have already edited files and neither can say what the original looked like.
- The service behaves differently now and no backup exists to compare against.

## Prerequisites and assumptions

- Read access to the service directory and enough disk for a code-only snapshot.
- Linux-first command shapes: `find -printf` and `ss -ltnp` are GNU/iproute2 specifics. On other platforms substitute your own inventory tool and say so.
- Assumption: you know which paths hold *mutable* state (databases, uploads, generated keys, caches, flag stores) — if you do not, that is the first thing to establish, not the last.

## Diagnostic sequence

1. Save the file list, listener list, and process tree → these are your "before" pictures; diff them after every change instead of arguing from memory.
2. Hash the files that matter for correctness (entrypoints, configs, route definitions) → `sha256sum $(cat <WORKDIR>/baseline/<SERVICE>/files.txt | sed 's|^|./|') > <WORKDIR>/baseline/<SERVICE>/hashes.txt` gives you a cheap tamper/corruption check later.
3. Identify mutable state by watching the file list change during normal traffic → branch A: state lives in identifiable paths, so untrack them; branch B: state is interleaved with code, so snapshot the whole tree as a tarball instead of trusting Git alone.

If branch A, continue to `card-ad-untrack-mutable-state`. If branch B, take a tarball and record that Git cannot be your rollback mechanism for this service.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `find . -type f -printf '%P\n' \| sort` | relative path list | the definitive "what exists" record; diff it after every deployment |
| `ss -ltnp` | listening sockets with owning processes | what is actually reachable; compare before/after every change |
| `ps -eo pid,ppid,user,etimes,args --forest` | process tree with elapsed seconds | distinguishes a long-lived service from a supervisor that restarts it constantly |
| `git log --oneline -n 1` | one commit hash | your rollback target; if this is empty you have no baseline |

## State-changing actions

- **Impact:** creates a Git repository and snapshot files inside or beside the service tree, and writes inventory files. Nothing in the service itself is modified, but a repository placed *inside* a served directory can become web-accessible.
- **Preconditions:** confirmed write permission; knowledge of which directory is web-served.
- **Health check before:** the saved legitimate smoke test — expect its baseline response.
- **Apply:** initialise the repository in `<SERVICE_DIR>` and commit code/config only; never commit secrets, live flags, or state databases.
- **Health check after:** legitimate smoke test unchanged, and `<HEALTH_URL>/.git/config` must **not** be retrievable — a served repository is a data leak. Regression probe: fetch one normally-public asset to confirm static serving still works.
- **Rollback:** `rm -rf <SERVICE_DIR>/.git` (or move the repository outside the served tree) and re-verify the smoke test. It is now unsafe to keep the repository there if any HTTP path under the service root can reach `.git/`.

## Failure modes and things teams stopped doing

- Teams stopped editing services by hand over SSH. A documented team workflow describes manual edits as painful and replaced them with a version-controlled deploy path so that every change has history and a rollback point. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped committing everything they could see. Mutable state belongs to the running service, not to the patch history; the same workflow treats deployment data separately from code for exactly this reason. [src-maplebacon-faustctf-patcher-bf21013c]
- Teams stopped assuming every service is a familiar stack. Public attack/defense service repositories span Rust, Go, C++, Python, Node, Java, and shell, so the inventory step must be generic rather than tuned to one runtime. [src-c4tbuts4d-stayhomectf2022-61868263]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No repository was created and no inventory command was executed in this session. `ss -ltnp` syntax is documented; the pipeline around it is our construction.
- **Our adaptation vs the source:** Maple Bacon's workflow motivates version-controlled deployment; the specific baseline triple (file list, listeners, process tree) is our addition for a first-time team that needs a rollback point before it needs a deploy pipeline. Running a Git account with elevated privileges, as the original workflow does, is deliberately **not** copied here.

## Sources

- `src-maplebacon-faustctf-patcher-bf21013c` — team retrospective on patch infrastructure, history, and rollback.
- `src-c4tbuts4d-stayhomectf2022-61868263` — breadth evidence for multi-language A/D services.
- `src-iproute2-ss-manpage-fc58f455` — meaning and limits of socket/process listing with `ss`.
- `src-faust-ad-beginners-779c0a5e` — organizer framing that intended service behaviour is what gets graded.
