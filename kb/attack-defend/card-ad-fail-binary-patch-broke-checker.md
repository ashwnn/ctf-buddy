# Failure story: patched a binary and broke the behaviour the checker graded

**First useful action.** Before touching a binary service, save a copy of the original and record the exact legitimate request/response pair that must survive the patch.

```bash
cp -a <SERVICE_BINARY> <WORKDIR>/bin/<SERVICE_BINARY>.orig && \
  sha256sum <SERVICE_BINARY> <WORKDIR>/bin/<SERVICE_BINARY>.orig && \
  curl -sS -o <WORKDIR>/bin/health.before -D <WORKDIR>/bin/health.before.headers '<HEALTH_URL>' && \
  head -c 200 <WORKDIR>/bin/health.before
```

Expected: hashes match and the legitimate response is captured. If you cannot state the legitimate response before patching, you have no way to tell a fixed service from a broken one.

## Symptoms

- The service is provided as a binary and the team has to patch it by bytes rather than by editing source.
- The exploit no longer works against your service but the checker or scoreboard says the service is failing.
- A patch "improved" the binary in more ways than intended, or a jump/nop change altered unrelated logic.

## Prerequisites and assumptions

- A way to patch the binary (hex edit, disassembler with patching support, or a wrapper) and confidence in the exact offset.
- A local copy to patch, never the live file in place.
- Assumption: with binary services the checker is the only authority on correctness; there is no source to reason from.

## Diagnostic sequence

1. Capture the legitimate behaviour and the exploit's behaviour against the unpatched binary → both are needed; without the legitimate baseline, every regression is invisible.
2. Identify the exact instruction or check that implements the vulnerable decision → branch A: you can describe the condition in one sentence, so patch it; branch B: you cannot, so keep analysing (go to the reverse-engineering path for this binary).
3. Patch a *copy*, run it on a different local port, and exercise both flows against the copy → branch A: exploit fails, legitimate flow passes; branch B: either both fail (patch too broad) or both pass (wrong location).
4. Only then replace the live binary, keeping the original on disk and the rollback as a file copy rather than a rebuild.

If the patched copy passes but the deployed service fails, check that the running process is actually the patched file (`card-ad-listener-to-process-owner`) before concluding the patch is wrong.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `sha256sum <SERVICE_BINARY>` before/after | two hashes | proves which binary is live; a mismatch after deployment means the copy never took effect |
| the legitimate request against the copy | baseline body/status | the invariant you must not break |
| the exploit against the copy | failure | the primitive is closed for the tested path |
| `/proc/<PID>/exe` | path to the running image | confirms the process was replaced, not merely the file on disk |

## State-changing actions

- **Impact:** replacing a service binary is the highest-blast-radius change available: a wrong offset can corrupt unrelated behaviour, and there is no source diff to review.
- **Preconditions:** original binary preserved with a recorded hash, legitimate and exploit baselines captured, patch rehearsed on a local copy on a separate port.
- **Health check before:** legitimate request against the live service, saved with headers.
- **Apply:** stop the service, replace the binary with the rehearsed copy, start it, and keep the original at a known path.
- **Health check after:** legitimate request matches the saved baseline; the exploit fails. Regression probe: the checker's full cycle, plus any secondary feature the patched instruction also served.
- **Rollback:** copy the preserved original back over the binary and restart; verify the hash matches the original. Rollback is unsafe if the patch also changed data format or state written by the patched code path.

## Failure modes and things teams stopped doing

- Teams stopped assuming a working patch is a sufficient patch. Team material from a mature event describes a binary patch that had to preserve service behaviour because checkers exercise functionality; a patch that stops the exploit and breaks a feature is a net loss on the availability side. [src-ntt-enowars8-writeup-8b4ecb49]
- Teams stopped treating binary services as web services. Finals retrospectives describe services and access conditions that do not resemble an HTTP app; the shared discipline is that the grader's view of correctness is the constraint, not developer intuition. [src-dttw-defcon2021-retro-14eb5491] [src-dttw-defcon2018-retro-83e7e6ea]
- Teams stopped shipping a patch they had not rehearsed off the live file. The patch-infrastructure lesson — that changes should be versioned and reversible — applies with more force to binaries, where a mistake is not visible in a diff. [src-maplebacon-faustctf-patcher-bf21013c]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No binary was copied, patched, or replaced in this session.
- **Our adaptation vs the source:** the rehearsal-on-a-copy procedure is ours. That binary patches must preserve graded behaviour is stated by the cited team material; the finals retrospectives are cited for the breadth of service shapes a team may meet.

## Sources

- `src-ntt-enowars8-writeup-8b4ecb49` — binary patch that had to preserve behaviour the checker exercises.
- `src-dttw-defcon2021-retro-14eb5491` — finals retrospective on binary-heavy services and workflow.
- `src-dttw-defcon2018-retro-83e7e6ea` — earlier finals retrospective on patching and service reasoning.
- `src-maplebacon-faustctf-patcher-bf21013c` — versioned, reversible change as the general rule.
