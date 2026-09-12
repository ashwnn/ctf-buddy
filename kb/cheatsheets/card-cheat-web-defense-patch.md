# Web defence: patch, deploy, verify, roll back

**First useful action.** Before editing anything, save the exact end-to-end workflow the checker
uses (login, create, list, download) as a script and run it once. A patch you cannot regression-test
is a coin flip on your own flag.

```bash
# one script, run before and after every change; on a fixture or your own VM
BASE='http://127.0.0.1:<PORT>'
curl -sS -c /tmp/cj -X POST "$BASE/login" -d 'user=<USER>&pass=<PASS>' -o /dev/null
curl -sS -b /tmp/cj "$BASE/item" -o /tmp/before.json && wc -c /tmp/before.json
```

Expected: the happy path works and its output is saved. After the patch, the *same* script must still
succeed; the exploit probe must fail. Two checks, no exceptions.

## Symptoms

- The checker is failing for your team and you have a candidate vuln in hand.
- You have five minutes between ticks and the patch is three lines.
- Someone applied a patch and the service stopped answering.

## Prerequisites and assumptions

- A saved legitimate workflow (above) and a saved exploit reproducer.
- Editor + shell access to the service tree, and a way to restart/reload the service.
- Stack/version: the commands below are examples for Flask/PHP behind nginx; the *order* is the point.

## Diagnostic sequence

1. Reproduce the flaw with the smallest request that still works → save it as `exploit.sh`.
2. Locate the source file that owns the route (`card-web-010-route-to-source-owner`), not the file
   that merely looks guilty.
3. Write the *narrowest* containment check at the sink: `send_from_directory` for Flask,
   `realpath()` prefix check for PHP file reads (`card-web-003-traversal-source-recovery`).
4. Restart only the component whose code changed (`docker compose restart <service>` or
   `systemctl restart <unit>`), never the whole stack "to be safe".
5. Run the legitimate workflow, then run `exploit.sh` and require failure. Record both outputs in the
   team log with a timestamp.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `docker compose restart <svc>` | `Container ... Restarted` (`-d` for background) | the code change is live, other services untouched |
| `nginx -t && nginx -s reload` | `syntax is ok` / `test is successful` | syntax-check before reloading the proxy |
| `apachectl configtest && apachectl graceful` | `Syntax OK` | same for Apache |
| `systemctl restart <unit>` | exit 0 | the unit restarted; then re-check the port answers |
| `curl -s -o /dev/null -w '%{http_code}\n' $BASE/` | `200`, `302`, `502` | `502` after a restart means the backend is not up yet |
| `rg -n 'send_file|file_get_contents|open\(' <APP_ROOT>` | sink list | every read that takes user input is a candidate |

```bash
# the two-check gate, in one line each
curl -sS -b /tmp/cj "$BASE/item" | head -c 200        # legitimate flow must still work
curl -sS "$BASE/download?file=../../../etc/passwd" | head -c 40   # exploit must NOT return file bytes
```

## State-changing actions (only if the card changes a host or service)

- **Impact:** one file in one service; one restart of that service only. A restart costs availability
  seconds, so batch edits before restarting, not after.
- **Preconditions:** legitimate workflow saved and passing; exploit reproducer saved and failing;
  a rollback copy of the file exists (`cp -a file file.bak-$(date +%s)`).
- **Health check before:** `curl` the happy path → expected 200/expected JSON.
- **Apply:** the narrow containment check at the sink.
- **Health check after:** happy path still passes **and** exploit fails; check the service log for new
  errors (`docker compose logs --tail 50 <svc>`).
- **Rollback:** restore the `.bak` file and restart the same unit; re-run the happy path. If the
  service is already down, restore first and diagnose second — points are lost while it is down.

## Exploit → patch pair (web/service cards where applicable)

- **Flaw:** user input reaches a file/read or query sink without a containment check.
- **Reproduce on the isolated fixture:** `python tools/ctfctl.py apply --plan latest --yes` against
  `fixtures/p1-flask-compose` (or p2), which is exactly the exploit-before/patch-after pair used in
  the shipped drills.
- **Narrow patch:** guard the sink only; do not touch authentication, logging, or route definitions.
- **Legitimate functionality that must keep working:** `/item` create + list, and the download route
  with a legal filename.
- **Verify:** `ctfctl verify <plan-id>` — the shipped profiles ship an exploit probe that must stop
  working while the workflow check stays green.

## Failure modes and things teams stopped doing

- Patching before understanding, then rolling back at the next tick: `card-ad-fail-patched-before-understanding`.
- Editing a service someone else owns: `card-ad-fail-edited-someone-elses-service`.
- Restoring a live state from a backup taken mid-tick and destroying the flags other teams planted
  (`card-ad-fail-restore-destroyed-live-state`).
- WAF-shaped "fixes" that exhaust RAM and take the service down faster than the attacker
  (`card-ad-fail-waf-ram-exhaustion`).

## Evidence status

- **Status:** reproduced locally against the two shipped fixtures (Flask/nginx and PHP/Apache).
- **What we actually ran:** `python tests/run_tests.py t_engine` and the Docker integration module:
  discover → plan → apply → exploit stops working → legitimate workflow passes → rollback restores
  the vulnerable state.
- **Our adaptation vs the source:** the two-check gate is our own term; the sources describe the same
  practice as "make a test for the service first".

## Sources

- `src-faust-todo-patches-r06-abf8d3d1` — the patch set for a real A/D service, used as the model for
  narrow patches.
- `src-maplebacon-faustctf-patcher-bf21013c` — patching infrastructure and workflow.
- `src-faust-ad-beginners-779c0a5e`, `src-d0gl0v3r-umcs2026-c85f0c19` — availability first, then patch.
- `src-flask-send-from-directory-24ec5c2a`, `src-php-realpath-3742a88e` — the two containment primitives.
- `src-nginx-switches-o19-a2887699`, `src-apachectl-o20-98508984` — reload after a config change.
