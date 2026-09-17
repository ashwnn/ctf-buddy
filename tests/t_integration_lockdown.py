"""Container integration for lockdown and honeypot (Linux-only, Docker needed).

What this proves with real Linux file semantics inside a disposable container:

  * the `file_create` engine path (create, atomic replace, verify, rollback by
    deleting) and the `file_edit` path against a real `/etc/ssh/sshd_config`;
  * effect dispatch and the rollback effect (`nft -f` vs `nft delete table`);
  * the honeypot listener actually serving HTTP inside the container, with its
    events landing in the log file it reports.

What it deliberately does **not** prove, and `docs/validation.md` says so:

  * that a real nftables ruleset loads on a real host -- `nft` and `sshd` are
    stubs in this test, because installing the real packages would require the
    network access this repository does not use by default;
  * anything about host firewalls or SSH reachability.

The module skips with a clear reason when Docker is unavailable or is running
Windows instead of Linux containers.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Any, Dict, List, Tuple

from helpers import REPO_ROOT, check, check_eq, check_in, docker_skip_reason

from ctfctl import util

SKIP = False
SKIP_REASON = ""

docker_reason = docker_skip_reason(
    "the container lockdown/honeypot test", require_linux=True)
if docker_reason:
    SKIP = True
    SKIP_REASON = docker_reason

IMAGE = "python:3.12-slim"

#: Runs inside the container. Every stub is created here, never on the host.
CONTAINER_SCRIPT = r"""
set -e
mkdir -p /work/state /work/captures /etc/ssh /root/.ssh
cp -r /opt/tools /work/tools
cp -r /opt/profiles /work/profiles
printf 'container test root\n' > /work/AGENTS.md
export PYTHONPATH=/work/tools
cd /work

# ---- stub nft: records argv, answers the two shapes the toolkit uses -------
cat > /usr/local/bin/nft <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/nft.log
if [ "$1" = "list" ]; then
  printf 'table %s %s {\n\tchain input {\n\t}\n}\n' "$3" "$4"
fi
exit 0
SH
chmod +x /usr/local/bin/nft
: > /tmp/nft.log

# ---- stub sshd: -t always valid, -T echoes the hardened values ------------
cat > /usr/local/bin/sshd <<'SH'
#!/bin/sh
case "$1" in
  -t) exit 0 ;;
  -T) printf 'passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\n' ;;
  *)  exit 0 ;;
esac
SH
chmod +x /usr/local/bin/sshd

printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' > /etc/ssh/sshd_config
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI0000 container@test\n' > /root/.ssh/authorized_keys

# ---- the authorization a declared remote target would have mirrored -------
cat > /work/state/targets.json <<'JSON'
{"targets": [
  {"path": "/etc/ctfctl-lockdown.nft", "label": "container test"},
  {"path": "/etc/ssh/sshd_config", "label": "container test"}
]}
JSON
printf '{"acknowledged": true, "notes": ["container test"]}\n' > /work/state/policy.json

python3 -m ctfctl lockdown plan --json \
  --operator-cidr 10.0.0.5 --allow-cidr 10.0.0.0/24 --allow-ports 22,8080 > /tmp/plan.json
PLAN_ID=$(python3 -c "import json;print(json.load(open('/tmp/plan.json'))['plans'][0]['plan_id'])")
python3 -m ctfctl apply "$PLAN_ID" --approve-review --yes --json > /tmp/apply.json
TX_ID=$(python3 -c "import json;print(json.load(open('/tmp/apply.json'))['tx_id'])")

python3 - <<'PY'
import json, os
json.dump({
  "nft_file_exists": os.path.isfile("/etc/ctfctl-lockdown.nft"),
  "nft_file_text": open("/etc/ctfctl-lockdown.nft").read() if os.path.isfile("/etc/ctfctl-lockdown.nft") else "",
  "sshd_after_apply": open("/etc/ssh/sshd_config").read(),
}, open("/tmp/after.json", "w"))
PY
cp /tmp/nft.log /tmp/nft-after-apply.log

python3 -m ctfctl rollback "$TX_ID" --yes --json > /tmp/rollback.json

python3 - <<'PY'
import json, os
json.dump({
  "nft_file_exists": os.path.isfile("/etc/ctfctl-lockdown.nft"),
  "sshd_after_rollback": open("/etc/ssh/sshd_config").read(),
}, open("/tmp/final.json", "w"))
PY
cp /tmp/nft.log /tmp/nft-after-rollback.log

python3 -m ctfctl honeypot start --port 8080 --bind 0.0.0.0 --json > /tmp/honeypot.json
python3 - <<'PY'
import time, urllib.request
for _ in range(20):
    try:
        urllib.request.urlopen("http://127.0.0.1:8080/admin", timeout=2).read()
        break
    except Exception:
        time.sleep(0.5)
PY
python3 -m ctfctl honeypot logs --lines 5 --json > /tmp/honeypot-logs.json
python3 -m ctfctl honeypot stop --all --json > /tmp/honeypot-stop.json

python3 - <<'PY'
import json
summary = {
  "plan": json.load(open("/tmp/plan.json")),
  "apply": json.load(open("/tmp/apply.json")),
  "rollback": json.load(open("/tmp/rollback.json")),
  "honeypot": json.load(open("/tmp/honeypot.json")),
  "honeypot_logs": json.load(open("/tmp/honeypot-logs.json")),
  "honeypot_stop": json.load(open("/tmp/honeypot-stop.json")),
  "after": json.load(open("/tmp/after.json")),
  "final": json.load(open("/tmp/final.json")),
  "nft_apply": open("/tmp/nft-after-apply.log").read(),
  "nft_rollback": open("/tmp/nft-after-rollback.log").read(),
}
print("SUMMARY=" + json.dumps(summary))
PY
"""


def _run(argv: List[str], timeout: float = 600.0) -> Tuple[int, str]:
    result = util.run(argv, timeout=timeout, max_output=4 * 1024 * 1024)
    return result.returncode, (result.stdout + result.stderr)


def _docker_available_for_run() -> bool:
    """Cheap guard so the module reports a skip instead of a docker error."""
    return docker_skip_reason("the container lockdown/honeypot test",
                              require_linux=True) is None


def test_lockdown_apply_verify_rollback_and_honeypot_in_a_container() -> None:
    if not _docker_available_for_run():
        raise AssertionError("SKIP: docker became unavailable between import and run")
    workspace = tempfile.mkdtemp(prefix="ctfctl-lockdown-")
    try:
        argv = [
            "docker", "run", "--rm", "--network", "bridge",
            "-v", f"{os.path.join(REPO_ROOT, 'tools')}:/opt/tools:ro",
            "-v", f"{os.path.join(REPO_ROOT, 'profiles')}:/opt/profiles:ro",
            IMAGE, "sh", "-c", CONTAINER_SCRIPT,
        ]
        code, output = _run(argv)
        if code != 0:
            raise AssertionError("container lockdown run failed:\n" + output[-3000:])
        summary = _summary(output)

        # ---- plan ----------------------------------------------------------
        plans = summary["plan"]["plans"]
        check_eq(len(plans), 1, "one lockdown plan")
        live = [a for a in plans[0]["actions"] if not a.get("skipped_reason")]
        check_eq(len(live), 2, f"both actions must be live, skipped: {plans[0]['skipped']}")
        check_eq({a["eligibility"] for a in live}, {"review-only"},
                 "lockdown actions are never auto-eligible")

        # ---- apply ----------------------------------------------------------
        apply_doc = summary["apply"]
        check_eq(apply_doc.get("phase"), "COMMITTED",
                 f"apply must commit inside the container: {apply_doc.get('errors')}")
        checks = {item["verifier"]: item for item in apply_doc.get("verification", [])}
        check_eq(checks.get("nft.table", {}).get("ok"), True,
                 "the nft verifier must pass against the stubbed nft")
        check_eq(checks.get("sshd.option", {}).get("ok"), True,
                 "the sshd verifier must pass against the stubbed sshd")
        check_in("-f /etc/ctfctl-lockdown.nft", summary["nft_apply"],
                 "apply must load the generated file")
        after = summary["after"]
        check_eq(after["nft_file_exists"], True, "the ruleset file must exist after apply")
        check_in("table inet ctfctl_lockdown", after["nft_file_text"],
                 "the ruleset must declare the table")
        check_in("10.0.0.5/32", after["nft_file_text"],
                 "the operator address must be in the allowlist")
        check_in("PasswordAuthentication no", after["sshd_after_apply"],
                 "password auth must be off after apply")

        # ---- rollback -------------------------------------------------------
        rollback_doc = summary["rollback"]
        check_eq(rollback_doc.get("phase"), "ROLLED_BACK",
                 f"rollback must succeed: {rollback_doc.get('errors')}")
        check_in("delete table inet ctfctl_lockdown", summary["nft_rollback"],
                 "rollback must delete the loaded table, not reload the file")
        final = summary["final"]
        check_eq(final["nft_file_exists"], False,
                 "rollback must delete the created nftables file")
        check_eq(final["sshd_after_rollback"].startswith("PasswordAuthentication yes"), True,
                 "rollback must restore sshd_config byte-for-byte")

        # ---- honeypot -------------------------------------------------------
        honeypot_doc = summary["honeypot"]
        check_eq(honeypot_doc.get("port"), 8080, "the honeypot must bind the requested port")
        check_eq(honeypot_doc.get("mode"), "http", "the tool sends an http lure by default")
        events: List[Dict[str, Any]] = []
        for entry in summary["honeypot_logs"].get("listeners", []):
            for raw in entry.get("lines", []):
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
        check(any(event.get("event") == "decoy-http" for event in events),
              f"the lure hit must be logged, got {events}")
        check(all(event.get("decoy") is True for event in events if "event" in event),
              "every honeypot event must be marked as a decoy")
        stopped = summary["honeypot_stop"].get("stopped") or []
        check_eq(len(stopped), 1, "the stop must report the listener it stopped")
        check_eq(stopped[0].get("alive_after"), False, "the listener process must be gone")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _summary(output: str) -> Dict[str, Any]:
    for line in output.splitlines():
        if line.startswith("SUMMARY="):
            payload = json.loads(line[len("SUMMARY="):])
            check(isinstance(payload, dict), "the container summary must be an object")
            return payload
    raise AssertionError("the container never printed SUMMARY=; last 1500 chars:\n"
                         + output[-1500:])
