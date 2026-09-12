"""Container integration: the two shipped profiles end-to-end against fixtures.

This module is the only test that needs Docker. It brings the fixture up if it is
not already running, then drives the real CLI: discover -> plan -> apply -> verify
-> rollback, asserting that the exploit stops working, the legitimate workflow
keeps working, and rollback restores the vulnerable state.

If Docker (or the fixture directory) is unavailable, the module sets SKIP with a
reason instead of pretending to pass.
"""

from __future__ import annotations

import io
import json
import os
import time
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from typing import Dict, List, Optional, Tuple

from helpers import REPO_ROOT, check, check_eq, check_in, docker_available

from ctfctl import cli, util

P1 = os.path.join(REPO_ROOT, "fixtures", "p1-flask-compose")
P2 = os.path.join(REPO_ROOT, "fixtures", "p2-php-compose")
P1_PORT = 8080
P2_PORT = 8081

SKIP = False
SKIP_REASON = ""

if not os.path.isdir(P1):
    SKIP = True
    SKIP_REASON = "fixtures/p1-flask-compose is missing"
elif not docker_available():
    SKIP = True
    SKIP_REASON = ("docker is not available (daemon not running or CLI missing); the container "
                   "integration test needs it, the rest of the suite does not")

_fixture_state: Dict[str, bool] = {}


# --------------------------------------------------------------------------
def _run(cmd: List[str], timeout: float = 300.0) -> Tuple[int, str]:
    result = util.run(cmd, timeout=timeout, max_output=2 * 1024 * 1024)
    return result.returncode, (result.stdout + result.stderr)


def _http_code(url: str, timeout: float = 5.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:
        return 0


def _compose(directory: str) -> List[str]:
    return ["docker", "compose", "-f", os.path.join(directory, "compose.yaml")]


def _ensure_fixture(directory: str, port: int, health_path: str) -> None:
    if _fixture_state.get(directory):
        return
    if _http_code(f"http://127.0.0.1:{port}{health_path}") != 200:
        code, output = _run(_compose(directory) + ["up", "-d", "--build"], timeout=600)
        check_eq(code, 0, f"docker compose up failed for {directory}: {output[-600:]}")
    deadline = time.time() + 120
    while time.time() < deadline:
        if _http_code(f"http://127.0.0.1:{port}{health_path}") == 200:
            _fixture_state[directory] = True
            return
        time.sleep(3)
    code, output = _run(_compose(directory) + ["logs", "--tail", "30"])
    raise AssertionError(f"fixture at {directory} never became healthy:\n{output[-800:]}")


def run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _latest_committed_tx() -> Optional[str]:
    from ctfctl import apply as apply_mod

    for entry in apply_mod.list_transactions():
        if entry["phase"] == "COMMITTED":
            return str(entry["tx_id"])
    return None


def _exploit_reaches_canary(port: int, path: str) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
            body = response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", "replace")
    except Exception:
        return False
    return "FIXTURE_CANARY" in body


# --------------------------------------------------------------------------
def test_p1_discover_plan_apply_rollback() -> None:
    _ensure_fixture(P1, P1_PORT, "/healthz")
    exploit_path = "/files?name=../../canary.txt"

    check(_exploit_reaches_canary(P1_PORT, exploit_path),
          "the fixture must be vulnerable before the test starts (run reset.sh if not)")

    code, out, err = run_cli(["discover", "--save", "--json"])
    check_eq(code, 0, f"discover failed: {err}")

    code, out, err = run_cli(["plan", "--profile", "web-nginx-flask-compose", "--json"])
    check_eq(code, 0, f"plan failed: {err}\n{out[:400]}")
    payload = json.loads(out)
    match = [p for p in payload["plans"] if p["profile"] == "web-nginx-flask-compose"]
    check(match, "the flask profile should be detected on its own fixture")
    plan = match[0]
    actions = [a for a in plan["actions"] if not a["skipped_reason"]]
    check(actions, f"at least one action expected: {plan['skipped']}")
    patch = [a for a in actions if a["action_id"] == "file.python_flask_send_from_directory"]
    check(patch, "the narrow source patch should be planned")
    check(patch[0]["diff"], "the plan must show the exact diff")

    code, out, err = run_cli(["apply", "--yes", "--json"])
    check_eq(code, 0, f"apply failed: {err}\n{out[:600]}")
    applied = json.loads(out)
    check_eq(applied["phase"], "COMMITTED", f"apply should commit: {applied.get('errors')}")
    verification = {v["verifier"] + str(v.get("tier")): v for v in applied["verification"]}
    for result in applied["verification"]:
        if result.get("required"):
            check(result["ok"], f"verification failed: {result}")

    check(not _exploit_reaches_canary(P1_PORT, exploit_path),
          "the traversal exploit must stop working after the patch")
    check_eq(_http_code(f"http://127.0.0.1:{P1_PORT}/files?name=welcome.txt"), 200,
             "a legitimate download must keep working after the patch")

    tx_id = _latest_committed_tx()
    check(tx_id, "a committed transaction should be listed")
    code, out, err = run_cli(["rollback", str(tx_id), "--yes", "--json"])
    check_eq(code, 0, f"rollback failed: {err}\n{out[:400]}")
    check(_exploit_reaches_canary(P1_PORT, exploit_path),
          "rollback must restore the vulnerable state (and restart the service so it is live)")


def test_p2_discover_plan_apply_rollback() -> None:
    _ensure_fixture(P2, P2_PORT, "/api.php?action=healthz")
    exploit_path = "/download.php?file=../../canary.txt"
    check(_exploit_reaches_canary(P2_PORT, exploit_path),
          "the php fixture must be vulnerable before the test starts")

    run_cli(["discover", "--save", "--json"])
    code, out, err = run_cli(["plan", "--profile", "web-php-apache-compose", "--json"])
    check_eq(code, 0, f"plan failed: {err}")
    payload = json.loads(out)
    match = [p for p in payload["plans"] if p["profile"] == "web-php-apache-compose"]
    check(match, "the php profile should be detected on its own fixture")
    plan = match[0]
    actions = [a for a in plan["actions"] if not a["skipped_reason"]]
    patch = [a for a in actions if a["action_id"] == "file.php_canonicalize_path_use"]
    check(patch, f"the php guard patch should be planned: {plan['skipped']}")
    validation = {c["name"]: c for c in patch[0]["validation"]}
    check(validation.get("php-lint", {}).get("ok"),
          "php -l inside the container must validate the candidate before replacement")

    code, out, err = run_cli(["apply", "--yes", "--json"])
    check_eq(code, 0, f"apply failed: {err}\n{out[:600]}")
    applied = json.loads(out)
    check_eq(applied["phase"], "COMMITTED", f"apply should commit: {applied.get('errors')}")
    check(not _exploit_reaches_canary(P2_PORT, exploit_path),
          "the traversal must be blocked after the guard is inserted")
    check_eq(_http_code(f"http://127.0.0.1:{P2_PORT}/download.php?file=legacy.txt"), 200,
             "a file that predates the patch must still download")

    tx_id = _latest_committed_tx()
    code, out, err = run_cli(["rollback", str(tx_id), "--yes", "--json"])
    check_eq(code, 0, f"rollback failed: {err}")
    check(_exploit_reaches_canary(P2_PORT, exploit_path),
          "rollback must restore the vulnerable php file")


def test_fixture_containers_stay_inside_their_project() -> None:
    """Discovery must attribute ports to the project that publishes them."""
    _ensure_fixture(P1, P1_PORT, "/healthz")
    _ensure_fixture(P2, P2_PORT, "/api.php?action=healthz")
    run_cli(["discover", "--save", "--json"])
    inventory = util.load_json(os.path.join(util.state_dir(root=REPO_ROOT),
                                            "inventory-latest.json"), {})
    by_port = {}
    for service in inventory["graph"]["services"]:
        by_port.setdefault(service["port"], []).append(service)
    for port, project in ((P1_PORT, "p1-flask-compose"), (P2_PORT, "p2-php-compose")):
        check_in(port, by_port, f"port {port} should be discovered")
        container = by_port[port][0].get("container") or {}
        check_eq(container.get("compose_project"), project,
                 f"port {port} must be attributed to {project}")
