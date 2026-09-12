"""Remote honeypot, lockdown and the one-command auto pipeline (no sockets).

The ssh transport is the same FakeSSH used by t_remote, so every command shape,
gate and report is exercised offline.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from helpers import Failure, check, check_eq, check_in

import t_remote
from t_remote import PROBE_TEXT, fake_ssh, remote_repo

from ctfctl import cli, remote, util


def _honeypot_status(*, port: int = 8080, log_rel: str = "captures/honeypot-8080-20260912T000000Z.jsonl",
                     extra: List[Dict[str, Any]] = None) -> str:
    listeners = [{
        "pid": 4242, "port": port, "bind": "0.0.0.0", "mode": "http", "banner": "",
        "marker": "honeypot-test", "log_path": log_rel,
        "started_at": "2026-09-12T00:00:00Z", "state": "running",
    }]
    return json.dumps({"root": "/home/x/.ctfctl", "running": listeners, "stopped": extra or [],
                       "max_listeners": 4, "marker": "decoy events carry decoy=true"})


def _honeypot_entry(port: int = 8080) -> Dict[str, Any]:
    """The single-listener payload that `honeypot start --json` prints."""
    return {
        "pid": 4242, "port": port, "bind": "0.0.0.0", "mode": "banner",
        "banner": "ssh", "marker": "honeypot-test",
        "log_path": f"captures/honeypot-{port}-20260912T000000Z.jsonl",
        "started_at": "2026-09-12T00:00:00Z",
    }


def _access_plan_doc() -> Dict[str, Any]:
    doc = t_remote._plan_doc()
    doc["actions"] = [{
        "key": "sshd", "action_id": "sshd.harden_authenticated_keys",
        "target_path": "/etc/ssh/sshd_config", "eligibility": "review-only",
        "diff": "--- a/sshd_config\n+++ b/sshd_config\n", "notes": [], "params": {},
        "pre_state": {}, "skipped_reason": "",
        "validation": [], "effects": [{"kind": "systemd_restart", "argv": ["systemctl", "restart", "ssh"]}],
    }]
    return doc


def _prepare_plan(root: str) -> None:
    with fake_ssh() as fake:
        t_remote._install_routes(fake, root)
        fake.route("command -v python3", 0, "/usr/bin/python3\n")
        fake.route("plan --json --no-save", 0, json.dumps(
            {"plans": [_access_plan_doc()], "matched": ["web-php-apache-compose"]}))
        fake.route("ctfctl plan --json", 0, json.dumps(
            {"plans": [_access_plan_doc()], "matched": ["web-php-apache-compose"]}))
        remote.plan(remote.Conn(host="vulnbox"), root=root)


# --------------------------------------------------------------------------
# Honeypot over ssh
# --------------------------------------------------------------------------
def test_honeypot_start_requires_declaration_policy_and_yes() -> None:
    with remote_repo() as root:
        conn = remote.Conn(host="vulnbox")
        with fake_ssh() as fake:
            try:
                remote.honeypot(conn, "start", port=8080, root=root)
            except util.CtfError as exc:
                check_in("declare", (str(exc) + (exc.hint or "")).lower(),
                         "an undeclared host must be refused with the fix")
            else:
                raise Failure("an undeclared host must be refused")
            check_eq(len(fake.calls), 0, "no ssh before the declaration gate")

        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            try:
                remote.honeypot(conn, "start", port=8080, root=root)
            except util.CtfError as exc:
                check_in("policy", (str(exc) + (exc.hint or "")).lower(),
                         "the policy gate must be named")
            else:
                raise Failure("an unacknowledged policy must block mutations")
            check_eq(len(fake.calls), 0, "no ssh before the policy gate")

        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            try:
                remote.honeypot(conn, "start", port=8080, root=root)
            except util.CtfError as exc:
                check_in("--yes", str(exc) + (exc.hint or ""), "the refusal must demand --yes")
            else:
                raise Failure("a mutation without --yes must be refused")
            check_eq(len(fake.calls), 0, "no ssh before the --yes gate")


def test_honeypot_start_forwards_validated_arguments() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("honeypot start", 0, json.dumps(_honeypot_entry()))
            code, payload = remote.honeypot(
                remote.Conn(host="vulnbox"), "start", port=8080, mode="banner",
                banner="ssh", yes=True, root=root,
            )
        check_eq(code, 0, "a successful start returns 0")
        check_eq(payload["port"], 8080, "the payload is passed through")
        calls = [c for c in fake.calls if "honeypot start" in c["argv"][-1]]
        check_eq(len(calls), 1, "exactly one remote honeypot call")
        check_in("--port 8080", calls[0]["argv"][-1], "the port must be forwarded")
        check_in("--mode banner", calls[0]["argv"][-1], "the mode must be forwarded")
        check_in("--banner ssh", calls[0]["argv"][-1], "the banner must be forwarded")


def test_honeypot_collect_only_reads_paths_it_created() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        status = json.loads(_honeypot_status(
            log_rel="captures/honeypot-8080-20260912T000000Z.jsonl",
            extra=[{"pid": 1, "port": 9999, "bind": "0.0.0.0", "mode": "http",
                    "log_path": "../../../../etc/shadow", "state": "stopped"}],
        ))
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("honeypot status", 0, json.dumps(status))
            fake.route('cat "$HOME/.ctfctl/captures/honeypot-8080',
                       0, '{"event":"decoy-http","decoy":true}\n')
            payload = remote.honeypot_collect(remote.Conn(host="vulnbox"), root=root)
        check_eq(payload["ok"], True, "collect must report success")
        check_eq(len(payload["collected"]), 1, "only the valid log path is collected")
        cats = [c for c in fake.calls if "captures/honeypot-8080" in c["argv"][-1]]
        check_eq(len(cats), 1, "exactly one cat call")
        joined = " ".join(c["argv"][-1] for c in cats)
        check("etc/shadow" not in joined, "an unvalidated path must never reach ssh")
        saved = os.path.join(root, payload["collected"][0]["saved_to"])
        check(os.path.isfile(saved), "the log must land in the local captures directory")


# --------------------------------------------------------------------------
# Auto pipeline
# --------------------------------------------------------------------------
def _auto_routes(fake: t_remote.FakeSSH, root: str) -> None:
    t_remote._install_routes(fake, root)
    # The probe and the python3 check both use `sh -s`; the routes are told apart
    # by the script text the fake receives on stdin.
    fake.route("have_timeout", 0, PROBE_TEXT)
    fake.route("command -v python3", 0, "/usr/bin/python3\n")
    fake.route("ctfctl discover", 0, json.dumps({"schema": "ctfctl.inventory/1", "gaps": []}))
    fake.route("plan --json --no-save", 0, t_remote._plan_payload())
    fake.route("ctfctl plan --json", 0, t_remote._plan_payload())
    fake.route("ctfctl files", 0, json.dumps(
        {"path": "/var/www", "entries": [{"name": "html", "type": "dir"}], "truncated": False}))


def test_auto_is_read_only_and_writes_a_report() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            _auto_routes(fake, root)
            report = remote.auto(remote.Conn(host="vulnbox"), root=root)
        check_eq(report["mutations_requested"], False, "the default pipeline mutates nothing")
        check("apply" not in report["steps"], "no apply step without --apply")
        check("honeypot" not in report["steps"], "no honeypot without --honeypot-port")
        mutate_calls = [c for c in fake.calls
                        if "ctfctl apply" in c["argv"][-1] or "honeypot start" in c["argv"][-1]]
        check_eq(mutate_calls, [], "no mutation may be sent")
        json_path = os.path.join(root, report["report_json"])
        md_path = os.path.join(root, report["report_markdown"])
        check(os.path.isfile(json_path), "the JSON report must be written")
        check(os.path.isfile(md_path), "the Markdown report must be written")
        with open(md_path, encoding="utf-8") as fh:
            markdown = fh.read()
        check_in("## Listeners", markdown, "the report must list listeners")
        check_in("ssh", markdown, "the probe evidence must reach the report")
        check(report["honeypot_suggestions"], "free ports must be suggested")


def test_auto_refuses_mutations_without_yes() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        for kwargs in ({"apply_mutations": True}, {"honeypot_port": 8080}):
            with fake_ssh() as fake:
                try:
                    remote.auto(remote.Conn(host="vulnbox"), root=root, **kwargs)
                except util.CtfError as exc:
                    check_in("--yes", str(exc) + (exc.hint or ""),
                             "the refusal must demand --yes")
                else:
                    raise Failure(f"auto with {kwargs} must refuse without --yes")
                check_eq(len(fake.calls), 0, "no ssh before the confirmation gate")


def test_auto_degrades_when_the_target_has_no_python3() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("have_timeout", 0, PROBE_TEXT)
            fake.route("command -v python3", 1, "", "python3: not found")
            report = remote.auto(remote.Conn(host="vulnbox"), root=root)
        check(report["gaps"], "the missing python3 must be reported as a gap")
        check_in("python3", " ".join(report["gaps"]), "the gap must name python3")
        check_in("probe", report["steps"], "the probe evidence must still be delivered")


# --------------------------------------------------------------------------
# Access-preserving apply guard
# --------------------------------------------------------------------------
def test_touches_access_detects_ssh_and_firewall_plans() -> None:
    check_eq(remote.touches_access(_access_plan_doc()), True, "an sshd edit touches access")
    check_eq(remote.touches_access({"actions": [{"target_path": "/etc/nftables.conf",
                                                 "effects": []}]}), True,
             "a firewall file touches access")
    check_eq(remote.touches_access({"actions": [
        {"target_path": "/var/www/app.py", "effects": [{"kind": "compose_restart",
                                                        "argv": ["docker", "compose", "restart"]}]}]}),
             False, "an ordinary web patch does not")


def test_apply_rolls_back_when_the_operator_cannot_reconnect() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        _prepare_plan(root)
        apply_json = json.dumps({"tx_id": "tx-ssh", "phase": "COMMITTED", "plan": "sha256:abc",
                                 "files": [], "verification": [], "errors": []})
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("ctfctl apply", 0, apply_json)
            fake.route("BatchMode=yes", 255, "", "ssh: connect to host vulnbox: timed out")
            fake.route("ctfctl rollback", 0, json.dumps({"tx_id": "tx-ssh", "phase": "ROLLED_BACK"}))
            code, payload = remote.apply(
                remote.Conn(host="vulnbox"), "latest", yes=True, root=root
            )
        recheck = payload.get("access_recheck")
        check(recheck is not None, "a plan that can cut ssh must be rechecked from the operator")
        check_eq(recheck["ok"], False, "the failed reconnect must be reported")
        check_eq(recheck["rollback"]["attempted"], True, "a rollback must be attempted")
        rollback_calls = [c for c in fake.calls if "ctfctl rollback" in c["argv"][-1]]
        check_eq(len(rollback_calls), 1, "exactly one automatic rollback")
        check_in("tx-ssh", rollback_calls[0]["argv"][-1], "the transaction must be named")
        check_in("--yes", rollback_calls[0]["argv"][-1], "the rollback must be confirmed")
        check_in("console", str(recheck.get("recovery", "")).lower(),
                 "the operator must be pointed at the console path")


def test_apply_does_not_reconnect_check_a_web_patch() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        _prepare_plan(root)
        apply_json = json.dumps({"tx_id": "tx-web", "phase": "COMMITTED", "plan": "sha256:abc",
                                 "files": [], "verification": [], "errors": []})
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("ctfctl apply", 0, apply_json)
            # An sshd plan touches access; swap in a plain web target for this test.
            # `latest` is resolved from plan-latest.json, not from plans/<id>.json.
            state = os.path.join(root, "state", "remote", "vulnbox")
            latest_path = os.path.join(state, "plan-latest.json")
            with open(latest_path, encoding="utf-8") as fh:
                payload = json.load(fh)
            for entry in payload.get("plans", []):
                for action in entry.get("actions", []):
                    action["target_path"] = "/var/www/app/index.php"
                    action["effects"] = [{"kind": "compose_restart",
                                          "argv": ["docker", "compose", "restart"]}]
            with open(latest_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            code, payload = remote.apply(
                remote.Conn(host="vulnbox"), "latest", yes=True, root=root
            )
        check("access_recheck" not in payload,
              "an ordinary patch must not pay for a reconnect probe")
        check(not [c for c in fake.calls if "BatchMode=yes" in c["argv"][-1]],
              "no reconnect probe may run for a non-access change")


# --------------------------------------------------------------------------
# Lockdown planning over ssh
# --------------------------------------------------------------------------
def test_lockdown_reads_the_operator_address_and_mirrors_only_when_acknowledged() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        lockdown_payload = json.dumps({"plans": [_access_plan_doc()]})
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("SSH_CONNECTION", 0,
                       "client_ip=203.0.113.9\nuid=0\nnft=present\n"
                       "authorized_keys=/root/.ssh/authorized_keys\n"
                       "unit=ssh\nsshd_config=/etc/ssh/sshd_config\n")
            fake.route("ctfctl lockdown plan", 0, lockdown_payload)
            fake.route("have_timeout", 0, PROBE_TEXT)
            payload = remote.lockdown(
                remote.Conn(host="vulnbox"), allow_cidrs=["10.10.0.0/16"],
                allow_ports=[80], root=root,
            )
        check_eq(payload["remote"]["operator_cidr"], "203.0.113.9/32",
                 "the operator address must be read from the ssh session")
        check_in("22", str(payload["remote"]["allowed_ports"]),
                 "the ssh port must stay reachable")
        check_eq(payload["remote"]["authorization_mirrored"], False,
                 "no policy ack means no mirrored authorization")
        commands = [c["argv"][-1] for c in fake.calls if "lockdown plan" in c["argv"][-1]]
        check(commands, "the lockdown plan must run on the target")
        check_in("--operator-cidr 203.0.113.9/32", commands[-1],
                 "the operator cidr must be passed to the plan builder")
        check_in("--allow-cidr 10.10.0.0/16", commands[-1], "the team range must be passed")
        check_in("--allow-cidr 203.0.113.9/32", commands[-1],
                 "the operator range must be in the allowlist")


def test_cli_auto_help_and_dispatch_are_wired() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["remote", "auto", "vulnbox", "--honeypot-port", "8080",
                              "--yes", "--json"])
    check_eq(args.command, "remote", "auto lives under remote")
    check_eq(args.honeypot_port, 8080, "the honeypot port option must parse")
    args = parser.parse_args(["remote", "honeypot", "vulnbox", "logs", "--honeypot-port", "8080"])
    check_eq(args.honeypot_action, "logs", "the honeypot action must parse")
    args = parser.parse_args(["lockdown", "plan", "--operator-cidr", "10.0.0.5"])
    check_eq(args.lockdown_command, "plan", "the lockdown subcommand must parse")
    args = parser.parse_args(["kb", "cheat", "web"])
    check_eq(args.kb_command, "cheat", "kb cheat must parse")


def _cli_json(argv: List[str]) -> tuple:
    """Run the real CLI entry point and parse its JSON stdout."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    text = out.getvalue().strip()
    payload = json.loads(text) if text.startswith("{") else {"stdout": text,
                                                             "stderr": err.getvalue()}
    return code, payload


def test_cli_remote_auto_and_lockdown_dispatch() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            _auto_routes(fake, root)
            code, payload = _cli_json(["remote", "auto", "vulnbox", "--json"])
        check_eq(code, 0, f"the CLI auto run must succeed: {payload}")
        check_in("report_markdown", payload, "the CLI must print the report path")
        check_eq(payload["mutations_requested"], False, "the CLI default stays read-only")

        lockdown_payload = json.dumps({"plans": [
            {**t_remote._plan_doc(), "detection": {"matched": True, "facts": {}},
             "actions": []}]})
        with fake_ssh() as fake:
            t_remote._install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("SSH_CONNECTION", 0, "client_ip=203.0.113.9\nnft=present\n")
            fake.route("ctfctl lockdown plan", 0, lockdown_payload)
            code, payload = _cli_json(["remote", "lockdown", "vulnbox",
                                       "--allow-cidr", "10.10.0.0/16", "--json"])
        check_eq(code, 0, f"the CLI lockdown run must succeed: {payload}")
        check_eq(payload["remote"]["operator_cidr"], "203.0.113.9/32",
                 "the CLI must forward the operator address")
        sent = [c["argv"][-1] for c in fake.calls if "lockdown plan" in c["argv"][-1]]
        check_in("--allow-cidr 10.10.0.0/16", sent[-1], "the team range must reach the target")
