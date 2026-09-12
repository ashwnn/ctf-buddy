"""Remote SSH layer: host validation, probe parsing, gating, bundle, plan flow.

No test here opens a socket. `SSH_RUNNER` is replaced with a fake that records
argv and returns canned remote output, so command construction, parsing and
authorization gating are all exercised offline.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shutil
import tarfile
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, List

from helpers import Failure, REPO_ROOT, check, check_eq, check_in, temp_dir

from ctfctl import cli, remote, util


class FakeSSH:
    """Records every ssh invocation and answers from a needle -> result table."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.routes: List[Any] = []

    def route(
        self, needle: str, returncode: int = 0, stdout: str = "", stderr: str = ""
    ) -> "FakeSSH":
        self.routes.append(
            (needle, util.ProcResult(["ssh"], returncode, stdout, stderr, 0.0))
        )
        return self

    def __call__(self, argv, *, input_text=None, timeout=None, max_output=None):
        self.calls.append({"argv": [str(a) for a in argv], "input": input_text})
        # Routes match argv *and* stdin: several calls share `sh -s` and are told
        # apart only by the script they are fed.
        joined = " ".join(str(a) for a in argv) + " " + str(input_text or "")
        for needle, result in self.routes:
            if needle in joined:
                result.argv = [str(a) for a in argv]
                return result
        return util.ProcResult([str(a) for a in argv], 0, "", "", 0.0)


@contextlib.contextmanager
def fake_ssh():
    original = remote.SSH_RUNNER
    fake = FakeSSH()
    remote.SSH_RUNNER = fake
    try:
        yield fake
    finally:
        remote.SSH_RUNNER = original


@contextlib.contextmanager
def remote_repo():
    """A throwaway repo root that contains the real toolkit and profiles."""
    with temp_dir("ctfctl-remote-") as root:
        shutil.copytree(
            os.path.join(REPO_ROOT, "tools"),
            os.path.join(root, "tools"),
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copytree(
            os.path.join(REPO_ROOT, "profiles"), os.path.join(root, "profiles")
        )
        os.makedirs(os.path.join(root, "state"))
        with open(os.path.join(root, "AGENTS.md"), "w", encoding="utf-8") as fh:
            fh.write("test root\n")
        previous = os.getcwd()
        os.chdir(root)
        try:
            yield root
        finally:
            os.chdir(previous)


PROBE_TEXT = """###ctfctl:meta###
__user=deploy
__uid=1000
__hostname=vulnbox
__kernel=Linux 6.8.0-31-generic x86_64 GNU/Linux
###ctfctl:os-release###
NAME="Debian GNU/Linux"
VERSION="12 (bookworm)"
###ctfctl:init###
__init=systemd
systemd
###ctfctl:listeners###
__tool=ss
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=610,fd=3))
tcp   LISTEN 0      511            0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=700,fd=6))
###ctfctl:processes###
    PID    PPID USER     ELAPSED COMMAND
      1       0 root        1-00:00:00 /sbin/init
    700       1 root           10:00 nginx: worker process --password=hunter2
###ctfctl:services###
nginx.service loaded active running A high performance web server
###ctfctl:containers###
__docker=present
__podman=absent
abc123|nginx:1.25|web|0.0.0.0:80->80/tcp|Up 2 hours
###ctfctl:firewall###
__nft=present
table inet filter { chain input { type filter hook input priority 0; } }
###ctfctl:scheduled###
* * * * * root /usr/local/bin/heartbeat token=abc123secret
###ctfctl:resources###
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        40G   12G   26G  33% /
###ctfctl:python###
__python3=/usr/bin/python3
Python 3.11.2
###ctfctl:end###
"""

PROC_PROBE_TEXT = """###ctfctl:meta###
__user=root
__uid=0
__hostname=legacy
###ctfctl:listeners###
__tool=proc
###tcp###
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346
###tcp6###
  sl  local_address                         remote_address                        st
###ctfctl:end###
"""


def _plan_doc(plan_id: str = "sha256:abc", *, matched: bool = True) -> Dict[str, Any]:
    return {
        "plan_id": plan_id,
        "profile": "web-php-apache-compose",
        "profile_support_level": "tested-auto",
        "created_at": "2026-09-12T00:00:00Z",
        "detection": {
            "matched": matched,
            "os_id": "debian",
            "init": "systemd",
            "facts": {"compose_project": "app"},
            "reasons": [] if matched else ["no matching container"],
        },
        "authorization": {
            "scope": "team-owned",
            "allows_mutation": True,
            "policy_acknowledged": True,
            "reason": "declared in state/targets.json",
        },
        "actions": [
            {
                "key": "php-download",
                "action_id": "php_guarded_path_use",
                "target_path": "/var/www/app/index.php",
                "eligibility": "auto",
                "diff": "--- a/index.php\n+++ b/index.php\n",
                "notes": [],
                "params": {},
                "pre_state": {},
                "skipped_reason": "",
                "validation": [],
                "effects": [],
            }
        ],
        "preconditions": [],
        "verifiers": [],
        "exploit_probe": None,
        "rollback": {"description": "restore the pre-edit files"},
        "risks": [],
        "skipped": [],
        "host_fingerprint": {},
        "notes": [],
        "inventory_digest": "d",
    }


def _plan_payload(plan_id: str = "sha256:abc") -> str:
    entry = _plan_doc(plan_id)
    return json.dumps(
        {"inventory_digest": "d", "plans": [entry], "matched": [entry["profile"]]}
    )


def _install_routes(fake: FakeSSH, root: str) -> None:
    """Make install a no-op: the remote marker already matches."""
    fingerprint = remote.toolkit_fingerprint(root)
    fake.route("CTFCTL_VERSION", 0, fingerprint + "\n")
    fake.route("base64 -d | tar", 0, "")


# --------------------------------------------------------------------------
# Host validation
# --------------------------------------------------------------------------
def test_parse_host_accepts_common_forms() -> None:
    conn = remote.parse_host("10.10.5.3")
    check_eq(conn.host, "10.10.5.3", "plain IPv4")
    check_eq(conn.target, "10.10.5.3", "target without user")
    conn = remote.parse_host("deploy@vuln.example:2222")
    check_eq(
        (conn.user, conn.host, conn.port),
        ("deploy", "vuln.example", 2222),
        "user@host:port",
    )
    conn = remote.parse_host("[::1]:22")
    check_eq(conn.host, "[::1]", "IPv6 in brackets")
    check_eq(conn.port, 22, "IPv6 port")
    conn = remote.parse_host("box", user="ops", port=2200)
    check_eq((conn.user, conn.port), ("ops", 2200), "explicit user/port")


def test_parse_host_rejects_shell_and_option_injection() -> None:
    for bad in (
        "-oProxyCommand=touch /tmp/x",
        "host;id",
        "host`id`",
        "host$(id)",
        "host name",
        "host|nc",
        "host&&id",
        "host'quote",
    ):
        try:
            remote.parse_host(bad)
        except util.CtfError:
            continue
        raise Failure(f"parse_host must refuse {bad!r}")


def test_parse_host_rejects_bad_ports() -> None:
    for bad in ("box:0", "box:99999", "box:port"):
        try:
            remote.parse_host(bad)
        except util.CtfError:
            continue
        raise Failure(f"parse_host must refuse port in {bad!r}")
    try:
        remote.parse_host("box", port=70000)
    except util.CtfError:
        return
    raise Failure("parse_host must refuse an out-of-range explicit port")


def test_ssh_argv_is_explicit_and_shell_free() -> None:
    conn = remote.Conn(host="box", user="ops", port=2222, identity="/tmp/k")
    argv = remote.ssh_argv(conn, "echo ok", batch=True)
    check_eq(argv[0], "ssh", "the executable must be ssh")
    check_in("ops@box", argv, "the target must appear exactly once")
    check_eq(argv.count("ops@box"), 1, "no duplicate target tokens")
    check_in("2222", argv, "the port must be passed")
    check_in("-i", argv, "the identity flag must be passed")
    check_eq(
        argv[-1], "echo ok", "the remote command must be the final single argv element"
    )
    batch = " ".join(argv)
    check_in("BatchMode=yes", batch, "non-interactive mode must be explicit")


# --------------------------------------------------------------------------
# Bundle and fingerprints
# --------------------------------------------------------------------------
def test_build_bundle_contains_toolkit_not_runtime_state() -> None:
    bundle = remote.build_bundle()
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        names = tar.getnames()
    check_in("AGENTS.md", names, "the bundle needs a repo marker")
    check_in("tools/ctfctl/cli.py", names, "the CLI must ship")
    check_in("tools/ctfctl/remote.py", names, "the remote module must ship")
    check(
        any(n.startswith("profiles/") and n.endswith(".json") for n in names),
        f"profiles must ship: {names}",
    )
    forbidden = [
        n
        for n in names
        if n.startswith(("tests/", "kb/", "state/", "sources/", "index/", "captures/"))
    ]
    check_eq(forbidden, [], "the bundle must exclude corpus and runtime state")


def test_toolkit_fingerprint_changes_with_content() -> None:
    with remote_repo() as root:
        first = remote.toolkit_fingerprint(root)
        with open(
            os.path.join(root, "tools", "ctfctl", "util.py"), "a", encoding="utf-8"
        ) as fh:
            fh.write("\n# fingerprint marker\n")
        second = remote.toolkit_fingerprint(root)
        check(first != second, "a changed toolkit must change its fingerprint")
        check_eq(
            remote.toolkit_fingerprint(root), second, "fingerprints must be stable"
        )


# --------------------------------------------------------------------------
# Probe parsing
# --------------------------------------------------------------------------
def test_parse_probe_ss_output() -> None:
    payload = remote.parse_probe(PROBE_TEXT, host="vulnbox")
    check_eq(payload["host"], "vulnbox", "host must be recorded")
    check_eq(payload["identity"]["user"], "deploy", "user parsed")
    check_eq(payload["identity"]["python3"], "/usr/bin/python3", "python3 parsed")
    check_eq(len(payload["listeners"]), 2, "both listeners parsed")
    ports = sorted(item["port"] for item in payload["listeners"])
    check_eq(ports, [22, 80], "ports parsed from ss output")
    sshd = [item for item in payload["listeners"] if item["port"] == 22][0]
    check_eq(sshd["process"], "sshd", "process parsed from users:")
    check_eq(sshd["pid"], 610, "pid parsed from users:")
    check_eq(len(payload["containers"]), 1, "container parsed")
    check(payload["firewall_lines"], "firewall output retained")
    fake = json.dumps(payload)
    check("hunter2" not in fake, "secret-looking process args must be redacted")
    check("abc123secret" not in fake, "secret-looking cron values must be redacted")
    check(
        any("unprivileged" in gap for gap in payload["gaps"]),
        f"an unprivileged probe must say so: {payload['gaps']}",
    )


def test_parse_probe_proc_fallback() -> None:
    payload = remote.parse_probe(PROC_PROBE_TEXT, host="legacy")
    check_eq(payload["identity"]["user"], "root", "root probe parses")
    ports = sorted(item["port"] for item in payload["listeners"])
    check_eq(ports, [22, 8080], "hex proc addresses decode to real ports")
    loopback = [item for item in payload["listeners"] if item["port"] == 22][0]
    check_eq(loopback["address"], "127.0.0.1", "little-endian IPv4 decodes correctly")


def test_parse_probe_empty_output_is_honest() -> None:
    payload = remote.parse_probe("", host="ghost")
    check_eq(payload["identity"]["user"], "unknown", "no guess when there is no output")
    check_eq(payload["listeners"], [], "no listeners when there is no evidence")
    check(payload["gaps"], "missing evidence must be reported as gaps")


# --------------------------------------------------------------------------
# Declaration gating
# --------------------------------------------------------------------------
def test_probe_refuses_undeclared_host_before_any_ssh() -> None:
    with remote_repo() as root:
        with fake_ssh() as fake:
            try:
                remote.probe(remote.Conn(host="10.0.0.9"), root=root)
            except util.CtfError as exc:
                check_in("not declared", str(exc), "the refusal must name the gate")
                check_in(
                    "targets declare",
                    str(exc) + (exc.hint or ""),
                    "the refusal must show the exact remediation",
                )
            else:
                raise Failure("probe must refuse an undeclared host")
            check_eq(len(fake.calls), 0, "no ssh call may happen first")


def test_probe_parses_and_saves_when_declared() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab box", root=root)
        with fake_ssh() as fake:
            fake.route("sh -s", 0, PROBE_TEXT)
            payload = remote.probe(remote.Conn(host="vulnbox"), save=True, root=root)
        check_eq(payload["identity"]["hostname"], "vulnbox", "probe identity parsed")
        saved = os.path.join(root, "state", "remote", "vulnbox", "probe-latest.json")
        check(os.path.isfile(saved), f"probe-latest.json must be saved: {saved}")
        check_eq(len(fake.calls), 1, "probe is exactly one ssh call")


def test_targets_declare_and_policy() -> None:
    with remote_repo() as root:
        result = remote.declare_target("box", label="lab", ack_policy=True, root=root)
        check_eq(result["policy_acknowledged"], True, "ack must be recorded")
        check(remote.find_declaration("box", root), "declaration must be found")
        check(remote.is_policy_acknowledged(root), "policy must be acknowledged")
        again = remote.declare_target("box", label="renamed", root=root)
        check_eq(again["replaced"], True, "re-declaring must update, not duplicate")
        check_eq(len(remote.load_targets(root)), 1, "exactly one declaration remains")
        check_eq(remote.load_targets(root)[0]["label"], "renamed", "label updated")


# --------------------------------------------------------------------------
# Plan and apply flows
# --------------------------------------------------------------------------
def test_plan_mirrors_authorization_and_saves() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            _install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("plan --json --no-save", 0, _plan_payload("sha256:abc"))
            fake.route("ctfctl plan --json", 0, _plan_payload("sha256:def"))
            payload = remote.plan(remote.Conn(host="vulnbox"), root=root)
        check_eq(
            payload["plans"][0]["plan_id"],
            "sha256:def",
            "the saved second pass must be the returned plan",
        )
        check_eq(
            payload["remote"]["authorization_mirrored"],
            True,
            "declared + acknowledged must mirror authorization",
        )
        plan_calls = [c for c in fake.calls if "ctfctl plan" in c["argv"][-1]]
        check_eq(len(plan_calls), 2, "plan must run twice: read-only, then authorized")
        check_in("--no-save", plan_calls[0]["argv"][-1], "first pass must not save")
        check("--no-save" not in plan_calls[1]["argv"][-1], "second pass must save")
        uploads = [
            c
            for c in fake.calls
            if c["input"] and "state/targets.json" in c["argv"][-1]
        ]
        check(uploads, "the mirrored targets.json must be uploaded")
        decoded = base64.b64decode(uploads[0]["input"]).decode("utf-8")
        check_in("/var/www/app/index.php", decoded, "target paths must be mirrored")
        state = os.path.join(root, "state", "remote", "vulnbox")
        check(
            os.path.isfile(os.path.join(state, "plan-latest.json")),
            "plan-latest.json must be saved",
        )
        check(
            os.path.isfile(os.path.join(state, "plans", "def.json")),
            "the matched plan must be saved under a filesystem-safe name",
        )


def test_plan_without_policy_ack_does_not_mirror() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            _install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("plan --json", 0, _plan_payload())
            payload = remote.plan(remote.Conn(host="vulnbox"), root=root)
        check_eq(
            payload["remote"]["authorization_mirrored"],
            False,
            "no policy ack means no mirrored authorization",
        )
        check(
            not [
                c for c in fake.calls if c["input"] and "targets.json" in c["argv"][-1]
            ],
            "nothing may be uploaded without a policy acknowledgement",
        )


def test_apply_refuses_without_yes_before_ssh() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            _install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("plan --json --no-save", 0, _plan_payload())
            fake.route("ctfctl plan --json", 0, _plan_payload())
            remote.plan(remote.Conn(host="vulnbox"), root=root)
        with fake_ssh() as second:
            try:
                remote.apply(remote.Conn(host="vulnbox"), "latest", root=root)
            except util.CtfError as exc:
                check_in(
                    "--yes",
                    str(exc) + (exc.hint or ""),
                    "the refusal must demand --yes",
                )
            else:
                raise Failure("apply must refuse without --yes")
            check_eq(
                len(second.calls), 0, "no ssh may happen before the confirmation gate"
            )


def test_apply_mirrors_authorization_then_calls_remote_apply() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            _install_routes(fake, root)
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("plan --json --no-save", 0, _plan_payload())
            fake.route("ctfctl plan --json", 0, _plan_payload())
            remote.plan(remote.Conn(host="vulnbox"), root=root)
        apply_json = json.dumps(
            {
                "tx_id": "tx-1",
                "phase": "COMMITTED",
                "plan": "sha256:abc",
                "files": [],
                "verification": [],
                "errors": [],
            }
        )
        with fake_ssh() as second:
            _install_routes(second, root)
            second.route("command -v python3", 0, "/usr/bin/python3\n")
            second.route("ctfctl apply", 0, apply_json)
            code, payload = remote.apply(
                remote.Conn(host="vulnbox"), "latest", yes=True, root=root
            )
        check_eq(code, 0, "a successful remote apply returns 0")
        check_eq(payload["tx_id"], "tx-1", "the remote apply JSON is passed through")
        apply_calls = [c for c in second.calls if "ctfctl apply" in c["argv"][-1]]
        check_eq(len(apply_calls), 1, "exactly one remote apply call")
        check_in("--yes", apply_calls[0]["argv"][-1], "confirmation must be forwarded")
        check_in(
            "sha256:abc", apply_calls[0]["argv"][-1], "the plan id must be forwarded"
        )
        targets = [
            c
            for c in second.calls
            if c["input"] and "state/targets.json" in c["argv"][-1]
        ]
        check(targets, "apply must re-mirror authorization for the exact plan")


def test_unreachable_host_is_reported_honestly() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            fake.route(
                "sh -s",
                255,
                "",
                "ssh: connect to host vulnbox port 22: Connection refused",
            )
            try:
                remote.probe(remote.Conn(host="vulnbox"), root=root)
            except util.CtfError as exc:
                check_in("vulnbox", str(exc), "the failing target must be named")
                check_in("could not connect", str(exc), "the failure must be explicit")
            else:
                raise Failure("an unreachable host must raise a clear error")


def test_remote_files_requires_absolute_path_before_ssh() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            try:
                remote.remote_files(
                    remote.Conn(host="vulnbox"), "list", "var/www", root=root
                )
            except util.CtfError as exc:
                check_in("absolute", str(exc), "relative paths must be refused")
            else:
                raise Failure("a relative remote path must be refused")
            check_eq(len(fake.calls), 0, "the refusal must happen before ssh")


def test_remote_run_allowlist() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh():
            try:
                remote.run_read_only(
                    remote.Conn(host="vulnbox"), ["apply", "--yes"], root=root
                )
            except util.CtfError as exc:
                check_in("read-only", str(exc), "mutating subcommands must be refused")
            else:
                raise Failure("remote run must not proxy apply")
        with fake_ssh() as fake:
            fake.route("CTFCTL_VERSION", 0, remote.toolkit_fingerprint(root) + "\n")
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("ctfctl doctor", 0, '{"ok": true}')
            out = io.StringIO()
            with redirect_stdout(out):
                code = remote.run_read_only(
                    remote.Conn(host="vulnbox"), ["doctor", "--json"], root=root
                )
        check_eq(code, 0, "an allowlisted subcommand passes through")
        check_in('{"ok": true}', out.getvalue(), "stdout must be streamed")


def test_cli_remote_refuses_undeclared_host() -> None:
    with remote_repo() as root:
        err = io.StringIO()
        with redirect_stderr(err):
            code = cli.main(["remote", "probe", "10.0.0.9"])
        check_eq(code, 1, "the CLI must return the expected-negative code")
        text = err.getvalue()
        check_in("not declared", text, "the CLI must explain the gate")
        check("Traceback" not in text, "no traceback for an expected refusal")


def test_cli_remote_run_absorbs_connection_flags_after_host() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", ack_policy=True, root=root)
        with fake_ssh() as fake:
            fake.route("CTFCTL_VERSION", 0, remote.toolkit_fingerprint(root) + "\n")
            fake.route("command -v python3", 0, "/usr/bin/python3\n")
            fake.route("ctfctl doctor", 0, '{"ok": true}')
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(
                    [
                        "remote",
                        "run",
                        "vulnbox",
                        "--user",
                        "ops",
                        "--port",
                        "2222",
                        "doctor",
                        "--json",
                    ]
                )
        check_eq(code, 0, "flags after the host must be absorbed, not proxied")
        check_in('{"ok": true}', out.getvalue(), "stdout must be streamed")
        doctor_calls = [c for c in fake.calls if "ctfctl doctor" in c["argv"][-1]]
        check(doctor_calls, "doctor must have been proxied")
        check_in("ops@vulnbox", doctor_calls[0]["argv"], "the absorbed user must apply")
        check(
            "--user" not in doctor_calls[0]["argv"][-1],
            "connection flags must not be proxied to the remote subcommand",
        )
        err = io.StringIO()
        with redirect_stderr(err):
            code2 = cli.main(["remote", "run", "vulnbox", "--port", "abc", "doctor"])
        check_eq(code2, 2, "a non-numeric port is a usage error")


def test_cli_targets_declare_round_trip() -> None:
    with remote_repo() as root:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(
                [
                    "targets",
                    "declare",
                    "box",
                    "--label",
                    "lab",
                    "--ack-policy",
                    "--json",
                ]
            )
        check_eq(code, 0, "declare must succeed")
        payload = json.loads(out.getvalue())
        check_eq(payload["host"], "box", "declare echoes the host")
        check_eq(payload["policy_acknowledged"], True, "policy ack recorded")
