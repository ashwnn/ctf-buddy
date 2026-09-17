"""Safety properties: offline guarantees, inert rendering, no free-form execution."""

from __future__ import annotations

import io
import json
import os
import socket
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Callable, List, Tuple

from helpers import Failure, check, check_eq, check_in, repo_copy, temp_dir

from ctfctl import cli, decoy, platformx, util


class NetworkGuard:
    """Fail any outbound connection that is not to loopback."""

    def __init__(self) -> None:
        self.violations: List[Tuple[str, int]] = []
        self._original_connect = socket.socket.connect
        self._original_connect_ex = socket.socket.connect_ex
        self._original_create = socket.create_connection

    def __enter__(self) -> "NetworkGuard":
        def is_loopback(address: Any) -> bool:
            if isinstance(address, tuple) and address:
                host = str(address[0])
                return host in ("127.0.0.1", "::1", "localhost", "0.0.0.0", "")
            return True

        def guard_connect(sock: socket.socket, address: Any) -> Any:
            if not is_loopback(address):
                self.violations.append(
                    ("connect", address[1] if isinstance(address, tuple) else 0)
                )
                raise AssertionError(f"unexpected outbound connection to {address}")
            return self._original_connect(sock, address)

        def guard_connect_ex(sock: socket.socket, address: Any) -> Any:
            if not is_loopback(address):
                self.violations.append(
                    ("connect_ex", address[1] if isinstance(address, tuple) else 0)
                )
                raise AssertionError(f"unexpected outbound connection to {address}")
            return self._original_connect_ex(sock, address)

        def guard_create(address: Any, *args: Any, **kwargs: Any) -> Any:
            if not is_loopback(address):
                self.violations.append(("create_connection", 0))
                raise AssertionError(f"unexpected outbound connection to {address}")
            return self._original_create(address, *args, **kwargs)

        socket.socket.connect = guard_connect  # type: ignore[assignment]
        socket.socket.connect_ex = guard_connect_ex  # type: ignore[assignment]
        socket.create_connection = guard_create  # type: ignore[assignment]
        return self

    def __exit__(self, *exc: Any) -> None:
        socket.socket.connect = self._original_connect  # type: ignore[assignment]
        socket.socket.connect_ex = self._original_connect_ex  # type: ignore[assignment]
        socket.create_connection = self._original_create  # type: ignore[assignment]


def run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def test_offline_commands_never_open_a_socket() -> None:
    with repo_copy() as root:
        previous = os.getcwd()
        os.chdir(root)
        try:
            with NetworkGuard() as guard:
                run_cli(["doctor", "--json", "--quick"])
                run_cli(["kb", "index", "--rebuild"])
                run_cli(["kb", "literal", "traversal", "--limit", "2"])
                run_cli(
                    ["discover", "--no-subprocess", "--system-root", root, "--json"]
                )
                run_cli(["plan", "--no-save"])
            check(not guard.violations, f"unexpected network use: {guard.violations}")
        finally:
            # Restore the directory captured before the copy existed:
            # util.repo_root() would resolve to the copy itself (it ships its own
            # AGENTS.md), and the copy is deleted right after this block, leaving
            # the process in a removed directory on POSIX.
            os.chdir(previous)


def test_doctor_json_is_well_formed_and_honest() -> None:
    code, out, _err = run_cli(["doctor", "--json", "--quick"])
    check_eq(code, 0, "doctor should succeed")
    payload = json.loads(out)
    check_in("summary", payload, "doctor must report a summary")
    check_eq(payload["summary"]["offline"], True, "doctor must declare itself offline")
    check(payload["checks"], "doctor must list its checks")
    for entry in payload["checks"]:
        check_in("name", entry, "each check must be named")
        check_in("ok", entry, "each check must have a verdict")


def test_cli_returns_negative_exit_for_no_matches() -> None:
    with repo_copy() as root:
        code, out, _err = run_cli(
            ["kb", "literal", "THIS_STRING_CANNOT_EXIST_ANYWHERE", "--limit", "2"]
        )
        check_eq(code, 1, "a miss is an expected negative result")
        check_in("no matches", out, "the miss must be reported on stdout")


def test_cli_punctuation_query_does_not_crash() -> None:
    with repo_copy() as root:
        for query in ["../", "$_GET", "403", "ss -lntup", "NEAR((("]:
            code, _out, err = run_cli(["kb", "search", query, "--limit", "1"])
            # 0 = hits, 1 = a clean negative result. Anything else (2 usage,
            # 3 internal) means the query escaped as a crash, which is the bug
            # this test exists to catch.
            check_in(
                code, (0, 1), f"query {query!r} must resolve cleanly, got {code}: {err}"
            )
            check("Traceback" not in err, f"query {query!r} raised: {err}")


def test_apply_without_confirmation_is_refused() -> None:
    with repo_copy() as root:
        code, _out, err = run_cli(["apply", "--json"])
        check_eq(code, 1, "apply without --yes must refuse")
        check(
            "plan" in err.lower() or "yes" in err.lower(),
            f"the refusal should explain itself: {err}",
        )


def test_decoy_status_is_safe_on_a_fresh_repository() -> None:
    with repo_copy() as root:
        previous = os.getcwd()
        os.chdir(root)
        try:
            code, out, _err = run_cli(["decoy", "status", "--json"])
            check_eq(code, 0, "status should succeed")
            payload = json.loads(out)
            check_eq(payload["enabled"], False, "the decoy must start disabled")
            check_eq(payload["running"], False, "nothing should be running")
        finally:
            os.chdir(previous)


def test_profiles_validate_command_is_green() -> None:
    code, out, _err = run_cli(["profiles", "validate", "--json"])
    check_eq(code, 0, f"shipped profiles must validate: {out}")
    payload = json.loads(out)
    check(payload["valid"], f"problems: {payload['problems']}")
    check(payload["count"] >= 1, "at least one profile must ship")


def test_untrusted_text_is_rendered_inert() -> None:
    hostile = "GET /\x1b[2J\x1b]0;pwned\x07\x00\x7f HTTP/1.1\r\nX: y"
    rendered = util.printable(hostile, 400)
    check("\x1b" not in rendered, "escape bytes must be removed")
    check("\x07" not in rendered, "bell must be removed")
    check("\x00" not in rendered, "NUL must be removed")
    check(
        "\\x1b" in rendered, "the escape should be shown escaped, not silently dropped"
    )
    check(len(util.printable("x" * 5000, 100)) <= 100, "rendering is length bounded")


def test_json_output_is_never_truncated_mid_structure() -> None:
    with repo_copy() as root:
        code, out, _err = run_cli(["doctor", "--json", "--quick"])
        payload = json.loads(out)  # raises if truncated
        check(payload, "payload should not be empty")


def test_reports_carry_no_secret_values() -> None:
    with temp_dir() as root:
        os.makedirs(os.path.join(root, "etc"), exist_ok=True)
        with open(os.path.join(root, "etc", "os-release"), "w", encoding="utf-8") as fh:
            fh.write("ID=debian\n")
        from ctfctl import discover

        inventory = discover.discover(
            system_root=root, allow_subprocess=False, quick=True
        )
        blob = json.dumps(inventory.as_dict())
        for banned in ("PRIVATE KEY", "BEGIN OPENSSH"):
            check(banned not in blob, f"{banned} must never appear in an inventory")


def test_plan_and_audit_records_never_contain_secret_values() -> None:
    """The audit record stores hashes and metadata, not file contents."""
    with repo_copy() as root:
        from ctfctl import apply as apply_mod

        tx_dir = os.path.join(root, "state", "tx", "tx-test")
        os.makedirs(tx_dir, exist_ok=True)
        record = {
            "tx_id": "tx-test",
            "plan_id": "sha256:test",
            "started_at": "2026-01-01T00:00:00Z",
            "phase": "COMMITTED",
            "changes": [
                {
                    "index": 0,
                    "action_key": "patch",
                    "action_id": "file.test",
                    "path": "/srv/app/app.py",
                    "pre_sha256": "a" * 64,
                    "post_sha256": "b" * 64,
                    "pre_backup": "state/tx/tx-test/pre/00-app.py",
                    "pre_state": {
                        "path": "/srv/app/app.py",
                        "exists": True,
                        "sha256": "a" * 64,
                    },
                    "replaced": True,
                    "effects": [],
                    "metadata_warnings": [],
                }
            ],
            "verification": [],
            "effects_run": [],
            "errors": [],
        }
        util.write_text_atomic(
            os.path.join(tx_dir, "tx.json"), util.dump_json(record), mode=0o600
        )
        loaded = apply_mod.list_transactions(root)
        check(loaded, "the transaction should be listed")
        blob = json.dumps(loaded)
        check("password" not in blob.lower(), "no credential material in audit state")


def test_action_dispatch_cannot_execute_free_form_strings() -> None:
    """Plans carry action ids + params; there is no code path that shells out."""
    import inspect

    from ctfctl import actions as actions_mod

    source = inspect.getsource(actions_mod)
    for banned in ("shell=True", "os.system", "subprocess.call(", "eval(", "exec("):
        check(banned not in source, f"actions.py must not contain {banned!r}")
    from ctfctl import apply as apply_mod

    apply_source = inspect.getsource(apply_mod)
    check("shell=True" not in apply_source, "apply.py must never use a shell")
    check("os.system" not in apply_source, "apply.py must never use os.system")


def test_effect_execution_uses_argv_only(
    monkeypatch_argv: Callable[..., Any] | None = None,
) -> None:
    from ctfctl import apply as apply_mod

    recorded: List[List[str]] = []
    original = util.run

    def capture(argv, **kwargs):  # type: ignore[no-untyped-def]
        recorded.append(list(argv))
        raise AssertionError("stop before executing")

    util.run = capture  # type: ignore[assignment]
    try:
        tx = apply_mod.Transaction(
            tx_id="tx-x",
            plan_id="sha256:x",
            started_at="now",
            phase="SERVICE_APPLIED",
            directory=temp_dir().__enter__(),
        )
        entry = type(
            "E",
            (),
            {
                "effects": [
                    {
                        "kind": "compose_restart",
                        "argv": ["docker", "compose", "restart", "web"],
                    }
                ]
            },
        )
        try:
            apply_mod._run_effects(tx, [entry], tx.errors)  # type: ignore[arg-type]
        except AssertionError:
            pass
        check(recorded, "the effect should have been executed through util.run")
        check_eq(
            recorded[0][0], "docker", "effects execute the allowlisted binary only"
        )
    finally:
        util.run = original  # type: ignore[assignment]
