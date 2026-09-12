"""Mutation engine: planning, stale detection, apply, verify, rollback, recovery.

These tests exercise the engine directly against a local fake service, so they
run without Docker and without touching a real host. Container integration is in
t_integration_docker.py.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from typing import Any, Dict

from helpers import (Failure, check, check_eq, fake_service, inventory_with,
                     repo_copy, temp_dir, compose_container)

from ctfctl import actions as actions_mod, apply as apply_mod, discover as discover_mod
from ctfctl import plan as plan_mod, profiles as profiles_mod, util

FLASK_SOURCE = '''"""Test service source."""

import os

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/srv/app/uploads"


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.get("/files")
def get_file():
    name = request.args.get("name", "")
    return send_file(os.path.join(UPLOAD_DIR, name), as_attachment=True)
'''


def _write_project(root: str, source: str = FLASK_SOURCE) -> Dict[str, str]:
    project = os.path.join(root, "fixtures", "p-test")
    service = os.path.join(project, "service")
    os.makedirs(service, exist_ok=True)
    app_path = os.path.join(service, "app.py")
    with open(app_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(source)
    compose = os.path.join(project, "compose.yaml")
    with open(compose, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(
            "services:\n"
            "  web:\n"
            "    build: ./service\n"
            "    container_name: ptest-web\n"
            "    volumes:\n"
            "      - ./service/app.py:/srv/app/app.py:ro\n"
            "  proxy:\n"
            "    image: nginx:1.27-alpine\n"
            "    ports:\n"
            '      - "8080:80"\n'
        )
    return {"project": project, "app": app_path, "compose": compose}


def _profile() -> profiles_mod.Profile:
    raw = {
        "schema": profiles_mod.PROFILE_SCHEMA,
        "profile_id": "test-flask",
        "title": "test profile",
        "scope": "compose-project",
        "support_level": "tested-auto",
        "requires": [],
        "notes": [],
        "detect": {
            "all": [
                {"predicate": "container_running",
                 "args": {"name_regex": "(^|-)web$", "image_regex": "flask|python|ptest"}},
                {"predicate": "listener_present", "args": {"published": True}},
                {"predicate": "file_exists", "args": {"path_glob": "service/app.py"}},
            ]
        },
        "facts": {
            "compose_project": {"resolver": "compose_project"},
            "compose_service": {"resolver": "compose_service"},
            "container_name": {"resolver": "container_name"},
            "compose_file": {"resolver": "compose_file"},
            "host_port": {"resolver": "host_port"},
            "app_file": {"resolver": "path_in_project_dir", "relative": "service/app.py"},
        },
        "actions": {
            "patch_traversal": {
                "action_id": "file.python_flask_send_from_directory",
                "eligibility": "auto",
                "params": {"path": "{app_file}"},
                "effects": [],
            }
        },
        "verifiers": [
            {"verifier": "tcp.connect", "tier": "liveness",
             "params": {"host": "127.0.0.1", "port": "{host_port}"}},
        ],
        "exploit_probe": None,
    }
    return profiles_mod._from_raw(raw, "<test>")


def _inventory(root: str, project_dir: str, port: int) -> Dict[str, Any]:
    container = compose_container(
        name="ptest-web", project="ptest", service="web", image="ptest-flask",
        workdir=project_dir, publish=("0.0.0.0", port, "8000/tcp"))
    return inventory_with(
        containers=[container],
        listeners=[{"port": port, "address": "0.0.0.0", "exposure": "all-interfaces",
                    "container": {"name": "ptest-web", "compose_project": "ptest",
                                  "compose_service": "web", "container_mode": "bridge"},
                    "evidence": [f"docker published 0.0.0.0:{port} -> ptest-web 8000/tcp"]}],
        app_roots=[{"path": project_dir, "source": "compose project",
                    "sample": ["service/app.py", "compose.yaml"]}],
    )


def test_plan_renders_an_exact_narrow_diff() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        check(plan.detection["matched"], f"detection failed: {plan.detection['reasons']}")
        check_eq(len(plan.automatic_actions()), 1, "one auto action expected")
        entry = plan.automatic_actions()[0]
        check("send_from_directory" in entry.diff, "diff should add the safe helper")
        check("send_file(os.path.join" in entry.diff, "diff should remove the vulnerable call")
        check_eq(entry.diff.count("-    return send_file"), 1, "exactly one removed line")
        check(entry.validation and all(c["ok"] for c in entry.validation),
              f"validations should pass: {entry.validation}")


def test_apply_patches_then_rollback_restores() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        before = util.sha256_file(paths["app"])
        tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=True)
        check_eq(tx.phase, "COMMITTED", f"apply should commit: {tx.errors}")
        after = util.read_text(paths["app"])
        check("send_from_directory" in after, "patched file should use the safe helper")
        check("send_file(os.path.join" not in after, "vulnerable call should be gone")

        tx2 = apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
        check_eq(tx2.phase, "ROLLED_BACK", f"rollback should succeed: {tx2.errors}")
        check_eq(util.sha256_file(paths["app"]), before, "rollback should restore the byte-exact file")


def test_rollback_is_idempotent_and_not_a_conflict() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
        second = apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
        check_eq(second.phase, "ROLLED_BACK", "a second rollback is a no-op, not a conflict")
        check(not second.errors, f"second rollback should not report errors: {second.errors}")


def test_stale_plan_is_refused() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        with open(paths["app"], "a", encoding="utf-8") as fh:
            fh.write("\n# a teammate edited this after planning\n")
        edited_hash = util.sha256_file(paths["app"])
        try:
            apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        except util.CtfError as exc:
            check("stale" in str(exc), f"expected a staleness refusal, got: {exc}")
        else:
            raise Failure("apply should refuse a stale plan")
        check_eq(util.sha256_file(paths["app"]), edited_hash,
                 "the teammate's edit must be untouched after a refused apply")


def test_repeat_apply_targets_already_satisfied_state() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        try:
            apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        except util.CtfError as exc:
            message = str(exc).lower()
            check("already applied" in message or "stale" in message,
                  f"second apply should be reported as a no-op or stale, got: {exc}")
        else:
            raise Failure("a second apply of the same plan must not silently run again")


def test_functional_regression_causes_automatic_rollback() -> None:
    with repo_copy() as root, fake_service(break_workflow=True) as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        profile = _profile()
        profile.verifiers.append({
            "verifier": "http.workflow", "tier": "functional", "required": True,
            "params": {"steps": [
                {"name": "create", "method": "POST",
                 "url": service.base_url + "/api/notes",
                 "body": {"title": "t", "body": "b"}, "expect_status": 201},
            ]},
        })
        plan = plan_mod.build_plan(profile, inventory, root=root)
        before = util.sha256_file(paths["app"])
        try:
            apply_mod.apply_plan(plan, root=root, yes=True, functional=True)
        except util.CtfError as exc:
            check("rolled back" in str(exc), f"expected a rollback report, got: {exc}")
        else:
            raise Failure("a failing tier-3 workflow must fail the transaction")
        check_eq(util.sha256_file(paths["app"]), before,
                 "the file must be restored after a verification failure")
        entries = apply_mod.list_transactions(root)
        check_eq(entries[0]["phase"], "ROLLED_BACK", "the transaction should be marked rolled back")


def test_failed_syntax_validation_blocks_the_apply() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        # A file the action cannot parse must never be rewritten.
        broken = "def broken(:\n    pass\n"
        with open(paths["app"], "w", encoding="utf-8", newline="\n") as fh:
            fh.write(broken)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        check(not plan.automatic_actions(),
              "an unparseable target must not produce an applicable action")
        check(plan.skipped, "the refusal should be recorded in plan.skipped")
        check_eq(util.read_text(paths["app"]), broken, "the file must be untouched")


def test_unknown_stack_produces_no_action() -> None:
    with repo_copy() as root:
        inventory = inventory_with(
            containers=[],
            listeners=[{"port": 3000, "address": "0.0.0.0", "exposure": "all-interfaces",
                        "evidence": ["listener 3000 (unknown owner)"]}],
        )
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        check(not plan.detection["matched"], "an unknown listener must not be claimed")
        check(not plan.actions, "no action may be proposed without evidence")
        check(plan.detection["reasons"], "the refusal must explain itself")


def test_conflicting_rollback_refuses_to_overwrite() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        with open(paths["app"], "a", encoding="utf-8") as fh:
            fh.write("\n# patched further by a teammate\n")
        teammate_version = util.sha256_file(paths["app"])
        after = apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
        check_eq(after.phase, "CONFLICTED", "rollback must report a conflict")
        check_eq(util.sha256_file(paths["app"]), teammate_version,
                 "the teammate's version must be preserved")


def test_metadata_is_preserved_across_patch_and_rollback() -> None:
    """POSIX mode/ownership preservation.

    Windows implements only the read-only attribute through chmod, and the
    toolkit's metadata path (uid/gid/mode/xattrs/ACL) is POSIX-specific, so this
    assertion is skipped there rather than weakened. The pre-state capture and
    the "could not restore ownership" warning are still exercised on Windows.
    """
    if os.name == "nt":
        with repo_copy() as root, fake_service() as service:
            paths = _write_project(root)
            inventory = _inventory(root, paths["project"], service.port)
            plan = plan_mod.build_plan(_profile(), inventory, root=root)
            entry = plan.automatic_actions()[0]
            check("mode" in entry.pre_state, "the plan must record the file mode")
            check("uid" in entry.pre_state, "the plan must record ownership")
            tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
            check(any("ownership" in w for c in tx.changes for w in c.metadata_warnings),
                  "on a platform without chown the tool must warn instead of claiming success")
        return
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        os.chmod(paths["app"], 0o640)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        check_eq(os.stat(paths["app"]).st_mode & 0o777, 0o640,
                 "the patch must preserve the file mode")
        apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
        check_eq(os.stat(paths["app"]).st_mode & 0o777, 0o640,
                 "the rollback must preserve the file mode")


def test_line_endings_are_not_rewritten() -> None:
    crlf_source = FLASK_SOURCE.replace("\n", "\r\n")
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root, source=crlf_source)
        with open(paths["app"], "wb") as fh:
            fh.write(crlf_source.encode("utf-8"))
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        raw = open(paths["app"], "rb").read()
        check(raw.count(b"\r\n") > 10, "CRLF endings must survive the patch")
        check_eq(raw.count(b"\n") - raw.count(b"\r\n"), 0, "no bare LF introduced")


def test_interrupted_transaction_recovery_reports_without_guessing() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        # Simulate a crash before commit: rewrite the record as in-flight.
        record_path = os.path.join(tx.directory, "tx.json")
        record = util.load_json(record_path, {})
        record["phase"] = "FILE_REPLACED"
        util.write_text_atomic(record_path, util.dump_json(record), mode=0o600)
        findings = apply_mod.recover(root)
        check(findings, "recover should report the interrupted transaction")
        finding = findings[0]
        check(finding["files"], "it should report the file states")
        check("rollback" in finding["requires"] or "verify" in finding["requires"],
              f"it should recommend an action, got: {finding['requires']}")


def test_recovery_refuses_to_touch_a_file_changed_after_crash() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        tx = apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        record_path = os.path.join(tx.directory, "tx.json")
        record = util.load_json(record_path, {})
        record["phase"] = "FILE_REPLACED"
        util.write_text_atomic(record_path, util.dump_json(record), mode=0o600)
        with open(paths["app"], "a", encoding="utf-8") as fh:
            fh.write("\n# changed after the crash\n")
        findings = apply_mod.recover(root)
        check(findings and "manual review" in findings[0]["requires"],
              f"recovery must escalate to a human, got: {findings[0]['requires'] if findings else None}")


def test_insufficient_disk_space_refuses_before_writing() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        original = util.disk_free

        def tiny(path: str):
            return {"free_bytes": 10, "total_bytes": 100, "free_inodes": 1}

        util.disk_free = tiny  # type: ignore[assignment]
        try:
            try:
                apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
            except util.CtfError as exc:
                check("capacity" in str(exc) or "free" in str(exc),
                      f"expected a capacity refusal, got: {exc}")
            else:
                raise Failure("apply must refuse when there is no room for a safe backup")
        finally:
            util.disk_free = original  # type: ignore[assignment]
        check("send_file(os.path.join" in util.read_text(paths["app"]),
              "the target must be untouched after a capacity refusal")


def test_single_writer_lock_blocks_a_second_writer() -> None:
    with repo_copy() as root:
        first = apply_mod.WriterLock(root)
        first.acquire()
        try:
            second = apply_mod.WriterLock(root)
            try:
                second.acquire()
            except util.CtfError as exc:
                check("lock" in str(exc), f"expected a lock error, got: {exc}")
            else:
                raise Failure("a second writer must not acquire the lock")
        finally:
            first.release()


def test_authorization_is_required_for_non_fixture_targets() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        # Move the project outside the fixtures directory and drop the declaration.
        outside = os.path.join(root, "services", "p-test")
        os.makedirs(os.path.dirname(outside), exist_ok=True)
        shutil.move(paths["project"], outside)
        app_path = os.path.join(outside, "service", "app.py")
        inventory = _inventory(root, outside, service.port)
        profile = _profile()
        plan = plan_mod.build_plan(profile, inventory, root=root)
        check(not plan.authorization["allows_mutation"],
              "a target outside fixtures/ with no declaration must not be mutable")
        try:
            apply_mod.apply_plan(plan, root=root, yes=True, functional=False)
        except util.CtfError as exc:
            check("authoriz" in str(exc).lower() or "declar" in str(exc).lower(),
                  f"expected an authorization refusal, got: {exc}")
        else:
            raise Failure("apply must refuse an undeclared target")
        check("send_file(os.path.join" in util.read_text(app_path),
              "the undeclared target must be untouched")


def test_declared_target_with_policy_ack_is_allowed() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        outside = os.path.join(root, "services", "p-test")
        os.makedirs(os.path.dirname(outside), exist_ok=True)
        shutil.move(paths["project"], outside)
        util.write_text_atomic(
            os.path.join(root, "state", "targets.json"),
            util.dump_json({"targets": [{"label": "team vm", "compose_project": "ptest"}]}),
            mode=0o600)
        util.write_text_atomic(
            os.path.join(root, "state", "policy.json"),
            util.dump_json({"acknowledged": True, "notes": ["test"]}), mode=0o600)
        inventory = _inventory(root, outside, service.port)
        plan = plan_mod.build_plan(_profile(), inventory, root=root)
        check(plan.authorization["allows_mutation"],
              f"declared+acknowledged target should be mutable: {plan.authorization}")


def test_effect_allowlist_rejects_destructive_commands() -> None:
    banned = [
        ("compose_up", ["docker", "compose", "down", "-v"]),
        ("compose_up", ["docker", "compose", "rm", "-f", "web"]),
        ("compose_restart", ["docker", "volume", "rm", "notes"]),
        ("compose_up", ["docker", "compose", "up", "-d", "--volumes"]),
        ("systemd_restart", ["systemctl", "stop", "ssh"]),
        ("systemd_restart", ["bash", "-c", "systemctl restart web"]),
        ("compose_up", ["sh", "-c", "docker compose up -d"]),
    ]
    for kind, argv in banned:
        check(not apply_mod._effect_allowed(kind, argv),
              f"{kind} {argv} must not be an allowed effect")
    allowed = [
        ("compose_restart", ["docker", "compose", "restart", "web"]),
        ("compose_up", ["docker", "compose", "up", "-d", "--no-deps", "--no-build", "proxy"]),
        ("systemd_reload", ["systemctl", "daemon-reload"]),
        ("systemd_restart", ["systemctl", "restart", "challenge.service"]),
    ]
    for kind, argv in allowed:
        check(apply_mod._effect_allowed(kind, argv),
              f"{kind} {argv} should be an allowed effect")


def test_plan_id_is_content_addressed() -> None:
    with repo_copy() as root, fake_service() as service:
        paths = _write_project(root)
        inventory = _inventory(root, paths["project"], service.port)
        first = plan_mod.build_plan(_profile(), inventory, root=root)
        second = plan_mod.build_plan(_profile(), inventory, root=root)
        check_eq(first.plan_id, second.plan_id,
                 "the same inputs must produce the same plan id")
        check(first.plan_id.startswith("sha256:"), "plan ids are content addressed")


def test_verifiers_do_not_store_response_bodies() -> None:
    with fake_service() as service:
        result = apply_mod.http_request(service.base_url + "/healthz")
        check(result.ok, f"health request should succeed: {result.detail}")
        payload = json.dumps(result.as_dict())
        check("status" in payload, "the evidence should record the status code")
        check('"ok"' not in payload or "detail" in payload,
              "evidence should not embed the response body verbatim")
        check("sha256" in result.evidence, "evidence should carry a response hash instead")
