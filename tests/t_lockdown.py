"""Lockdown actions and the file-create engine path.

Pure logic plus one real apply/rollback against files in a throwaway root. No
network, no root, no /etc writes: the production paths are validated as strings,
the engine behaviour is proven on temporary files, and the nft/sshd binaries are
stubbed so the tests run identically on Windows.
"""

from __future__ import annotations

import contextlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from helpers import Failure, check, check_eq, check_in, repo_copy

from ctfctl import actions as actions_mod
from ctfctl import apply as apply_mod
from ctfctl import plan as plan_mod
from ctfctl import profiles as profiles_mod
from ctfctl import util


@contextlib.contextmanager
def stub_tools(*, which: Optional[Dict[str, str]] = None,
               run_ok: bool = True, run_stdout: str = "") -> Any:
    """Replace util.which/util.run for the duration of one test."""
    original_which, original_run = util.which, util.run
    seen: List[List[str]] = []
    table = {
        "nft": "/usr/sbin/nft",
        "sshd": "/usr/sbin/sshd",
        "systemctl": "/usr/bin/systemctl",
    } if which is None else which  # an empty dict means "no tools at all"

    def fake_which(name: str) -> Optional[str]:
        return table.get(name)

    def fake_run(argv, **kwargs):
        seen.append([str(a) for a in argv])
        return util.ProcResult([str(a) for a in argv], 0 if run_ok else 1,
                               run_stdout, "" if run_ok else "stub failure", 0.0)

    util.which, util.run = fake_which, fake_run
    try:
        yield seen
    finally:
        util.which, util.run = original_which, original_run


FIREWALL_PARAMS: Dict[str, Any] = {
    "path": "/etc/ctfctl-lockdown.nft",
    "allow_cidrs": "10.10.5.0/24, 192.168.7.9/32",
    "operator_cidr": "192.168.7.9/32",
    "allow_tcp_ports": "22,80,443",
    "allow_udp_ports": "none",
    "table": "ctfctl_lockdown",
    "log_drops": False,
    "note": "unit test",
}


def test_firewall_action_renders_an_additive_table() -> None:
    action = actions_mod.get("firewall.nft_lockdown_table")
    check_eq(action.kind, "file_create", "the firewall action creates its own file")
    ctx = actions_mod.ActionContext(root=".", target_path=FIREWALL_PARAMS["path"], pre_text="")
    candidate = action.render(ctx, FIREWALL_PARAMS)
    check(candidate is not None, "the action must render a candidate")
    text = candidate.new_text
    check_in("table inet ctfctl_lockdown {", text, "the table must be named")
    check_in("priority filter + 10", text, "the chain must run after existing rules")
    check_in("counter drop", text, "the default verdict must be drop")
    check("flush ruleset" not in text, "the ruleset must never flush other tables")
    check_in("192.168.7.9/32", text, "the operator address must be in the allowlist")
    check_in("tcp dport { 22, 80, 443 }", text, "listed ports must be accepted")
    check("udp dport" not in text, "'none' must parse to an empty UDP set")


def test_firewall_action_refuses_unsafe_allowlists() -> None:
    action = actions_mod.get("firewall.nft_lockdown_table")
    problems = action.preflight({**FIREWALL_PARAMS, "allow_cidrs": "0.0.0.0/0"})
    check(any("whole internet" in p for p in problems),
          f"a /0 allowlist must be refused, got {problems}")
    problems = action.preflight({**FIREWALL_PARAMS, "allow_cidrs": "10.0.0.0/8"})
    check(any("cut off" in p for p in problems),
          f"an allowlist that excludes the operator must be refused, got {problems}")
    problems = action.preflight({**FIREWALL_PARAMS, "path": "/tmp/lockdown.nft"})
    check(any("under /etc" in p for p in problems),
          f"a path outside /etc must be refused, got {problems}")
    problems = action.preflight({**FIREWALL_PARAMS, "allow_cidrs": "10.0.0.0/8, nonsense"})
    check(any("CIDR" in p for p in problems), f"a bad CIDR must be refused, got {problems}")


def test_firewall_rollback_deletes_the_table_instead_of_reloading() -> None:
    action = actions_mod.get("firewall.nft_lockdown_table")
    ctx = actions_mod.ActionContext(root=".", target_path=FIREWALL_PARAMS["path"], pre_text="")
    effects = action.effects(ctx, FIREWALL_PARAMS)
    check_eq(len(effects), 1, "one effect")
    check_eq(effects[0].argv, ["nft", "-f", "/etc/ctfctl-lockdown.nft"],
             "apply loads the generated file")
    check_eq(effects[0].rollback_argv,
             ["nft", "delete", "table", "inet", "ctfctl_lockdown"],
             "rollback deletes the table: reloading is not its own inverse here")


def test_nft_effect_allowlist_is_shape_strict() -> None:
    allow = [
        ["nft", "-f", "/etc/ctfctl-lockdown.nft"],
        ["nft", "delete", "table", "inet", "ctfctl_lockdown"],
    ]
    refuse = [
        ["nft", "-f", "/tmp/x.nft"],
        ["nft", "-f", "/etc/ok.nft; rm -rf /"],
        ["nft", "flush", "ruleset"],
        ["nft", "delete", "table", "inet", "a;b"],
        ["sh", "-c", "nft -f /etc/x.nft"],
    ]
    for argv in allow:
        check(apply_mod._effect_allowed("nft_load_file", argv), f"{argv} must be allowed")
    for argv in refuse:
        check(not apply_mod._effect_allowed("nft_load_file", argv), f"{argv} must be refused")


def test_sshd_action_refuses_configs_it_cannot_reason_about() -> None:
    action = actions_mod.get("sshd.harden_authenticated_keys")
    params = {
        "path": "/etc/ssh/sshd_config",
        "authorized_keys_path": "/root/.ssh/authorized_keys",
        "service_unit": "ssh",
    }
    match_ctx = actions_mod.ActionContext(
        root=".", target_path=params["path"],
        pre_text="PasswordAuthentication yes\nMatch User deploy\n  PasswordAuthentication yes\n",
    )
    try:
        action.render(match_ctx, params)
        raise Failure("a Match block must be refused: appended lines land inside it")
    except actions_mod.ActionError as exc:
        check_in("Match", str(exc), "the refusal must name the Match problem")
    empty_ctx = actions_mod.ActionContext(root=".", target_path=params["path"], pre_text="")
    try:
        action.render(empty_ctx, params)
        raise Failure("an empty sshd_config must not be replaced with an invented one")
    except actions_mod.ActionError as exc:
        check_in("empty", str(exc), "the refusal must explain itself")


def test_sshd_action_is_idempotent_and_replaces_active_directives() -> None:
    action = actions_mod.get("sshd.harden_authenticated_keys")
    params = {
        "path": "/etc/ssh/sshd_config",
        "authorized_keys_path": "/root/.ssh/authorized_keys",
        "permit_root_login": "prohibit-password",
        "service_unit": "ssh",
    }
    ctx = actions_mod.ActionContext(
        root=".", target_path=params["path"],
        pre_text="# banner\nPermitRootLogin yes\nPasswordAuthentication yes\n",
    )
    first = action.render(ctx, params)
    check_in("PasswordAuthentication no", first.new_text, "password auth must be disabled")
    check_in("PermitRootLogin prohibit-password", first.new_text, "root login must be restricted")
    check("PermitRootLogin yes" not in first.new_text, "the old directive must be replaced")
    check_eq(first.new_text.count("PasswordAuthentication"), 1,
             "exactly one directive of each kind remains")
    again = actions_mod.ActionContext(root=".", target_path=params["path"],
                                      pre_text=first.new_text)
    check(action.render(again, params) is None, "a second render must be a no-op")


def test_authorized_key_is_required_before_touching_sshd() -> None:
    action = actions_mod.get("sshd.harden_authenticated_keys")
    with repo_copy() as root:
        keys = os.path.join(root, "authorized_keys")
        params = {
            "path": os.path.join(root, "sshd_config"),
            "authorized_keys_path": keys,
            "service_unit": "ssh",
        }
        with open(params["path"], "w", encoding="utf-8") as fh:
            fh.write("PasswordAuthentication yes\n")
        ctx = actions_mod.ActionContext(root=root, target_path=params["path"],
                                        pre_text="PasswordAuthentication yes\n")
        candidate = action.render(ctx, params)
        with stub_tools(run_ok=True, run_stdout="passwordauthentication no\n"):
            checks = {c.name: c for c in action.validate(ctx, params, candidate)}
        check_eq(checks["authorized-key-present"].ok, False,
                 "a missing key file must fail validation")
        with open(keys, "w", encoding="utf-8") as fh:
            fh.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI0000 test@team\n")
        effective = ("passwordauthentication no\n"
                     "kbdinteractiveauthentication no\n"
                     "permitrootlogin prohibit-password\n")
        with stub_tools(run_ok=True, run_stdout=effective):
            checks = {c.name: c for c in action.validate(ctx, params, candidate)}
        check_eq(checks["authorized-key-present"].ok, True, "a real key line passes")
        check_eq(checks["sshd-effective"].ok, True, "the stubbed sshd -T reports the values")
        with stub_tools(run_ok=True, run_stdout="passwordauthentication yes\n"):
            checks = {c.name: c for c in action.validate(ctx, params, candidate)}
        check_eq(checks["sshd-effective"].ok, False,
                 "an effective config that still allows passwords must fail")


def test_sshd_verifier_checks_the_effective_config() -> None:
    with stub_tools(run_ok=True, run_stdout="passwordauthentication yes\n"):
        result = apply_mod.sshd_option(option="passwordauthentication", value="no")
    check_eq(result.ok, False, "an unhardened effective config must fail the verifier")
    with stub_tools(run_ok=True, run_stdout="passwordauthentication no\npermitrootlogin no\n"):
        result = apply_mod.sshd_option(option="passwordauthentication", value="no")
    check_eq(result.ok, True, "the hardened effective config must pass")
    check_eq(apply_mod.VERIFIERS["nft.table"] is not None, True, "nft.table must be registered")


def test_lockdown_plan_is_review_only_and_skips_without_tools() -> None:
    with repo_copy() as root:
        inventory = _lockdown_inventory()
        spec = plan_mod.LockdownSpec(
            operator_cidr="192.168.7.9/32",
            allow_cidrs=["10.10.5.0/24"],
            allow_tcp_ports=[22, 80],
            include_firewall=True,
            include_ssh=True,
        )
        real_isdir = os.path.isdir
        os.path.isdir = lambda p: True if str(p).startswith("/etc") else real_isdir(p)
        try:
            with stub_tools(which={}):  # no nft, no sshd: both actions must refuse
                plan = plan_mod.build_lockdown_plan(spec, inventory, root=root,
                                                    allow_fixture=True)
        finally:
            os.path.isdir = real_isdir
        check(plan.detection.get("matched") is True,
              f"the lockdown profile must always match, got {plan.detection}")
        check_eq(plan.profile_support_level, "review-only", "support level")
        reasons = " ".join(str(item.get("reason")) for item in plan.skipped)
        check_in("nft", reasons, "without nft the firewall action must be skipped, not applied")
        for action in plan.actions:
            check_eq(action.eligibility, "review-only",
                     "no lockdown action may ever be auto-eligible")


def test_lockdown_plan_renders_when_the_tools_exist() -> None:
    with repo_copy() as root:
        inventory = _lockdown_inventory()
        spec = plan_mod.LockdownSpec(
            operator_cidr="192.168.7.9/32",
            allow_cidrs=["10.10.5.0/24"],
            allow_tcp_ports=[22, 80],
            include_firewall=True,
            include_ssh=False,
        )
        # The /etc path rule is deliberate; the directory check is the only thing
        # that needs a real filesystem, so it is stubbed for a cross-platform run.
        real_isdir = os.path.isdir
        os.path.isdir = lambda p: True if str(p).startswith("/etc") else real_isdir(p)
        try:
            with stub_tools():
                plan = plan_mod.build_lockdown_plan(spec, inventory, root=root,
                                                    allow_fixture=True)
        finally:
            os.path.isdir = real_isdir
        live = [a for a in plan.actions if not a.skipped_reason]
        check_eq(len(live), 1, f"one live action expected, skipped: {plan.skipped}")
        entry = live[0]
        check_in("table inet ctfctl_lockdown", entry.candidate_text, "the ruleset is rendered")
        check_eq([e["kind"] for e in entry.effects], ["nft_load_file"], "effect kind")
        check_eq(entry.effects[0]["rollback_argv"],
                 ["nft", "delete", "table", "inet", "ctfctl_lockdown"], "rollback argv")


def test_lockdown_needs_at_least_one_action() -> None:
    with repo_copy() as root:
        spec = plan_mod.LockdownSpec(
            operator_cidr="192.168.7.9/32", allow_cidrs=["10.0.0.0/8"], allow_tcp_ports=[22],
            include_firewall=False, include_ssh=False,
        )
        try:
            plan_mod.build_lockdown_plan(spec, _lockdown_inventory(), root=root)
            raise Failure("a lockdown with no actions must be refused")
        except util.CtfError as exc:
            check_in("nothing to plan", str(exc), "the refusal must be explicit")


# --------------------------------------------------------------------------
# Engine: file creation and its rollback
# --------------------------------------------------------------------------
class _CreateFileAction(actions_mod.Action):
    """Test-only action: create a file. Registered by the test, never shipped."""

    id = "test.create_file"
    kind = "file_create"
    summary = "create a file (engine test)"
    eligibility = "auto"
    required_params = ("path", "body")

    def render(self, ctx, params):
        if os.path.isfile(ctx.target_path):
            current = util.read_text(ctx.target_path, 4096)
            if current == params["body"]:
                return None
        return actions_mod.Candidate(
            path=ctx.target_path, new_text=str(params["body"]),
            diff=actions_mod.unified_diff(ctx.target_path, ctx.pre_text, str(params["body"])),
            notes=["created by the engine test"],
        )


def test_file_creation_applies_and_rolls_back_by_deleting() -> None:
    actions_mod.ACTIONS[_CreateFileAction.id] = _CreateFileAction()
    try:
        with repo_copy() as root:
            target = os.path.join(root, "fixtures", "created.nft")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            entry = plan_mod.PlanAction(
                key="create", action_id=_CreateFileAction.id,
                params={"path": target, "body": "table inet x {}\n"},
                eligibility="auto", target_path=target,
            )
            plan = plan_mod.Plan(
                plan_id="", created_at=util.iso_now(), schema=plan_mod.PLAN_SCHEMA,
                profile_id="test", profile_support_level="tested-auto",
                authorization={"scope": "fixture-local", "allows_mutation": True,
                               "policy_acknowledged": True, "reason": "test"},
                detection={"matched": True, "facts": {}}, preconditions=[],
                actions=[entry], verifiers=[], exploit_probe=None,
                rollback={"description": "remove the created file"}, risks=[], skipped=[],
                host_fingerprint={}, notes=[], inventory_digest="digest",
            )
            plan.plan_id = plan_mod._plan_id(plan)
            check(not os.path.exists(target), "the target starts absent")
            tx = apply_mod.apply_plan(plan, root=root, yes=True, run_verifiers=False)
            check_eq(tx.phase, "COMMITTED", f"apply must commit, errors={tx.errors}")
            check(os.path.isfile(target), "the file must exist after apply")
            check_eq(tx.changes[0].created, True, "the change must be recorded as a creation")
            check_eq(tx.changes[0].pre_backup, "", "a created file has no pre-image to back up")

            rolled = apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
            check_eq(rolled.phase, "ROLLED_BACK", f"rollback must succeed, {rolled.errors}")
            check(not os.path.exists(target), "rollback must delete the file it created")
    finally:
        actions_mod.ACTIONS.pop(_CreateFileAction.id, None)


def test_created_file_rollback_refuses_to_delete_a_later_edit() -> None:
    actions_mod.ACTIONS[_CreateFileAction.id] = _CreateFileAction()
    try:
        with repo_copy() as root:
            target = os.path.join(root, "fixtures", "created2.nft")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            entry = plan_mod.PlanAction(
                key="create", action_id=_CreateFileAction.id,
                params={"path": target, "body": "original\n"},
                eligibility="auto", target_path=target,
            )
            plan = plan_mod.Plan(
                plan_id="", created_at=util.iso_now(), schema=plan_mod.PLAN_SCHEMA,
                profile_id="test", profile_support_level="tested-auto",
                authorization={"scope": "fixture-local", "allows_mutation": True,
                               "policy_acknowledged": True, "reason": "test"},
                detection={"matched": True, "facts": {}}, preconditions=[],
                actions=[entry], verifiers=[], exploit_probe=None,
                rollback={"description": "remove the created file"}, risks=[], skipped=[],
                host_fingerprint={}, notes=[], inventory_digest="digest",
            )
            plan.plan_id = plan_mod._plan_id(plan)
            tx = apply_mod.apply_plan(plan, root=root, yes=True, run_verifiers=False)
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("a teammate changed this\n")
            rolled = apply_mod.rollback_tx(tx.tx_id, root=root, yes=True, verify=False)
            check_eq(rolled.phase, "CONFLICTED", "a later edit must conflict, not be deleted")
            check(os.path.isfile(target), "the teammate's file must survive")
    finally:
        actions_mod.ACTIONS.pop(_CreateFileAction.id, None)


def _lockdown_inventory() -> Dict[str, Any]:
    return {
        "schema": "ctfctl.inventory/1",
        "mode": "fixture-root",
        "system_root": "/",
        "generated_at": "2026-01-01T00:00:00Z",
        "host": {"kernel": "test", "arch": "x86_64", "os_id": "debian", "is_root": True,
                 "euid": 0, "init_system": "systemd", "boot_id": "test-boot", "tools": {}},
        "evidence": [],
        "graph": {"services": [
            {"port": 22, "address": "0.0.0.0", "proto": "tcp", "exposure": "all-interfaces",
             "stack_candidates": ["ssh"], "evidence": ["listener 22"], "confidence": "high",
             "process": "sshd", "pid": 610, "unit": "ssh.service", "container": None,
             "app_root": None, "unsupported_reason": None},
            {"port": 80, "address": "0.0.0.0", "proto": "tcp", "exposure": "all-interfaces",
             "stack_candidates": ["nginx"], "evidence": ["listener 80"], "confidence": "high",
             "process": "nginx", "pid": 700, "unit": None, "container": "web",
             "app_root": "/var/www/html", "unsupported_reason": None},
        ], "containers": [], "reverse_proxies": [], "confidence_legend": {}},
        "gaps": [],
        "redactions": 0,
    }
