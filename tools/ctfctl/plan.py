"""Detection -> plan. A plan is content-addressed, immutable JSON.

The plan is the only thing `apply` will execute, and `apply` re-validates every
precondition immediately before mutating. A plan never contains a shell string,
never contains secret values, and always carries: the evidence that produced it,
the exact diff, the validations that must pass, the follow-up effects, the
verification steps, and the rollback description.

Authorization is a first-class field:
    scope=fixture-local   -> paths/containers clearly belonging to this repo
    scope=team-owned      -> declared in state/targets.json by a teammate
    scope=undeclared      -> read-only; mutations are refused
Unknown event rules do not block read-only work or fixture practice.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import actions as actions_mod
from . import profiles as profiles_mod
from . import util

PLAN_SCHEMA = "ctfctl.plan/1"
PLANS_DIRNAME = os.path.join("state", "plans")
TARGETS_REL = os.path.join("state", "targets.json")
POLICY_REL = os.path.join("state", "policy.json")
FIXTURE_MARKERS = ("fixtures/", "fixtures\\", "ctf-buddy", "ctfdemo", "notehub")


# --------------------------------------------------------------------------
# Authorization
# --------------------------------------------------------------------------
@dataclass
class Authorization:
    scope: str = "undeclared"
    reason: str = ""
    declaration: Optional[Dict[str, Any]] = None
    policy_acknowledged: bool = False
    policy_notes: List[str] = field(default_factory=list)

    @property
    def allows_mutation(self) -> bool:
        if self.scope == "fixture-local":
            return True
        if self.scope == "team-owned" and self.policy_acknowledged:
            return True
        return False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.scope,
            "reason": self.reason,
            "allows_mutation": self.allows_mutation,
            "policy_acknowledged": self.policy_acknowledged,
            "policy_notes": self.policy_notes,
            "declaration": self.declaration,
        }


def resolve_authorization(root: str, *, paths: List[str], compose_projects: List[str],
                          allow_fixture: bool = True) -> Authorization:
    declarations: List[Dict[str, Any]] = []
    targets_path = os.path.join(root, TARGETS_REL)
    if os.path.isfile(targets_path):
        payload = util.load_json(targets_path, {})
        if isinstance(payload, dict):
            declarations = list(payload.get("targets") or [])
        elif isinstance(payload, list):
            declarations = payload
    policy_path = os.path.join(root, POLICY_REL)
    policy = util.load_json(policy_path, {}) if os.path.isfile(policy_path) else {}
    acknowledged = bool(policy.get("acknowledged")) if isinstance(policy, dict) else False
    notes = [str(n) for n in (policy.get("notes") or [])] if isinstance(policy, dict) else []

    matched: Optional[Dict[str, Any]] = None
    for declaration in declarations:
        if not isinstance(declaration, dict):
            continue
        if declaration.get("path") and any(
            os.path.abspath(str(declaration["path"])) == os.path.abspath(p) for p in paths
        ):
            matched = declaration
            break
        if declaration.get("compose_project") and str(declaration["compose_project"]) in \
                compose_projects:
            matched = declaration
            break
        for pattern in declaration.get("path_globs") or []:
            import fnmatch

            if any(fnmatch.fnmatch(p, str(pattern)) for p in paths):
                matched = declaration
                break
    if matched:
        return Authorization(
            scope="team-owned",
            reason=f"declared in {TARGETS_REL} as {matched.get('label') or matched.get('name')}",
            declaration=matched,
            policy_acknowledged=acknowledged,
            policy_notes=notes,
        )
    if allow_fixture:
        fixture_hit = None
        for path in paths:
            lowered = path.replace(os.sep, "/").lower()
            if any(marker.lower() in lowered for marker in FIXTURE_MARKERS):
                fixture_hit = path
                break
        if fixture_hit:
            return Authorization(
                scope="fixture-local",
                reason=f"target path is inside this repository's disposable fixtures ({fixture_hit})",
                policy_acknowledged=True,
                policy_notes=["fixture-local work is always allowed by the project rules"],
            )
        for project in compose_projects:
            if project and any(marker in project.lower() for marker in ("fixture", "ctfdemo",
                                                                       "notehub", "drill")):
                return Authorization(
                    scope="fixture-local",
                    reason=f"compose project {project!r} is a drill fixture",
                    policy_acknowledged=True,
                )
    return Authorization(
        scope="undeclared",
        reason=(
            "no authorization found. Read-only work is unaffected. To plan a mutation, add the "
            f"target to {TARGETS_REL} with its path or compose project, and acknowledge the "
            f"event policy in {POLICY_REL}."
        ),
        policy_acknowledged=acknowledged,
        policy_notes=notes,
    )


# --------------------------------------------------------------------------
# Preconditions
# --------------------------------------------------------------------------
def file_precondition(path: str, *, protected: bool = True) -> Dict[str, Any]:
    state = util.capture_file_state(path)
    data = state.as_dict()
    data["kind"] = "file"
    data["protected"] = protected
    return data


def boot_precondition(root: str = "/") -> Dict[str, Any]:
    boot = ""
    candidate = os.path.join(root, "proc/sys/kernel/random/boot_id") if root != "/" else \
        "/proc/sys/kernel/random/boot_id"
    if os.path.isfile(candidate):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                boot = fh.read().strip()
        except OSError:
            boot = ""
    return {"kind": "boot_id", "value": boot}


def container_precondition(name: str, docker: Optional[str] = None) -> Dict[str, Any]:
    docker = docker or util.which("docker")
    if not docker:
        return {"kind": "container", "name": name, "available": False}
    res = util.run([docker, "inspect", "--format",
                    "{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.RestartCount}}", name],
                   timeout=20)
    if not res.ok:
        return {"kind": "container", "name": name, "available": False,
                "error": util.printable(res.stderr.strip(), 200)}
    parts = res.stdout.strip().split("|")
    return {
        "kind": "container",
        "name": name,
        "available": True,
        "id": parts[0] if parts else "",
        "image": parts[1] if len(parts) > 1 else "",
        "started_at": parts[2] if len(parts) > 2 else "",
        "restart_count": parts[3] if len(parts) > 3 else "",
    }


def compose_precondition(compose_argv: List[str], compose_file: str) -> Dict[str, Any]:
    directory = os.path.dirname(os.path.abspath(compose_file)) or "."
    res = util.run(list(compose_argv) + ["-f", compose_file, "config", "--format", "json"],
                   timeout=45, cwd=directory, max_output=4 * 1024 * 1024)
    if not res.ok:
        return {"kind": "compose_config", "file": compose_file, "available": False,
                "error": util.printable(res.stderr.strip(), 300)}
    return {
        "kind": "compose_config",
        "file": compose_file,
        "available": True,
        "digest": util.sha256_text(res.stdout.strip()),
        "service_count": len((json.loads(res.stdout).get("services") or {}))
        if res.stdout.strip().startswith("{") else None,
    }


def listener_precondition(port: int, address: str = "") -> Dict[str, Any]:
    return {"kind": "listener", "port": port, "address": address}


# --------------------------------------------------------------------------
# Plan
# --------------------------------------------------------------------------
@dataclass
class PlanAction:
    key: str
    action_id: str
    params: Dict[str, Any]
    eligibility: str
    diff: str = ""
    notes: List[str] = field(default_factory=list)
    validation: List[Dict[str, Any]] = field(default_factory=list)
    effects: List[Dict[str, Any]] = field(default_factory=list)
    target_path: str = ""
    pre_state: Dict[str, Any] = field(default_factory=dict)
    candidate_text: Optional[str] = None  # kept only in memory, never written to the plan file
    skipped_reason: str = ""

    def as_dict(self, include_candidate: bool = False) -> Dict[str, Any]:
        out = {
            "key": self.key,
            "action_id": self.action_id,
            "params": self.params,
            "eligibility": self.eligibility,
            "diff": self.diff,
            "notes": self.notes,
            "validation": self.validation,
            "effects": self.effects,
            "target_path": self.target_path,
            "pre_state": self.pre_state,
            "skipped_reason": self.skipped_reason,
        }
        if include_candidate and self.candidate_text is not None:
            out["candidate_sha256"] = util.sha256_text(self.candidate_text)
        return out


@dataclass
class Plan:
    plan_id: str
    created_at: str
    schema: str
    profile_id: str
    profile_support_level: str
    authorization: Dict[str, Any]
    detection: Dict[str, Any]
    preconditions: List[Dict[str, Any]]
    actions: List[PlanAction]
    verifiers: List[Dict[str, Any]]
    exploit_probe: Optional[Dict[str, Any]]
    rollback: Dict[str, Any]
    risks: List[str]
    skipped: List[Dict[str, Any]]
    host_fingerprint: Dict[str, Any]
    notes: List[str]
    inventory_digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        body = {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "created_at": self.created_at,
            "profile": self.profile_id,
            "profile_support_level": self.profile_support_level,
            "authorization": self.authorization,
            "detection": self.detection,
            "host_fingerprint": self.host_fingerprint,
            "preconditions": self.preconditions,
            "actions": [a.as_dict() for a in self.actions],
            "verifiers": self.verifiers,
            "exploit_probe": self.exploit_probe,
            "rollback": self.rollback,
            "risks": self.risks,
            "skipped": self.skipped,
            "notes": self.notes,
            "inventory_digest": self.inventory_digest,
        }
        return body

    def save(self, root: Optional[str] = None) -> str:
        root = root or util.repo_root()
        directory = os.path.join(root, PLANS_DIRNAME)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        path = os.path.join(directory, f"{self.plan_id.replace('sha256:', '')}.json")
        util.write_text_atomic(path, util.dump_json(self.as_dict()), mode=0o600)
        util.write_text_atomic(os.path.join(directory, "latest"),
                               self.plan_id.replace("sha256:", "") + "\n", mode=0o600)
        return path

    def can_mutate(self) -> Tuple[bool, str]:
        if not self.authorization.get("allows_mutation"):
            return False, str(self.authorization.get("reason") or "authorization missing")
        live = [a for a in self.actions if not a.skipped_reason]
        if not live:
            return False, "the plan contains no applicable action"
        return True, ""

    def automatic_actions(self) -> List[PlanAction]:
        return [a for a in self.actions if a.eligibility == "auto" and not a.skipped_reason]

    def review_actions(self) -> List[PlanAction]:
        return [a for a in self.actions if a.eligibility != "auto" and not a.skipped_reason]


def load_plan(plan_id: str, root: Optional[str] = None) -> Plan:
    root = root or util.repo_root()
    directory = os.path.join(root, PLANS_DIRNAME)
    if plan_id in ("latest", ""):
        latest_path = os.path.join(directory, "latest")
        if not os.path.isfile(latest_path):
            raise util.CtfError("no plans have been generated yet",
                                hint="run: ctfctl plan")
        plan_id = util.read_text(latest_path).strip()
    candidate = os.path.join(directory, f"{plan_id.replace('sha256:', '')}.json")
    if not os.path.isfile(candidate):
        raise util.CtfError(f"plan not found: {plan_id}")
    payload = util.load_json(candidate, {})
    return _plan_from_dict(payload, candidate)


def _plan_from_dict(payload: Dict[str, Any], path: str) -> Plan:
    actions = []
    for item in payload.get("actions") or []:
        actions.append(PlanAction(
            key=str(item.get("key", "")),
            action_id=str(item.get("action_id", "")),
            params=item.get("params") or {},
            eligibility=str(item.get("eligibility", "review-only")),
            diff=str(item.get("diff", "")),
            notes=[str(n) for n in item.get("notes") or []],
            validation=list(item.get("validation") or []),
            effects=list(item.get("effects") or []),
            target_path=str(item.get("target_path", "")),
            pre_state=item.get("pre_state") or {},
            candidate_text=None,
            skipped_reason=str(item.get("skipped_reason", "")),
        ))
    return Plan(
        plan_id=str(payload.get("plan_id", "")),
        created_at=str(payload.get("created_at", "")),
        schema=str(payload.get("schema", PLAN_SCHEMA)),
        profile_id=str(payload.get("profile", "")),
        profile_support_level=str(payload.get("profile_support_level", "")),
        authorization=payload.get("authorization") or {},
        detection=payload.get("detection") or {},
        preconditions=list(payload.get("preconditions") or []),
        actions=actions,
        verifiers=list(payload.get("verifiers") or []),
        exploit_probe=payload.get("exploit_probe"),
        rollback=payload.get("rollback") or {},
        risks=[str(r) for r in payload.get("risks") or []],
        skipped=list(payload.get("skipped") or []),
        host_fingerprint=payload.get("host_fingerprint") or {},
        notes=[str(n) for n in payload.get("notes") or []],
        inventory_digest=str(payload.get("inventory_digest") or ""),
    )


# --------------------------------------------------------------------------
# Plan construction
# --------------------------------------------------------------------------
def build_plan(profile: profiles_mod.Profile, inventory: Dict[str, Any], *,
               root: Optional[str] = None, allow_fixture: bool = True) -> Plan:
    root = root or util.repo_root()
    detection = profiles_mod.detect(profile, inventory)
    risks: List[str] = []
    skipped: List[Dict[str, Any]] = []
    actions: List[PlanAction] = []
    preconditions: List[Dict[str, Any]] = []
    host = inventory.get("host") or {}

    if not detection.matched:
        plan = Plan(
            plan_id="", created_at=util.iso_now(), schema=PLAN_SCHEMA,
            profile_id=profile.profile_id, profile_support_level=profile.support_level,
            authorization={"scope": "n/a", "reason": "no detection, no plan",
                            "allows_mutation": False},
            detection=detection.as_dict(), preconditions=[], actions=[], verifiers=[],
            exploit_probe=None,
            rollback={"description": "nothing to roll back"},
            risks=["no action proposed: the stack was not identified with enough evidence"],
            skipped=[{"reason": r} for r in detection.reasons],
            host_fingerprint=_fingerprint(host),
            notes=profile.notes,
        )
        plan.plan_id = _plan_id(plan)
        return plan

    facts = detection.facts
    paths: List[str] = []
    compose_projects: List[str] = []
    if facts.get("compose_project"):
        compose_projects.append(str(facts["compose_project"]))

    for key, spec in profile.actions.items():
        action_id = str(spec.get("action_id"))
        try:
            action = actions_mod.get(action_id)
        except actions_mod.ActionError as exc:
            skipped.append({"key": key, "reason": str(exc)})
            continue
        params = profiles_mod.substitute(spec.get("params") or {}, facts)
        unresolved = profiles_mod.unresolved_tokens(params)
        if unresolved:
            skipped.append({"key": key,
                            "reason": f"unresolved fact token(s): {unresolved}"})
            continue
        problems = action.preflight(params)
        if problems:
            skipped.append({"key": key, "reason": "; ".join(problems)})
            continue
        target_path = str(params.get("path") or params.get("file") or "")
        if target_path:
            paths.append(target_path)
        eligibility = str(spec.get("eligibility", action.eligibility))
        entry = PlanAction(
            key=key, action_id=action_id, params=params, eligibility=eligibility,
            target_path=target_path,
            effects=[e.__dict__ for e in
                     profiles_mod.effects_from_spec(spec, profile, facts)],
        )
        if not os.path.isfile(target_path) and action.kind == "file_edit":
            entry.skipped_reason = f"target file not found: {target_path}"
            skipped.append({"key": key, "reason": entry.skipped_reason})
            actions.append(entry)
            continue
        ctx = actions_mod.ActionContext(
            root=root, target_path=target_path, profile_id=profile.profile_id,
        )
        if target_path and os.path.isfile(target_path):
            ctx.pre_text, ctx.pre_newline = util.read_text_preserving(target_path, 4 * 1024 * 1024)
            ctx.pre_state = util.capture_file_state(target_path)
            expected = params.get("expect_sha256")
            if expected and ctx.pre_state.sha256 != expected:
                entry.skipped_reason = (
                    f"file hash does not match the profile expectation "
                    f"(expected {str(expected)[:12]}..., found {ctx.pre_state.sha256[:12]}...)"
                )
                skipped.append({"key": key, "reason": entry.skipped_reason})
                actions.append(entry)
                continue
            entry.pre_state = ctx.pre_state.as_dict()
        try:
            candidate = action.render(ctx, params)
        except actions_mod.ActionError as exc:
            entry.skipped_reason = str(exc)
            skipped.append({"key": key, "reason": f"{key}: {exc}"})
            actions.append(entry)
            continue
        if candidate is None:
            entry.skipped_reason = "the target already satisfies the intended state (no-op)"
            skipped.append({"key": key, "reason": entry.skipped_reason})
            actions.append(entry)
            continue
        entry.candidate_text = candidate.new_text
        entry.diff = candidate.diff
        entry.notes = candidate.notes
        try:
            checks = action.validate(ctx, params, candidate)
        except actions_mod.ActionError as exc:
            entry.skipped_reason = str(exc)
            skipped.append({"key": key, "reason": f"{key}: {exc}"})
            actions.append(entry)
            continue
        entry.validation = [c.as_dict() for c in checks]
        failed = [c for c in checks if c.required and not c.ok]
        if failed:
            entry.skipped_reason = "candidate validation failed: " + "; ".join(
                f"{c.name}: {c.detail}" for c in failed
            )
            skipped.append({"key": key, "reason": entry.skipped_reason})
        actions.append(entry)

    # Preconditions: only for actions that will actually run.
    live_actions = [a for a in actions if not a.skipped_reason]
    for entry in live_actions:
        if entry.target_path and os.path.isfile(entry.target_path):
            preconditions.append(file_precondition(entry.target_path))
    preconditions.append(boot_precondition())
    container_name = facts.get("container_name")
    if container_name:
        preconditions.append(container_precondition(str(container_name)))
    compose_file = facts.get("compose_file")
    compose_argv = ["docker", "compose"]
    if compose_file:
        preconditions.append(compose_precondition(compose_argv, str(compose_file)))
    host_port = facts.get("host_port")
    if host_port:
        preconditions.append(listener_precondition(int(host_port)))

    authorization = resolve_authorization(
        root, paths=paths, compose_projects=compose_projects, allow_fixture=allow_fixture
    )

    if profile.support_level != "tested-auto":
        for entry in actions:
            if entry.eligibility == "auto":
                entry.eligibility = "review-only"
                entry.notes.append(
                    "downgraded to review-only: this profile has not passed the disposable-VM "
                    "test matrix, so automatic application is not authorised"
                )
    if not authorization.allows_mutation:
        risks.append(
            "authorization: " + str(authorization.reason)
        )

    verifiers = []
    for item in profile.verifiers or []:
        params = profiles_mod.substitute(item.get("params") or {}, facts)
        # `{note_id}`-style tokens produced by an earlier workflow step are local
        # to the verifier, not unresolved profile facts.
        local_tokens = profiles_mod._extracted_tokens(params)
        unresolved = [t for t in profiles_mod.unresolved_tokens(params) if t not in local_tokens]
        if unresolved:
            skipped.append({"key": item.get("verifier"), "reason": f"unresolved tokens {unresolved}"})
            continue
        verifiers.append({
            "verifier": item.get("verifier"),
            "tier": item.get("tier", "protocol"),
            "params": params,
            "description": item.get("description", ""),
        })
    exploit_probe = None
    if profile.exploit_probe:
        params = profiles_mod.substitute(profile.exploit_probe.get("params") or {}, facts)
        if not profiles_mod.unresolved_tokens(params):
            exploit_probe = {
                "verifier": profile.exploit_probe.get("verifier"),
                "params": params,
                "description": profile.exploit_probe.get("description", ""),
            }

    risks.extend(_risks_for(live_actions, profile))
    plan = Plan(
        plan_id="",
        created_at=util.iso_now(),
        schema=PLAN_SCHEMA,
        profile_id=profile.profile_id,
        profile_support_level=profile.support_level,
        authorization=authorization.as_dict(),
        detection=detection.as_dict(),
        preconditions=preconditions,
        actions=actions,
        verifiers=verifiers,
        exploit_probe=exploit_probe,
        rollback={
            "description": (
                "Each file action stores a bounded pre-image inside its transaction directory "
                "(mode 0700) before the atomic replace. Rollback restores exactly those files "
                "and only if they still match this plan's post-image hash. Service effects are "
                "reversed by restarting the same service; no volume, database or user data is "
                "ever restored or deleted."
            ),
            "preserves": ["named volumes", "container data mounts", "files not named by this plan"],
            "refuses_when": ["the target file changed after apply",
                             "the transaction directory is incomplete or tampered with"],
        },
        risks=risks,
        skipped=skipped,
        host_fingerprint=_fingerprint(host),
        notes=list(profile.notes),
        inventory_digest=util.sha256_text(json.dumps(
            {"graph": inventory.get("graph"), "generated_at": inventory.get("generated_at")},
            sort_keys=True)),
    )
    plan.plan_id = _plan_id(plan)
    return plan


# --------------------------------------------------------------------------
# Lockdown plan (host firewall + sshd), review-only by construction
# --------------------------------------------------------------------------
LOCKDOWN_PROFILE_ID = "local-lockdown"


@dataclass
class LockdownSpec:
    """Operator-supplied parameters for one lockdown plan.

    Everything here is explicit input, never inferred: the whole point of the
    plan is that a human chose the allowlist before the box was locked down.
    """

    operator_cidr: str
    allow_cidrs: List[str]
    allow_tcp_ports: List[int]
    allow_udp_ports: List[int] = field(default_factory=list)
    include_firewall: bool = True
    include_ssh: bool = True
    log_drops: bool = False
    nft_path: str = "/etc/ctfctl-lockdown.nft"
    table: str = "ctfctl_lockdown"
    sshd_path: str = "/etc/ssh/sshd_config"
    authorized_keys_path: str = "/root/.ssh/authorized_keys"
    service_unit: str = "ssh"
    sshd_port: int = 22
    note: str = ""


def normalize_cidrs(values: Any, *, what: str = "allowlist entry") -> List[str]:
    """Accept `10.0.0.5` as well as `10.0.0.0/24`, and refuse anything else.

    A bare address becomes a /32 (or /128): the firewall grammar needs a prefix,
    and silently dropping a malformed entry would weaken the allowlist.
    """
    import ipaddress

    out: List[str] = []
    items = [values] if isinstance(values, str) else list(values or [])
    for raw in items:
        text = str(raw).strip()
        if not text:
            continue
        try:
            if "/" in text:
                out.append(str(ipaddress.ip_network(text, strict=False)))
            else:
                address = ipaddress.ip_address(text)
                out.append(f"{address}/{'32' if address.version == 4 else '128'}")
        except ValueError as exc:
            raise util.CtfError(
                f"{what} {text!r} is not an IP address or network: {exc}",
                hint="use a CIDR such as 10.10.0.0/16, or a single address such as 10.10.5.9",
            )
    return list(dict.fromkeys(out))


def _lockdown_profile(spec: LockdownSpec) -> profiles_mod.Profile:
    """Build an in-code profile. No detection predicate: the operator asked for it."""
    # The operator's own address is always in the allowlist, whatever was passed:
    # a lockdown that locks out the person applying it is a self-inflicted zero.
    operator_cidr = normalize_cidrs([spec.operator_cidr], what="operator address")[0]
    allow_cidrs = normalize_cidrs(list(spec.allow_cidrs) + [operator_cidr])
    facts: Dict[str, Any] = {
        "allow_cidrs_list": allow_cidrs,
        "nft_path": spec.nft_path,
        "table": spec.table,
        "allow_cidrs": ",".join(allow_cidrs),
        "operator_cidr": operator_cidr,
        # "none" rather than "": facts must be resolved to something non-empty,
        # and the action parses "none" back to an empty port set.
        "allow_tcp_ports": ",".join(str(p) for p in spec.allow_tcp_ports) or "none",
        "allow_udp_ports": ",".join(str(p) for p in spec.allow_udp_ports) or "none",
        "log_drops": spec.log_drops,
        "note": spec.note or f"lockdown requested by the operator ({operator_cidr})",
        "sshd_path": spec.sshd_path,
        "authorized_keys_path": spec.authorized_keys_path,
        "service_unit": spec.service_unit,
    }
    actions: Dict[str, Any] = {}
    if spec.include_firewall:
        actions["firewall"] = {
            "action_id": "firewall.nft_lockdown_table",
            "eligibility": "review-only",
            "params": {
                "path": "{nft_path}",
                "table": "{table}",
                "allow_cidrs": "{allow_cidrs}",
                "operator_cidr": "{operator_cidr}",
                "allow_tcp_ports": "{allow_tcp_ports}",
                "allow_udp_ports": "{allow_udp_ports}",
                "log_drops": "{log_drops}",
                "note": "{note}",
            },
            "effects": [{
                "kind": "nft_load_file",
                "argv": ["nft", "-f", "{nft_path}"],
                "rollback_argv": ["nft", "delete", "table", "inet", "{table}"],
                "description": "load the additive lockdown table",
                "timeout": 30,
            }],
        }
    if spec.include_ssh:
        actions["sshd"] = {
            "action_id": "sshd.harden_authenticated_keys",
            "eligibility": "review-only",
            "params": {
                "path": "{sshd_path}",
                "authorized_keys_path": "{authorized_keys_path}",
                "permit_root_login": "prohibit-password",
                "disable_password_auth": True,
                "disable_keyboard_interactive": True,
                "service_unit": "{service_unit}",
            },
        }
    verifiers: List[Dict[str, Any]] = [
        {"verifier": "tcp.connect", "tier": "protocol",
         "params": {"host": "127.0.0.1", "port": spec.sshd_port},
         "description": "the box still accepts SSH connections"},
    ]
    if spec.include_firewall:
        verifiers.append({
            "verifier": "nft.table", "tier": "protocol",
            "params": {"table": spec.table, "family": "inet"},
            "description": "the lockdown table is loaded in the running ruleset",
        })
    if spec.include_ssh:
        verifiers.append({
            "verifier": "sshd.option", "tier": "protocol",
            "params": {"option": "passwordauthentication", "value": "no"},
            "description": "sshd reports password authentication as disabled",
        })
    return profiles_mod.Profile(
        profile_id=LOCKDOWN_PROFILE_ID,
        title="Operator-requested lockdown (additive nftables allowlist + sshd key-only)",
        scope="host",
        support_level="review-only",
        requires=["root on the host", "nft for the firewall action", "an out-of-band console"],
        detect={"all": []},
        facts=facts,
        actions=actions,
        verifiers=verifiers,
        exploit_probe=None,
        notes=[
            "Every action here is review-only: read the diff before approving.",
            "The operator's own SSH source CIDR is in the firewall allowlist by construction.",
            "IPv6 inbound is dropped unless an IPv6 allowlist entry is supplied.",
            "Rollback deletes the added nftables table and restores sshd_config.",
            "The generated nftables file is not auto-loaded at boot on every distro: "
            "re-apply after a reboot, or wire it into the distro's own loader.",
        ],
    )


def build_lockdown_plan(spec: LockdownSpec, inventory: Dict[str, Any], *,
                        root: Optional[str] = None,
                        allow_fixture: bool = True) -> Plan:
    """Build a review-only lockdown plan against a discovery inventory."""
    if not spec.include_firewall and not spec.include_ssh:
        raise util.CtfError(
            "nothing to plan: enable the firewall action, the sshd action, or both"
        )
    profile = _lockdown_profile(spec)
    plan = build_plan(profile, inventory, root=root, allow_fixture=allow_fixture)
    if not plan.actions:
        plan.risks.append(
            "no lockdown action could be rendered; see the skipped entries for the reason"
        )
    _prune_lockdown_verifiers(plan, inventory, spec)
    return plan


def _prune_lockdown_verifiers(plan: Plan, inventory: Dict[str, Any],
                              spec: LockdownSpec) -> None:
    """Keep only checks that describe this host, and only for live actions.

    A verifier that cannot pass is not a safety net, it is a guaranteed
    auto-rollback: `tcp.connect 22` would fail on a box whose sshd is stopped or
    listens elsewhere, and the readiness gate would then undo a correct lockdown.
    """
    live_keys = {action.key for action in plan.actions if not action.skipped_reason}
    listening: set = set()
    for service in ((inventory.get("graph") or {}).get("services") or []):
        try:
            listening.add(int(service.get("port")))
        except (TypeError, ValueError):
            continue
    kept: List[Dict[str, Any]] = []
    for verifier in plan.verifiers:
        name = str(verifier.get("verifier"))
        params = verifier.get("params") or {}
        if name == "nft.table" and "firewall" not in live_keys:
            plan.skipped.append({"key": name, "reason": "the firewall action was not rendered"})
            continue
        if name == "sshd.option" and "sshd" not in live_keys:
            plan.skipped.append({"key": name, "reason": "the sshd action was not rendered"})
            continue
        if name == "tcp.connect":
            port = int(params.get("port") or 0)
            if port not in listening:
                plan.skipped.append({
                    "key": name,
                    "reason": f"nothing is listening on port {port} on this host, so there is "
                              "no listener to re-check after the change",
                })
                continue
        kept.append(verifier)
    plan.verifiers = kept


def _fingerprint(host: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("kernel", "arch", "os_id", "os_version_id", "init_system", "boot_id")
    return {key: host.get(key) for key in keys}


def _risks_for(actions: Sequence[PlanAction], profile: profiles_mod.Profile) -> List[str]:
    risks: List[str] = []
    for entry in actions:
        spec = actions_mod.ACTIONS.get(entry.action_id)
        if spec is None:
            continue
        if spec.impact:
            risks.append(f"{entry.key}: {spec.impact}")
    if any(e.eligibility == "auto" for e in actions):
        risks.append(
            "Automatic application is limited to actions this repository has already exercised "
            "against the disposable fixture for this exact profile."
        )
    for note in profile.notes:
        risks.append(f"profile note: {note}")
    return risks


def _plan_id(plan: Plan) -> str:
    body = plan.as_dict()
    body.pop("plan_id", None)
    body.pop("created_at", None)
    return "sha256:" + util.sha256_text(json.dumps(body, sort_keys=True))


# --------------------------------------------------------------------------
# Staleness
# --------------------------------------------------------------------------
def check_stale(plan: Plan, root: Optional[str] = None) -> List[str]:
    """Re-verify every precondition. Any mismatch means: do not apply."""
    root = root or util.repo_root()
    problems: List[str] = []
    for precondition in plan.preconditions:
        kind = precondition.get("kind")
        if kind == "file":
            path = precondition.get("path") or ""
            current = util.capture_file_state(path)
            if not current.exists and precondition.get("exists"):
                problems.append(f"file disappeared: {path}")
                continue
            if current.sha256 != precondition.get("sha256"):
                problems.append(
                    f"file content changed since the plan was made: {path} "
                    f"(planned {str(precondition.get('sha256'))[:12]}..., "
                    f"now {current.sha256[:12]}...)"
                )
            if current.mode != precondition.get("mode"):
                problems.append(
                    f"file mode changed: {path} "
                    f"({oct(int(precondition.get('mode') or 0))} -> {oct(current.mode)})"
                )
            if precondition.get("is_symlink") != current.is_symlink:
                problems.append(f"symlink state changed: {path}")
        elif kind == "boot_id":
            live = boot_precondition()["value"]
            if live and precondition.get("value") and live != precondition.get("value"):
                problems.append("the host rebooted since the plan was made")
        elif kind == "container":
            name = precondition.get("name") or ""
            current = container_precondition(name)
            if precondition.get("available") and not current.get("available"):
                problems.append(f"container {name} is no longer inspectable")
                continue
            if precondition.get("id") and current.get("id") and \
                    precondition["id"] != current["id"]:
                problems.append(
                    f"container {name} was recreated since the plan was made "
                    "(container id changed)"
                )
        elif kind == "compose_config":
            compose_file = precondition.get("file") or ""
            if not os.path.isfile(compose_file):
                problems.append(f"compose file missing: {compose_file}")
                continue
            current = compose_precondition(["docker", "compose"], compose_file)
            if precondition.get("available") and current.get("available") and \
                    precondition.get("digest") != current.get("digest"):
                problems.append(
                    f"resolved Compose configuration changed since the plan was made: "
                    f"{compose_file}"
                )
        elif kind == "listener":
            port = precondition.get("port")
            if not _port_listening(int(port or 0)):
                problems.append(f"port {port} is no longer listening")
    return problems


def _port_listening(port: int) -> bool:
    import socket as _socket

    for family, address in ((_socket.AF_INET, "127.0.0.1"), (_socket.AF_INET6, "::1")):
        try:
            with _socket.socket(family, _socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                if sock.connect_ex((address, port)) == 0:
                    return True
        except OSError:
            continue
    return False


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def render(plan: Plan, *, verbose: bool = False) -> str:
    lines: List[str] = []
    auth = plan.authorization
    lines.append(f"plan      {plan.plan_id}")
    lines.append(f"profile   {plan.profile_id}  support={plan.profile_support_level}")
    lines.append(f"scope     {auth.get('scope')}  mutation_allowed={auth.get('allows_mutation')}")
    lines.append(f"reason    {auth.get('reason')}")
    detection = plan.detection or {}
    lines.append("")
    lines.append("detection evidence:")
    for item in (detection.get("evidence") or [])[:10]:
        lines.append(f"  + {util.printable(item, 160)}")
    for reason in (detection.get("reasons") or [])[:6]:
        lines.append(f"  - not matched: {util.printable(reason, 160)}")
    lines.append("")
    if not plan.actions:
        lines.append("no actions proposed for this profile.")
    for entry in plan.actions:
        status = "SKIPPED" if entry.skipped_reason else f"[{entry.eligibility}]"
        lines.append(f"action    {entry.key}  {entry.action_id}  {status}")
        if entry.skipped_reason:
            lines.append(f"          reason: {util.printable(entry.skipped_reason, 300)}")
            continue
        lines.append(f"          target: {entry.target_path}")
        for note in entry.notes:
            lines.append(f"          note:   {note}")
        if entry.diff:
            lines.append("          diff:")
            for diff_line in entry.diff.splitlines():
                lines.append(f"            {util.printable(diff_line, 200)}")
        for check in entry.validation:
            mark = "ok  " if check.get("ok") else "FAIL"
            lines.append(f"          validate {mark} {check.get('name')}: "
                         f"{util.printable(str(check.get('detail')), 160)}")
        for effect in entry.effects:
            lines.append(f"          effect: {effect.get('description')} "
                         f"({' '.join(effect.get('argv') or [])})")
    if plan.verifiers:
        lines.append("")
        lines.append("verification plan (our checks; not proof the organiser checker passes):")
        for verifier in plan.verifiers:
            lines.append(f"  [{verifier.get('tier')}] {verifier.get('verifier')} "
                         f"{util.printable(json.dumps(verifier.get('params')), 200)}")
    if plan.exploit_probe:
        lines.append(f"  [negative] {plan.exploit_probe.get('verifier')} "
                     f"{util.printable(json.dumps(plan.exploit_probe.get('params')), 200)}")
    if plan.skipped:
        lines.append("")
        lines.append("skipped / not attempted:")
        for item in plan.skipped:
            lines.append(f"  - {util.printable(str(item.get('reason')), 220)}")
    lines.append("")
    lines.append("risks:")
    for risk in plan.risks:
        lines.append(f"  ! {util.printable(risk, 220)}")
    lines.append("")
    lines.append("rollback: " + util.printable(str(plan.rollback.get("description")), 400))
    if verbose:
        lines.append("")
        lines.append("preconditions:")
        for precondition in plan.preconditions:
            lines.append("  " + util.printable(json.dumps(precondition), 240))
    return "\n".join(lines)
