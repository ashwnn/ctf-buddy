"""Profile loading, validation and declarative detection.

A profile is data. It names:

  * `detect`  -- a list of predicate items evaluated against a discovery
                 inventory. Predicates are drawn from a fixed allowlist; a
                 profile cannot introduce new behaviour, only new combinations.
  * `facts`   -- values extracted from the matched evidence (compose file path,
                 service name, host port, ...) used to fill action and verifier
                 parameters via `{fact}` substitution.
  * `actions` -- allowlisted action ids with structured parameters, effects and
                 an eligibility level. Only `auto` actions may run under
                 `--yes`; everything else needs explicit operator approval.
  * `verifiers` -- tiered checks: liveness, protocol, functional workflow, and
                 the negative exploit probe.

Detection is broader than mutation support on purpose: a profile may be able to
*recognise* a stack and still have no tested action for it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import actions as actions_mod
from . import util

PROFILE_SCHEMA = "ctfctl.profile/1"
SUPPORT_LEVELS = ("tested-auto", "tested-review-only", "detection-only")
ELIGIBILITY = ("auto", "review-only", "refused")
EFFECT_KINDS = ("compose_restart", "compose_up", "systemd_reload", "systemd_restart",
                "none")
EFFECT_REQUIRES = {
    "compose_restart": ["docker"],
    "compose_up": ["docker"],
    "systemd_reload": ["systemctl"],
    "systemd_restart": ["systemctl"],
    "none": [],
}

FACT_TOKEN = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


# --------------------------------------------------------------------------
# Detection predicates
# --------------------------------------------------------------------------
PredicateFn = Callable[[Dict[str, Any], Dict[str, Any], Dict[str, Any]],
                       Tuple[bool, List[str], Optional[str]]]


def _iter_containers(inventory: Dict[str, Any]):
    graph = inventory.get("graph") or {}
    for container in graph.get("containers") or []:
        yield container


def _iter_services(inventory: Dict[str, Any]):
    graph = inventory.get("graph") or {}
    for service in graph.get("services") or []:
        yield service


def pred_container_running(args: Dict[str, Any], inventory: Dict[str, Any],
                           ctx: Dict[str, Any]):
    wanted_name = args.get("name_regex")
    wanted_image = args.get("image_regex")
    wanted_service = args.get("compose_service_regex")
    wanted_project = args.get("compose_project")
    evidence: List[str] = []
    matched_container = None
    for container in _iter_containers(inventory):
        if wanted_name and not re.search(wanted_name, container.get("name") or ""):
            continue
        if wanted_image and not re.search(wanted_image, container.get("image") or "", re.I):
            continue
        if wanted_service and not re.search(wanted_service,
                                            container.get("compose_service") or ""):
            continue
        if wanted_project and container.get("compose_project") != wanted_project:
            continue
        if container.get("state") and container.get("state") != "running":
            continue
        matched_container = container
        evidence.append(
            f"container {container.get('name')} image={container.get('image')} "
            f"service={container.get('compose_service')} project={container.get('compose_project')}"
        )
        break
    if not matched_container:
        return False, [], "no running container matched the requested name/image/service pattern"
    # Facts must come from the container that actually satisfied detection, never
    # from whatever container happened to be listed first.
    ctx.setdefault("containers", []).append(matched_container)
    return True, evidence, None


def pred_listener_present(args: Dict[str, Any], inventory: Dict[str, Any],
                          ctx: Dict[str, Any]):
    port = args.get("port")
    exposure = args.get("exposure")
    process_regex = args.get("process_regex")
    published_only = bool(args.get("published", False))
    # Scope listener evidence to the Compose project / container set that already
    # matched, so a second project on the same host cannot supply this profile's
    # port. Within one project a listener may belong to a sibling service (a
    # proxy publishing the port for the app), so project scope is the right unit.
    matched_containers = ctx.get("containers") or []
    scope_names = {c.get("name") for c in matched_containers if c.get("name")}
    scope_projects = {c.get("compose_project") for c in matched_containers
                      if c.get("compose_project")}
    evidence: List[str] = []
    for service in _iter_services(inventory):
        if port is not None and service.get("port") != port:
            continue
        if exposure and service.get("exposure") != exposure:
            continue
        if process_regex and not re.search(process_regex, service.get("process") or "", re.I):
            continue
        if published_only and not service.get("container"):
            continue
        if scope_names or scope_projects:
            owner = service.get("container") or {}
            if owner.get("name") not in scope_names and \
                    owner.get("compose_project") not in scope_projects:
                continue
        service_evidence = list(service.get("evidence") or [])
        if not service_evidence:
            continue
        evidence.extend(service_evidence)
        ctx.setdefault("listeners", []).append(service)
        return True, evidence, None
    return False, [], f"no listener matched port={port} exposure={exposure}"


def pred_process_present(args: Dict[str, Any], inventory: Dict[str, Any],
                         ctx: Dict[str, Any]):
    pattern = args.get("comm_regex", "")
    for item in inventory.get("evidence") or []:
        if item.get("kind") != "processes":
            continue
        for proc in item.get("data", {}).get("processes", []) or []:
            if re.search(pattern, proc.get("comm") or "", re.I):
                return True, [f"process '{proc.get('comm')}' pid={proc.get('pid')}"], None
    return False, [], f"no running process matched {pattern!r}"


def pred_unit_present(args: Dict[str, Any], inventory: Dict[str, Any], ctx: Dict[str, Any]):
    pattern = args.get("unit_regex", "")
    for item in inventory.get("evidence") or []:
        if item.get("kind") != "units":
            continue
        for unit in item.get("data", {}).get("units", []) or []:
            if re.search(pattern, unit.get("unit") or "", re.I):
                return True, [f"systemd unit {unit.get('unit')}"], None
    return False, [], f"no systemd unit matched {pattern!r}"


def pred_proxy_upstream(args: Dict[str, Any], inventory: Dict[str, Any],
                        ctx: Dict[str, Any]):
    kind = args.get("kind", "nginx")
    upstream_port = args.get("upstream_port")
    for item in inventory.get("evidence") or []:
        if item.get("kind") != "reverse_proxy":
            continue
        for proxy in item.get("data", {}).get("reverse_proxies", []) or []:
            if proxy.get("kind") != kind:
                continue
            blocks = proxy.get("servers") or proxy.get("vhosts") or []
            for block in blocks:
                for upstream in (block.get("proxy_pass") or block.get("proxypass") or []):
                    if upstream_port is None or f":{upstream_port}" in upstream:
                        return True, [f"{kind} {block.get('file')} -> {upstream}"], None
    return False, [], f"no {kind} upstream matched port {upstream_port}"


def pred_file_exists(args: Dict[str, Any], inventory: Dict[str, Any], ctx: Dict[str, Any]):
    pattern = args.get("path_glob") or args.get("path") or ""
    candidates: List[str] = []
    for item in inventory.get("evidence") or []:
        if item.get("kind") != "app_roots":
            continue
        for candidate in item.get("data", {}).get("candidates", []) or []:
            candidates.append(candidate.get("path") or "")
            for sample in candidate.get("sample") or []:
                candidates.append(os.path.join(candidate.get("path") or "", sample))
    import fnmatch

    for path in candidates:
        normalized = (path or "").replace("\\", "/")
        if normalized and (fnmatch.fnmatch(normalized, pattern)
                           or normalized.endswith(pattern.lstrip("*"))):
            return True, [f"path present in inventory: {normalized}"], None
    return False, [], (
        f"no path matching {pattern!r} was observed in the inventory "
        "(discovery only enumerates bounded samples)"
    )


def pred_tool_present(args: Dict[str, Any], inventory: Dict[str, Any], ctx: Dict[str, Any]):
    tool = args.get("tool", "")
    host = inventory.get("host") or {}
    tools = host.get("tools") or {}
    if tools.get(tool):
        return True, [f"{tool} available"], None
    return False, [], f"required tool {tool!r} is not installed"


def pred_os_family(args: Dict[str, Any], inventory: Dict[str, Any], ctx: Dict[str, Any]):
    wanted = set(args.get("ids") or [])
    host = inventory.get("host") or {}
    os_id = (host.get("os_id") or "").lower()
    if not wanted:
        return True, [], None
    if os_id in wanted:
        return True, [f"os-release ID={os_id}"], None
    return False, [], f"os {os_id or 'unknown'} not in {sorted(wanted)}"


PREDICATES: Dict[str, PredicateFn] = {
    "container_running": pred_container_running,
    "listener_present": pred_listener_present,
    "process_present": pred_process_present,
    "unit_present": pred_unit_present,
    "proxy_upstream": pred_proxy_upstream,
    "file_exists": pred_file_exists,
    "tool_present": pred_tool_present,
    "os_family": pred_os_family,
}


# --------------------------------------------------------------------------
# Profile model
# --------------------------------------------------------------------------
@dataclass
class Profile:
    profile_id: str
    title: str
    scope: str
    support_level: str
    requires: List[str]
    detect: Dict[str, Any]
    facts: Dict[str, Any]
    actions: Dict[str, Any]
    verifiers: List[Dict[str, Any]]
    exploit_probe: Optional[Dict[str, Any]]
    notes: List[str]
    path: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def automatic_actions(self) -> Dict[str, Any]:
        return {k: v for k, v in self.actions.items()
                if str(v.get("eligibility", "review-only")) == "auto"}

    def as_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "title": self.title,
            "scope": self.scope,
            "support_level": self.support_level,
            "requires": self.requires,
            "actions": self.actions,
            "verifiers": self.verifiers,
            "exploit_probe": self.exploit_probe,
            "notes": self.notes,
        }


@dataclass
class Detection:
    matched: bool
    profile_id: str
    evidence: List[str] = field(default_factory=list)
    facts: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile_id,
            "matched": self.matched,
            "evidence": self.evidence,
            "facts": self.facts,
            "reasons": self.reasons,
            "gaps": self.gaps,
        }


def profiles_dir(root: Optional[str] = None) -> str:
    return os.path.join(root or util.repo_root(), "profiles")


def load_all(root: Optional[str] = None) -> List[Profile]:
    directory = profiles_dir(root)
    out: List[Profile] = []
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        raw = util.load_json(path, {})
        if not isinstance(raw, dict) or raw.get("schema") != PROFILE_SCHEMA:
            continue
        out.append(_from_raw(raw, path))
    return out


def load(profile_id: str, root: Optional[str] = None) -> Profile:
    for profile in load_all(root):
        if profile.profile_id == profile_id:
            return profile
    known = ", ".join(sorted(p.profile_id for p in load_all(root))) or "none"
    raise util.CtfError(f"unknown profile {profile_id!r}", hint=f"available profiles: {known}")


def _from_raw(raw: Dict[str, Any], path: str) -> Profile:
    return Profile(
        profile_id=str(raw.get("profile_id", "")),
        title=str(raw.get("title", "")),
        scope=str(raw.get("scope", "")),
        support_level=str(raw.get("support_level", "detection-only")),
        requires=[str(r) for r in raw.get("requires", []) or []],
        detect=raw.get("detect") or {},
        facts=raw.get("facts") or {},
        actions=raw.get("actions") or {},
        verifiers=raw.get("verifiers") or [],
        exploit_probe=raw.get("exploit_probe"),
        notes=[str(n) for n in raw.get("notes", []) or []],
        path=path,
        raw=raw,
    )


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def validate(profile: Profile) -> List[str]:
    """Structural problems that would make the profile unsafe to trust."""
    problems: List[str] = []
    if not profile.profile_id:
        problems.append("missing profile_id")
    if profile.support_level not in SUPPORT_LEVELS:
        problems.append(f"support_level must be one of {SUPPORT_LEVELS}")
    detect = profile.detect or {}
    predicate_names: List[str] = []
    for key in ("all", "any"):
        for item in detect.get(key) or []:
            name = item.get("predicate")
            predicate_names.append(str(name))
            if name not in PREDICATES:
                problems.append(f"unknown detection predicate {name!r}")
    if not predicate_names:
        problems.append("profile has no detection predicates: it could match anything")
    if len(detect.get("all") or []) < 2:
        problems.append(
            "detection must require at least two independent predicates; a single listener "
            "match is not enough evidence to identify a stack"
        )
    fact_names = set(profile.facts.keys())
    for key, spec in (profile.actions or {}).items():
        action_id = spec.get("action_id")
        if action_id not in actions_mod.ACTIONS:
            problems.append(f"action '{key}' references unknown action_id {action_id!r}")
            continue
        eligibility = str(spec.get("eligibility", "review-only"))
        if eligibility not in ELIGIBILITY:
            problems.append(f"action '{key}' has invalid eligibility {eligibility!r}")
        if eligibility == "auto" and profile.support_level != "tested-auto":
            problems.append(
                f"action '{key}' is marked auto but the profile is not 'tested-auto'"
            )
        problems.extend(_check_tokens(spec.get("params") or {}, fact_names, f"action '{key}'"))
        problems.extend(_check_command_prefixes(spec.get("params") or {}, key))
        for effect in spec.get("effects") or []:
            kind = effect.get("kind")
            if kind not in EFFECT_KINDS:
                problems.append(f"action '{key}' declares unknown effect kind {kind!r}")
            argv = effect.get("argv") or []
            if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
                problems.append(f"action '{key}' effect argv must be a list of strings")
            elif kind in ("compose_restart", "compose_up") and "docker" not in argv[:1]:
                problems.append(
                    f"action '{key}' effect argv must start with the docker binary for {kind}"
                )
            elif kind.startswith("systemd") and argv[:1] != ["systemctl"]:
                problems.append(f"action '{key}' effect argv must start with systemctl")
    for index, verifier in enumerate(profile.verifiers or []):
        if "verifier" not in verifier:
            problems.append(f"verifier[{index}] has no 'verifier' key")
        # Tokens produced by an earlier workflow step are local, not profile facts.
        local_tokens = _extracted_tokens(verifier.get("params") or {})
        problems.extend(_check_tokens(verifier.get("params") or {},
                                      fact_names | local_tokens, f"verifier[{index}]"))
    if profile.exploit_probe:
        problems.extend(_check_tokens(profile.exploit_probe.get("params") or {}, fact_names,
                                      "exploit_probe"))
    return problems


def _extracted_tokens(params: Dict[str, Any]) -> set:
    """Names produced by `extract` in workflow steps (available to later steps)."""
    tokens: set = set()
    steps = params.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict):
                for name in (step.get("extract") or {}):
                    tokens.add(str(name))
    return tokens


def _check_command_prefixes(params: Dict[str, Any], key: str) -> List[str]:
    """Validator commands may only drive a small set of trusted binaries."""
    problems: List[str] = []
    prefix = params.get("php_binary")
    if isinstance(prefix, list):
        if not prefix or not all(isinstance(a, str) for a in prefix):
            problems.append(f"action '{key}': php_binary must be a list of strings")
        elif prefix[0] not in ("docker", "php", "php8", "php8.3", "php8.2"):
            problems.append(
                f"action '{key}': php_binary may only start with docker or php, got {prefix[0]!r}"
            )
        elif prefix[0] == "docker" and "exec" not in prefix:
            problems.append(
                f"action '{key}': a docker php_binary must use `docker compose ... exec`"
            )
    return problems


def _check_tokens(value: Any, fact_names: set, where: str) -> List[str]:
    problems: List[str] = []
    if isinstance(value, dict):
        for item in value.values():
            problems.extend(_check_tokens(item, fact_names, where))
    elif isinstance(value, list):
        for item in value:
            problems.extend(_check_tokens(item, fact_names, where))
    elif isinstance(value, str):
        for token in FACT_TOKEN.findall(value):
            if token not in fact_names:
                problems.append(f"{where}: unknown fact token {{{token}}}")
    return problems


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def detect(profile: Profile, inventory: Dict[str, Any]) -> Detection:
    result = Detection(matched=False, profile_id=profile.profile_id)
    detect_spec = profile.detect or {}
    all_items = detect_spec.get("all") or []
    any_items = detect_spec.get("any") or []
    ctx: Dict[str, Any] = {}

    for item in all_items:
        name = item.get("predicate")
        fn = PREDICATES.get(name)
        if fn is None:
            result.reasons.append(f"unsupported predicate {name!r}")
            return result
        ok, evidence, gap = fn(item.get("args") or {}, inventory, ctx)
        if ok:
            result.evidence.extend(evidence)
        else:
            result.reasons.append(f"{name}: {gap or 'not matched'}")
            return result
        if gap:
            result.gaps.append(f"{name}: {gap}")

    if any_items:
        matched_any = False
        for item in any_items:
            name = item.get("predicate")
            fn = PREDICATES.get(name)
            if fn is None:
                continue
            ok, evidence, gap = fn(item.get("args") or {}, inventory, ctx)
            if ok:
                matched_any = True
                result.evidence.extend(evidence)
                break
        if not matched_any:
            result.reasons.append("none of the 'any' predicates matched")
            return result

    facts = _resolve_facts(profile, inventory, ctx)
    missing = [name for name, value in facts.items() if value in (None, "")]
    if missing:
        result.reasons.append(
            "required fact(s) could not be resolved from evidence: " + ", ".join(sorted(missing))
        )
        return result
    result.facts = facts
    result.matched = True
    return result


def _resolve_facts(profile: Profile, inventory: Dict[str, Any],
                   ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve profile facts from a fixed set of resolvers (no expressions).

    Facts are resolved against the *matched* evidence recorded in ctx, so a
    second Compose project on the same host can never supply the port or the
    file path for this plan.
    """
    facts: Dict[str, Any] = {}
    matched_container = (ctx.get("containers") or [None])[0]
    matched_listener = (ctx.get("listeners") or [None])[0]

    def container_field(field: str) -> Any:
        if matched_container is not None:
            return matched_container.get(field)
        return _first_container_field(inventory, field)

    resolvers: Dict[str, Callable[[Dict[str, Any]], Any]] = {
        "compose_project": lambda inv: container_field("compose_project"),
        "compose_service": lambda inv: container_field("compose_service"),
        "container_name": lambda inv: container_field("name"),
        "container_image": lambda inv: container_field("image"),
        "compose_file": lambda inv: _compose_file_for(container_field("compose_working_dir"),
                                                     container_field("compose_config_files")),
        "project_dir": lambda inv: container_field("compose_working_dir"),
        "host_port": lambda inv: _listener_port(matched_listener, profile, inv),
        "container_port": lambda inv: _container_port(matched_listener),
        "os_id": lambda inv: (inv.get("host") or {}).get("os_id") or "",
        "inventory_generated_at": lambda inv: inv.get("generated_at") or "",
    }
    for name, spec in profile.facts.items():
        if isinstance(spec, dict):
            resolver = str(spec.get("resolver") or "")
            if resolver == "path_in_project_dir":
                base = container_field("compose_working_dir")
                relative = str(spec.get("relative") or "")
                candidate = os.path.join(base, relative) if base and relative else None
                if candidate and not os.path.isfile(candidate):
                    compose_file = container_field("compose_config_files")
                    if compose_file:
                        first = str(compose_file).split(",")[0].strip()
                        fallback = os.path.join(os.path.dirname(first), relative)
                        if os.path.isfile(fallback):
                            candidate = fallback
                facts[name] = candidate
                continue
            fn = resolvers.get(resolver)
            facts[name] = fn(inventory) if fn else None
        elif isinstance(spec, str):
            fn = resolvers.get(spec)
            facts[name] = fn(inventory) if fn else spec
        else:
            facts[name] = spec
    return facts


def _compose_file_for(working_dir: Optional[str], config_files: Optional[str]) -> Optional[str]:
    if config_files:
        first = str(config_files).split(",")[0].strip()
        if os.path.isfile(first):
            return first
        if working_dir:
            candidate = os.path.join(working_dir, os.path.basename(first))
            if os.path.isfile(candidate):
                return candidate
    if working_dir:
        for name in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"):
            candidate = os.path.join(working_dir, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _listener_port(matched_listener: Optional[Dict[str, Any]], profile: Profile,
                   inventory: Dict[str, Any]) -> Optional[int]:
    if matched_listener and matched_listener.get("port") is not None:
        return int(matched_listener["port"])
    return _probe_host_port(profile, inventory)


def _container_port(matched_listener: Optional[Dict[str, Any]]) -> Optional[str]:
    if matched_listener and matched_listener.get("container"):
        return matched_listener["container"].get("container_port")
    if matched_listener:
        return matched_listener.get("published_container_port")
    return None


def _first_container_field(inventory: Dict[str, Any], field: str) -> Optional[str]:
    graph = inventory.get("graph") or {}
    best = None
    for container in graph.get("containers") or []:
        if container.get("compose_project") and container.get(field):
            return container.get(field)
        if best is None and container.get(field):
            best = container.get(field)
    return best


def _first_compose_file(inventory: Dict[str, Any]) -> Optional[str]:
    graph = inventory.get("graph") or {}
    for container in graph.get("containers") or []:
        raw = container.get("compose_config_files")
        if raw:
            first = str(raw).split(",")[0].strip()
            if os.path.isfile(first):
                return first
            base = container.get("compose_working_dir")
            if base:
                candidate = os.path.join(base, os.path.basename(first))
                if os.path.isfile(candidate):
                    return candidate
    return None


def _probe_host_port(profile: Profile, inventory: Dict[str, Any]) -> Optional[int]:
    graph = inventory.get("graph") or {}
    wanted_service = _first_container_field(inventory, "compose_service")
    for container in graph.get("containers") or []:
        if wanted_service and container.get("compose_service") != wanted_service:
            continue
        for published in container.get("published") or []:
            try:
                return int(published.get("host_port"))
            except (TypeError, ValueError):
                continue
    for service in graph.get("services") or []:
        if service.get("container") and service.get("port"):
            return int(service["port"])
    return None


def _first_published_container_port(inventory: Dict[str, Any]) -> Optional[str]:
    graph = inventory.get("graph") or {}
    for container in graph.get("containers") or []:
        for published in container.get("published") or []:
            return str(published.get("container_port"))
    return None


# --------------------------------------------------------------------------
# Parameter substitution
# --------------------------------------------------------------------------
def substitute(value: Any, facts: Dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {k: substitute(v, facts) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, facts) for v in value]
    if isinstance(value, str):
        def repl(match: "re.Match[str]") -> str:
            return str(facts.get(match.group(1), match.group(0)))

        return FACT_TOKEN.sub(repl, value)
    return value


def unresolved_tokens(value: Any) -> List[str]:
    out: List[str] = []
    if isinstance(value, dict):
        for item in value.values():
            out.extend(unresolved_tokens(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(unresolved_tokens(item))
    elif isinstance(value, str):
        out.extend(FACT_TOKEN.findall(value))
    return out


def effects_from_spec(spec: Dict[str, Any], profile: Profile,
                      facts: Dict[str, Any]) -> List[actions_mod.Effect]:
    out: List[actions_mod.Effect] = []
    for effect in spec.get("effects") or []:
        kind = str(effect.get("kind"))
        if kind == "none":
            continue
        argv = substitute(effect.get("argv") or [], facts)
        out.append(actions_mod.Effect(
            kind=kind,
            argv=[str(a) for a in argv],
            description=str(effect.get("description") or kind),
            timeout=float(effect.get("timeout") or 120.0),
            requires=(EFFECT_REQUIRES.get(kind) or [""])[0],
        ))
    return out
