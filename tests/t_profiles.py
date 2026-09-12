"""Profiles: structural validation, refusal rules, fact substitution, scoping."""

from __future__ import annotations

import json
import os

from helpers import check, check_eq, check_in, compose_container, inventory_with, repo_copy

from ctfctl import actions as actions_mod, plan as plan_mod, profiles as profiles_mod, util


def _valid_raw() -> dict:
    return {
        "schema": profiles_mod.PROFILE_SCHEMA,
        "profile_id": "test-profile",
        "title": "test",
        "scope": "compose-project",
        "support_level": "tested-auto",
        "requires": [],
        "notes": [],
        "detect": {
            "all": [
                {"predicate": "container_running", "args": {"name_regex": "web"}},
                {"predicate": "listener_present", "args": {"published": True}},
            ]
        },
        "facts": {"compose_project": {"resolver": "compose_project"},
                  "host_port": {"resolver": "host_port"}},
        "actions": {},
        "verifiers": [],
        "exploit_probe": None,
    }


def _load(raw: dict) -> profiles_mod.Profile:
    return profiles_mod._from_raw(raw, "<test>")


def test_shipped_profiles_are_valid() -> None:
    shipped = profiles_mod.load_all()
    check(shipped, "the repository should ship at least one profile")
    for profile in shipped:
        problems = profiles_mod.validate(profile)
        check(not problems, f"{profile.profile_id}: {problems}")


def test_single_predicate_detection_is_rejected() -> None:
    raw = _valid_raw()
    raw["detect"] = {"all": [{"predicate": "listener_present", "args": {"published": True}}]}
    problems = profiles_mod.validate(_load(raw))
    check(any("two independent predicates" in p for p in problems),
          f"one predicate is not enough evidence: {problems}")


def test_unknown_predicate_is_rejected() -> None:
    raw = _valid_raw()
    raw["detect"]["all"].append({"predicate": "vibes", "args": {}})
    problems = profiles_mod.validate(_load(raw))
    check(any("unknown detection predicate" in p for p in problems), str(problems))


def test_unknown_action_id_is_rejected() -> None:
    raw = _valid_raw()
    raw["actions"] = {"do_thing": {"action_id": "file.shell_out", "params": {}}}
    problems = profiles_mod.validate(_load(raw))
    check(any("unknown action_id" in p for p in problems), str(problems))


def test_auto_eligibility_requires_a_tested_profile() -> None:
    raw = _valid_raw()
    raw["support_level"] = "detection-only"
    raw["actions"] = {"patch": {"action_id": "file.python_flask_send_from_directory",
                                "eligibility": "auto", "params": {"path": "/tmp/x.py"}}}
    problems = profiles_mod.validate(_load(raw))
    check(any("marked auto" in p for p in problems), str(problems))


def test_unresolved_fact_token_is_rejected() -> None:
    raw = _valid_raw()
    raw["actions"] = {"patch": {"action_id": "file.python_flask_send_from_directory",
                                "eligibility": "auto",
                                "params": {"path": "{nonexistent_fact}"}}}
    problems = profiles_mod.validate(_load(raw))
    check(any("unknown fact token" in p for p in problems), str(problems))


def test_effect_argv_must_be_allowlisted() -> None:
    raw = _valid_raw()
    raw["actions"] = {
        "patch": {
            "action_id": "file.python_flask_send_from_directory",
            "eligibility": "auto",
            "params": {"path": "/tmp/x.py"},
            "effects": [{"kind": "compose_restart", "argv": ["sh", "-c", "rm -rf /"]}],
        }
    }
    problems = profiles_mod.validate(_load(raw))
    check(any("must start with the docker binary" in p for p in problems), str(problems))


def test_php_binary_prefix_restriction() -> None:
    raw = _valid_raw()
    raw["actions"] = {
        "patch": {
            "action_id": "file.php_canonicalize_path_use",
            "eligibility": "auto",
            "params": {"path": "/tmp/x.php", "root_expr": "'/srv'", "guard_var": "$root",
                       "php_binary": ["bash", "-c", "php -l"]},
        }
    }
    problems = profiles_mod.validate(_load(raw))
    check(any("may only start with docker or php" in p for p in problems), str(problems))


def test_detection_scopes_facts_to_the_matched_project() -> None:
    """A second Compose project on the same host must not supply this plan's port."""
    raw = _valid_raw()
    # Precise patterns are required for this to be meaningful; a loose regex would
    # (correctly, but uselessly) match whichever container is listed first.
    raw["detect"]["all"][0]["args"] = {"name_regex": "(^|-)web$"}
    raw["facts"]["app_file"] = {"resolver": "path_in_project_dir", "relative": "service/app.py"}
    profile = _load(raw)
    decoy_container = compose_container("webapp-legacy", "other-project", "web", "python:3.12",
                                       "/srv/other", ("0.0.0.0", 9999, "80/tcp"))
    target_container = compose_container("target-web", "target-project", "web", "python:3.12",
                                         "/srv/target", ("0.0.0.0", 8080, "8000/tcp"))
    listener_other = {"port": 9999, "address": "0.0.0.0", "exposure": "all-interfaces",
                      "container": {"name": "webapp-legacy", "compose_project": "other-project"},
                      "evidence": ["docker published 0.0.0.0:9999"]}
    listener_target = {"port": 8080, "address": "0.0.0.0", "exposure": "all-interfaces",
                       "container": {"name": "target-web", "compose_project": "target-project"},
                       "evidence": ["docker published 0.0.0.0:8080"]}
    inventory = inventory_with(containers=[decoy_container, target_container],
                               listeners=[listener_other, listener_target],
                               app_roots=[{"path": "/srv/target", "source": "compose",
                                           "sample": ["service/app.py"]}])
    detection = profiles_mod.detect(profile, inventory)
    check(detection.matched, f"detection should match: {detection.reasons}")
    check_eq(detection.facts.get("compose_project"), "target-project",
             "facts must come from the matched container")
    check_eq(detection.facts.get("host_port"), 8080,
             "the port must come from the matched project's listener, not the first one seen")


def test_detection_requires_every_all_predicate() -> None:
    raw = _valid_raw()
    profile = _load(raw)
    inventory = inventory_with(containers=[], listeners=[])
    detection = profiles_mod.detect(profile, inventory)
    check(not detection.matched, "an empty inventory must not match")
    check(detection.reasons, "the miss must be explained")


def test_missing_fact_refuses_instead_of_guessing() -> None:
    raw = _valid_raw()
    raw["facts"]["app_file"] = {"resolver": "path_in_project_dir", "relative": "missing.py"}
    profile = _load(raw)
    container = compose_container("web", "proj", "web", "python:3.12", "/srv/nonexistent",
                                  ("0.0.0.0", 8080, "8000/tcp"))
    inventory = inventory_with(
        containers=[container],
        listeners=[{"port": 8080, "address": "0.0.0.0", "exposure": "all-interfaces",
                    "container": {"name": "web", "compose_project": "proj"},
                    "evidence": ["docker published 0.0.0.0:8080"]}])
    detection = profiles_mod.detect(profile, inventory)
    # A path that does not exist must not become an action target.
    if detection.matched:
        check(detection.facts["app_file"] is None or not os.path.exists(
            str(detection.facts["app_file"])),
            "the unresolved fact is what it is")
    else:
        check(any("fact" in reason for reason in detection.reasons), str(detection.reasons))


def test_action_registry_is_closed() -> None:
    """No action may exist outside the reviewed registry."""
    check(actions_mod.ACTIONS, "the registry must not be empty")
    for action_id, action in actions_mod.ACTIONS.items():
        check(action_id == action.id, f"{action_id} does not match its action id")
        check(action.summary, f"{action_id} needs a summary")
        check(action.impact, f"{action_id} must describe its impact")
        check(action.rollback_text, f"{action_id} must describe its rollback")
        check_in(action.eligibility, ("auto", "review-only", "refused"),
                 f"{action_id} eligibility")
    try:
        actions_mod.get("file.arbitrary_shell")
    except actions_mod.ActionError as exc:
        check("unknown action id" in str(exc), str(exc))
    else:
        raise AssertionError("an unknown action id must be rejected")


def test_action_preflight_rejects_unknown_parameters() -> None:
    action = actions_mod.get("file.python_flask_send_from_directory")
    problems = action.preflight({"path": "/tmp/x.py", "cmd": "rm -rf /"})
    check(any("unknown parameter" in p for p in problems), str(problems))


def test_plan_records_evidence_and_rollback_text() -> None:
    with repo_copy() as root:
        profile = profiles_mod.load_all(root)[0]
        plan = plan_mod.build_plan(profile, inventory_with(), root=root)
        payload = plan.as_dict()
        check("authorization" in payload, "a plan must carry its authorization decision")
        check("rollback" in payload, "a plan must carry rollback instructions")
        check("preconditions" in payload, "a plan must carry preconditions")
        check_eq(payload["actions"], [], "a non-matching inventory produces no actions")
        check(payload["risks"], "a plan must state its risks")
