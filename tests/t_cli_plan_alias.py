"""The documented `--plan` examples must stay parseable on the real CLI.

Docs spell the plan id as `remote apply <host> --plan <id> --yes` and the same
for `remote verify` and top-level `apply`. These tests pin the parser wiring
through `cli.main` in process:

* an invalid host string proves the argv parsed and the handler ran, because a
  parse failure would say "unrecognized arguments" instead of "refusing host";
* a valid host with no saved plan proves which id the alias resolved to before
  any ssh happens (`SSH_RUNNER` is faked, so no test opens a socket).
"""

from __future__ import annotations

import io
import os
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from typing import Iterator, List, Tuple

from helpers import check, check_eq, check_in

from t_remote import fake_ssh, remote_repo

from ctfctl import cli, remote

#: A host string the allowlist refuses, so no ssh can ever be attempted.
BAD_HOST = "bad host"


def _run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


@contextmanager
def _wide_help() -> Iterator[None]:
    """Force a wide formatter so `[--plan PLAN_ID]` cannot be wrapped."""
    previous = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "200"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = previous


# --------------------------------------------------------------------------
# The documented forms reach host validation, not an argparse error
# --------------------------------------------------------------------------
def test_remote_apply_plan_alias_reaches_host_validation() -> None:
    code, _out, err = _run_cli(
        ["remote", "apply", BAD_HOST, "--plan", "sha256:alias", "--yes"]
    )
    check_eq(code, 2, "a refused host is a usage error")
    check_in("refusing host", err, "the alias must parse and reach host validation")
    check(
        "unrecognized arguments" not in err,
        f"--plan must be a real option, not an argparse leftover: {err}",
    )
    check("Traceback" not in err, "an expected refusal must not trace")


def test_remote_verify_plan_alias_reaches_host_validation() -> None:
    code, _out, err = _run_cli(["remote", "verify", BAD_HOST, "--plan", "sha256:alias"])
    check_eq(code, 2, "a refused host is a usage error")
    check_in("refusing host", err, "the alias must parse and reach host validation")
    check(
        "unrecognized arguments" not in err,
        f"--plan must be a real option, not an argparse leftover: {err}",
    )


def test_remote_apply_positional_and_default_forms_parse() -> None:
    # Host validation runs before plan-id resolution, so the invalid host also
    # proves the positional and the omitted spelling parse. The "latest"
    # default itself is pinned by test_remote_apply_defaults_to_latest.
    for argv in (
        ["remote", "apply", BAD_HOST, "sha256:pos", "--yes"],
        ["remote", "apply", BAD_HOST, "--yes"],
    ):
        code, _out, err = _run_cli(argv)
        check_eq(code, 2, f"a refused host is a usage error for {argv}")
        check_in("refusing host", err, f"argv must parse: {argv}")
        check(
            "unrecognized arguments" not in err,
            f"argv must parse, not fail in argparse: {argv}",
        )


# --------------------------------------------------------------------------
# The resolved id is the one the plan lookup sees (still no ssh)
# --------------------------------------------------------------------------
def test_remote_apply_plan_alias_resolves_to_the_plan_lookup() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            code, _out, err = _run_cli(
                ["remote", "apply", "vulnbox", "--plan", "sha256:alias", "--yes"]
            )
        check_eq(code, 1, "a missing saved plan is an expected negative result")
        check_in("sha256:alias", err, "the --plan value must reach the plan lookup")
        check_in("not saved locally", err, "the lookup must name the failure")
        check_eq(fake.calls, [], "resolution must not open ssh")


def test_remote_apply_positional_plan_id_still_resolves() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            code, _out, err = _run_cli(
                ["remote", "apply", "vulnbox", "sha256:pos", "--yes"]
            )
        check_eq(code, 1, "a missing saved plan is an expected negative result")
        check_in("sha256:pos", err, "the positional must reach the plan lookup")
        check_in("not saved locally", err, "the lookup must name the failure")
        check_eq(fake.calls, [], "resolution must not open ssh")


def test_remote_apply_defaults_to_latest() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            code, _out, err = _run_cli(["remote", "apply", "vulnbox", "--yes"])
        check_eq(code, 1, "a missing saved plan is an expected negative result")
        check_in(
            "no saved plan for vulnbox",
            err,
            "neither spelling must fall back to latest",
        )
        check_eq(fake.calls, [], "resolution must not open ssh")


def test_remote_verify_plan_alias_resolves_to_the_plan_lookup() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            code, _out, err = _run_cli(
                ["remote", "verify", "vulnbox", "--plan", "sha256:alias"]
            )
        check_eq(code, 1, "a missing saved plan is an expected negative result")
        check_in("sha256:alias", err, "the --plan value must reach the plan lookup")
        check_in("not saved locally", err, "the lookup must name the failure")
        check_eq(fake.calls, [], "resolution must not open ssh")


def test_remote_apply_matching_alias_and_positional_do_not_conflict() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            code, _out, err = _run_cli(
                [
                    "remote",
                    "apply",
                    "vulnbox",
                    "sha256:same",
                    "--plan",
                    "sha256:same",
                    "--yes",
                ]
            )
        check_eq(code, 1, "the matching ids must fall through to the plan lookup")
        check_in("sha256:same", err, "the shared id must reach the plan lookup")
        check(
            "conflicting plan ids" not in err,
            "identical spellings must not be reported as a conflict",
        )
        check_eq(fake.calls, [], "resolution must not open ssh")


# --------------------------------------------------------------------------
# Conflicts are usage errors and never touch ssh
# --------------------------------------------------------------------------
def test_remote_apply_conflicting_plan_ids_is_usage_error() -> None:
    with remote_repo() as root:
        remote.declare_target("vulnbox", label="lab", root=root)
        with fake_ssh() as fake:
            code, _out, err = _run_cli(
                [
                    "remote",
                    "apply",
                    "vulnbox",
                    "sha256:pos",
                    "--plan",
                    "sha256:alias",
                    "--yes",
                ]
            )
        check_eq(code, 2, "two different plan ids must be a usage error")
        check_in("conflicting plan ids", err, "the conflict must be named")
        check("Traceback" not in err, "a usage error must not trace")
        check_eq(fake.calls, [], "the conflict must be caught before ssh")


def test_top_level_apply_conflicting_plan_ids_is_usage_error() -> None:
    with remote_repo() as root:
        code, _out, err = _run_cli(
            ["apply", "sha256:pos", "--plan", "sha256:alias", "--yes"]
        )
        check_eq(code, 2, "two different plan ids must be a usage error")
        check_in("conflicting plan ids", err, "the conflict must be named")
        check("Traceback" not in err, "a usage error must not trace")


# --------------------------------------------------------------------------
# Top-level apply: pre-work guard keeps the alias test side-effect free
# --------------------------------------------------------------------------
def test_top_level_apply_plan_alias_reaches_plan_load() -> None:
    # Pre-work guard: a missing plan is refused by load_plan before any
    # mutation, so this runs the alias end to end without applying anything.
    with remote_repo() as root:
        for argv in (
            ["apply", "--plan", "sha256:deadbeef", "--yes"],
            ["apply", "sha256:deadbeef", "--yes"],
        ):
            code, _out, err = _run_cli(argv)
            check_eq(code, 1, f"a missing plan is an expected negative: {argv}")
            check_in(
                "plan not found: sha256:deadbeef",
                err,
                f"argv must resolve the id, not a parse error: {argv}",
            )


def test_top_level_apply_defaults_to_latest() -> None:
    with remote_repo() as root:
        code, _out, err = _run_cli(["apply", "--yes"])
        check_eq(code, 1, "no generated plan is an expected negative result")
        check_in(
            "no plans have been generated yet",
            err,
            "neither spelling must fall back to latest",
        )


# --------------------------------------------------------------------------
# Help and parser wiring
# --------------------------------------------------------------------------
def test_plan_alias_appears_in_help() -> None:
    for argv in (
        ["remote", "apply", "--help"],
        ["remote", "verify", "--help"],
        ["apply", "--help"],
    ):
        with _wide_help():
            code, out, _err = _run_cli(argv)
        check_eq(code, 0, f"{argv} must exit 0")
        check_in("[--plan PLAN_ID]", out, f"{argv} must document the alias")


def test_parser_wires_the_plan_alias_on_all_three_commands() -> None:
    parser = cli.build_parser()
    alias_forms = (
        ["remote", "apply", "vulnbox", "--plan", "sha256:x", "--yes"],
        ["remote", "verify", "vulnbox", "--plan", "sha256:x"],
        ["apply", "--plan", "sha256:x", "--yes"],
    )
    positional_forms = (
        ["remote", "apply", "vulnbox", "sha256:x", "--yes"],
        ["remote", "verify", "vulnbox", "sha256:x"],
        ["apply", "sha256:x", "--yes"],
    )
    for argv in alias_forms:
        args = parser.parse_args(argv)
        check_eq(args.plan, "sha256:x", f"--plan must parse: {argv}")
        check(args.plan_id is None, f"the positional must stay unset: {argv}")
    for argv in positional_forms:
        args = parser.parse_args(argv)
        check_eq(args.plan_id, "sha256:x", f"the positional must parse: {argv}")
        check(args.plan is None, f"--plan must stay unset: {argv}")
