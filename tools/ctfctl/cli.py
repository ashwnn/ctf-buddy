"""Command-line interface.

Exit codes: 0 success, 1 expected negative result (refused / stale / no match),
2 usage error, 3 internal error. Machine-readable output goes to stdout under
`--json`; all diagnostics stay on stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from typing import Any, Dict, List, Optional

from . import (
    __version__,
    apply as apply_mod,
    decoy as decoy_mod,
    discover as discover_mod,
)
from . import doctor as doctor_mod, files as files_mod, honeypot as honeypot_mod
from . import kbindex, observe as observe_mod
from . import (
    plan as plan_mod,
    platformx,
    profiles as profiles_mod,
    remote as remote_mod,
)
from . import sources_check, util


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfctl",
        description="Offline-first preparation toolkit for a first-time CTF team "
        "(local fixtures and team-owned targets only)",
    )
    parser.add_argument("--version", action="version", version=f"ctfctl {__version__}")
    sub = parser.add_subparsers(dest="command")

    # doctor
    p = sub.add_parser("doctor", help="offline dependency and capability report")
    p.add_argument("--json", action="store_true")
    p.add_argument("--quick", action="store_true", help="skip subprocess probes")

    # discover
    p = sub.add_parser("discover", help="read-only bounded host inventory")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--system-root",
        default="/",
        help="read path-based evidence from a synthetic root (test fixtures)",
    )
    p.add_argument(
        "--no-subprocess",
        action="store_true",
        help="skip every external command (deterministic, unprivileged)",
    )
    p.add_argument(
        "--save", action="store_true", help="write the inventory under state/"
    )
    p.add_argument("--quick", action="store_true")

    # plan
    p = sub.add_parser("plan", help="detect stacks and propose exact, reviewed changes")
    p.add_argument("--profile", help="profile id (default: try every profile)")
    p.add_argument(
        "--inventory", help="use a saved inventory JSON instead of re-discovering"
    )
    p.add_argument("--system-root", default="/")
    p.add_argument("--no-subprocess", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--no-save", action="store_true", help="do not persist the plan")
    p.add_argument(
        "--allow-fixture",
        action="store_true",
        default=True,
        help="fixture-local targets are always allowed (default)",
    )

    # apply
    p = sub.add_parser("apply", help="apply a reviewed plan (or run a tested profile)")
    p.add_argument("plan_id", nargs="?", default=None)
    p.add_argument(
        "--plan",
        metavar="PLAN_ID",
        help="plan id to apply (default: latest); alias for the positional",
    )
    p.add_argument(
        "--yes", action="store_true", help="required for non-interactive apply"
    )
    p.add_argument(
        "--approve-review",
        action="store_true",
        help="also apply review-only actions in the plan",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="validate everything, change nothing"
    )
    p.add_argument(
        "--no-functional",
        action="store_true",
        help="skip tier-3 workflow verifiers (not recommended)",
    )
    p.add_argument("--json", action="store_true")

    # verify
    p = sub.add_parser(
        "verify", help="run a plan's health checks and report degradation"
    )
    p.add_argument("plan_id", nargs="?", default="latest")
    p.add_argument("--no-functional", action="store_true")
    p.add_argument("--json", action="store_true")

    # rollback / recover
    p = sub.add_parser(
        "rollback", help="revert one change batch with conflict detection"
    )
    p.add_argument("tx_id", nargs="?")
    p.add_argument("--list", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser(
        "recover", help="inspect interrupted transactions (never guesses)"
    )
    p.add_argument("--json", action="store_true")

    # watch
    p = sub.add_parser("watch", help="bounded log and network observation")
    p.add_argument("--logs", action="append", default=[], metavar="PATH")
    p.add_argument("--unit", action="append", default=[], metavar="UNIT")
    p.add_argument("--iface", help="capture interface (never 'any', never promiscuous)")
    p.add_argument("--filter", default="tcp or udp", help="tcpdump filter expression")
    p.add_argument("--seconds", type=int, default=60)
    p.add_argument("--max-lines", type=int, default=500)
    p.add_argument("--include", help="only log lines matching this regex")
    p.add_argument("--exclude", help="drop log lines matching this regex")
    p.add_argument(
        "--count", type=int, default=500, help="packets per capture rotation"
    )
    p.add_argument("--snaplen", type=int, default=256)
    p.add_argument(
        "--dry-run", action="store_true", help="print the capture command only"
    )
    p.add_argument("--json", action="store_true")

    # decoy
    p = sub.add_parser(
        "decoy", help="optional isolated HTTP decoy (disabled by default)"
    )
    decoy_sub = p.add_subparsers(dest="decoy_command")
    d = decoy_sub.add_parser(
        "enable", help="acknowledge rules and name unused ports/paths"
    )
    d.add_argument("--json", action="store_true")
    d.add_argument("--port", action="append", type=int, default=[])
    d.add_argument("--path", action="append", default=[])
    d.add_argument("--bind", default="127.0.0.1")
    d.add_argument("--notes", default="")
    d.add_argument("--ack-rules", action="store_true")
    d = decoy_sub.add_parser("start")
    d.add_argument("--port", type=int)
    d.add_argument("--bind")
    d.add_argument("--mode", choices=["http", "banner"], default="http")
    d.add_argument("--banner", default="", help="custom text or a preset name")
    d.add_argument("--json", action="store_true")
    d = decoy_sub.add_parser("status")
    d.add_argument("--json", action="store_true")
    d = decoy_sub.add_parser("stop")
    d.add_argument("--json", action="store_true")
    p.add_argument("--json", action="store_true")

    # kb
    p = sub.add_parser("kb", help="knowledge-base indexing and search")
    kb_sub = p.add_subparsers(dest="kb_command")
    k = kb_sub.add_parser("index", help="build or refresh the search index")
    k.add_argument("--rebuild", action="store_true")
    k.add_argument("--json", action="store_true")
    k = kb_sub.add_parser("search", help="ranked search")
    k.add_argument("query")
    k.add_argument("--phrase", action="store_true", help="treat input as one phrase")
    k.add_argument("--any", action="store_true", help="OR the terms for recall")
    k.add_argument("--fts", action="store_true", help="pass raw FTS5 syntax (advanced)")
    k.add_argument("--tag")
    k.add_argument("--stack")
    k.add_argument("--kind", choices=["card", "source"])
    k.add_argument("--limit", type=int, default=10)
    k.add_argument("--json", action="store_true")
    k = kb_sub.add_parser("literal", help="exact string / code search (no FTS syntax)")
    k.add_argument("pattern")
    k.add_argument("--regex", action="store_true")
    k.add_argument("--tag")
    k.add_argument("--stack")
    k.add_argument("--limit", type=int, default=20)
    k.add_argument("--json", action="store_true")
    k = kb_sub.add_parser("show", help="print one card (or its path) by id or path")
    k.add_argument("identifier")
    k.add_argument("--path-only", action="store_true")
    k = kb_sub.add_parser(
        "verify", help="validate manifests, index and source references"
    )
    k.add_argument("--json", action="store_true")
    k = kb_sub.add_parser("stats", help="corpus counts and coverage")
    k.add_argument("--json", action="store_true")
    k = kb_sub.add_parser("export", help="write a shareable or local-event archive")
    k.add_argument("directory")
    k.add_argument(
        "--shareable",
        action="store_true",
        help="exclude snapshots whose licence does not permit redistribution",
    )
    k.add_argument("--json", action="store_true")
    k = kb_sub.add_parser(
        "open", help="print the local path of a search hit (for $EDITOR)"
    )
    k.add_argument("identifier")
    k = kb_sub.add_parser(
        "cheat", help="quick-reference cards (no query lists them all)"
    )
    k.add_argument("topic", nargs="?", default="",
                   help="topic to match, e.g. 'web', 'pcap', 'lockdown'")
    k.add_argument("--limit", type=int, default=20)
    k.add_argument("--json", action="store_true")

    # profiles
    p = sub.add_parser("profiles", help="inspect supported stack profiles")
    pr_sub = p.add_subparsers(dest="profiles_command")
    l = pr_sub.add_parser("list")
    l.add_argument("--json", action="store_true")
    s = pr_sub.add_parser("show")
    s.add_argument("profile_id")
    s.add_argument("--json", action="store_true")
    v = pr_sub.add_parser("validate")
    v.add_argument("--json", action="store_true")
    p.add_argument("--json", action="store_true")

    # prep-online
    p = sub.add_parser(
        "prep-online",
        help="the ONLY command that may use the network (run before the event)",
    )
    p.add_argument(
        "--check-sources",
        action="store_true",
        help="re-verify source URLs in sources/verified-index.jsonl",
    )
    p.add_argument(
        "--all", action="store_true", help="re-check already verified sources"
    )
    p.add_argument(
        "--require-tools",
        nargs="*",
        default=[],
        help="exit non-zero if these tools are missing",
    )
    p.add_argument("--json", action="store_true")

    # targets
    p = sub.add_parser(
        "targets", help="declare team-owned hosts (gates every mutation)"
    )
    tsub = p.add_subparsers(dest="targets_command")
    t = tsub.add_parser(
        "declare", help="declare one host as team-owned or event-authorized"
    )
    t.add_argument("host")
    t.add_argument("--label", default="", help="what this host is, for the record")
    t.add_argument(
        "--role",
        default="vulnbox",
        choices=["vulnbox", "jumpbox", "practice", "other"],
    )
    t.add_argument("--notes", default="")
    t.add_argument(
        "--ack-policy",
        action="store_true",
        help="also acknowledge the event policy (required before remote apply)",
    )
    t.add_argument("--json", action="store_true")
    t = tsub.add_parser("list", help="list declared targets and policy state")
    t.add_argument("--json", action="store_true")
    p.add_argument("--json", action="store_true")

    # files (local, and the engine behind `remote files`)
    p = sub.add_parser("files", help="bounded read-only filesystem exploration")
    fsub = p.add_subparsers(dest="files_command")
    f = fsub.add_parser("list", help="bounded directory listing")
    f.add_argument("path")
    f.add_argument(
        "--depth",
        type=int,
        default=1,
        help=f"1-{files_mod.MAX_DEPTH} levels (default 1)",
    )
    f.add_argument("--limit", type=int, default=files_mod.DEFAULT_LIMIT)
    f.add_argument("--json", action="store_true")
    f = fsub.add_parser("read", help="read a bounded, redacted head of one file")
    f.add_argument("path")
    f.add_argument("--max-bytes", type=int, default=files_mod.DEFAULT_READ_BYTES)
    f.add_argument(
        "--no-redact",
        action="store_true",
        help="debugging only: do not scrub secret-looking values",
    )
    f.add_argument("--json", action="store_true")
    f = fsub.add_parser("find", help="bounded filename search")
    f.add_argument("path")
    f.add_argument("--name", required=True, help="shell-style glob, e.g. '*.py'")
    f.add_argument("--limit", type=int, default=files_mod.DEFAULT_LIMIT)
    f.add_argument("--max-depth", type=int, default=files_mod.MAX_DEPTH)
    f.add_argument("--json", action="store_true")
    p.add_argument("--json", action="store_true")

    # remote
    p = sub.add_parser("remote", help="operate on a declared team-owned host over ssh")
    rsub = p.add_subparsers(dest="remote_command")

    def connection_options(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--port", type=int, help="ssh port (or use host:port)")
        sp.add_argument("--user", default="", help="ssh user (or use user@host)")
        sp.add_argument("--identity", default="", help="private key for ssh -i")
        sp.add_argument(
            "--timeout",
            type=float,
            default=None,
            help="per-ssh-call timeout in seconds",
        )

    r = rsub.add_parser(
        "probe", help="read-only host inventory (needs no remote python)"
    )
    r.add_argument("host")
    connection_options(r)
    r.add_argument(
        "--save", action="store_true", help="save the parsed probe under state/"
    )
    r.add_argument(
        "--keep-raw",
        action="store_true",
        help="also save the redacted raw probe output under state/",
    )
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser("install", help="upload the read-only toolkit to ~/.ctfctl")
    r.add_argument("host")
    connection_options(r)
    r.add_argument("--force", action="store_true", help="re-upload even if current")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser(
        "plan", help="detect stacks on the host and pull the exact plan"
    )
    r.add_argument("host")
    connection_options(r)
    r.add_argument("--profile", help="limit to one profile id")
    r.add_argument("--verbose", action="store_true", help="show full diffs")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser("apply", help="apply a reviewed plan on the host")
    r.add_argument("host")
    r.add_argument("plan_id", nargs="?", default=None)
    r.add_argument(
        "--plan",
        metavar="PLAN_ID",
        help="plan id to apply (default: latest); alias for the positional",
    )
    connection_options(r)
    r.add_argument("--yes", action="store_true", help="required for a real apply")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--approve-review", action="store_true")
    r.add_argument("--no-functional", action="store_true")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser("verify", help="run the plan's health checks on the host")
    r.add_argument("host")
    r.add_argument("plan_id", nargs="?", default=None)
    r.add_argument(
        "--plan",
        metavar="PLAN_ID",
        help="plan id to verify (default: latest); alias for the positional",
    )
    connection_options(r)
    r.add_argument("--no-functional", action="store_true")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser("rollback", help="revert one change batch on the host")
    r.add_argument("host")
    connection_options(r)
    r.add_argument("--tx", dest="tx_id", help="transaction id (omit for --list)")
    r.add_argument("--list", action="store_true")
    r.add_argument("--yes", action="store_true", help="required for a real rollback")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser("recover", help="inspect interrupted remote transactions")
    r.add_argument("host")
    connection_options(r)
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser("run", help="proxy one allowlisted read-only subcommand")
    r.add_argument("host")
    connection_options(r)
    r.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="e.g. doctor --json; mutations must use remote apply/rollback",
    )

    r = rsub.add_parser("files", help="bounded read-only file exploration on the host")
    r.add_argument("host")
    connection_options(r)
    r.add_argument("files_action", choices=["list", "read", "find"])
    r.add_argument("path")
    r.add_argument("--depth", type=int, default=1)
    r.add_argument("--limit", type=int, default=files_mod.DEFAULT_LIMIT)
    r.add_argument("--name", default="", help="glob for the find action")
    r.add_argument("--max-bytes", type=int, default=files_mod.DEFAULT_READ_BYTES)
    r.add_argument("--max-depth", type=int, default=files_mod.MAX_DEPTH)
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser(
        "auto",
        help="one pass from an IP: probe, discover, plan, report; then optionally defend",
    )
    r.add_argument("host")
    connection_options(r)
    r.add_argument(
        "--apply",
        dest="apply_mutations",
        action="store_true",
        help="apply the first matching tested-auto plan (needs --yes)",
    )
    r.add_argument(
        "--approve-review",
        action="store_true",
        help="also allow review-only actions in that plan",
    )
    r.add_argument(
        "--honeypot-port",
        type=int,
        default=0,
        help="start an HTTP honeypot on this unused port (needs --yes)",
    )
    r.add_argument(
        "--honeypot-mode",
        choices=["http", "banner"],
        default="http",
        help="honeypot listener type (banner fakes an ssh/smtp/ftp greeting)",
    )
    r.add_argument("--honeypot-banner", default="", help="banner text or preset name")
    r.add_argument(
        "--lockdown",
        action="store_true",
        help="also plan AND apply the review-only lockdown (needs --approve-review --yes)",
    )
    r.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help="team/checker range the lockdown keeps reachable (repeatable)",
    )
    r.add_argument("--yes", action="store_true", help="required for any mutation")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser(
        "honeypot",
        help="run decoy listeners on the host to distract attackers",
    )
    r.add_argument("host")
    connection_options(r)
    r.add_argument("honeypot_action", choices=list(remote_mod.HONEYPOT_ACTIONS))
    r.add_argument(
        "--honeypot-port",
        type=int,
        help="unused target port for the listener (--port is the ssh port)",
    )
    r.add_argument("--mode", choices=["http", "banner"], default="http")
    r.add_argument("--bind", default="0.0.0.0")
    r.add_argument("--banner", default="", help="banner text or preset name")
    r.add_argument("--lines", type=int, default=50)
    r.add_argument("--all", dest="all_listeners", action="store_true")
    r.add_argument("--yes", action="store_true", help="required to start or stop")
    r.add_argument("--json", action="store_true")

    r = rsub.add_parser(
        "lockdown",
        help="pull a review-only firewall + sshd lockdown plan for the host",
    )
    r.add_argument("host")
    connection_options(r)
    r.add_argument(
        "--operator-cidr",
        default="",
        help="your own address as the target sees it (default: read from the ssh session)",
    )
    r.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help="team/checker range to keep reachable (repeatable)",
    )
    r.add_argument(
        "--allow-port",
        action="append",
        type=int,
        default=[],
        help="extra TCP port to keep reachable (repeatable)",
    )
    r.add_argument("--allow-udp-ports", default="", help="comma-separated UDP ports to keep")
    r.add_argument("--log-drops", action="store_true", help="log dropped packets (rate limited)")
    r.add_argument("--no-firewall", action="store_true")
    r.add_argument("--no-ssh", action="store_true")
    r.add_argument("--sshd-port", type=int, default=22)
    r.add_argument("--verbose", action="store_true", help="show full diffs")
    r.add_argument("--json", action="store_true")

    # honeypot (local lifecycle; the remote wrapper drives this over ssh)
    p = sub.add_parser("honeypot", help="honeypot listeners on this host or a target")
    honeypot_sub = p.add_subparsers(dest="honeypot_command")
    h = honeypot_sub.add_parser("start", help="start one listener on an unused port")
    h.add_argument("--port", type=int, required=True)
    h.add_argument("--mode", choices=["http", "banner"], default="http")
    h.add_argument("--bind", default="0.0.0.0")
    h.add_argument("--banner", default="", help="custom text or a preset name")
    h.add_argument("--path", action="append", default=[], help="HTTP lure path (repeatable)")
    h.add_argument("--allow-privileged", action="store_true")
    h.add_argument("--json", action="store_true")
    h = honeypot_sub.add_parser("status")
    h.add_argument("--json", action="store_true")
    h = honeypot_sub.add_parser("logs", help="bounded tail of the listener logs")
    h.add_argument("--lines", type=int, default=50)
    h.add_argument("--port", type=int)
    h.add_argument("--json", action="store_true")
    h = honeypot_sub.add_parser("stop")
    h.add_argument("--port", type=int)
    h.add_argument("--all", dest="all_listeners", action="store_true")
    h.add_argument("--json", action="store_true")

    # lockdown (local planning; `remote lockdown` drives this over ssh)
    p = sub.add_parser(
        "lockdown",
        help="review-only firewall + sshd plan for this host (run it on the target)",
    )
    lockdown_sub = p.add_subparsers(dest="lockdown_command")
    lock = lockdown_sub.add_parser("plan", help="build the lockdown plan")
    lock.add_argument("--operator-cidr", required=True,
                      help="your own address; it is always added to the allowlist")
    lock.add_argument("--allow-cidr", action="append", default=[])
    lock.add_argument("--allow-ports", default="", help="comma-separated TCP ports to keep")
    lock.add_argument("--allow-udp-ports", default="")
    lock.add_argument("--no-firewall", action="store_true")
    lock.add_argument("--no-ssh", action="store_true")
    lock.add_argument("--log-drops", action="store_true")
    lock.add_argument("--sshd-path", default="/etc/ssh/sshd_config")
    lock.add_argument("--authorized-keys", default="")
    lock.add_argument("--service-unit", default="ssh")
    lock.add_argument("--sshd-port", type=int, default=22)
    lock.add_argument("--nft-path", default="/etc/ctfctl-lockdown.nft")
    lock.add_argument("--table", default="ctfctl_lockdown")
    lock.add_argument("--note", default="")
    lock.add_argument("--inventory", help="inventory JSON to plan against (default: discover now)")
    lock.add_argument("--no-save", action="store_true")
    lock.add_argument("--verbose", action="store_true")
    lock.add_argument("--allow-fixture", action="store_true", default=False,
                       help="allow fixture-local authorization (drills only)")
    lock.add_argument("--json", action="store_true")

    return parser


# --------------------------------------------------------------------------
# Command implementations
# --------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    data = doctor_mod.report(quick=args.quick)
    if args.json:
        util.emit_json(data)
    else:
        print(doctor_mod.render(data))
    return util.EXIT_OK


def cmd_discover(args: argparse.Namespace) -> int:
    inventory = discover_mod.discover(
        system_root=args.system_root,
        allow_subprocess=not args.no_subprocess,
        quick=args.quick,
    )
    payload = inventory.as_dict()
    if args.save:
        directory = util.state_dir(root=util.repo_root())
        path = os.path.join(directory, f"inventory-{util.utc_stamp()}.json")
        util.write_text_atomic(path, util.dump_json(payload), mode=0o600)
        util.write_text_atomic(
            os.path.join(directory, "inventory-latest.json"),
            util.dump_json(payload),
            mode=0o600,
        )
        payload["saved_to"] = os.path.relpath(path, util.repo_root()).replace(
            os.sep, "/"
        )
    if args.json:
        util.emit_json(payload)
    else:
        print(discover_mod.summary(inventory))
        if payload.get("saved_to"):
            print(f"\nsaved     {payload['saved_to']}")
    return util.EXIT_OK


def _load_inventory(args: argparse.Namespace) -> Dict[str, Any]:
    if getattr(args, "inventory", None):
        payload = util.load_json(args.inventory, None)
        if payload is None:
            raise util.UsageError(f"inventory file not readable: {args.inventory}")
        return payload
    latest = os.path.join(
        util.state_dir(root=util.repo_root()), "inventory-latest.json"
    )
    if getattr(args, "use_latest", False) and os.path.isfile(latest):
        return util.load_json(latest, {})
    inventory = discover_mod.discover(
        system_root=getattr(args, "system_root", "/"),
        allow_subprocess=not getattr(args, "no_subprocess", False),
        quick=False,
    )
    return inventory.as_dict()


def cmd_plan(args: argparse.Namespace) -> int:
    inventory = _load_inventory(args)
    if args.profile:
        chosen = [profiles_mod.load(args.profile)]
    else:
        chosen = profiles_mod.load_all()
    if not chosen:
        raise util.CtfError(
            "no profiles are installed", hint="check the profiles/ directory"
        )
    plans: List[plan_mod.Plan] = []
    for profile in chosen:
        plan = plan_mod.build_plan(profile, inventory, allow_fixture=args.allow_fixture)
        plans.append(plan)
    matched = [p for p in plans if p.detection.get("matched")]
    if not args.no_save:
        for plan in plans:
            if plan.detection.get("matched"):
                plan.save()
    if args.json:
        util.emit_json(
            {
                "inventory_digest": plans[0].inventory_digest if plans else "",
                "plans": [p.as_dict() for p in plans],
                "matched": [p.profile_id for p in matched],
            }
        )
    else:
        for index, plan in enumerate(plans):
            if index:
                print()
            if plan.detection.get("matched"):
                print(plan_mod.render(plan, verbose=args.verbose))
            elif args.profile:
                print(f"profile {plan.profile_id}: NOT DETECTED")
                for reason in plan.detection.get("reasons", []):
                    print(f"  - {util.printable(reason, 200)}")
        if not matched:
            print(
                "\nNo profile matched this host. That is a normal outcome for an unfamiliar "
                "service: discovery evidence is above, and no mutation is proposed."
            )
    return util.EXIT_OK if matched else util.EXIT_NEGATIVE


def _resolve_plan_id(args: argparse.Namespace) -> str:
    """Merge the positional plan id with its --plan alias.

    Either spelling is accepted; passing both with different values is a usage
    error rather than silently picking one. Neither keeps the "latest" default.
    """
    plan_id = args.plan_id
    alias = args.plan
    if plan_id is not None and alias is not None and plan_id != alias:
        raise util.UsageError(
            f"conflicting plan ids: {plan_id!r} positional and {alias!r} for --plan",
            hint="pass the plan id once, positionally or with --plan",
        )
    if plan_id is not None:
        return plan_id
    if alias is not None:
        return alias
    return "latest"


def cmd_apply(args: argparse.Namespace) -> int:
    plan = plan_mod.load_plan(_resolve_plan_id(args))
    if not plan.automatic_actions() and not args.approve_review:
        raise util.CtfError(
            "the plan has no auto-eligible actions",
            hint="review the diff, then re-run with --approve-review",
        )
    if not args.yes and not args.dry_run:
        raise util.CtfError(
            "refusing to mutate without --yes",
            hint="read the plan first: ctfctl plan --verbose, then ctfctl apply --yes",
        )
    tx = apply_mod.apply_plan(
        plan,
        yes=args.yes,
        include_review=args.approve_review,
        dry_run=args.dry_run,
        functional=not args.no_functional,
    )
    payload = {
        "tx_id": tx.tx_id,
        "phase": tx.phase,
        "dry_run": tx.dry_run,
        "plan": plan.plan_id,
        "files": [
            {
                "path": c.path,
                "pre": c.pre_sha256[:12],
                "post": c.post_sha256[:12],
                "replaced": c.replaced,
            }
            for c in tx.changes
        ],
        "effects": tx.effects_run,
        "verification": tx.verification,
        "errors": tx.errors,
        "journal": os.path.relpath(tx.journal_path, util.repo_root()).replace(
            os.sep, "/"
        ),
    }
    if args.json:
        util.emit_json(payload)
    else:
        print(
            f"transaction {tx.tx_id}  phase={tx.phase}"
            + ("  (dry run: nothing was changed)" if tx.dry_run else "")
        )
        for change in tx.changes:
            print(
                f"  file {change.path}  {change.pre_sha256[:12]} -> "
                f"{change.post_sha256[:12] or '(unchanged)'}"
            )
        for effect in tx.effects_run:
            print(f"  effect {' '.join(effect['argv'])} -> ok={effect['ok']}")
        for result in tx.verification:
            print(
                f"  verify {'ok  ' if result.get('ok') else 'FAIL'} "
                f"[{result.get('tier')}] {result.get('verifier')}: "
                f"{util.printable(str(result.get('detail')), 160)}"
            )
        if tx.dry_run:
            print(
                "dry run complete: all preconditions, candidates and validations passed"
            )
        else:
            print(f"\nrollback with: ctfctl rollback {tx.tx_id}")
    return util.EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    plan = plan_mod.load_plan(args.plan_id)
    results = apply_mod.run_verifier_set(plan, functional=not args.no_functional)
    ok = all(r.get("ok") for r in results if r.get("required"))
    if args.json:
        util.emit_json({"plan": plan.plan_id, "ok": ok, "results": results})
    else:
        print(f"verification of {plan.profile_id} (plan {plan.plan_id})")
        for result in results:
            print(
                f"  {'ok  ' if result.get('ok') else 'FAIL'} [{result.get('tier')}] "
                f"{result.get('verifier')}: {util.printable(str(result.get('detail')), 200)}"
            )
        print()
        print(
            "These are OUR checks, not the organiser checker. A pass means the legitimate "
            "workflow still works and the known exploit probe no longer does."
        )
    return util.EXIT_OK if ok else util.EXIT_NEGATIVE


def cmd_rollback(args: argparse.Namespace) -> int:
    if args.list or not args.tx_id:
        entries = apply_mod.list_transactions()
        if args.json:
            util.emit_json({"transactions": entries})
        else:
            if not entries:
                print("no transactions recorded")
            for entry in entries:
                print(
                    f"{entry['tx_id']}  {entry['phase']:<12} {entry['started_at']}  "
                    f"{len(entry['files'])} file(s)"
                )
                for error in entry.get("errors") or []:
                    print(f"    ! {util.printable(str(error), 160)}")
        return util.EXIT_OK
    if not args.yes:
        raise util.CtfError(
            "refusing to roll back without --yes",
            hint=f"ctfctl rollback {args.tx_id} --yes",
        )
    tx = apply_mod.rollback_tx(args.tx_id, yes=args.yes)
    payload = {
        "tx_id": tx.tx_id,
        "phase": tx.phase,
        "files": [c.path for c in tx.changes],
        "restored": tx.restored_paths,
        "effects": tx.effects_run,
        "verification": tx.verification,
        "errors": tx.errors,
    }
    if args.json:
        util.emit_json(payload)
    else:
        print(f"transaction {tx.tx_id}: {tx.phase}")
        for path in tx.restored_paths:
            print(f"  restored {path}")
        if not tx.restored_paths and tx.phase == "ROLLED_BACK":
            print("  nothing to restore: the files already matched the pre-images")
        for effect in [e for e in tx.effects_run if e.get("phase") == "rollback"]:
            print(f"  effect {' '.join(effect['argv'])} -> ok={effect['ok']}")
        if tx.verification:
            print(
                "  post-rollback state check (the pre-patch state is expected here, so the"
            )
            print(
                "  negative exploit probe should FAIL again — that means the rollback worked):"
            )
        for result in tx.verification:
            print(
                f"  verify {'ok  ' if result.get('ok') else 'FAIL'} "
                f"[{result.get('tier')}] {result.get('verifier')}: "
                f"{util.printable(str(result.get('detail')), 160)}"
            )
        for error in tx.errors:
            print(f"  ! {util.printable(str(error), 200)}")
        if tx.phase == "CONFLICTED":
            print(
                "\nA file changed after the transaction, so it was left alone. "
                "Resolve the difference by hand; nothing was overwritten."
            )
    return util.EXIT_OK if tx.phase == "ROLLED_BACK" else util.EXIT_NEGATIVE


def cmd_recover(args: argparse.Namespace) -> int:
    findings = apply_mod.recover()
    if args.json:
        util.emit_json({"interrupted": findings})
    else:
        if not findings:
            print("no interrupted transactions")
        for finding in findings:
            print(f"{finding['tx_id']}  phase={finding['phase']}")
            for item in finding["files"]:
                print(f"  {item['state']}: {item['path']} -> {item['action']}")
            print(f"  next: {finding['requires']}")
    return util.EXIT_OK


def cmd_watch(args: argparse.Namespace) -> int:
    config = observe_mod.ObservationConfig(
        log_paths=list(args.logs),
        journal_units=list(args.unit),
        include_regex=args.include,
        exclude_regex=args.exclude,
        seconds=args.seconds,
        max_lines=args.max_lines,
        net_interface=(args.iface if args.iface or args.dry_run else None),
        net_filter=args.filter,
        net_count=args.count,
        net_snaplen=args.snaplen,
        dry_run=args.dry_run,
    )
    results = observe_mod.run(config)
    if args.json:
        util.emit_json(results)
    else:
        print(observe_mod.summarize(results))
    return util.EXIT_OK


def cmd_decoy(args: argparse.Namespace) -> int:
    command = args.decoy_command or "status"
    if command == "enable":
        policy = decoy_mod.enable(
            util.repo_root(),
            ports=list(args.port),
            paths=list(args.path),
            bind=args.bind,
            notes=args.notes,
            acknowledge=args.ack_rules,
        )
        payload = policy.as_dict()
        if args.json:
            util.emit_json(payload)
        else:
            print(
                "decoy enabled for ports "
                + ", ".join(str(p) for p in policy.allowed_ports)
            )
            print("paths: " + ", ".join(policy.allowed_paths))
            print(
                "Reminder: a decoy is an observation aid. It must never shadow a scored "
                "service and it does not replace log review."
            )
        return util.EXIT_OK
    if command == "start":
        state = decoy_mod.start(util.repo_root(), port=args.port, bind=args.bind,
                                mode=getattr(args, "mode", "http"),
                                banner=getattr(args, "banner", ""))
        if args.json:
            util.emit_json(state)
        else:
            print(
                f"decoy started pid={state['pid']} on {state['bind']}:{state['port']}"
                f" mode={state.get('mode', 'http')}"
            )
            print(f"events -> {state['log_path']}")
        return util.EXIT_OK
    if command == "stop":
        result = decoy_mod.stop(util.repo_root())
        if args.json:
            util.emit_json(result)
        else:
            print(
                f"stopped={result.get('stopped')} verified_port_released="
                f"{result.get('verified')}"
            )
        return util.EXIT_OK if result.get("verified") else util.EXIT_NEGATIVE
    state = decoy_mod.status(util.repo_root())
    if args.json:
        util.emit_json(state)
    else:
        print(decoy_mod.summarize(state))
    return util.EXIT_OK


def cmd_honeypot(args: argparse.Namespace) -> int:
    command = args.honeypot_command or "status"
    root = util.repo_root()
    if command == "start":
        entry = honeypot_mod.start(
            root, port=args.port, mode=args.mode, bind=args.bind, banner=args.banner,
            paths=list(args.path) or None, allow_privileged=args.allow_privileged,
        )
        if args.json:
            util.emit_json(entry)
        else:
            print(f"honeypot listening on {entry['bind']}:{entry['port']} "
                  f"mode={entry['mode']} pid={entry['pid']}")
            print(f"events -> {entry['log_path']}  (every event carries decoy=true)")
            print("It must never sit on a port a scored service or the checker uses.")
        return util.EXIT_OK
    if command == "logs":
        payload = honeypot_mod.logs(root, lines=args.lines, port=args.port)
        if args.json:
            util.emit_json(payload)
        else:
            print(honeypot_mod.logs_text(payload))
        return util.EXIT_OK
    if command == "stop":
        if not args.port and not args.all_listeners:
            raise util.UsageError("honeypot stop needs --port <PORT> or --all")
        payload = honeypot_mod.stop(root, port=args.port, all_listeners=args.all_listeners)
        if args.json:
            util.emit_json(payload)
        else:
            stopped = payload.get("stopped") or []
            if not stopped:
                print("no honeypot listener matched that selection")
            for entry in stopped:
                print(f"stopped port {entry.get('port')} "
                      f"(process gone: {not entry.get('alive_after')})")
        return util.EXIT_OK
    payload = honeypot_mod.status(root)
    if args.json:
        util.emit_json(payload)
    else:
        print(honeypot_mod.summarize(payload))
    return util.EXIT_OK


def cmd_lockdown(args: argparse.Namespace) -> int:
    command = args.lockdown_command or "plan"
    if command != "plan":
        raise util.UsageError(f"unknown lockdown subcommand {command!r}")
    inventory = _load_inventory(args)
    spec = plan_mod.LockdownSpec(
        operator_cidr=args.operator_cidr,
        allow_cidrs=list(args.allow_cidr),
        allow_tcp_ports=[int(p) for p in str(args.allow_ports).replace(";", ",").split(",")
                         if p.strip()],
        allow_udp_ports=[int(p) for p in str(args.allow_udp_ports).replace(";", ",").split(",")
                         if p.strip()],
        include_firewall=not args.no_firewall,
        include_ssh=not args.no_ssh,
        log_drops=args.log_drops,
        nft_path=args.nft_path,
        table=args.table,
        sshd_path=args.sshd_path,
        authorized_keys_path=args.authorized_keys or "/root/.ssh/authorized_keys",
        service_unit=args.service_unit,
        sshd_port=args.sshd_port,
        note=args.note,
    )
    plan = plan_mod.build_lockdown_plan(
        spec, inventory, allow_fixture=args.allow_fixture
    )
    if not args.no_save and plan.detection.get("matched"):
        plan.save()
    if args.json:
        util.emit_json({"plans": [plan.as_dict()]})
    else:
        print(plan_mod.render(plan, verbose=args.verbose))
    return util.EXIT_OK


def cmd_targets(args: argparse.Namespace) -> int:
    command = args.targets_command or "list"
    if command == "declare":
        result = remote_mod.declare_target(
            args.host,
            label=args.label,
            role=args.role,
            notes=args.notes,
            ack_policy=args.ack_policy,
        )
        if args.json:
            util.emit_json(result)
        else:
            action = "updated" if result.get("replaced") else "declared"
            print(f"{action} target {result['host']}  label={result['label']}")
            print(f"targets file        {result['targets_file']}")
            print(f"policy acknowledged {result['policy_acknowledged']}")
            if not result["policy_acknowledged"]:
                print(
                    "Mutating actions stay blocked until the event policy is acknowledged: "
                    f"re-run with --ack-policy once the rules are confirmed."
                )
        return util.EXIT_OK
    targets = remote_mod.load_targets()
    payload = {
        "targets": targets,
        "policy_acknowledged": remote_mod.is_policy_acknowledged(),
        "targets_file": remote_mod.TARGETS_REL,
        "policy_file": remote_mod.POLICY_REL,
    }
    if args.json:
        util.emit_json(payload)
    else:
        if not targets:
            print(
                "no targets declared. Read-only local work needs none; remote work does:\n"
                "  ctfctl targets declare <host> --label '<what it is>' [--ack-policy]"
            )
        for item in targets:
            print(
                f"{item.get('host', '?'):<40} {item.get('role', '?'):<10} "
                f"{item.get('label', '')}"
            )
        print(f"policy acknowledged: {payload['policy_acknowledged']}")
    return util.EXIT_OK


def cmd_files(args: argparse.Namespace) -> int:
    command = args.files_command or "list"
    # Local use allows relative paths; they are resolved here so the same
    # exploration code always sees a clean absolute path.
    local_path = files_mod.resolve_local_path(args.path)
    if command == "list":
        payload = files_mod.list_dir(local_path, depth=args.depth, limit=args.limit)
        if args.json:
            util.emit_json(payload)
        else:
            print(files_mod.render_listing(payload))
        return util.EXIT_OK
    if command == "read":
        payload = files_mod.read_file(
            local_path, max_bytes=args.max_bytes, redact=not args.no_redact
        )
        if args.json:
            util.emit_json(payload)
        else:
            print(files_mod.render_read(payload))
        return util.EXIT_OK
    if command == "find":
        payload = files_mod.find_files(
            local_path,
            name=args.name,
            limit=args.limit,
            max_depth=args.max_depth,
        )
        if args.json:
            util.emit_json(payload)
        else:
            print(files_mod.render_matches(payload))
        return util.EXIT_OK
    raise util.UsageError(f"unknown files action {command!r}")


def _absorb_run_connection_options(args: argparse.Namespace) -> List[str]:
    """Move connection flags that argparse left in REMAINDER back onto args.

    `remote run <host> --user root doctor` is the natural order, but REMAINDER
    captures everything after the host. Absorbing the known flags here means
    both orders work and the proxied subcommand never sees them.
    """
    tail = list(getattr(args, "args", []) or [])
    consumed = 0
    while consumed < len(tail) and tail[consumed] in (
        "--user",
        "--port",
        "--identity",
        "--timeout",
    ):
        flag = tail[consumed]
        if consumed + 1 >= len(tail):
            raise util.UsageError(f"{flag} needs a value")
        value = tail[consumed + 1]
        if flag == "--user":
            args.user = value
        elif flag == "--identity":
            args.identity = value
        elif flag == "--port":
            try:
                args.port = int(value)
            except ValueError:
                raise util.UsageError(
                    f"--port must be a number, got {value!r}"
                ) from None
        elif flag == "--timeout":
            try:
                args.timeout = float(value)
            except ValueError:
                raise util.UsageError(
                    f"--timeout must be a number, got {value!r}"
                ) from None
        consumed += 2
    return tail[consumed:]


def _remote_command_prefix(args: argparse.Namespace, subcommand: str) -> str:
    """A copy-pasteable command prefix matching the connection options in use."""
    parts = ["ctfctl", "remote", subcommand]
    if getattr(args, "user", ""):
        parts += ["--user", shlex.quote(args.user)]
    if getattr(args, "port", None):
        parts += ["--port", str(args.port)]
    if getattr(args, "identity", ""):
        parts += ["--identity", shlex.quote(args.identity)]
    return " ".join(parts)


def _remote_conn(args: argparse.Namespace) -> remote_mod.Conn:
    conn = remote_mod.parse_host(
        args.host,
        user=getattr(args, "user", "") or "",
        port=getattr(args, "port", None),
    )
    if getattr(args, "identity", ""):
        conn.identity = args.identity
    if getattr(args, "timeout", None):
        conn.timeout = args.timeout
    return conn


def cmd_remote(args: argparse.Namespace) -> int:
    command = args.remote_command
    if not command:
        raise util.UsageError(
            "remote needs a subcommand",
            hint="try: ctfctl remote probe <host>",
        )
    if command == "run":
        args.args = _absorb_run_connection_options(args)
    conn = _remote_conn(args)
    if command == "probe":
        payload = remote_mod.probe(conn, save=args.save, keep_raw=args.keep_raw)
        if args.json:
            util.emit_json(payload)
        else:
            print(remote_mod.summarize_probe(payload))
            if payload.get("saved_to"):
                print(f"\nsaved   {payload['saved_to']}")
        return util.EXIT_OK
    if command == "install":
        payload = remote_mod.install(conn, force=args.force)
        if args.json:
            util.emit_json(payload)
        else:
            if payload.get("installed"):
                print(
                    f"uploaded toolkit {payload['fingerprint']} to "
                    f"~/.ctfctl on {conn.target}"
                )
            else:
                print(f"toolkit on {conn.target} is current ({payload['fingerprint']})")
        return util.EXIT_OK
    if command == "plan":
        payload = remote_mod.plan(conn, profile=args.profile)
        matched = [
            p for p in payload.get("plans", []) if p.get("detection", {}).get("matched")
        ]
        if args.json:
            util.emit_json(payload)
        else:
            remote_meta = payload.get("remote", {})
            print(
                f"host {conn.target}: toolkit={remote_meta.get('toolkit', '?')} "
                f"uploaded={remote_meta.get('installed')} "
                f"authorization_mirrored={remote_meta.get('authorization_mirrored')} "
                f"policy_acknowledged={remote_meta.get('policy_acknowledged')}"
            )
            if not matched:
                print(
                    "\nNo profile matched this host. That is a normal outcome for an "
                    "unfamiliar service: the probe evidence is the deliverable, and no "
                    "mutation is proposed."
                )
            for entry in matched:
                print()
                print(remote_mod.render_plan(entry, verbose=args.verbose))
                plan_id = entry.get("plan_id", "latest")
                prefix = _remote_command_prefix(args, "apply")
                verify_prefix = _remote_command_prefix(args, "verify")
                print(
                    f"\nnext: {prefix} {conn.target} --plan {plan_id} --yes"
                    f"\n      {verify_prefix} {conn.target} --plan {plan_id}"
                )
        return util.EXIT_OK if matched else util.EXIT_NEGATIVE
    if command == "apply":
        code, payload = remote_mod.apply(
            conn,
            _resolve_plan_id(args),
            yes=args.yes,
            dry_run=args.dry_run,
            approve_review=args.approve_review,
            no_functional=args.no_functional,
        )
        if args.json:
            util.emit_json(payload)
        else:
            print(_render_apply(payload))
        return code
    if command == "verify":
        code, payload = remote_mod.verify(
            conn, _resolve_plan_id(args), no_functional=args.no_functional
        )
        if args.json:
            util.emit_json(payload)
        else:
            results = payload.get("verification") or payload.get("results") or []
            if not results and "error" in payload:
                print(f"verify failed: {payload['error']}")
            for item in results:
                state = "ok  " if item.get("ok") else "FAIL"
                print(
                    f"{state} [{item.get('tier', '?')}] {item.get('verifier', '?')}: "
                    f"{item.get('detail', '')}"
                )
            if not results and payload.get("ok"):
                print("verify ok")
        return code
    if command == "rollback":
        code, payload = remote_mod.rollback(
            conn, tx_id=args.tx_id, list_only=args.list, yes=args.yes
        )
        if args.json:
            util.emit_json(payload)
        else:
            transactions = payload.get("transactions") or payload.get("results") or []
            if payload.get("tx_id"):
                # A confirmed rollback returns a single-transaction payload, not a list.
                transactions = [payload]
            if not transactions and "error" in payload:
                print(f"rollback failed: {payload['error']}")
            for item in transactions:
                print(
                    f"{item.get('tx_id', '?')}  phase={item.get('phase', '?')}  "
                    f"files={len(item.get('files') or [])}"
                )
                for path in item.get("restored") or []:
                    print(f"  restored {path}")
                for error in item.get("errors") or []:
                    print(f"  ! {util.printable(str(error), 160)}")
            if not transactions and "error" not in payload:
                print("no remote transactions recorded")
            if payload.get("rolled_back"):
                print("rolled back")
        return code
    if command == "recover":
        code, payload = remote_mod.recover(conn)
        if args.json:
            util.emit_json(payload)
        else:
            interrupted = payload.get("interrupted") or []
            if not interrupted:
                print("no interrupted remote transactions")
            for finding in interrupted:
                print(f"{finding.get('tx_id', '?')}  phase={finding.get('phase', '?')}")
                for item in finding.get("files") or []:
                    print(
                        f"  {item.get('state', '?')}: {item.get('path', '?')} -> "
                        f"{item.get('action', '?')}"
                    )
                print(f"  next: {finding.get('requires', 'review')}")
        return code
    if command == "run":
        return remote_mod.run_read_only(conn, list(args.args))
    if command == "files":
        return remote_mod.remote_files(
            conn,
            args.files_action,
            args.path,
            depth=args.depth,
            limit=args.limit,
            name=args.name,
            max_bytes=args.max_bytes,
            max_depth=args.max_depth,
            as_json=args.json,
        )
    if command == "honeypot":
        if args.honeypot_action == "collect":
            payload = remote_mod.honeypot_collect(conn)
            if args.json:
                util.emit_json(payload)
            else:
                if not payload.get("collected"):
                    print(f"nothing collected from {conn.target} "
                          f"({payload.get('error') or 'no honeypot logs'})")
                for item in payload.get("collected", []):
                    print(f"port {item.get('port'):>5}  {item.get('bytes', 0):>8} bytes  "
                          f"-> {item.get('saved_to') or item.get('error')}")
            return util.EXIT_OK if payload.get("ok") else util.EXIT_NEGATIVE
        code, payload = remote_mod.honeypot(
            conn, args.honeypot_action, port=args.honeypot_port, mode=args.mode,
            bind=args.bind,
            banner=args.banner, lines=args.lines, all_listeners=args.all_listeners,
            yes=args.yes,
        )
        if args.json:
            util.emit_json(payload)
        elif args.honeypot_action == "status":
            print(remote_mod.render_honeypot_status(payload))
        elif args.honeypot_action == "logs":
            print(util.printable(remote_mod.render_honeypot_logs(payload), 8000))
        elif args.honeypot_action == "start":
            if payload.get("port"):
                print(f"honeypot on {conn.target}: port {payload['port']} "
                      f"mode={payload.get('mode')} log={payload.get('log_path')}")
                print("Collect the events with: ctfctl remote honeypot "
                      f"{conn.target} collect")
            else:
                print(f"honeypot did not start: {util.printable(str(payload), 400)}")
        else:
            print(f"stopped: {util.printable(str(payload.get('stopped') or payload), 400)}")
        return code
    if command == "lockdown":
        payload = remote_mod.lockdown(
            conn,
            operator_cidr=args.operator_cidr,
            allow_cidrs=list(args.allow_cidr),
            allow_ports=list(args.allow_port),
            allow_udp_ports=[int(p) for p in str(args.allow_udp_ports).replace(";", ",")
                             .split(",") if p.strip()],
            include_firewall=not args.no_firewall,
            include_ssh=not args.no_ssh,
            log_drops=args.log_drops,
            sshd_port=args.sshd_port,
        )
        matched = [
            entry for entry in (payload.get("plans") or [])
            if (entry.get("detection") or {}).get("matched")
        ]
        if args.json:
            util.emit_json(payload)
        else:
            meta = payload.get("remote") or {}
            print(
                f"host {conn.target}: operator={meta.get('operator_cidr')} "
                f"ports_kept={meta.get('allowed_ports')} "
                f"authorization_mirrored={meta.get('authorization_mirrored')} "
                f"policy_acknowledged={meta.get('policy_acknowledged')}"
            )
            if not meta.get("authorization_mirrored"):
                print(
                    "\nThe local policy is not acknowledged, so the plan would be refused by "
                    "the apply step on the target. This is a review copy only."
                )
            for entry in matched:
                print()
                print(remote_mod.render_plan(entry, verbose=args.verbose))
                plan_id = entry.get("plan_id", "latest")
                prefix = _remote_command_prefix(args, "apply")
                print(
                    f"\nnext: read the diff above, confirm you have a console, then\n"
                    f"      {prefix} {conn.target} --plan {plan_id} --approve-review --yes"
                )
        return util.EXIT_OK if matched else util.EXIT_NEGATIVE
    if command == "auto":
        payload = remote_mod.auto(
            conn,
            apply_mutations=args.apply_mutations,
            approve_review=args.approve_review,
            honeypot_port=args.honeypot_port,
            honeypot_mode=args.honeypot_mode,
            honeypot_banner=args.honeypot_banner,
            lockdown_requested=args.lockdown,
            allow_cidrs=list(args.allow_cidr),
            yes=args.yes,
        )
        if args.json:
            util.emit_json(payload)
        else:
            print(remote_mod.render_auto_report(payload))
            print(f"\nsaved: {payload['report_json']}")
            print(f"       {payload['report_markdown']}")
        failed = [
            key for key, code_key in (("apply", "apply_exit_code"),
                                      ("honeypot", "honeypot_exit_code"))
            if key in (payload.get("steps") or {}) and payload.get(code_key) not in (None, 0)
        ]
        return util.EXIT_NEGATIVE if failed or payload.get("gaps") else util.EXIT_OK
    raise util.UsageError(f"unknown remote subcommand {command!r}")


def _render_apply(payload: dict) -> str:
    if payload.get("error"):
        return f"apply refused: {payload['error']}"
    lines = [
        f"tx          {payload.get('tx_id', '?')}",
        f"phase       {payload.get('phase', '?')}",
        f"plan        {payload.get('plan', '?')}",
    ]
    for item in payload.get("files", []):
        replaced = "replaced" if item.get("replaced") else "unchanged"
        lines.append(
            f"  file      {item.get('path', '?')}  "
            f"{item.get('pre', '')[:12]} -> {item.get('post', '')[:12]}  {replaced}"
        )
    for item in payload.get("verification", []):
        state = "ok  " if item.get("ok") else "FAIL"
        lines.append(
            f"  check     {state} [{item.get('tier', '?')}] {item.get('verifier', '?')}: "
            f"{item.get('detail', '')}"
        )
    for error in payload.get("errors", []):
        lines.append(f"  error     {error}")
    return "\n".join(lines)


def cmd_kb(args: argparse.Namespace) -> int:
    command = args.kb_command or "stats"
    if command == "index":
        stats = kbindex.build(rebuild=args.rebuild)
        payload = stats.as_dict()
        if args.json:
            util.emit_json(payload)
        else:
            print(
                f"index {stats.mode}: added={stats.added} updated={stats.updated} "
                f"deleted={stats.deleted} unchanged={stats.unchanged} total={stats.total}"
            )
            print(f"fts5={'yes' if stats.fts5 else 'NO (literal fallback only)'}")
            for warning in stats.warnings:
                print(f"  ! {warning}")
        return util.EXIT_OK
    if command == "search":
        mode = "phrase" if args.phrase else ("any" if args.any else "auto")
        if args.fts:
            mode = "raw"
        try:
            hits = kbindex.search(
                args.query,
                mode=mode,
                tag=args.tag,
                stack=args.stack,
                limit=args.limit,
                kind=args.kind,
            )
        except util.CtfError as exc:
            if not args.json:
                util.eprint(f"ERROR query: {exc}")
                if exc.hint:
                    util.eprint(f"HINT: {exc.hint}")
            else:
                util.emit_json({"error": str(exc), "hint": exc.hint, "hits": []})
            return util.EXIT_NEGATIVE
        return _emit_hits(hits, args.json)
    if command == "cheat":
        try:
            hits = kbindex.search(
                args.topic, mode="auto", tag="cheatsheet", limit=args.limit
            ) if args.topic else kbindex.by_tag("cheatsheet", limit=args.limit)
        except util.CtfError as exc:
            if args.json:
                util.emit_json({"error": str(exc), "hint": exc.hint, "hits": []})
            else:
                util.eprint(f"ERROR query: {exc}")
            return util.EXIT_NEGATIVE
        if args.json:
            util.emit_json({"hits": [h.as_dict() for h in hits]})
        else:
            if not hits:
                print(
                    "No cheatsheet cards are indexed. Build the index first "
                    "(`ctfctl kb index`) or drop Markdown into kb/cheatsheets/."
                )
            for hit in hits:
                print(f"{hit.title}")
                print(f"  id   {hit.stable_id}")
                print(f"  path {hit.path}")
                if hit.snippet:
                    print(f"  {util.printable(hit.snippet, 200)}")
            if hits:
                print("\nfull text: ctfctl kb show <id>   everything: ctfctl kb search <terms>")
        return util.EXIT_OK if hits else util.EXIT_NEGATIVE
    if command == "literal":
        hits = kbindex.literal(
            args.pattern,
            tag=args.tag,
            stack=args.stack,
            limit=args.limit,
            fixed=not args.regex,
        )
        return _emit_hits(hits, args.json)
    if command == "show":
        return _show_document(args.identifier, args.path_only)
    if command == "verify":
        report = kbindex.verify()
        if args.json:
            util.emit_json(report)
        else:
            print(f"knowledge base verify: {'OK' if report['ok'] else 'PROBLEMS'}")
            for check in report["checks"]:
                print(
                    f"  {'ok  ' if check['ok'] else 'FAIL'} {check['name']}: {check['detail']}"
                )
            for warning in report["warnings"]:
                print(f"  warn {warning}")
        return util.EXIT_OK if report["ok"] else util.EXIT_NEGATIVE
    if command == "stats":
        data = kbindex.stats()
        if args.json:
            util.emit_json(data)
        else:
            print(
                f"cards      {data['cards_on_disk']} on disk / {data['cards_manifest']} in manifest"
            )
            print(
                f"sources    {data['sources_total']} total, {data['sources_primary']} primary, "
                f"{data['teams_organizers']} teams/organizers"
            )
            print(
                f"index      {data['index']['path']} exists={data['index']['exists']}"
            )
            print(
                "tags       "
                + ", ".join(f"{k}({v})" for k, v in list(data["tags"].items())[:12])
            )
            print(
                "stacks     "
                + ", ".join(f"{k}({v})" for k, v in list(data["stacks"].items())[:12])
            )
        return util.EXIT_OK
    if command == "export":
        return _export(args)
    if command == "open":
        return _show_document(args.identifier, path_only=True)
    raise util.UsageError(f"unknown kb subcommand {command!r}")


def _emit_hits(hits: List[kbindex.Hit], as_json: bool) -> int:
    if as_json:
        util.emit_json({"count": len(hits), "hits": [h.as_dict() for h in hits]})
        return util.EXIT_OK if hits else util.EXIT_NEGATIVE
    if not hits:
        print("no matches")
        print(
            "hint: try `ctfctl kb literal <text>` for exact code/error strings, or "
            "`ctfctl kb index` if the index is missing."
        )
        return util.EXIT_NEGATIVE
    for hit in hits:
        location = hit.path + (f":{hit.line}" if hit.line else "")
        print(f"{hit.title or hit.path}")
        print(f"  {location}   [{hit.match_kind}] score={hit.score:.2f}")
        if hit.snippet:
            print(f"  {util.printable(hit.snippet, 300)}")
    return util.EXIT_OK


def _show_document(identifier: str, path_only: bool) -> int:
    root = util.repo_root()
    if identifier.startswith("card-") or identifier.startswith("src-"):
        for entry in util.load_jsonl(os.path.join(root, "kb", "manifest.jsonl")):
            if entry.get("card_id") == identifier:
                identifier = str(entry.get("path"))
                break
        else:
            for entry in kbindex._all_source_records(root):
                if entry.get("source_id") == identifier:
                    print(json.dumps(entry, indent=2, ensure_ascii=False))
                    return util.EXIT_OK
    path = identifier if os.path.isabs(identifier) else os.path.join(root, identifier)
    if not os.path.isfile(path):
        raise util.CtfError(f"no such card or path: {identifier}")
    if path_only:
        print(path)
        return util.EXIT_OK
    print(util.read_text(path, 1 * 1024 * 1024))
    return util.EXIT_OK


def _export(args: argparse.Namespace) -> int:
    import shutil

    root = util.repo_root()
    destination = os.path.abspath(args.directory)
    if os.path.isfile(destination):
        raise util.CtfError(
            f"refusing to export into an existing file: {destination}",
            hint="choose a new directory",
        )
    if os.path.exists(destination) and os.listdir(destination):
        raise util.CtfError(
            f"refusing to export into a non-empty directory: {destination}",
            hint="choose a new directory",
        )
    os.makedirs(destination, exist_ok=True)
    copied: List[str] = []
    excluded: List[Dict[str, Any]] = []
    for relative in ("README.md", "AGENTS.md"):
        source = os.path.join(root, relative)
        if os.path.isfile(source):
            shutil.copy2(source, os.path.join(destination, relative))
            copied.append(relative)
    for relative in (
        "kb",
        "docs",
        "tools",
        "profiles",
        "fixtures",
        "tests",
        "drills",
        "research",
    ):
        source = os.path.join(root, relative)
        if not os.path.isdir(source):
            continue
        target = os.path.join(destination, relative)
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3"),
        )
        copied.append(relative + "/")
    sources_dir = os.path.join(destination, "sources")
    os.makedirs(sources_dir, exist_ok=True)
    manifest_lines = []
    for name in ("manifest.jsonl", "verified-index.jsonl"):
        path = os.path.join(root, "sources", name)
        if os.path.isfile(path):
            shutil.copy2(path, os.path.join(sources_dir, name))
            copied.append(f"sources/{name}")
            manifest_lines.extend(util.load_jsonl(path))
    text_root = os.path.join(root, "sources", "text")
    if os.path.isdir(text_root):
        allowed_policy = {"allowed", "allowed-with-attribution"}
        for dirpath, _dirnames, filenames in os.walk(text_root):
            for name in sorted(filenames):
                absolute = os.path.join(dirpath, name)
                relative = os.path.relpath(absolute, root).replace(os.sep, "/")
                record = next(
                    (
                        r
                        for r in manifest_lines
                        if str(r.get("local_path") or "").replace(os.sep, "/")
                        == relative
                    ),
                    None,
                )
                policy = (record or {}).get("redistribution", "unknown")
                if args.shareable and policy not in allowed_policy:
                    excluded.append({"path": relative, "redistribution": policy})
                    continue
                target = os.path.join(destination, relative)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(absolute, target)
                copied.append(relative)
    payload = {
        "destination": destination,
        "shareable": bool(args.shareable),
        "copied": copied,
        "excluded_snapshots": excluded,
        "note": (
            "shareable export excludes any stored snapshot whose redistribution policy is "
            "not 'allowed' or 'allowed-with-attribution'. Runtime state, captures, index "
            "and plans are never exported."
        ),
    }
    util.write_text_atomic(
        os.path.join(destination, "EXPORT.json"), util.dump_json(payload), mode=0o644
    )
    if args.json:
        util.emit_json(payload)
    else:
        print(f"exported to {destination}")
        for item in excluded:
            print(f"  excluded (licence {item['redistribution']}): {item['path']}")
    return util.EXIT_OK


def cmd_profiles(args: argparse.Namespace) -> int:
    command = args.profiles_command or "list"
    if command == "list":
        entries = [p.as_dict() for p in profiles_mod.load_all()]
        if args.json:
            util.emit_json({"profiles": entries})
        else:
            for profile in entries:
                print(
                    f"{profile['profile_id']:<32} {profile['support_level']:<20} "
                    f"{profile['title']}"
                )
                auto = [
                    k
                    for k, v in profile["actions"].items()
                    if str(v.get("eligibility")) == "auto"
                ]
                print(
                    f"  scope={profile['scope']}  actions={len(profile['actions'])} "
                    f"auto={auto or 'none'}"
                )
        return util.EXIT_OK
    if command == "show":
        profile = profiles_mod.load(args.profile_id)
        if args.json:
            util.emit_json(
                {**profile.as_dict(), "problems": profiles_mod.validate(profile)}
            )
        else:
            print(util.dump_json(profile.as_dict()))
            problems = profiles_mod.validate(profile)
            print("\nvalidation: " + ("ok" if not problems else "; ".join(problems)))
        return util.EXIT_OK
    if command == "validate":
        problems: List[str] = []
        profiles = profiles_mod.load_all()
        for profile in profiles:
            for problem in profiles_mod.validate(profile):
                problems.append(f"{profile.profile_id}: {problem}")
        if args.json:
            util.emit_json(
                {"valid": not problems, "problems": problems, "count": len(profiles)}
            )
        else:
            print(f"profiles validated: {len(profiles)}")
            for problem in problems:
                print(f"  FAIL {problem}")
            if not problems:
                print("  all profiles are structurally valid")
        return util.EXIT_OK if not problems else util.EXIT_NEGATIVE
    raise util.UsageError(f"unknown profiles subcommand {command!r}")


def cmd_prep_online(args: argparse.Namespace) -> int:
    """The only command allowed to touch the network. Explicitly invoked."""
    results: Dict[str, Any] = {"network_used": True, "steps": []}
    index_path = os.path.join(util.repo_root(), "sources", "verified-index.jsonl")
    if args.check_sources:
        if not os.path.isfile(index_path):
            raise util.CtfError(f"no source index at {index_path}")
        records, summary = sources_check.check_manifest(
            index_path, only_missing=not args.all
        )
        sources_check.write_index(index_path, records)
        results["steps"].append(
            {
                "step": "check-sources",
                "summary": summary,
                "verified": sum(1 for r in records if r.get("verified")),
                "failed": [
                    r.get("source_id") for r in records if not r.get("verified")
                ],
            }
        )
    caps = platformx.probe()
    missing = [tool for tool in (args.require_tools or []) if not caps.tools.get(tool)]
    results["tools"] = {"required": list(args.require_tools or []), "missing": missing}
    results["fixtures_note"] = (
        "Container images are cached with your normal `docker pull` / `docker compose build`. "
        "This command deliberately does not build or pull anything implicitly."
    )
    if args.json:
        util.emit_json(results)
    else:
        for step in results["steps"]:
            print(f"{step['step']}: {step['summary']}")
        if args.require_tools:
            print(f"required tools missing: {missing or 'none'}")
        print(results["fixtures_note"])
    return util.EXIT_OK if not missing else util.EXIT_NEGATIVE


def _emit_hits_or_error(exc: util.CtfError) -> int:
    util.eprint(f"error: {exc}")
    if exc.hint:
        util.eprint(f"hint: {exc.hint}")
    return exc.exit_code


# --------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse has already printed usage/errors to stderr. Returning the code
        # instead of propagating keeps main() usable in-process (tests, SDK).
        return int(exc.code) if exc.code is not None else util.EXIT_OK
    if not args.command:
        parser.print_help()
        return util.EXIT_USAGE
    handlers = {
        "doctor": cmd_doctor,
        "discover": cmd_discover,
        "plan": cmd_plan,
        "apply": cmd_apply,
        "verify": cmd_verify,
        "rollback": cmd_rollback,
        "recover": cmd_recover,
        "watch": cmd_watch,
        "decoy": cmd_decoy,
        "honeypot": cmd_honeypot,
        "lockdown": cmd_lockdown,
        "kb": cmd_kb,
        "profiles": cmd_profiles,
        "prep-online": cmd_prep_online,
        "targets": cmd_targets,
        "files": cmd_files,
        "remote": cmd_remote,
    }
    handler = handlers[args.command]
    try:
        return handler(args)
    except util.CtfError as exc:
        return _emit_hits_or_error(exc)
    except KeyboardInterrupt:
        util.eprint("interrupted")
        return util.EXIT_NEGATIVE
    except BrokenPipeError:  # pragma: no cover
        return util.EXIT_OK
    except Exception as exc:  # pragma: no cover - unexpected
        if os.environ.get("CTFCTL_DEBUG"):
            raise
        util.eprint(f"internal error: {type(exc).__name__}: {exc}")
        util.eprint(
            "set CTFCTL_DEBUG=1 for a traceback; please report this with the command"
        )
        return util.EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
