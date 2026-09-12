"""Offline dependency and capability report.

`doctor` answers one question: *what works right now, on this machine, with no
Internet and no installation step?* Everything it reports is a local check. It
never contacts the network and never installs anything.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from . import kbindex, platformx, profiles as profiles_mod, util

REQUIRED_FOR_CORE = ("python3",)
RECOMMENDED = {
    "rg": "literal search fallback (without it, search uses a slower pure-Python scan)",
    "curl": "tier-2/3 HTTP verification (the toolkit can use its built-in client instead)",
    "docker": "container inventory and Compose-scoped profiles",
    "tcpdump": "bounded packet capture for `ctfctl watch`",
    "tshark": "offline PCAP analysis in drills",
    "ss": "faster listener inventory (falls back to /proc/net)",
}


def report(root: Optional[str] = None, *, quick: bool = False) -> Dict[str, Any]:
    root = root or util.repo_root()
    caps = platformx.probe(quick=quick)
    out: Dict[str, Any] = {
        "schema": "ctfctl.doctor/1",
        "repo_root": root,
        "generated_at": util.iso_now(),
        "platform": caps.as_dict(),
        "checks": [],
        "warnings": [],
        "blocking": [],
    }

    def check(name: str, ok: bool, detail: str, *, blocking: bool = False,
              warn: bool = False) -> None:
        out["checks"].append({"name": name, "ok": bool(ok), "detail": detail,
                              "blocking": bool(blocking)})
        if not ok:
            out["blocking" if blocking else "warnings"].append(f"{name}: {detail}")
        elif warn:
            out["warnings"].append(f"{name}: {detail}")

    check("python", True, f"Python {caps.python_version} on {caps.platform}")
    check("sqlite-fts5", caps.fts5, caps.fts5_detail, warn=not caps.fts5)
    check("file-locking", caps.fcntl_lock,
          "fcntl.flock available" if caps.fcntl_lock
          else "falling back to exclusive-create lock files", warn=not caps.fcntl_lock)
    check("linux-host", caps.is_linux,
          "Linux detected" if caps.is_linux
          else "not Linux: discovery is read-only/partial and host mutation is unavailable")

    for tool, why in sorted(RECOMMENDED.items()):
        present = bool(caps.tools.get(tool))
        check(f"tool:{tool}", present, why if present else f"missing — {why}", warn=not present)

    # Corpus
    stats = kbindex.stats(root)
    check("corpus-cards", stats["cards_on_disk"] >= 1,
          f"{stats['cards_on_disk']} card(s) on disk "
          f"({stats['cards_manifest']} in manifest)",
          blocking=stats["cards_on_disk"] == 0)
    check("corpus-sources", stats["sources_primary"] >= 1,
          f"{stats['sources_primary']} primary source record(s), "
          f"{stats['teams_organizers']} identifiable teams/organizers")
    if stats["cards_manifest"] != stats["cards_on_disk"]:
        check("manifest-parity", False,
              f"{stats['cards_manifest']} manifest entries vs {stats['cards_on_disk']} files",
              warn=True)
    else:
        check("manifest-parity", True, "every manifest entry has a file")

    # Index
    index_file = kbindex.index_path(root)
    if os.path.isfile(index_file):
        try:
            report_ = kbindex.verify(root)
            check("index-integrity", report_["ok"],
                  "index verifies" if report_["ok"] else "; ".join(report_["errors"][:3]))
            for warning in report_["warnings"]:
                out["warnings"].append(warning)
        except util.CtfError as exc:
            check("index-integrity", False, str(exc), warn=True)
    else:
        check("index-integrity", False,
              "no index yet — `ctfctl kb index` builds one; Markdown search still works "
              "via `ctfctl kb literal`", warn=True)

    # Profiles
    profile_problems: List[str] = []
    for profile in profiles_mod.load_all(root):
        problems = profiles_mod.validate(profile)
        if problems:
            profile_problems.append(f"{profile.profile_id}: {'; '.join(problems)}")
    check("profiles", not profile_problems,
          f"{len(profiles_mod.load_all(root))} profile(s) loaded and valid"
          if not profile_problems else " | ".join(profile_problems))
    tested = [p.profile_id for p in profiles_mod.load_all(root)
              if p.support_level == "tested-auto"]
    check("tested-profiles", bool(tested),
          f"fast-apply tested: {', '.join(tested)}" if tested
          else "no profile has passed the disposable fixture matrix")

    # Fixtures / drills
    fixtures = os.path.join(root, "fixtures")
    names = sorted(d for d in os.listdir(fixtures)) if os.path.isdir(fixtures) else []
    check("fixtures", bool(names), f"{len(names)} fixture(s): {', '.join(names[:8])}"
          if names else "no fixtures present", warn=not names)
    drills = os.path.join(root, "drills")
    drill_count = len([f for f in os.listdir(drills)]) if os.path.isdir(drills) else 0
    check("drills", drill_count > 0, f"{drill_count} drill document(s)")

    # Authorization state
    targets = os.path.join(root, "state", "targets.json")
    policy = os.path.join(root, "state", "policy.json")
    declared = 0
    if os.path.isfile(targets):
        payload = util.load_json(targets, {})
        declared = len(payload.get("targets") or []) if isinstance(payload, dict) else \
            len(payload or [])
    acknowledged = False
    if os.path.isfile(policy):
        acknowledged = bool(util.load_json(policy, {}).get("acknowledged"))
    check("target-declarations", declared > 0,
          f"{declared} declared target(s)" if declared else
          "no team-owned target declared: mutations are blocked, read-only work is unaffected",
          warn=declared == 0)
    check("event-policy", acknowledged,
          "event policy acknowledged" if acknowledged else
          "event policy not acknowledged in state/policy.json (required for host mutations on "
          "declared targets)", warn=not acknowledged)

    out["summary"] = {
        "ready_for_readonly": True,
        "ready_for_kb_search": stats["cards_on_disk"] > 0,
        "ready_for_ranking": caps.fts5,
        "ready_for_mutation": caps.is_linux and not out["blocking"],
        "tested_profiles": tested,
        "offline": True,
    }
    return out


def render(report_data: Dict[str, Any]) -> str:
    lines: List[str] = []
    caps = report_data["platform"]
    lines.append(f"ctfctl doctor — {report_data['generated_at']}")
    lines.append(f"repo      {report_data['repo_root']}")
    lines.append(f"platform  {caps['platform']}  linux={caps['is_linux']}  root={caps['is_root']}"
                 f"  euid={caps['euid']}")
    lines.append(f"init      {caps['init_system']}  {caps['init_detail']}")
    lines.append(f"python    {caps['python_version']}   sqlite {caps['sqlite_version']}")
    lines.append("")
    lines.append("checks")
    for check in report_data["checks"]:
        mark = "ok   " if check["ok"] else ("BLOCK" if check["blocking"] else "warn ")
        lines.append(f"  {mark} {check['name']:<22} {check['detail']}")
    if report_data["blocking"]:
        lines.append("")
        lines.append("blocking issues")
        for item in report_data["blocking"]:
            lines.append(f"  ! {item}")
    summary = report_data["summary"]
    lines.append("")
    lines.append("summary")
    lines.append(f"  read-only discovery        {'yes' if summary['ready_for_readonly'] else 'no'}")
    lines.append(f"  knowledge-base search      {'yes' if summary['ready_for_kb_search'] else 'no'}")
    lines.append(f"  ranked (FTS5) search      {'yes' if summary['ready_for_ranking'] else 'no (literal only)'}")
    lines.append(f"  host mutation              {'yes' if summary['ready_for_mutation'] else 'no'}")
    lines.append(f"  fast-apply tested profiles {summary['tested_profiles'] or 'none'}")
    lines.append("")
    lines.append("This report performs no network access and installs nothing. Run "
                 "`ctfctl prep-online` (explicitly, before the event) if something is missing.")
    return "\n".join(lines)
