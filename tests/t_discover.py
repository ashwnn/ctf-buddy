"""Discovery: unprivileged behaviour, evidence gaps, redaction, non-attribution."""

from __future__ import annotations

import os

from helpers import check, check_eq, check_in, temp_dir

from ctfctl import discover, platformx, util

PROC_NET_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123458 1 0000000000000000 100 0 0 10 0
"""

PROC_NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123457 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 123458 1 0000000000000000 100 0 0 10 0
"""


def _fake_sysroot(root: str) -> None:
    os.makedirs(os.path.join(root, "proc", "net"), exist_ok=True)
    os.makedirs(os.path.join(root, "etc"), exist_ok=True)
    with open(os.path.join(root, "proc", "net", "tcp"), "w", encoding="utf-8") as fh:
        fh.write(PROC_NET_TCP)
    with open(os.path.join(root, "proc", "net", "tcp6"), "w", encoding="utf-8") as fh:
        fh.write(PROC_NET_TCP6)
    with open(os.path.join(root, "proc", "uptime"), "w", encoding="utf-8") as fh:
        fh.write("1234.56 9876.54\n")
    with open(os.path.join(root, "proc", "meminfo"), "w", encoding="utf-8") as fh:
        fh.write("MemTotal:  2048000 kB\nMemAvailable: 1024000 kB\n")
    with open(os.path.join(root, "etc", "os-release"), "w", encoding="utf-8") as fh:
        fh.write('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n')


def test_proc_net_parsing_without_privileges() -> None:
    with temp_dir() as root:
        _fake_sysroot(root)
        sockets, gaps = discover.parse_proc_net(root)
        check_eq(gaps, [], "a readable /proc/net/tcp should not report a gap")
        by_port = {s["port"]: s for s in sockets}
        check_in(8080, by_port, "8080 (0x1F90) should be parsed")
        check_eq(by_port[8080]["address"], "127.0.0.1", "IPv4 little-endian decode")
        check_eq(by_port[8080]["state"], "listen", "0A is LISTEN")
        check_in(80, by_port, "port 80 should be parsed")
        check_eq(by_port[80]["address"], "0.0.0.0", "wildcard bind")
        check_in(8081, by_port, "the IPv6 table entry should be parsed")


def test_discovery_without_proc_reports_gaps_not_guesses() -> None:
    with temp_dir() as root:
        os.makedirs(os.path.join(root, "etc"), exist_ok=True)
        inventory = discover.discover(system_root=root, allow_subprocess=False, quick=True)
        gaps = "\n".join(inventory.gaps())
        check("os-release" in gaps or "distribution" in gaps,
              f"a missing os-release must be reported: {gaps}")
        check("socket probe" in gaps or "/proc/net/tcp" in gaps,
              f"a missing socket table must be reported: {gaps}")
        check_eq(inventory.graph["services"], [], "no listeners means no services")
        check("is_root" in inventory.host, "the host block must still be present")
        check("euid" in inventory.host, "the host block must record the effective uid")


def test_unknown_listener_is_reported_without_a_stack_claim() -> None:
    with temp_dir() as root:
        _fake_sysroot(root)
        inventory = discover.discover(system_root=root, allow_subprocess=False, quick=True)
        services = inventory.graph["services"]
        check(services, "the fake listeners should produce service candidates")
        for service in services:
            if not service.get("process") and not service.get("container"):
                check_eq(service["confidence"], "low",
                         "an unattributed listener must be low confidence")
                check(service["unsupported_reason"],
                      "an unattributed listener must explain why it is not a target")
            check(service["evidence"], "every service candidate must cite evidence")


def test_exposure_classification() -> None:
    check_eq(discover._exposure("0.0.0.0"), "all-interfaces", "wildcard is exposed")
    check_eq(discover._exposure("::"), "all-interfaces", "v6 wildcard is exposed")
    check_eq(discover._exposure("127.0.0.1"), "loopback-only", "loopback is local")
    check_eq(discover._exposure("10.0.0.5"), "specific-address", "specific bind")


def test_secret_looking_files_are_stat_only() -> None:
    with temp_dir() as root:
        app = os.path.join(root, "srv", "app")
        os.makedirs(app, exist_ok=True)
        secret = os.path.join(app, "id_rsa")
        with open(secret, "w", encoding="utf-8") as fh:
            fh.write("-----BEGIN OPENSSH PRIVATE KEY-----\nSHOULD_NOT_BE_READ\n")
        evidence = discover.collect_filesystem_risk(root, ["/srv/app"])
        findings = evidence.data["findings"]
        blobs = util.dump_json(evidence.data)
        check(any(f["issue"] == "sensitive-looking filename" for f in findings),
              "a private key filename should be flagged")
        check("SHOULD_NOT_BE_READ" not in blobs,
              "discovery must never include the contents of a private key")
        check("stat only" in blobs, "the finding should say that only metadata was read")


def test_compose_project_directory_is_enumerated_not_dumped() -> None:
    with temp_dir() as root:
        project = os.path.join(root, "proj")
        os.makedirs(os.path.join(project, "service"), exist_ok=True)
        with open(os.path.join(project, "service", "app.py"), "w", encoding="utf-8") as fh:
            fh.write("SECRET_CONTENT = 'do not leak'\n")
        container = {
            "name": "web", "compose_working_dir": project, "mounts": [],
            "compose_project": "proj", "compose_service": "web",
        }
        evidence = discover.collect_app_roots(None, root, [], [container])  # type: ignore[arg-type]
        blob = util.dump_json(evidence.data)
        check("service/app.py" in blob, "the project file list should be present")
        check("do not leak" not in blob, "file contents must never be collected")


def test_environment_values_are_never_collected() -> None:
    with temp_dir() as root:
        proc = os.path.join(root, "proc", "4242")
        os.makedirs(proc, exist_ok=True)
        with open(os.path.join(proc, "environ"), "wb") as fh:
            fh.write(b"PATH=/usr/bin\x00DATABASE_URL=postgres://u:p@db/app\x00")
        evidence = discover.collect_env_names(None, root, [4242])  # type: ignore[arg-type]
        names = evidence.data["by_pid"]["4242"]
        blob = util.dump_json(evidence.data)
        check_in("DATABASE_URL", names, "variable names are useful signal")
        check("postgres://" not in blob, "environment values must never be collected")


def test_docker_evidence_absent_is_explicit() -> None:
    caps = platformx.probe(quick=True)
    evidence = discover.collect_containers(caps, allow_subprocess=False)
    check_in(evidence.status, ("unsupported", "partial", "ok"),
             "collector status must be explicit")
    check(evidence.detail, "the collector must explain its status")


def test_redaction_of_connection_strings_and_tokens() -> None:
    text = ("DATABASE_URL=postgres://user:hunter2@db:5432/app\n"
            "Authorization: Bearer abcdefghijklmnop\n"
            "password = 'sup3rsecret'\n"
            "flag{th1s_looks_like_a_flag}\n")
    redacted = util.redact(text)
    for secret in ("hunter2", "abcdefghijklmnop", "sup3rsecret", "th1s_looks_like_a_flag"):
        check(secret not in redacted, f"{secret!r} should have been redacted")
    check("postgres://user:" in redacted, "the non-secret part should survive for context")
