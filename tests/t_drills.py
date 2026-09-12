"""Drill material: the synthetic PCAP generator and the drill sheet contract."""

from __future__ import annotations

import json
import os
import struct
import sys

from helpers import REPO_ROOT, check, check_eq, check_in, temp_dir

from ctfctl import util

GENERATOR = os.path.join(REPO_ROOT, "drills", "assets", "make-synthetic-pcap.py")
DRILLS_DIR = os.path.join(REPO_ROOT, "drills")


def _generate(directory: str, *extra: str) -> dict:
    out = os.path.join(directory, "drill02.pcap")
    result = util.run([sys.executable, GENERATOR, out, "--json", *extra], timeout=60)
    check_eq(result.returncode, 0, f"generator failed: {result.stderr[-300:]}")
    return json.loads(result.stdout)


def test_generator_writes_a_valid_pcap() -> None:
    with temp_dir() as root:
        summary = _generate(root)
        check_eq(summary["packets"], 10, "expected ten packets")
        path = summary["pcap"]
        raw = open(path, "rb").read()
        magic, vmaj, vmin, _tz, _sig, snaplen, link = struct.unpack_from(
            "<IHHiIII", raw, 0
        )
        check_eq(magic, 0xA1B2C3D4, "little-endian pcap magic")
        check_eq((vmaj, vmin), (2, 4), "pcap version")
        check_eq(link, 1, "Ethernet link type")
        check_eq(snaplen, 65535, "snaplen")
        offset = 24
        count = 0
        while offset + 16 <= len(raw):
            _ts, _us, incl, orig = struct.unpack_from("<IIII", raw, offset)
            check_eq(incl, orig, "captured length must equal original length")
            offset += 16 + incl
            count += 1
        check_eq(offset, len(raw), "packet lengths must add up exactly")
        check_eq(count, 10, "packet count from the file itself")
        check(
            b"FLAG{synthetic_pcap_reconstruction_7f3a}" in raw,
            "the synthetic flag must be present in a packet payload",
        )


def test_generator_is_deterministic() -> None:
    with temp_dir() as root:
        first = _generate(root)
        second = _generate(root)
        check_eq(
            first["sha256"], second["sha256"], "same input must produce same bytes"
        )


def test_transcript_matches_the_declared_ground_truth() -> None:
    with temp_dir() as root:
        summary = _generate(root, "--transcript")
        text = open(summary["transcript"], encoding="utf-8").read()
        check_in(summary["flag"], text, "flag must appear in the transcript")
        for request in summary["requests"]:
            check_in(
                request["method"], text, f"method {request['method']} in transcript"
            )
            check_in(request["path"], text, f"path {request['path']} in transcript")
        check_in("drill-client/1.0", text, "user agent in transcript")
        check_in("10.0.0.10:8080", text, "server endpoint in transcript")
        check("Content-Length: 93" in text, "declared body length must be present")


def test_drill_sheets_have_the_required_sections() -> None:
    sheets = sorted(
        name
        for name in os.listdir(DRILLS_DIR)
        if name.endswith(".md") and name[0].isdigit()
    )
    check_eq(len(sheets), 5, f"expected five drill sheets, found {sheets}")
    for name in sheets:
        text = open(os.path.join(DRILLS_DIR, name), encoding="utf-8").read()
        for section in (
            "## Goal",
            "## Setup",
            "## Tasks",
            "## Expected",
            "## Success",
            "## Reset",
        ):
            check(section in text, f"{name} must contain a '{section}' section")


def test_answers_cover_every_drill() -> None:
    text = open(os.path.join(DRILLS_DIR, "answers.md"), encoding="utf-8").read()
    for number in ("01", "02", "03", "04", "05"):
        check(f"Drill {number}" in text, f"answers.md must cover drill {number}")
