"""`ctfctl decode`: bounded decode chains over values, plus file and CLI edges.

Fixtures are literals or standard-library builds (`base64`, `gzip`) so the
module is offline and fast. Known answers assert the exact `depth`,
`chain_text`, `classification` and `flag_like` fields. Malformed inputs assert
quiet exit 0 because the module documents a missing or unreadable file as its
only negative result (exit 1). The oversized-file case writes one temporary
file of the documented cap plus slack through `temp_dir`.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, List, Optional, Tuple

from helpers import Failure, check, check_eq, check_in, temp_dir

from ctfctl import cli
from ctfctl import decode as decode_mod
from ctfctl import util

#: Literal known answers, one per codec under test.
B64_FLAG = "ZmxhZ3tiNjR9"  # flag{b64}
B32_FLAG = "MZWGCZ33MIZTE7I="  # flag{b32}
HEX_FLAG = "666c61677b6865787d"  # flag{hex}
URL_FLAG = "flag%7Burl%7D"
BIN_FLAG = "".join(f"{byte:08b}" for byte in b"flag{bin}")
ROT_FLAG = "synt{ebg}"  # flag{rot}
DEEP_FLAG = "Wm14aFozdGlOalI5"  # base64(base64("flag{b64}"))

_BASE32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
def _run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _decode_json(*argv: str) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """Run `decode ... --json`; payload is None on a non-zero exit."""
    code, out, err = _run_cli(["decode", *argv, "--json"])
    payload = json.loads(out) if code == util.EXIT_OK else None
    return code, payload, err


def _result(payload: Dict[str, Any], chain_text: str) -> Dict[str, Any]:
    for item in payload["results"]:
        if item["chain_text"] == chain_text:
            return item
    raise Failure(f"no result with chain_text {chain_text!r}")


def _gzip64_fixture() -> str:
    """A gzip stream in base64 whose text cannot be read as base32.

    Trailing letters are appended only if a zlib build produced an encoding
    that stays inside the base32 alphabet, so the `base64 -> gzip` chain stays
    the unique best chain for the final value on any host.
    """
    for extra in range(5):
        plain = b"flag{gz64}" + b"A" * extra
        encoded = base64.b64encode(gzip.compress(plain, mtime=0)).decode("ascii")
        if set(encoded) - _BASE32_ALPHABET:
            return encoded
    raise Failure("could not build a base64 gzip fixture outside the base32 alphabet")


# --------------------------------------------------------------------------
# Known answers
# --------------------------------------------------------------------------
def test_base64_flag_knows_the_answer() -> None:
    code, payload, err = _decode_json(B64_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    check_eq(payload["schema"], decode_mod.SCHEMA, "schema is stable")
    check_eq(payload["input"]["source"], "argument", "the value came from the argument")
    item = _result(payload, "base64")
    check_eq(item["depth"], 1, "a direct base64 step is depth 1")
    check_eq(item["chain"], ["base64"], "the chain labels the codec used")
    check_eq(
        item["classification"], "proven", "strict base64 consumed the step exactly"
    )
    check_eq(item["preview"], "flag{b64}", "the preview is the decoded flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{b64}", item["flag_matches"], "the recovered flag is surfaced")
    check_eq(item["bytes"], len(b"flag{b64}"), "the decoded byte count is reported")


def test_base32_flag_knows_the_answer() -> None:
    code, payload, err = _decode_json(B32_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "base32")
    check_eq(item["depth"], 1, "a direct base32 step is depth 1")
    check_eq(item["chain"], ["base32"], "the chain labels the codec used")
    check_eq(item["classification"], "proven", "strict base32 is proven")
    check_eq(item["preview"], "flag{b32}", "the preview is the decoded flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{b32}", item["flag_matches"], "the recovered flag is surfaced")


def test_hex_flag_knows_the_answer() -> None:
    code, payload, err = _decode_json(HEX_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "hex")
    check_eq(item["depth"], 1, "a direct hex step is depth 1")
    check_eq(item["chain"], ["hex"], "the chain labels the codec used")
    check_eq(item["classification"], "proven", "strict hex is proven")
    check_eq(item["preview"], "flag{hex}", "the preview is the decoded flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{hex}", item["flag_matches"], "the recovered flag is surfaced")


def test_url_percent_flag_knows_the_answer() -> None:
    code, payload, err = _decode_json(URL_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "url")
    check_eq(item["depth"], 1, "a direct percent-decoding step is depth 1")
    check_eq(item["chain"], ["url"], "the chain labels the codec used")
    check_eq(item["classification"], "proven", "strict percent decoding is proven")
    check_eq(item["preview"], "flag{url}", "the preview is the decoded flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{url}", item["flag_matches"], "the recovered flag is surfaced")


def test_binary_flag_knows_the_answer() -> None:
    code, payload, err = _decode_json(BIN_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "binary")
    check_eq(item["depth"], 1, "a direct binary step is depth 1")
    check_eq(item["chain"], ["binary"], "the chain labels the codec used")
    check_eq(item["classification"], "proven", "8-bit aligned binary is proven")
    check_eq(item["preview"], "flag{bin}", "the preview is the decoded flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{bin}", item["flag_matches"], "the recovered flag is surfaced")


def test_rot13_flag_knows_the_answer() -> None:
    code, payload, err = _decode_json(ROT_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    check_eq(
        len(payload["results"]),
        1,
        "rot13 is an involution, so the root value is cycle-guarded instead of repeated",
    )
    item = payload["results"][0]
    check_eq(item["chain_text"], "rot13", "the only step is the rot13 decode")
    check_eq(item["classification"], "proven", "whole ASCII input is consumed exactly")
    check_eq(item["preview"], "flag{rot}", "the preview is the decoded flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{rot}", item["flag_matches"], "the recovered flag is surfaced")


# --------------------------------------------------------------------------
# Gzip chains
# --------------------------------------------------------------------------
def test_hex_then_gzip_chain_is_labeled_and_proven() -> None:
    payload_bytes, expected = gzip.compress(b"flag{gzip}", mtime=0), "flag{gzip}"
    code, payload, err = _decode_json(payload_bytes.hex())
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "hex -> gzip")
    check_eq(item["depth"], 2, "two transforms mean depth 2")
    check_eq(item["chain"], ["hex", "gzip"], "both steps are named in order")
    check_eq(
        item["classification"], "proven", "both steps consumed their input exactly"
    )
    check_in(expected, item["preview"], "the preview shows the decompressed flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in(expected, item["flag_matches"], "the recovered flag is surfaced")


def test_base64_then_gzip_chain_is_labeled_and_proven() -> None:
    fixture = _gzip64_fixture()
    code, payload, err = _decode_json(fixture)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "base64 -> gzip")
    check_eq(item["depth"], 2, "two transforms mean depth 2")
    check_eq(item["chain"], ["base64", "gzip"], "both steps are named in order")
    check_eq(
        item["classification"], "proven", "both steps consumed their input exactly"
    )
    check_in("flag{gz64}", item["preview"], "the preview shows the decompressed flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_in("flag{gz64}", item["flag_matches"], "the recovered flag is surfaced")


def test_nested_base64_chain_reports_depth_two() -> None:
    code, payload, err = _decode_json(DEEP_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "base64 -> base64")
    check_eq(item["depth"], 2, "the shallowest reach of the flag is depth 2")
    check_eq(item["chain"], ["base64", "base64"], "both steps are named in order")
    check_eq(item["classification"], "proven", "both strict base64 steps are proven")
    check_eq(item["preview"], "flag{b64}", "the inner flag is recovered")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
def test_whitespace_collapsed_base64_is_heuristic_not_proven() -> None:
    encoded = base64.b64encode(b"flag{heur}").decode("ascii")
    wrapped = encoded[:4] + "\n" + encoded[4:]
    code, payload, err = _decode_json(wrapped)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "base64")
    check_eq(item["depth"], 1, "the collapsed retry is still one step")
    check_eq(
        item["classification"],
        "heuristic",
        "removing whitespace discarded bytes, so the step is heuristic",
    )
    check_eq(item["preview"], "flag{heur}", "the collapsed decode still finds the flag")
    check_eq(item["flag_like"], True, "the flag regex must mark this value")
    check_eq(
        [
            r["classification"]
            for r in payload["results"]
            if r["preview"] == "flag{heur}"
        ],
        ["heuristic"],
        "the flag value is never presented as a proven result",
    )


def test_proven_and_flag_like_are_never_claimed_as_proof() -> None:
    for value in (B64_FLAG, HEX_FLAG):
        code, payload, err = _decode_json(value)
        check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
        check(
            all(
                item["classification"] in ("proven", "heuristic")
                for item in payload["results"]
            ),
            "every result carries one of the two documented labels",
        )
        check_in("not proof", payload["note"], "the payload note denies proof")
    human = _run_cli(["decode", B64_FLAG])[1]
    check_in("triage, not proof", human, "the human summary denies proof")
    check_in("flag-like: yes", human, "the lead marker is shown but not called proof")


# --------------------------------------------------------------------------
# Chains: dedup, ordering, determinism
# --------------------------------------------------------------------------
def test_results_are_unique_by_value_and_cycle_guarded() -> None:
    code, payload, err = _decode_json(DEEP_FLAG)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    digests = [item["sha256"] for item in payload["results"]]
    check_eq(
        len(digests), len(set(digests)), "identical final values are never repeated"
    )
    inner = [item for item in payload["results"] if item["preview"] == B64_FLAG]
    check_eq(len(inner), 1, "the inner base64 text is reported exactly once")
    check(
        all(item["preview"] != DEEP_FLAG for item in payload["results"]),
        "the root value never reappears in the results",
    )


def test_results_are_sorted_and_deterministic_across_two_runs() -> None:
    first_code, first_out, first_err = _run_cli(["decode", DEEP_FLAG, "--json"])
    second_code, second_out, second_err = _run_cli(["decode", DEEP_FLAG, "--json"])
    check_eq(first_code, util.EXIT_OK, f"decode must succeed: {first_err}")
    check_eq(second_code, util.EXIT_OK, f"decode must succeed: {second_err}")
    check_eq(first_out, second_out, "two runs must produce byte-identical JSON")
    payload = json.loads(first_out)
    keys = [(item["depth"], item["chain_text"]) for item in payload["results"]]
    check_eq(keys, sorted(keys), "results are ordered by (depth, chain text)")


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------
def test_tiny_max_depth_stops_recursion_and_reports_the_cap() -> None:
    code, payload, err = _decode_json(DEEP_FLAG, "--max-depth", "1")
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    check_eq(payload["limits"]["max_depth"], 1, "the payload reports the effective cap")
    check(
        all(item["depth"] == 1 for item in payload["results"]),
        "no chain may run past the depth cap",
    )
    check(
        all(item["chain_text"] != "base64 -> base64" for item in payload["results"]),
        "the depth-2 chain must not be explored",
    )
    human = _run_cli(["decode", DEEP_FLAG, "--max-depth", "1"])[1]
    check_eq(
        human.count("depth=1"),
        len(payload["results"]),
        "the human summary reports the depth of every surviving chain",
    )


def test_max_depth_is_clamped_to_the_hard_cap() -> None:
    code, payload, err = _decode_json(DEEP_FLAG, "--max-depth", "99")
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    check_eq(
        payload["limits"]["max_depth"],
        decode_mod.MAX_DEPTH_CAP,
        "an oversized depth is clamped to the hard cap",
    )


def test_max_depth_zero_is_a_usage_error() -> None:
    code, out, err = _run_cli(["decode", DEEP_FLAG, "--max-depth", "0", "--json"])
    check_eq(code, util.EXIT_USAGE, "depth 0 is refused")
    check_in("at least 1", err, "the refusal names the bound")
    check_eq(out, "", "a usage error prints no payload")


def test_oversized_file_is_truncated_and_reported() -> None:
    with temp_dir("ctfctl-decode-") as root:
        path = os.path.join(root, "big.bin")
        with open(path, "wb") as handle:
            handle.write(b"%" * (decode_mod.MAX_FILE_BYTES + 512))
        code, payload, err = _decode_json("--file", path)
        check_eq(code, util.EXIT_OK, f"a capped file must not fail: {err}")
        check_eq(
            payload["input"]["source"], "file", "the payload names the file source"
        )
        check_eq(payload["input"]["truncated"], True, "truncation must be reported")
        check_eq(
            payload["input"]["bytes"],
            decode_mod.MAX_FILE_BYTES,
            "the reported size is the read cap",
        )
        check_eq(payload["results"], [], "the percent-only body decodes to nothing")
        human = _run_cli(["decode", "--file", path])[1]
        check_in(
            "truncated to the file cap", human, "the human summary reports truncation"
        )


def test_oversized_argument_is_a_usage_error() -> None:
    oversized = "A" * (decode_mod.MAX_INPUT_BYTES + 1)
    code, out, err = _run_cli(["decode", oversized, "--json"])
    check_eq(code, util.EXIT_USAGE, "an argument beyond the input cap is refused")
    check_in("argument cap", err, "the refusal names the cap")
    check_eq(out, "", "a usage error prints no payload")


def test_value_and_file_together_are_a_usage_error() -> None:
    code, out, err = _run_cli(["decode", B64_FLAG, "--file", "somewhere", "--json"])
    check_eq(code, util.EXIT_USAGE, "value and --file are mutually exclusive")
    check_in("not both", err, "the refusal explains the conflict")


def test_preview_is_capped_at_the_documented_length() -> None:
    code, payload, err = _decode_json("41" * 300)
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    item = _result(payload, "hex")
    check_eq(item["bytes"], 300, "the decoded value is 300 bytes")
    check_eq(
        len(item["preview"]),
        decode_mod.PREVIEW_CHARS,
        "the preview is capped at the documented length",
    )
    check(
        item["preview"].endswith("..."), "the capped preview is marked with an ellipsis"
    )


# --------------------------------------------------------------------------
# Malformed input: quiet, exit 0, never a traceback
# --------------------------------------------------------------------------
def test_bad_base64_padding_produces_no_base64_result_and_no_crash() -> None:
    for value in ("ZmxhZ3t4fQ=", "====", "A==="):
        code, payload, err = _decode_json(value)
        check_eq(code, util.EXIT_OK, f"malformed {value!r} stays an expected outcome")
        check("Traceback" not in err, f"no traceback for {value!r}: {err}")
        check(
            all(item["chain_text"] != "base64" for item in payload["results"]),
            f"rejected padding must not yield a base64 result for {value!r}",
        )


def test_odd_hex_and_lone_percent_are_rejected_quietly() -> None:
    for value in ("abc", "100%", "%%41", "%2"):
        code, payload, err = _decode_json(value)
        check_eq(code, util.EXIT_OK, f"malformed {value!r} stays an expected outcome")
        check("Traceback" not in err, f"no traceback for {value!r}: {err}")
        check(
            all(
                item["chain_text"] not in ("hex", "url") for item in payload["results"]
            ),
            f"rejected input must not yield a hex or url result for {value!r}",
        )


def test_empty_value_yields_no_results_and_exit_zero() -> None:
    code, payload, err = _decode_json("")
    check_eq(code, util.EXIT_OK, f"an empty value is not a usage error: {err}")
    check_eq(payload["input"]["bytes"], 0, "the empty input is zero bytes")
    check_eq(payload["results"], [], "nothing decodes from an empty value")


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------
def test_missing_file_is_a_negative_result_exit_one() -> None:
    with temp_dir("ctfctl-decode-") as root:
        missing = os.path.join(root, "does-not-exist.txt")
        code, out, err = _run_cli(["decode", "--file", missing, "--json"])
        check_eq(code, util.EXIT_NEGATIVE, "a missing file is the documented exit 1")
        check_in("file does not exist", err, "the error names the problem")
        check_eq(out, "", "no payload is printed on a negative result")
        code, out, err = _run_cli(["decode", "--file", root, "--json"])
        check_eq(code, util.EXIT_NEGATIVE, "a directory is not a regular file")
        check_in("not a regular file", err, "the error names the problem")


def test_json_output_parses_and_matches_the_human_summary() -> None:
    code, out_json, err = _run_cli(["decode", B64_FLAG, "--json"])
    check_eq(code, util.EXIT_OK, f"decode must succeed: {err}")
    payload = json.loads(out_json)
    human_code, human, human_err = _run_cli(["decode", B64_FLAG])
    check_eq(human_code, util.EXIT_OK, f"human decode must succeed: {human_err}")
    for item in payload["results"]:
        check_in(
            item["preview"], human, "every JSON preview appears in the human summary"
        )
    check_in("depth=1", human, "the human summary reports depths")
    check_in("[proven]", human, "the human summary reports classification")
    check_in("flag-like: yes", human, "the human summary reports the lead marker")
