"""Classical-crypto candidate recovery, bounded and explicitly heuristic.

Every output here is a lead, not a solution. caesar and vigenere rank English
letter chi-squared, xor-single ranks printable ratio then chi-squared, and
xor-crib counts how many known-plaintext bytes agree with a constant key at
each offset. A flag-regex match only sets ``flag_like``; it is never asserted
as the expected flag.

Limits: input defaults to 16 KiB and is clamped to 256 KiB (``--max-bytes``);
``--top`` defaults to 5; vigenere key lengths default to 20 and hard-cap at 64,
only lengths with at least 4 letters per column are recovered, and lengths are
ranked by the index-of-coincidence rise over their proper divisors so a real
period beats its multiples; a recovered key is reduced to its shortest
repeating period, so a LEMONLEMON answer is reported once as LEMON. xor-crib
cribs are capped at 256 bytes and slide under a 1,000,000 comparison budget;
xor-crib output is capped at 2048 deduplicated rows even with ``--all``.
Previews are escaped with ``util.printable`` and capped at 200 characters.
Nothing is executed, nothing is written, no network is used.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern, Sequence, Tuple

from . import util

SCHEMA = "ctfctl.crypto/1"

DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_]{2,32}\{[^\s{}]{3,200}\}"
MAX_FLAG_REGEX = 512
MAX_FLAG_MATCHES = 20
PREVIEW_CHARS = 200

DEFAULT_MAX_BYTES = 16 * 1024
MAX_BYTES_CAP = 256 * 1024

DEFAULT_TOP = 5
MAX_TOP = 64

DEFAULT_MAX_KEY_LEN = 20
MAX_KEY_LEN_CAP = 64
MAX_KEY_LENGTH_ROWS = 10
#: A key length is only recovered when each column keeps at least this many
#: letters; below it the index of coincidence is sample noise.
MIN_COLUMN_LETTERS = 4
#: Index of coincidence for unrelated letters (used as the length-1 baseline).
RANDOM_IC = 0.038
#: A length counts as the fundamental period when its IC exceeds the best IC of
#: its proper divisors by at least this much.
IC_GAP_MIN = 0.015

MAX_CRIB_BYTES = 256
MAX_CRIB_WORK = 1000 * 1000
MAX_CRIB_ROWS = 2048

NOTE = (
    "candidates are heuristic: scoring narrows the search, it does not prove "
    "the plaintext; a flag-regex match is a lead to verify against the "
    "challenge."
)

#: Relative frequencies of A-Z in English text (standard table).
_ENGLISH_FREQ: Tuple[float, ...] = (
    0.08167,
    0.01492,
    0.02782,
    0.04253,
    0.12702,
    0.02228,
    0.02015,
    0.06094,
    0.06966,
    0.00153,
    0.00772,
    0.04025,
    0.02406,
    0.06749,
    0.07507,
    0.01929,
    0.00095,
    0.05987,
    0.06327,
    0.09056,
    0.02758,
    0.00978,
    0.02360,
    0.00150,
    0.01974,
    0.00074,
)

#: Printable for scoring: tab, LF, CR and 0x20-0x7e.
_PRINTABLE_KEEP = frozenset([9, 10, 13] + list(range(0x20, 0x7F)))
_NONPRINTABLE = bytes(b for b in range(256) if b not in _PRINTABLE_KEEP)
_NONLETTER = bytes(
    b for b in range(256) if not (0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A)
)

_ASCII_WS = re.compile(r"\s+")


def _caesar_table(shift: int) -> Dict[int, int]:
    table: Dict[int, int] = {}
    for index in range(26):
        table[ord("A") + index] = ord("A") + (index - shift) % 26
        table[ord("a") + index] = ord("a") + (index - shift) % 26
    return table


_CAESAR_TABLES: Tuple[Dict[int, int], ...] = tuple(
    _caesar_table(shift) for shift in range(26)
)


class CryptoError(util.CtfError):
    """Expected negative result: malformed input such as invalid hex (exit 1)."""


# --------------------------------------------------------------------------
# Scoring helpers
# --------------------------------------------------------------------------
def _score_key(value: Optional[float]) -> float:
    """Sort key for an optional chi-squared: missing scores rank last."""
    return value if value is not None else 1e18


def _chi_squared_counts(counts: Sequence[int]) -> Optional[float]:
    total = sum(counts)
    if total < 2:
        return None
    score = 0.0
    for observed, frequency in zip(counts, _ENGLISH_FREQ):
        expected = total * frequency
        if expected <= 0:
            continue
        diff = observed - expected
        score += diff * diff / expected
    return round(score, 4)


def _chi_squared_bytes(data: bytes) -> Optional[float]:
    upper = data.upper()
    counts = [upper.count(0x41 + index) for index in range(26)]
    return _chi_squared_counts(counts)


def _chi_squared_text(text: str) -> Optional[float]:
    return _chi_squared_bytes(text.encode("utf-8", "replace"))


def _letter_count_bytes(data: bytes) -> int:
    return len(data.translate(None, _NONLETTER))


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return len(data.translate(None, _NONPRINTABLE)) / len(data)


def _index_of_coincidence(letters: Sequence[int], key_len: int) -> float:
    """Average per-column IC; 0.0 when fewer than two letters per column."""
    if key_len < 1 or len(letters) < key_len:
        return 0.0
    total = 0.0
    columns = 0
    for column in range(key_len):
        col = letters[column::key_len]
        if len(col) < 2:
            continue
        counts = [0] * 26
        for value in col:
            counts[value] += 1
        pairs = sum(count * (count - 1) for count in counts)
        total += pairs / (len(col) * (len(col) - 1))
        columns += 1
    return total / columns if columns else 0.0


# --------------------------------------------------------------------------
# Flag matching and previews
# --------------------------------------------------------------------------
def _compile_flag_regex(flag_regex: str) -> Pattern[bytes]:
    if not isinstance(flag_regex, str):
        raise util.UsageError("--flag-regex must be a string")
    try:
        raw = flag_regex.encode("ascii")
    except UnicodeEncodeError as exc:
        raise util.UsageError("--flag-regex must be ASCII") from exc
    if not raw or len(raw) > MAX_FLAG_REGEX:
        raise util.UsageError(f"--flag-regex must be 1-{MAX_FLAG_REGEX} bytes")
    try:
        return re.compile(raw)
    except re.error as exc:
        raise util.UsageError(f"invalid --flag-regex: {exc}") from exc


def _flag_matches(pattern: Pattern[bytes], data: bytes) -> List[str]:
    found: List[str] = []
    for match in pattern.findall(data):
        if len(found) >= MAX_FLAG_MATCHES:
            break
        text = match.decode("ascii", "replace")
        if text not in found:
            found.append(util.printable(text, 160))
    return found


def _preview_text(text: str) -> str:
    return util.printable(text, PREVIEW_CHARS)


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------
def _clamp_max_bytes(value: Any) -> int:
    try:
        cap = int(value)
    except (TypeError, ValueError):
        raise util.UsageError("--max-bytes must be an integer") from None
    if cap < 1:
        raise util.UsageError("--max-bytes must be at least 1")
    return min(cap, MAX_BYTES_CAP)


def _clamp_top(value: Any, candidates: int) -> int:
    try:
        top = int(value)
    except (TypeError, ValueError):
        raise util.UsageError("--top must be an integer") from None
    if top < 1:
        raise util.UsageError("--top must be at least 1")
    return min(top, MAX_TOP, candidates)


def _cap_input(text: str, max_bytes: int) -> Tuple[str, int, bool]:
    """Bound raw UTF-8 bytes; normalized text always decodes with replace."""
    raw = text.encode("utf-8", "replace")
    total = len(raw)
    truncated = total > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", "replace"), total, truncated


def _hex_bytes(value: str, *, truncated: bool = False) -> bytes:
    compact = _ASCII_WS.sub("", value)
    if truncated and len(compact) % 2:
        compact = compact[:-1]
    if not compact:
        raise CryptoError("hex input is empty")
    if len(compact) % 2:
        raise CryptoError("invalid hex: odd number of digits")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise CryptoError(f"invalid hex: {exc}") from exc


def _payload(
    method: str,
    input_info: Dict[str, Any],
    limits: Dict[str, Any],
    candidates: List[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    matches: List[str] = []
    for candidate in candidates:
        for match in candidate.get("flag_matches", []):
            if match not in matches and len(matches) < MAX_FLAG_MATCHES:
                matches.append(match)
    payload: Dict[str, Any] = {
        "schema": SCHEMA,
        "method": method,
        "classification": "heuristic",
        "input": input_info,
        "limits": limits,
        "candidates": candidates,
        "flag_like": bool(matches),
        "flag_matches": matches,
        "note": NOTE,
    }
    if extra:
        payload.update(extra)
    return payload


# --------------------------------------------------------------------------
# caesar
# --------------------------------------------------------------------------
def caesar(
    text: str,
    *,
    top: int = DEFAULT_TOP,
    max_bytes: int = DEFAULT_MAX_BYTES,
    flag_regex: str = DEFAULT_FLAG_REGEX,
) -> Dict[str, Any]:
    """Score all 26 shifts by English letter chi-squared (heuristic)."""
    if text is None or not str(text):
        raise util.UsageError("caesar needs a non-empty value")
    cap = _clamp_max_bytes(max_bytes)
    pattern = _compile_flag_regex(flag_regex)
    top_n = _clamp_top(top, 26)
    body, raw_bytes, truncated = _cap_input(str(text), cap)
    letters = _letter_count_bytes(body.encode("utf-8", "replace"))

    candidates: List[Dict[str, Any]] = []
    for shift in range(26):
        plain = body.translate(_CAESAR_TABLES[shift])
        matches = _flag_matches(pattern, plain.encode("utf-8", "replace"))
        candidates.append(
            {
                "shift": shift,
                "key": chr(ord("A") + shift),
                "chi_squared": _chi_squared_text(plain),
                "letters": letters,
                "preview": _preview_text(plain),
                "flag_like": bool(matches),
                "flag_matches": matches,
            }
        )
    candidates.sort(key=lambda c: (_score_key(c["chi_squared"]), c["shift"]))

    return _payload(
        "caesar",
        {"bytes": raw_bytes, "max_bytes": cap, "truncated": truncated},
        {"top": top_n, "shifts": 26, "letters_scored": letters},
        candidates[:top_n],
    )


# --------------------------------------------------------------------------
# xor-single / xor-crib
# --------------------------------------------------------------------------
def xor_single(
    hex_value: str,
    *,
    top: int = DEFAULT_TOP,
    max_bytes: int = DEFAULT_MAX_BYTES,
    flag_regex: str = DEFAULT_FLAG_REGEX,
) -> Dict[str, Any]:
    """Score all 256 single-byte XOR keys (printable ratio, chi-squared)."""
    if hex_value is None or not str(hex_value).strip():
        raise util.UsageError("xor-single needs a hex value")
    cap = _clamp_max_bytes(max_bytes)
    pattern = _compile_flag_regex(flag_regex)
    top_n = _clamp_top(top, 256)
    body, raw_bytes, truncated = _cap_input(str(hex_value), cap)
    cipher = _hex_bytes(body, truncated=truncated)
    cipher_int = int.from_bytes(cipher, "big")

    candidates: List[Dict[str, Any]] = []
    for key in range(256):
        if key == 0:
            plain = cipher
        else:
            mask = int.from_bytes(bytes([key]) * len(cipher), "big")
            plain = (cipher_int ^ mask).to_bytes(len(cipher), "big")
        ratio = _printable_ratio(plain)
        chi = _chi_squared_bytes(plain)
        matches = _flag_matches(pattern, plain)
        candidates.append(
            {
                "key": key,
                "key_hex": f"0x{key:02x}",
                "printable_ratio": round(ratio, 4),
                "chi_squared": chi,
                "letters": _letter_count_bytes(plain),
                "preview": util.printable(
                    plain.decode("utf-8", "replace"), PREVIEW_CHARS
                ),
                "flag_like": bool(matches),
                "flag_matches": matches,
            }
        )
    candidates.sort(
        key=lambda c: (
            0 if c["printable_ratio"] >= 1.0 else 1,
            _score_key(c["chi_squared"]),
            c["key"],
        )
    )

    return _payload(
        "xor-single",
        {
            "bytes": raw_bytes,
            "cipher_bytes": len(cipher),
            "max_bytes": cap,
            "truncated": truncated,
        },
        {"top": top_n, "keys": 256, "cipher_bytes": len(cipher)},
        candidates[:top_n],
    )


def xor_crib(
    hex_value: str,
    known: str,
    *,
    top: int = DEFAULT_TOP,
    all_offsets: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    flag_regex: str = DEFAULT_FLAG_REGEX,
) -> Dict[str, Any]:
    """Slide a known plaintext crib over hex ciphertext at a constant key."""
    if hex_value is None or not str(hex_value).strip():
        raise util.UsageError("xor-crib needs a hex value")
    if known is None or not str(known):
        raise util.UsageError("--known must be a non-empty crib")
    cap = _clamp_max_bytes(max_bytes)
    pattern = _compile_flag_regex(flag_regex)
    top_n = _clamp_top(top, MAX_CRIB_ROWS)
    body, raw_bytes, truncated = _cap_input(str(hex_value), cap)
    cipher = _hex_bytes(body, truncated=truncated)
    crib = str(known).encode("utf-8", "replace")
    if len(crib) > MAX_CRIB_BYTES:
        raise util.UsageError(
            f"--known is {len(crib)} bytes; the crib cap is {MAX_CRIB_BYTES} bytes"
        )

    offsets_total = max(0, len(cipher) - len(crib) + 1)
    budget_offsets = MAX_CRIB_WORK // max(1, len(crib))
    scanned = min(offsets_total, budget_offsets)
    display_cap = MAX_CRIB_ROWS if all_offsets else top_n

    crib_int = int.from_bytes(crib, "big") if crib else 0
    rows: List[Tuple[int, int, int]] = []
    for offset in range(scanned):
        xored = (
            int.from_bytes(cipher[offset : offset + len(crib)], "big") ^ crib_int
        ).to_bytes(len(crib), "big")
        key = xored[0]
        rows.append((xored.count(key), offset, key))
    rows.sort(key=lambda row: (-row[0], row[1]))

    seen_segments = set()
    duplicates = 0
    rows_truncated = False
    shown: List[Dict[str, Any]] = []
    for score, offset, key in rows:
        segment = bytes(b ^ key for b in cipher[offset : offset + len(crib)])
        if segment in seen_segments:
            duplicates += 1
            continue
        seen_segments.add(segment)
        if len(shown) >= display_cap:
            rows_truncated = True
            continue
        matches = _flag_matches(pattern, segment)
        shown.append(
            {
                "offset": offset,
                "key": key,
                "key_hex": f"0x{key:02x}",
                "score": score,
                "crib_bytes": len(crib),
                "exact": score == len(crib),
                "segment_preview": util.printable(
                    segment.decode("utf-8", "replace"), PREVIEW_CHARS
                ),
                "flag_like": bool(matches),
                "flag_matches": matches,
            }
        )

    extra = {
        "crib": {
            "bytes": len(crib),
            "preview": util.printable(crib.decode("utf-8", "replace"), 80),
        },
        "offsets_total": offsets_total,
        "offsets_scanned": scanned,
        "scan_limit_hit": scanned < offsets_total,
        "duplicates_removed": duplicates,
        "rows_truncated": rows_truncated,
        "all_offsets": bool(all_offsets),
    }
    return _payload(
        "xor-crib",
        {
            "bytes": raw_bytes,
            "cipher_bytes": len(cipher),
            "max_bytes": cap,
            "truncated": truncated,
        },
        {
            "top": top_n,
            "display_cap": display_cap,
            "max_crib_bytes": MAX_CRIB_BYTES,
            "work_budget": MAX_CRIB_WORK,
        },
        shown,
        extra,
    )


# --------------------------------------------------------------------------
# vigenere
# --------------------------------------------------------------------------
def _minimal_key_period(key: str) -> str:
    """Reduce a recovered key to its shortest repeating period."""
    for period in range(1, len(key) + 1):
        if len(key) % period == 0 and key == key[:period] * (len(key) // period):
            return key[:period]
    return key


def _divisor_gap(ic_by_length: Dict[int, float], length: int) -> float:
    """How far a length's IC rises above its proper divisors' best IC.

    Multiples of the true key length show an elevated IC too; the fundamental
    period is the length whose IC is not explained by a shorter one.
    """
    if length <= 1:
        return ic_by_length.get(1, 0.0) - RANDOM_IC
    best_divisor = max(
        (
            ic_by_length[divisor]
            for divisor in range(1, length)
            if length % divisor == 0
        ),
        default=0.0,
    )
    return ic_by_length.get(length, 0.0) - best_divisor


def _vigenere_decrypt(text: str, key: str) -> str:
    out: List[str] = []
    position = 0
    for ch in text:
        if "A" <= ch <= "Z" or "a" <= ch <= "z":
            shift = ord(key[position % len(key)]) - ord("A")
            position += 1
            base = ord("A") if ch <= "Z" else ord("a")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(
    text: str,
    *,
    top: int = DEFAULT_TOP,
    max_key_len: int = DEFAULT_MAX_KEY_LEN,
    max_bytes: int = DEFAULT_MAX_BYTES,
    flag_regex: str = DEFAULT_FLAG_REGEX,
) -> Dict[str, Any]:
    """Recover key-length and key candidates (IC plus per-column chi-squared)."""
    if text is None or not str(text):
        raise util.UsageError("vigenere needs a non-empty value")
    cap = _clamp_max_bytes(max_bytes)
    pattern = _compile_flag_regex(flag_regex)
    top_n = _clamp_top(top, 26)
    try:
        key_cap = int(max_key_len)
    except (TypeError, ValueError):
        raise util.UsageError("--max-key-len must be an integer") from None
    if key_cap < 1:
        raise util.UsageError("--max-key-len must be at least 1")
    key_cap = min(key_cap, MAX_KEY_LEN_CAP)

    body, raw_bytes, truncated = _cap_input(str(text), cap)
    letters = [ord(ch) - ord("A") for ch in body.upper() if "A" <= ch <= "Z"]
    input_info = {"bytes": raw_bytes, "max_bytes": cap, "truncated": truncated}

    if len(letters) < 2:
        return _payload(
            "vigenere",
            input_info,
            {"top": top_n, "max_key_len": key_cap},
            [],
            {"letters": len(letters), "key_lengths": []},
        )

    key_cap = min(key_cap, len(letters))
    ic_rows: List[Dict[str, Any]] = []
    for length in range(1, key_cap + 1):
        ic_rows.append(
            {
                "length": length,
                "index_of_coincidence": round(
                    _index_of_coincidence(letters, length), 4
                ),
            }
        )
    ic_by_length = {row["length"]: row["index_of_coincidence"] for row in ic_rows}
    gaps = {length: _divisor_gap(ic_by_length, length) for length in ic_by_length}
    for row in ic_rows:
        row["divisor_gap"] = round(gaps[row["length"]], 4)
    ranked = sorted(
        ic_rows, key=lambda row: (-row["index_of_coincidence"], row["length"])
    )
    plausible = [
        row for row in ic_rows if len(letters) // row["length"] >= MIN_COLUMN_LETTERS
    ]
    if not plausible:
        plausible = ic_rows
    # Order recovery by divisor gap: a length whose IC is merely a multiple of a
    # shorter period is tried after that shorter period.
    by_gap = sorted(plausible, key=lambda row: (-row["divisor_gap"], row["length"]))
    candidate_lengths = [row["length"] for row in by_gap[:MAX_KEY_LENGTH_ROWS]]

    best: Dict[str, Dict[str, Any]] = {}
    for length in candidate_lengths:
        key_chars: List[str] = []
        for column in range(length):
            counts = [0] * 26
            for value in letters[column::length]:
                counts[value] += 1
            best_shift = 0
            best_chi: Optional[float] = None
            for shift in range(26):
                rotated = counts[shift:] + counts[:shift]
                chi = _chi_squared_counts(rotated)
                if chi is not None and (best_chi is None or chi < best_chi):
                    best_shift, best_chi = shift, chi
            key_chars.append(chr(ord("A") + best_shift))
        # A key that repeats is really its shortest period: a length-10
        # recovery of LEMONLEMON answers the same question as LEMON.
        key = _minimal_key_period("".join(key_chars))
        plain = _vigenere_decrypt(body, key)
        matches = _flag_matches(pattern, plain.encode("utf-8", "replace"))
        entry = {
            "key": key,
            "key_length": len(key),
            "recovered_from": length,
            "index_of_coincidence": ic_by_length.get(len(key), 0.0),
            "divisor_gap": round(gaps.get(len(key), 0.0), 4),
            "chi_squared": _chi_squared_text(plain),
            "preview": _preview_text(plain),
            "flag_like": bool(matches),
            "flag_matches": matches,
        }
        previous = best.get(key)
        if previous is None or _score_key(entry["chi_squared"]) < _score_key(
            previous["chi_squared"]
        ):
            best[key] = entry

    def rank(candidate: Dict[str, Any]) -> Tuple[int, float, int, str]:
        # A key length that stands above its divisors ranks first (fundamental
        # period evidence); inside a rank band the plaintext chi-squared decides.
        fundamental = 0 if candidate["divisor_gap"] >= IC_GAP_MIN else 1
        return (
            fundamental,
            _score_key(candidate["chi_squared"]),
            candidate["key_length"],
            candidate["key"],
        )

    candidates = sorted(best.values(), key=rank)[:top_n]

    return _payload(
        "vigenere",
        input_info,
        {"top": top_n, "max_key_len": key_cap},
        candidates,
        {"letters": len(letters), "key_lengths": ranked[:MAX_KEY_LENGTH_ROWS]},
    )


# --------------------------------------------------------------------------
# Human rendering
# --------------------------------------------------------------------------
def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else str(value)


def render_crypto(payload: Dict[str, Any]) -> str:
    """Human summary; the JSON payload stays the machine interface."""
    method = payload.get("method", "?")
    info = payload.get("input", {})
    lines = [f"crypto {method}: {info.get('bytes', 0)} bytes (heuristic, not proof)"]
    if info.get("truncated"):
        lines.append("  input truncated to --max-bytes")
    candidates = payload.get("candidates", [])
    if not candidates:
        lines.append("  no candidates within the bounds")
    for index, item in enumerate(candidates, 1):
        flag = "  flag-like: yes" if item.get("flag_like") else ""
        if method == "caesar":
            lines.append(
                f"  {index}. shift={item['shift']} key={item['key']} "
                f"chi2={_fmt(item['chi_squared'])}{flag}"
            )
            lines.append(f"     {item['preview']}")
        elif method == "xor-single":
            lines.append(
                f"  {index}. key={item['key_hex']} ({item['key']}) "
                f"printable={item['printable_ratio']} "
                f"chi2={_fmt(item['chi_squared'])}{flag}"
            )
            lines.append(f"     {item['preview']}")
        elif method == "xor-crib":
            exact = "yes" if item["exact"] else "no"
            lines.append(
                f"  {index}. offset={item['offset']} key={item['key_hex']} "
                f"match={item['score']}/{item['crib_bytes']} exact={exact}{flag}"
            )
            lines.append(f"     {item['segment_preview']}")
        else:
            lines.append(
                f"  {index}. key={item['key']} len={item['key_length']} "
                f"ic={item['index_of_coincidence']} "
                f"chi2={_fmt(item['chi_squared'])}{flag}"
            )
            lines.append(f"     {item['preview']}")
    if method == "xor-crib":
        if payload.get("scan_limit_hit"):
            lines.append("  ! work budget reached: not every offset was scanned")
        if payload.get("rows_truncated"):
            lines.append("  ! display cap reached: more offsets exist")
    if method == "vigenere" and payload.get("key_lengths"):
        rows = ", ".join(
            f"{row['length']}:{row['index_of_coincidence']}"
            for row in payload["key_lengths"][:6]
        )
        lines.append(f"  key lengths by IC (length:ic): {rows}")
    lines.append("")
    lines.append(
        "heuristic: verify candidates against the challenge; a regex match is "
        "a lead, not proof."
    )
    return "\n".join(lines)
