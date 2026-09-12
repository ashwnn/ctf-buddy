"""Corpus integration: merge parallel research fragments into the real manifests.

Parallel workers wrote:

    kb/<category>/*.md
    kb/manifest.<worker>.jsonl
    sources/fragments/<worker>.jsonl

with *placeholder* source ids, because a worker session has no compute tool to
derive `sha256(canonical_url)`. This module is the single integration pass:

  1. gather every source record (fragments + verified index);
  2. canonicalise ids by URL, so duplicate citations of one article collapse to
     one identity no matter which placeholder spelling a worker used;
  3. rewrite every `src-...` reference in card text and card manifests;
  4. optionally re-verify each URL over the network (explicit, online-only);
  5. write sources/manifest.jsonl + kb/manifest.jsonl and a merge report.

It is idempotent: running it twice produces the same output.
"""

from __future__ import annotations

import argparse
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import kbindex, sources_check, util

PLACEHOLDER_SUFFIX = re.compile(r"-(?:s\d{1,3}|tr\d|ad\d|rj\d|x\d{1,2}|v\d)$", re.I)
CARD_REF = re.compile(r"\bsrc-[a-z0-9][a-z0-9._-]*")


# --------------------------------------------------------------------------
def gather_source_records(root: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (fragment records, reference records) without merging yet."""
    fragments: List[Dict[str, Any]] = []
    fragment_dir = os.path.join(root, "sources", "fragments")
    if os.path.isdir(fragment_dir):
        for name in sorted(os.listdir(fragment_dir)):
            if not name.endswith(".jsonl"):
                continue
            for record in util.load_jsonl(os.path.join(fragment_dir, name)):
                record["_origin"] = f"sources/fragments/{name}"
                fragments.append(record)
    references: List[Dict[str, Any]] = []
    for name in ("verified-index.jsonl", "manifest.jsonl"):
        path = os.path.join(root, "sources", name)
        if os.path.isfile(path):
            for record in util.load_jsonl(path):
                record["_origin"] = f"sources/{name}"
                references.append(record)
    return fragments, references


def _slug_from_id(source_id: str) -> str:
    slug = source_id[4:] if source_id.startswith("src-") else source_id
    slug = PLACEHOLDER_SUFFIX.sub("", slug)
    slug = re.sub(r"[^a-z0-9]+", "-", slug.lower()).strip("-")
    return slug or "source"


def build_mapping(fragments: Sequence[Dict[str, Any]],
                  references: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """Map every placeholder id to the canonical id for its URL."""
    by_url: Dict[str, str] = {}
    for record in references:
        url = record.get("canonical_url")
        sid = record.get("source_id")
        if url and sid:
            by_url[sources_check.canonical_url(url)] = sid
    mapping: Dict[str, str] = {}
    for record in list(references) + list(fragments):
        sid = record.get("source_id")
        url = record.get("canonical_url")
        if not sid or not url:
            continue
        key = sources_check.canonical_url(url)
        canonical = by_url.get(key) or sources_check.derive_source_id(
            _slug_from_id(sid), url)
        by_url.setdefault(key, canonical)
        mapping[sid] = canonical
    return mapping


def merge_source_records(records: Sequence[Dict[str, Any]], mapping: Dict[str, str],
                         *, online: bool = True) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Collapse records by canonical id, preferring already-verified metadata."""
    order: List[str] = []
    merged: Dict[str, Dict[str, Any]] = {}
    for record in records:
        sid = record.get("source_id")
        url = record.get("canonical_url")
        if not sid or not url:
            continue
        canonical = mapping.get(sid, sid)
        candidate = {k: v for k, v in record.items() if not k.startswith("_")}
        candidate["source_id"] = canonical
        candidate["canonical_url"] = sources_check.canonical_url(url)
        candidate.setdefault("verified", False)
        existing = merged.get(canonical)
        if existing is None:
            merged[canonical] = candidate
            order.append(canonical)
            continue
        # Prefer a record that is already verified, and keep more specific fields.
        prefer_new = bool(candidate.get("verified")) and not existing.get("verified")
        primary, secondary = (candidate, existing) if prefer_new else (existing, candidate)
        for key, value in secondary.items():
            if primary.get(key) in (None, "", [], {}, False) and value:
                primary[key] = value
        notes = [str(primary.get("notes") or ""), str(secondary.get("notes") or "")]
        distinct = [n for n in dict.fromkeys(n.strip() for n in notes if n and n.strip())]
        primary["notes"] = " | ".join(distinct)[:900]
        origins = set()
        for source in (primary, secondary):
            if source.get("_origin"):
                origins.add(source["_origin"])
        if origins:
            primary["merged_from"] = sorted(origins)
        merged[canonical] = primary

    records_out = [merged[sid] for sid in order]
    quarantined: List[Dict[str, Any]] = []
    if online:
        for record in records_out:
            check = sources_check.check_url(record["canonical_url"], timeout=20)
            record.update({k: v for k, v in check.items() if k != "canonical_url"})
            if check.get("verified"):
                record["verified"] = True
                record["verified_at"] = util.iso_now()
                record["verification_method"] = "http-fetch"
            else:
                record["verified"] = False
                record["verified_at"] = None
                record["verification_method"] = "failed"
                record["quarantined"] = True
                quarantined.append(record)
    return records_out, quarantined


def merge_cards(root: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    problems: List[str] = []
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for name in sorted(os.listdir(os.path.join(root, "kb"))):
        if not name.startswith("manifest.") or not name.endswith(".jsonl"):
            continue
        path = os.path.join(root, "kb", name)
        for record in util.load_jsonl(path):
            card_id = record.get("card_id")
            if not card_id:
                problems.append(f"{name}: record without card_id")
                continue
            if card_id in merged:
                problems.append(f"duplicate card_id {card_id} in {name}")
                continue
            record.setdefault("content_origin", "original-summary")
            record.setdefault("evidence_status", "source-supported but untested")
            record["path"] = str(record.get("path", "")).replace(os.sep, "/")
            if not os.path.isfile(os.path.join(root, record["path"])):
                problems.append(f"{card_id}: file missing: {record['path']}")
                continue
            merged[card_id] = record
            order.append(card_id)
    return [merged[c] for c in order], problems


def rewrite_references(root: str, mapping: Dict[str, str]) -> Dict[str, int]:
    """Rewrite placeholder source ids to canonical ids in cards and manifests."""
    changed_files = 0
    changed_tokens = 0
    targets: List[str] = []
    for dirpath, _dirnames, filenames in os.walk(os.path.join(root, "kb")):
        for name in filenames:
            if name.endswith(".md") or name.endswith(".jsonl"):
                targets.append(os.path.join(dirpath, name))
    for path in sorted(targets):
        text = util.read_text(path, 8 * 1024 * 1024)
        replaced = 0

        def repl(match: "re.Match[str]") -> str:
            nonlocal replaced
            token = match.group(0)
            canonical = mapping.get(token)
            if canonical and canonical != token:
                replaced += 1
                return canonical
            return token

        new_text = CARD_REF.sub(repl, text)
        if replaced:
            util.write_text_atomic(path, new_text)
            changed_files += 1
            changed_tokens += replaced
    return {"files": changed_files, "tokens": changed_tokens}


def run(root: Optional[str] = None, *, online: bool = True,
        check_cards: bool = True) -> Dict[str, Any]:
    root = root or util.repo_root()
    fragments, references = gather_source_records(root)
    mapping = build_mapping(fragments, references)
    records, quarantined = merge_source_records(fragments + references, mapping, online=online)
    # Cards must be rewritten before their manifests are merged so that
    # source_ids in the manifest are canonical.
    rewrite_stats = rewrite_references(root, mapping)
    cards, card_problems = merge_cards(root)
    missing_refs = []
    known = {record["source_id"] for record in records}
    for card in cards:
        for sid in card.get("source_ids") or []:
            if sid not in known:
                missing_refs.append(f"{card['card_id']} -> {sid}")

    util.write_text_atomic(os.path.join(root, "sources", "manifest.jsonl"),
                           util.dump_jsonl(sorted(records, key=lambda r: r["source_id"])))
    util.write_text_atomic(os.path.join(root, "kb", "manifest.jsonl"),
                           util.dump_jsonl(sorted(cards, key=lambda r: r["card_id"])))

    report = {
        "generated_at": util.iso_now(),
        "sources": {
            "fragment_records": len(fragments),
            "reference_records": len(references),
            "placeholder_ids_mapped": len(mapping),
            "canonical_records": len(records),
            "duplicates_collapsed": len(fragments) + len(references) - len(records),
            "verified": sum(1 for r in records if r.get("verified")),
            "quarantined": [
                {"source_id": r["source_id"], "url": r["canonical_url"],
                 "error": r.get("error") or "not verified"}
                for r in quarantined
            ],
            "primary": sum(1 for r in records if r.get("primary") is True),
            "teams": len({r.get("team") for r in records if r.get("team")}),
        },
        "cards": {
            "merged": len(cards),
            "unresolved_source_refs": missing_refs,
            "problems": card_problems,
        },
        "rewrites": rewrite_stats,
    }
    if check_cards:
        report["kb_verify"] = kbindex.verify(root)
    return report


def render(report: Dict[str, Any]) -> str:
    lines = ["corpus integration report", ""]
    src = report["sources"]
    lines.append(f"sources   {src['canonical_records']} canonical "
                 f"(from {src['fragment_records']} fragment + {src['reference_records']} "
                 f"reference records)")
    lines.append(f"          {src['duplicates_collapsed']} duplicate citation(s) collapsed by URL")
    lines.append(f"          {src['verified']} URL(s) verified, "
                 f"{len(src['quarantined'])} quarantined")
    lines.append(f"          {src['primary']} primary, {src['teams']} identifiable teams/organisers")
    for item in src["quarantined"]:
        lines.append(f"            QUARANTINED {item['source_id']}: {item['error']} ({item['url']})")
    cards = report["cards"]
    lines.append("")
    lines.append(f"cards     {cards['merged']} merged")
    if cards["problems"]:
        for problem in cards["problems"][:10]:
            lines.append(f"            PROBLEM {problem}")
    if cards["unresolved_source_refs"]:
        lines.append(f"          {len(cards['unresolved_source_refs'])} unresolved source "
                     "reference(s):")
        for item in cards["unresolved_source_refs"][:10]:
            lines.append(f"            {item}")
    rewrites = report["rewrites"]
    lines.append("")
    lines.append(f"rewrite   {rewrites['tokens']} source id reference(s) in "
                 f"{rewrites['files']} file(s)")
    verify = report.get("kb_verify")
    if verify:
        lines.append("")
        lines.append(f"kb verify {'OK' if verify['ok'] else 'PROBLEMS'}")
        for error in verify["errors"][:6]:
            lines.append(f"          FAIL {error}")
        for warning in verify["warnings"][:6]:
            lines.append(f"          warn {warning}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="merge corpus fragments into the manifests")
    parser.add_argument("--offline", action="store_true",
                        help="skip URL re-verification (no network access)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run(online=not args.offline)
    if args.json:
        util.emit_json(report)
    else:
        print(render(report))
    problems = report["cards"]["problems"] or report["cards"]["unresolved_source_refs"]
    return util.EXIT_OK if not problems else util.EXIT_NEGATIVE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
