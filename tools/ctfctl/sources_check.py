"""Online source verification for `ctfctl prep-online --check-sources`.

This module is the ONLY place in the toolkit that performs outbound network
access, and it is never called by `discover`, `plan`, `apply`, `verify`,
`rollback`, `watch`, `decoy` or `kb`. It is a preparation-time tool.

It records, per URL: HTTP status, final URL after redirects, content type,
content length, a bounded-body SHA-256, and ETag/Last-Modified when present.
It does not snapshot article text by default; snapshotting is opt-in per source
and only when the manifest policy allows redistribution.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from . import util

USER_AGENT = "ctf-prep-source-check/0.1 (+local offline preparation tool)"
MAX_BODY = 2 * 1024 * 1024


def canonical_url(url: str) -> str:
    """Normalize for identity: lowercase scheme/host, drop fragment/default port."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "https").lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def derive_source_id(slug: str, url: str) -> str:
    digest = hashlib.sha256(canonical_url(url).encode("utf-8")).hexdigest()[:8]
    return f"src-{slug}-{digest}"


def check_url(url: str, *, timeout: float = 20.0, capture_body: bool = False,
              insecure: bool = False) -> Dict[str, Any]:
    """Fetch one URL with a hard cap. Returns a verification record."""
    target = canonical_url(url)
    record: Dict[str, Any] = {
        "canonical_url": target,
        "checked_url": url,
        "http_status": None,
        "final_url": None,
        "content_type": None,
        "content_length": None,
        "etag": None,
        "last_modified": None,
        "content_sha256": None,
        "verified": False,
        "error": None,
    }
    context = None
    if insecure:
        context = ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-in only
    request = urllib.request.Request(target, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            record["http_status"] = response.status
            record["final_url"] = response.geturl()
            record["content_type"] = response.headers.get("Content-Type")
            record["etag"] = response.headers.get("ETag")
            record["last_modified"] = response.headers.get("Last-Modified")
            length = response.headers.get("Content-Length")
            record["content_length"] = int(length) if length and length.isdigit() else None
            if capture_body:
                body = response.read(MAX_BODY)
                record["content_sha256"] = util.sha256_bytes(body)
                record["content_length"] = len(body)
            record["verified"] = 200 <= response.status < 400
    except urllib.error.HTTPError as exc:
        record["http_status"] = exc.code
        record["final_url"] = exc.geturl()
        record["error"] = f"HTTP {exc.code} {exc.reason}"
    except urllib.error.URLError as exc:
        record["error"] = f"URL error: {exc.reason}"
    except (TimeoutError, OSError, ValueError) as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


def check_manifest(index_path: str, *, only_missing: bool = True, timeout: float = 20.0,
                   capture_snapshots: bool = False) -> Tuple[List[Dict[str, Any]], str]:
    """Verify every source in the index. Returns (records, summary_text)."""
    records = util.load_jsonl(index_path)
    results: List[Dict[str, Any]] = []
    for record in records:
        url = record.get("canonical_url")
        if not url:
            results.append({**record, "verified": False, "error": "no canonical_url"})
            continue
        if only_missing and record.get("verified") is True and record.get("verified_at"):
            results.append(record)
            continue
        capture = bool(capture_snapshots and record.get("storage") == "snapshot-text")
        check = check_url(url, timeout=timeout, capture_body=capture)
        merged = dict(record)
        merged.update({k: v for k, v in check.items() if k != "canonical_url"})
        if check.get("verified"):
            merged["verified"] = True
            merged["verified_at"] = util.iso_now()
            merged["verification_method"] = "http-fetch"
        else:
            merged["verified"] = False
            merged.setdefault("verified_at", None)
            merged["verification_method"] = "failed"
        results.append(merged)
    ok = sum(1 for r in results if r.get("verified"))
    failed = [r for r in results if not r.get("verified")]
    lines = [f"sources checked: {len(results)}  verified: {ok}  failed: {len(failed)}"]
    for record in failed:
        lines.append(
            f"  FAILED {record.get('source_id', '?')}: {record.get('error') or 'not verified'}"
        )
    return results, "\n".join(lines)


def write_index(path: str, records: List[Dict[str, Any]]) -> None:
    ordered = sorted(records, key=lambda r: (r.get("source_id") or ""))
    util.write_text_atomic(path, util.dump_jsonl(ordered))


if __name__ == "__main__":  # pragma: no cover - manual use
    import argparse

    parser = argparse.ArgumentParser(description="Verify source URLs (online preparation only)")
    parser.add_argument("index", nargs="?", default=util.repo_path("sources", "verified-index.jsonl"))
    parser.add_argument("--all", action="store_true", help="re-check already verified sources")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    recs, summary = check_manifest(args.index, only_missing=not args.all, timeout=args.timeout)
    print(summary)
    write_index(args.index, recs)
