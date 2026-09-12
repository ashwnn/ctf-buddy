#!/usr/bin/env python3
"""Mock submission endpoint for rehearsal. Standard library only.

Binds loopback only. Accepts POST /submit with a JSON body {"flag": "..."} and
answers {"accepted": bool, "detail": "..."}. Every request is logged to stdout
so a rehearsal can see exactly what automation sent.

This server exists so the submission template can be exercised offline. It is
not an organizer endpoint and must never be pointed at one.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

MAX_BODY = 8 * 1024
DEFAULT_REGEX = r"[A-Za-z0-9_]{2,20}\{[^}]{3,200}\}"


class MockHandler(BaseHTTPRequestHandler):
    server_version = "ctfctl-mock/1.0"

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/submit":
            self._send(404, {"accepted": False, "detail": "unknown path"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send(413, {"accepted": False, "detail": "body size out of range"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            self._send(400, {"accepted": False, "detail": "invalid JSON"})
            return
        flag = str(payload.get("flag") or "")
        accepted = bool(getattr(self.server, "accept_all", False)) or bool(
            re.fullmatch(getattr(self.server, "pattern"), flag)
        )
        print(f"mock: flag={flag[:80]!r} accepted={accepted}", flush=True)
        self._send(
            200,
            {
                "accepted": accepted,
                "detail": "mock accepted" if accepted else "mock rejected",
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        self._send(405, {"accepted": False, "detail": "use POST /submit"})

    def log_message(self, fmt: str, *args: Any) -> None:  # keep output tidy
        return


def build_server(port: int, *, pattern: str, accept_all: bool) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), MockHandler)
    server.pattern = re.compile(pattern)  # type: ignore[attr-defined]
    server.accept_all = accept_all  # type: ignore[attr-defined]
    return server


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--pattern", default=DEFAULT_REGEX)
    parser.add_argument("--accept-all", action="store_true")
    args = parser.parse_args(argv)

    server = build_server(args.port, pattern=args.pattern, accept_all=args.accept_all)
    print(
        f"mock submission endpoint on http://127.0.0.1:{args.port}/submit "
        f"(accept_all={args.accept_all})",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("mock: stopping", file=sys.stderr)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
