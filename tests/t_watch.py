"""`watch` and observe.py: bounded observation without network or ssh.

Every run here is bounded by a line budget or by --seconds, and no test opens a
socket, starts tcpdump, or touches ssh:

* CLI runs pass --dry-run, which prints the planned capture command instead of
  starting it;
* direct observe runs pass an empty --filter, so the capture branch is skipped
  entirely;
* the only threads append lines to a temp file and are stopped before the test
  returns.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
from typing import Iterator, List, Optional, Tuple

from helpers import check, check_eq, check_in, temp_dir

from ctfctl import cli, observe as observe_mod, util


@contextlib.contextmanager
def _watch_repo() -> Iterator[str]:
    """A throwaway repo root: watch writes its events under captures/ there."""
    with temp_dir("ctfctl-watch-") as root:
        util.write_text_atomic(os.path.join(root, "AGENTS.md"), "test root\n")
        previous = os.getcwd()
        os.chdir(root)
        try:
            yield root
        finally:
            os.chdir(previous)


@contextlib.contextmanager
def _wide_help() -> Iterator[None]:
    """Force a wide formatter so help flags cannot be wrapped onto two lines."""
    previous = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "200"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = previous


def _run_cli(argv: List[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class _Appender:
    """Appends lines to a file from a daemon thread, stoppable for cleanup."""

    def __init__(
        self, path: str, lines: List[str], *, delay: float = 0.05, gap: float = 0.02
    ) -> None:
        self.path = path
        self.lines = list(lines)
        self.delay = delay
        self.gap = gap
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "_Appender":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self) -> None:
        if self._stop.wait(self.delay):
            return
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                for line in self.lines:
                    if self._stop.is_set():
                        break
                    fh.write(line + "\n")
                    fh.flush()
                    if self._stop.wait(self.gap):
                        break
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)


@contextlib.contextmanager
def _appending(path: str, lines: List[str]) -> Iterator[None]:
    appender = _Appender(path, lines).start()
    try:
        yield
    finally:
        appender.stop()


def _config(
    log: str, caps: str, *, seconds: int, max_lines: int = 500, **extra: object
) -> observe_mod.ObservationConfig:
    """A logs-only observation: an empty filter skips the capture branch."""
    return observe_mod.ObservationConfig(
        log_paths=[log],
        seconds=seconds,
        max_lines=max_lines,
        output_dir=caps,
        net_filter="",
        **extra,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------
# Parser and help wiring
# --------------------------------------------------------------------------
def test_parser_wires_the_bounded_flags() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "watch",
            "--logs",
            "a.log",
            "--logs",
            "b.log",
            "--unit",
            "sshd",
            "--iface",
            "eth0",
            "--filter",
            "tcp port 80",
            "--seconds",
            "5",
            "--max-lines",
            "10",
            "--count",
            "7",
            "--snaplen",
            "64",
            "--include",
            "keep",
            "--exclude",
            "drop",
            "--dry-run",
            "--json",
        ]
    )
    check_eq(args.command, "watch", "watch is a top-level command")
    check_eq(args.logs, ["a.log", "b.log"], "--logs is repeatable")
    check_eq(args.unit, ["sshd"], "--unit is repeatable")
    check_eq(args.iface, "eth0", "--iface must parse")
    check_eq(args.filter, "tcp port 80", "--filter must parse")
    check_eq(args.seconds, 5, "--seconds must parse")
    check_eq(args.max_lines, 10, "--max-lines must parse")
    check_eq(args.count, 7, "--count must parse")
    check_eq(args.snaplen, 64, "--snaplen must parse")
    check_eq(args.include, "keep", "--include must parse")
    check_eq(args.exclude, "drop", "--exclude must parse")
    check_eq(args.dry_run, True, "--dry-run must parse")
    check_eq(args.json, True, "--json must parse")
    # The defaults are the bounded posture: 60s, 500 lines, no chosen interface.
    args = parser.parse_args(["watch"])
    check_eq(args.seconds, 60, "the default window must be bounded")
    check_eq(args.max_lines, 500, "the default line budget must be bounded")
    check_eq(args.iface, None, "no interface is chosen by default")
    check_eq(args.dry_run, False, "a bare watch must not be a dry run")


def test_watch_help_documents_every_bound() -> None:
    with _wide_help():
        code, out, err = _run_cli(["watch", "--help"])
    check_eq(code, 0, f"watch --help must exit 0: {err}")
    for needle in (
        "--logs",
        "--unit",
        "--iface",
        "--filter",
        "--seconds",
        "--max-lines",
        "--count",
        "--snaplen",
        "--dry-run",
        "--json",
    ):
        check_in(needle, out, f"watch help must document {needle}")


# --------------------------------------------------------------------------
# CLI runs: reported lines, JSON shape, clean exit
# --------------------------------------------------------------------------
def test_watch_cli_reports_lines_and_stops_at_the_line_budget() -> None:
    with _watch_repo() as root:
        log = os.path.join(root, "app.log")
        util.write_text_atomic(log, "")
        with _appending(log, ["first line", "second line"]):
            started = time.time()
            code, out, err = _run_cli(
                [
                    "watch",
                    "--logs",
                    log,
                    "--seconds",
                    "5",
                    "--max-lines",
                    "2",
                    "--dry-run",
                ]
            )
            elapsed = time.time() - started
        check_eq(code, util.EXIT_OK, f"a bounded watch must exit cleanly: {err}")
        check_eq(err, "", "a clean watch writes nothing to stderr")
        check(elapsed < 4.0, f"the line budget must stop the run, took {elapsed:.1f}s")
        check_in(
            "logs      2 line(s)", out, "the summary must count the appended lines"
        )
        check_in(log, out, "the summary must name the source")
        check_in(
            "stopped early: line/byte budget reached",
            out,
            "the budget stop must be reported",
        )
        check_in("dry run", out, "a dry run must not start a capture")
        check_in("tcpdump", out, "the planned capture command must be printed")
        check(
            os.path.isdir(os.path.join(root, "captures")),
            "events must land under captures/",
        )


def test_watch_json_mode_reports_logs_net_and_event_files() -> None:
    with _watch_repo() as root:
        log = os.path.join(root, "app.log")
        util.write_text_atomic(log, "")
        with _appending(log, ["json line"]):
            code, out, err = _run_cli(
                [
                    "watch",
                    "--logs",
                    log,
                    "--seconds",
                    "5",
                    "--max-lines",
                    "1",
                    "--dry-run",
                    "--json",
                ]
            )
        check_eq(code, util.EXIT_OK, f"a json watch must exit cleanly: {err}")
        payload = json.loads(out)
        check_eq(payload["logs"]["lines"], 1, "json must count the appended line")
        check_eq(
            payload["logs"]["stopped_by_budget"],
            True,
            "the line budget stop must be reported",
        )
        check_eq(
            payload["logs"]["sources"][0]["source"],
            log,
            "the source path must be reported verbatim",
        )
        check_eq(
            payload["logs"]["sources"][0]["status"],
            "tailing",
            "a readable source must be tailed",
        )
        check_eq(payload["net"]["dry_run"], True, "json must report the dry run")
        check_eq(
            payload["net"]["argv"][0],
            "tcpdump",
            "the planned capture starts no process",
        )
        check_eq(
            len(payload["events_files"]), 2, "log and capture events each get a file"
        )
        for path in payload["events_files"]:
            check(os.path.isfile(path), f"event file must exist: {path}")
        check("note" not in payload, "a watched source is not 'nothing observed'")


# --------------------------------------------------------------------------
# observe.py: time bound, filters, missing sources, hostile text
# --------------------------------------------------------------------------
def test_watch_stops_at_the_time_bound() -> None:
    with _watch_repo() as root:
        with temp_dir() as caps:
            log = os.path.join(root, "app.log")
            util.write_text_atomic(log, "")
            with _appending(log, ["one", "two"]):
                started = time.time()
                result = observe_mod.run(_config(log, caps, seconds=1), root=root)
                elapsed = time.time() - started
            check(
                elapsed >= 0.8, f"the time bound must be honoured, took {elapsed:.1f}s"
            )
            check(
                elapsed < 3.0, f"the loop must stop at the bound, took {elapsed:.1f}s"
            )
            check(result["logs"]["lines"] >= 1, "appended lines must be observed")
            check_eq(
                result["logs"]["stopped_by_budget"],
                False,
                "two lines are far under the budgets",
            )
            check_eq(
                result["net"], None, "an empty filter must skip the capture branch"
            )
            check_eq(
                result["events_files"],
                [result["logs"]["events_file"]],
                "only the log events file is produced",
            )


def test_watch_filters_include_and_exclude() -> None:
    with _watch_repo() as root:
        with temp_dir() as caps:
            log = os.path.join(root, "app.log")
            util.write_text_atomic(log, "")
            with _appending(log, ["keep one", "drop this", "keep two", "keep three"]):
                result = observe_mod.run(
                    _config(
                        log,
                        caps,
                        seconds=5,
                        max_lines=2,
                        include_regex="keep",
                        exclude_regex="three",
                    ),
                    root=root,
                )
            check_eq(result["logs"]["lines"], 2, "include and exclude must both apply")
            events = util.load_jsonl(result["logs"]["events_file"])
            lines = [record["line"] for record in events if record.get("kind") == "log"]
            check_eq(
                lines,
                ["keep one", "keep two"],
                "only surviving lines may reach the event file",
            )


def test_watch_reports_a_missing_source() -> None:
    with _watch_repo() as root:
        with temp_dir() as caps:
            missing = os.path.join(root, "missing.log")
            result = observe_mod.run(_config(missing, caps, seconds=1), root=root)
            check_eq(result["logs"]["lines"], 0, "a missing file yields no lines")
            check_eq(
                result["logs"]["sources"][0]["status"],
                "missing",
                "the source must be reported missing, not failed",
            )


@contextlib.contextmanager
def _no_journalctl() -> Iterator[None]:
    """Hide journalctl so the unsupported path is deterministic everywhere."""
    original = util.which

    def _which(name: str) -> Optional[str]:
        if name == "journalctl":
            return None
        return original(name)

    util.which = _which  # type: ignore[assignment]
    try:
        yield
    finally:
        util.which = original  # type: ignore[assignment]


def test_watch_degrades_when_journalctl_is_missing() -> None:
    with _watch_repo() as root:
        with temp_dir() as caps:
            with _no_journalctl():
                config = observe_mod.ObservationConfig(
                    journal_units=["sshd"], seconds=1, output_dir=caps, net_filter=""
                )
                result = observe_mod.run(config, root=root)
            check_eq(
                result["logs"]["lines"], 0, "nothing can be read without journalctl"
            )
            check_eq(
                result["logs"]["sources"][0]["status"],
                "unavailable",
                "the missing journal must be reported, not raised",
            )


def test_watch_escapes_control_sequences_in_events() -> None:
    with _watch_repo() as root:
        with temp_dir() as caps:
            log = os.path.join(root, "app.log")
            util.write_text_atomic(log, "")
            with _appending(log, ["evil \x1b[2J clear"]):
                result = observe_mod.run(
                    _config(log, caps, seconds=5, max_lines=1), root=root
                )
            text = util.read_text(result["logs"]["events_file"])
            check(
                "\x1b" not in text, "raw escape bytes must never reach the event file"
            )
            check_in("\\x1b", text, "the escape must be rendered as inert text")
