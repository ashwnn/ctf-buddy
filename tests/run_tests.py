#!/usr/bin/env python3
"""Stdlib test runner: `python tests/run_tests.py [module ...]`.

Runs every tests/t_*.py module that satisfies the selection, prints a summary and
exits non-zero on failure. No pytest, no network, no Docker unless a module
explicitly opts in and reports a skip.
"""

from __future__ import annotations

import importlib
import os
import sys
import time
from typing import List

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
if os.path.join(os.path.dirname(TESTS_DIR), "tools") not in sys.path:
    sys.path.insert(0, os.path.join(os.path.dirname(TESTS_DIR), "tools"))

import helpers  # noqa: E402


def discover(selection: List[str]) -> List[str]:
    modules = []
    for name in sorted(os.listdir(TESTS_DIR)):
        if not (name.startswith("t_") and name.endswith(".py")):
            continue
        if selection and not any(sel in name for sel in selection):
            continue
        modules.append(name[:-3])
    return modules


def main(argv: List[str]) -> int:
    selection = [a for a in argv[1:] if not a.startswith("-")]
    verbose = "-v" in argv
    modules = discover(selection)
    if not modules:
        print("no test modules matched")
        return 2
    total_passed = 0
    all_failures: List[str] = []
    skipped: List[str] = []
    started = time.time()
    for name in modules:
        module = importlib.import_module(name)
        print(f"\n== {name} ==")
        if getattr(module, "SKIP", None):
            reason = getattr(module, "SKIP_REASON", "no reason given")
            print(f"  SKIP  {reason}")
            skipped.append(f"{name}: {reason}")
            continue
        passed, failures = helpers.run_module(module)
        total_passed += passed
        all_failures.extend(failures)
    elapsed = time.time() - started
    print("\n" + "=" * 68)
    print(f"tests: {total_passed} passed, {len(all_failures)} failed, "
          f"{len(skipped)} module(s) skipped, {elapsed:.1f}s")
    for failure in all_failures:
        print(f"  FAIL {failure}")
    for item in skipped:
        print(f"  SKIP {item}")
    if not all_failures:
        print("RESULT: PASS")
    return 1 if all_failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
