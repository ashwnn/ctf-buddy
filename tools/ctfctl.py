#!/usr/bin/env python3
"""Windows/dev convenience runner: `python tools/ctfctl.py <command>`.

The canonical entry point is the `./ctfctl` shell wrapper. This file exists so
the toolkit can be exercised on a development host (including Windows) without
setting PYTHONPATH by hand.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctfctl.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
