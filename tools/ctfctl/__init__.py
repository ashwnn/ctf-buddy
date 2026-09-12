"""ctfctl — offline-first preparation toolkit for a first-time CTF team.

Standard library only. Linux-first with explicit degradation elsewhere.

Modules:
    util      bounded IO, redaction, hashing, structured subprocess
    platformx host capability detection
    kbindex   FTS5 knowledge-base index with literal ripgrep fallback
    discover  read-only bounded host inventory
    profiles  declarative profile loading and validation
    plan      detection, planning, stale-check and diff generation
    apply     transactional mutation engine with rollback
    observe   bounded log and packet observation
    decoy     optional minimal unprivileged HTTP decoy
    doctor    offline dependency and capability report
"""

__all__ = [
    "apply",
    "cli",
    "decoy",
    "discover",
    "doctor",
    "files",
    "kbindex",
    "observe",
    "plan",
    "platformx",
    "profiles",
    "remote",
    "util",
]

__version__ = "0.1.0"
