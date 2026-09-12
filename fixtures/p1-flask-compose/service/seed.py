"""Seed the fixture database and download directory (idempotent)."""

from __future__ import annotations

import os
import sqlite3
import uuid

DB_PATH = os.environ.get("NOTES_DB", "/data/notes.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/srv/app/uploads")


def main() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    legacy_path = os.path.join(UPLOAD_DIR, "legacy-upload.txt")
    if not os.path.exists(legacy_path):
        with open(legacy_path, "w", encoding="utf-8") as fh:
            fh.write("a file that existed before the patch and must keep downloading\n")
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS notes ("
            " id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,"
            " created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        if count == 0:
            conn.execute("INSERT INTO notes (id, title, body) VALUES (?,?,?)",
                         (uuid.uuid4().hex, "seeded", "seeded note body"))
        conn.commit()
    finally:
        conn.close()
    print(f"seed: {DB_PATH} ready, {len(os.listdir(UPLOAD_DIR))} file(s) in {UPLOAD_DIR}")


if __name__ == "__main__":
    main()
