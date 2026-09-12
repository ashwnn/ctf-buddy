"""Deliberately vulnerable practice service (profile web-nginx-flask-compose).

ONE planted defect: the download route joins a client-supplied name onto the
upload directory and hands the result to ``send_file``. Everything else is
written the way it should be, so that a patch to the download route cannot be
confused with a patch to the rest of the service.

Do not deploy this anywhere. It is a training target that binds to a loopback
port of a disposable compose project.
"""

from __future__ import annotations

import os
import sqlite3
import uuid

from flask import Flask, abort, jsonify, request, send_file

app = Flask(__name__)

DB_PATH = os.environ.get("NOTES_DB", "/data/notes.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/srv/app/uploads")
MAX_BODY = 64 * 1024


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/healthz")
def healthz():
    """Liveness plus a real database read: a running process is not enough."""
    try:
        with db() as conn:
            conn.execute("SELECT COUNT(*) FROM notes").fetchone()
    except sqlite3.Error as exc:
        return jsonify({"status": "degraded", "error": str(exc)}), 503
    return jsonify({"status": "ok", "uploads": sorted(os.listdir(UPLOAD_DIR))})


# --------------------------------------------------------------------------
# Legitimate workflow: create / read / delete a note (sqlite on a named volume)
# --------------------------------------------------------------------------
@app.post("/api/notes")
def create_note():
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title", ""))[:200]
    body = str(payload.get("body", ""))[:MAX_BODY]
    if not title:
        abort(400, "title is required")
    note_id = uuid.uuid4().hex
    with db() as conn:
        # Parameterised on purpose: the planted defect is path handling, not SQL.
        conn.execute("INSERT INTO notes (id, title, body) VALUES (?,?,?)",
                     (note_id, title, body))
    return jsonify({"id": note_id, "title": title}), 201


@app.get("/api/notes/<note_id>")
def read_note(note_id: str):
    with db() as conn:
        row = conn.execute("SELECT id, title, body FROM notes WHERE id = ?",
                           (note_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify({"id": row["id"], "title": row["title"], "body": row["body"]})


@app.delete("/api/notes/<note_id>")
def delete_note(note_id: str):
    with db() as conn:
        cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    if cur.rowcount == 0:
        abort(404)
    return "", 204


# --------------------------------------------------------------------------
# The planted defect
#
# The name is taken from the query string, which nginx forwards verbatim. The
# path-segment form of this bug (/files/<path:name>) is NOT reachable through the
# proxy: nginx returns 400 for an encoded-slash traversal attempt before it ever
# reaches the application. That difference is itself part of the exercise --
# "it did not work through the proxy" is not the same as "it is not vulnerable".
# --------------------------------------------------------------------------
@app.get("/files")
def get_file():
    name = request.args.get("name", "")
    return send_file(os.path.join(UPLOAD_DIR, name), as_attachment=True)


if __name__ == "__main__":  # convenience for a quick local run; gunicorn is used in compose
    app.run(host="127.0.0.1", port=8000, debug=False)
