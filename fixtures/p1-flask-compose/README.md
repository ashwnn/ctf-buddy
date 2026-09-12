# p1 — Flask/Gunicorn behind nginx, with a real path-traversal defect

Disposable practice fixture for **profile `web-nginx-flask-compose`**.
It exists to be attacked, diagnosed, patched and rolled back. It is not a model
of a secure service and must never be deployed anywhere else.

```
proxy (nginx:1.27-alpine, published 127.0.0.1:8080 -> 80)
  └── web (python:3.12-slim, gunicorn + flask, NOT published)
        ├── /srv/app/uploads   legitimate download root  (seeded with welcome.txt)
        ├── /srv/canary.txt    outside the download root (tier-3 negative probe target)
        └── /data/notes.db     sqlite data on a named volume (never touched by patches)
```

## The defect (deliberate)

`service/app.py`:

```python
@app.get("/files/<path:name>")
def get_file(name):
    return send_file(os.path.join(UPLOAD_DIR, name), as_attachment=True)
```

`send_file(os.path.join(...))` trusts the client-supplied name, so
`/files/..%2f..%2fcanary.txt` escapes `uploads/`. The narrow fix is
`send_from_directory(UPLOAD_DIR, name, ...)` — the same route, the same
response options, the same legitimate downloads.

## Legitimate workflow that must keep working

| Step | Request | Expected |
|---|---|---|
| health | `GET /healthz` | `200 {"status":"ok"}` |
| download seeded file | `GET /files/welcome.txt` | `200` with the seeded body, `Content-Disposition: attachment` |
| create note | `POST /api/notes {"title":...,"body":...}` | `201 {"id": "<id>"}` |
| read note | `GET /api/notes/<id>` | `200` with the stored body |
| delete note | `DELETE /api/notes/<id>` | `204`, then the read returns `404` |

The note round-trip is the persistence check: it proves the patch did not break
application state handling, and it is what the tier-3 verifier drives.

## Start / reset

```bash
docker compose up -d --build          # first run pulls/buils locally
curl -sS http://127.0.0.1:8080/healthz
./reset.sh                            # down -v, restore tracked files, up -d --build
```

`reset.sh` removes the named volume on purpose: this is a throwaway fixture.
Routine `ctfctl rollback` never removes volumes — only this script does, and only
because the fixture has no data worth keeping.

## Practice

```bash
./ctfctl run discovery+plan   # see README "Reproduce the validated run"
```

Use `docker compose logs web` to watch the fixture's own request log while
attacking it. Everything here binds to loopback by default.
