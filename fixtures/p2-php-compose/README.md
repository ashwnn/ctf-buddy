# p2 — PHP/Apache service with a real path-traversal defect

Disposable practice fixture for **profile `web-php-apache-compose`**.

```
web (php:8.3-apache, published 127.0.0.1:8081 -> 80)
  ├── /srv/app/files      legitimate download root (seeded with welcome.txt)
  ├── /srv/canary.txt     outside the download root (tier-3 negative probe target)
  └── /data/notes/*.json  note store on a named volume (never touched by patches)
```

## The defect (deliberate)

`service/download.php`:

```php
$path = FILES_DIR . '/' . $file;
...
$content = file_get_contents($path);
```

No canonicalisation, so `download.php?file=../../canary.txt` reads outside
`FILES_DIR`. The narrow fix is a `realpath()` containment check immediately
before the read — the download feature, the response headers and every
in-directory file keep working unchanged.

## Legitimate workflow that must keep working

| Step | Request | Expected |
|---|---|---|
| health | `GET /healthz` | `200 {"status":"ok",...}` |
| download seeded file | `GET /download.php?file=welcome.txt` | `200` with the seeded body |
| create note | `POST /api/notes {"title":...,"body":...}` | `201 {"id":"<id>"}` |
| read note | `GET /api/notes/<id>` | `200` with the stored body |
| delete note | `DELETE /api/notes/<id>` | `204`, then the read returns `404` |

## Start / reset

```bash
docker compose up -d --build
curl -sS http://127.0.0.1:8081/healthz
./reset.sh        # down -v, restore tracked files, up -d --build
```
