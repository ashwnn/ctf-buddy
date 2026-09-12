# Drill answers and expected values

Keep this out of the way until a drill is finished. Values are verified against
the shipped fixtures; the synthetic PCAP values come from the generator itself.

## Drill 01 — Web diagnosis and narrow patch

| Question | Answer |
|---|---|
| Exploit request | `GET /files?name=../../canary.txt` |
| Canary value | `FIXTURE_CANARY_value_outside_the_download_root` |
| Vulnerable line | `return send_file(os.path.join(UPLOAD_DIR, name), as_attachment=True)` in `get_file` |
| Why the path-segment form is a red herring | nginx rejects encoded-slash traversal with 400 before Flask sees it; the query-string form reaches the app |
| Narrow fix | import and call `send_from_directory(UPLOAD_DIR, name, as_attachment=True)` |
| Plan profile / action | `web-nginx-flask-compose` / `file.python_flask_send_from_directory`, eligibility `auto` |
| After apply | `phase: COMMITTED`; exploit returns 404; `/healthz` 200; `welcome.txt` 200; note create/read/delete round-trip passes; static check finds `send_from_directory` |
| After rollback | `phase: ROLLED_BACK`; exploit returns the canary again (baseline restored) |

## Drill 02 — PCAP to request reconstruction

| Question | Answer |
|---|---|
| Endpoints / server port | `10.0.0.42:49152` to `10.0.0.10:8080` |
| Requests | `GET /healthz HTTP/1.1`, then `POST /api/notes HTTP/1.1` |
| User-Agent | `drill-client/1.0` |
| POST body | `{"title":"drill note","body":"FLAG{synthetic_pcap_reconstruction_7f3a}","tags":["synthetic"]}` |
| Content-Length | `93` |
| Flag | `FLAG{synthetic_pcap_reconstruction_7f3a}` |
| Response to the POST | `HTTP/1.1 201 Created` with `{"id":"note-7"}` |
| Packet count | 10 (SYN, SYN-ACK, ACK, request, response, request, response, FIN, FIN, ACK) |

Reproducible commands (tshark):

```bash
tshark -r captures/drill02.pcap -q -z conv,tcp
tshark -r captures/drill02.pcap -Y 'tcp.stream == 0' -T fields \
  -e http.request.method -e http.request.uri -e http.user_agent
tshark -r captures/drill02.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data
tshark -r captures/drill02.pcap -q -z follow,tcp,ascii,0
```

## Drill 03 — Unknown VM inventory

The local track has no fixed answer; grade it on evidence. For the p2 fixture
track, the verified facts are:

| Fact | Value |
|---|---|
| Published listener | `127.0.0.1:8081 -> 80/tcp` (loopback only) |
| Container | `p2-web` (image `php:8.3-apache`) |
| Compose project / service | `p2-php-compose` / `web` |
| Project dir / compose file | `fixtures/p2-php-compose` / `fixtures/p2-php-compose/compose.yaml` |
| Vulnerable file the profile targets | `service/public/download.php` |
| Matched profile | `web-php-apache-compose` (all `all:` predicates and one `any`) |

Good answers also name gaps such as: no root so socket ownership is incomplete;
no nginx/apache config found so proxy topology is unknown; scheduled-job evidence
may simply be absent; `/proc/<pid>/environ` unreadable; container inventory empty
without a Docker daemon. A declaration would be
`ctfctl targets declare <host> --label '<service>'`, and patching requires the
event rules to confirm that patching is allowed.

## Drill 04 — Patch regression and rollback

| Question | Answer |
|---|---|
| First failing check after the edit | a required `http.request` verifier for `GET /healthz`, reporting a non-200 status (500) |
| Rollback behavior | refusal; the message has the shape `<path> changed after this transaction (expected post-image <hash>..., found <hash>...): refusing to overwrite. Resolve by hand.` |
| Why refusing is correct | the engine cannot tell a teammate's deliberate edit from corruption; overwriting would destroy a human's work |
| Recovery | `ctfctl recover` reports the state; `git restore -- fixtures/p1-flask-compose/service/app.py` returns the tracked (vulnerable) file; restart the service |
| Restored baseline | health 200, legitimate download 200, exploit canary reachable again |

## Drill 05 — Decoy detection

| Question | Answer |
|---|---|
| `/admin.php` response | 200 with the decoy's own login page and `X-Decoy: ctfctl` |
| Unknown path | 404, still marked `X-Decoy: ctfctl` |
| Log records | one JSON object per event with `"decoy": true` and `"event": "decoy-http"` |
| Escape byte | recorded inertly (for example `\x1b`), never written raw |
| Reflection | the decoy never reflects request data into the response |
| Stop | `decoy stop` reports `verified: true` only after the port is released |
| What it does not prove | a planted file or banner with no instrumentation produces no events; the decoy detects interaction with *its* port, and nothing else |
