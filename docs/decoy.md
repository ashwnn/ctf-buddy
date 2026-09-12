# Decoys and honeypots

Two related but different tools:

| | `ctfctl decoy` | `ctfctl honeypot` |
|---|---|---|
| Where | this machine only | this machine or a declared host (`remote honeypot`) |
| Gate | `decoy enable --ack-rules --port <UNUSED>` | `--yes` (and over ssh: declaration + policy ack) |
| Modes | one local HTTP lure | several listeners, `http` and `banner`, on unused ports |
| State | `state/decoy.json` | `state/honeypot.json` |
| Logs | `captures/decoy-<stamp>.jsonl` | `captures/honeypot-<port>-<stamp>.jsonl` |
| Purpose | one clearly-marked lure for local log observation | distract and observe attackers on a box you own |

Both are **observation aids**, not defences. Neither can protect a scored service,
and neither replaces reading the checker's traffic. A honeypot on a port the
checker or a scored service uses is worse than no honeypot: the toolkit refuses
to bind a port that is already in use, and refuses privileged ports unless you
say otherwise.

## Rules before you start

1. **Confirm the event permits decoys/honeypots.** Not every event does; some ban
   them outright and some count a decoy hit as a penalty. Ask, then record the
   answer in `docs/event-facts.md`.
2. **Never displace a scored service.** The port must be free; the toolkit bind
   tests it before starting and refuses if anything answers.
3. **Expect them to be found.** A honeypot that logs a scanner has done its job;
   it will not stop a determined team. Treat every log line as a hypothesis about
   who probed you, not as attribution.
4. **Do not use a honeypot as an autoban source.** Reacting to decoy hits with
   firewall blocks is exactly the broad-block behaviour this toolkit refuses to
   automate.

## Local decoy (single HTTP lure)

```bash
./ctfctl decoy enable --ack-rules --port 18080          # ack the rules, name the port
./ctfctl decoy start --port 18080                       # or --mode banner --banner ssh
./ctfctl decoy status
./ctfctl decoy stop                                     # waits for the port to be released
```

The HTTP lure answers `200` on the configured paths (`/admin`, `/.env`,
`/wp-login.php`, ...) with an inert sign-in page, and `404` on everything else.
It never reflects input, so it cannot be turned into a vector against other
participants, and every response carries `X-Decoy: ctfctl`.

## Honeypot (multi-listener)

```bash
# local
./ctfctl honeypot start --port 8080 --mode http
./ctfctl honeypot start --port 2222 --mode banner --banner ssh     # fakes an ssh greeting
./ctfctl honeypot status
./ctfctl honeypot logs --lines 50
./ctfctl honeypot stop --all
```

`--mode banner` prints one fixed line on connect (presets: `ssh`, `smtp`, `ftp`,
`telnet`, or your own text), reads at most 512 bytes of whatever the client
sends, logs it, and closes. It does not speak the protocol, so it cannot be
exploited itself.

Free ports to consider (anything the probe shows as unused): `2222`, `8080`,
`8443`, `3306`, `5432`, `6379`, `9200`. Attackers scan everything, so any free
high port works; a port that *looks* like a database or admin panel collects more
interesting traffic than a random one.

## Remote honeypot (on the vuln box)

```bash
./ctfctl targets declare 10.10.5.3 --label 'our vuln box' --ack-policy
./ctfctl remote honeypot 10.10.5.3 start --honeypot-port 8080 --yes
./ctfctl remote honeypot 10.10.5.3 status
./ctfctl remote honeypot 10.10.5.3 logs --lines 100
./ctfctl remote honeypot 10.10.5.3 collect      # copies the logs into captures/
./ctfctl remote honeypot 10.10.5.3 stop --all --yes
```

`--honeypot-port` is the listener port; `--port` is the ssh port. Start/stop are
mutations and need the declaration, the acknowledged policy and `--yes`; status,
logs and collect are read-only.

`collect` only ever reads paths this toolkit created (`captures/honeypot-<port>-<stamp>.jsonl`
inside `~/.ctfctl`), validated against that naming scheme before they reach an
`ssh` argv.

## What the logs contain

Every event is one JSON object with `"decoy": true`:

```json
{"at": "2026-09-12T17:06:37Z", "event": "decoy-http", "decoy": true,
 "method": "GET", "path": "/admin", "status": 200, "client": "10.10.9.4",
 "user_agent": "curl/8.5.0", "marker": "honeypot-3f97f279"}
```

```bash
rg '"decoy":true' captures/ | jq -r '.client' | sort | uniq -c | sort -rn   # noisy neighbours
rg 'decoy-banner' captures/ | jq -r '.preview' | head                      # what they typed
```

Bounds, all enforced in the listener process: at most 8 concurrent threads, a
4 MiB log budget per listener, 64 KiB maximum request body, 10 s request
timeout, and rlimits (address space, file descriptors, CPU) where the platform
supports them. Log events are escaped and length-capped, so attacker input can
never forge a log line or move your terminal cursor.

## Failure modes

* Starting a honeypot and forgetting the scored service on the same port: refused
  by the bind test before anything starts.
* Treating a honeypot hit as proof of who attacked: it is a source address, not
  an identity.
* Leaving a listener running after the event: `ctfctl honeypot stop --all` (and
  the container tests start from a clean state each run).
* Honeypotting on a host you do not own: the declaration gate exists for that.
