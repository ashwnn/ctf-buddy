# Drill 05 — Decoy detection (optional)

**Time:** 15 minutes. **Track:** observation.
**Prerequisites:** decoys must be permitted by the event rules and you must name
an unused port. This drill is local-only and uses no event target.

## Goal

Stand up the minimal HTTP decoy on an unused loopback port, generate harmless
noise against it, and read the marked events. Learn what the decoy does and,
more importantly, what it does **not** prove.

## Setup

```bash
./ctfctl decoy enable --ack-rules --port 9099 --path /admin.php --bind 127.0.0.1
./ctfctl decoy start
./ctfctl decoy status
```

`9099` must be free. If anything is already listening there, pick another port;
never displace a real service.

## Tasks

1. Hit a configured path and an unconfigured one:
   * `curl -si http://127.0.0.1:9099/admin.php`
   * `curl -si http://127.0.0.1:9099/does-not-exist`
   Record the status codes and the `X-Decoy` header.
2. Send a hostile-looking request with an ANSI escape and a newline in the path,
   for example with `printf` and `nc`, and then read the newest
   `captures/decoy-*.jsonl`.
3. Answer from the log:
   * which events are marked `decoy: true`;
   * whether the escape byte survived or was rendered inert;
   * whether the response ever reflected your input.
4. Stop the decoy and confirm the port is released:
   `./ctfctl decoy stop`.
5. Write two sentences: what this decoy detects, and why a planted file with no
   instrumentation is not an alerting system.

## Expected evidence

* Configured path returns its own inert login page with `X-Decoy: ctfctl`;
  unconfigured paths return 404.
* The log contains one JSON object per event with `"decoy": true`, escaped
  control characters, and no reflected payload.
* `decoy stop` reports the port released.

## Success criteria

* Every decoy event you quote is marked as a decoy, so it can never be confused
  with a real service event.
* You can state the decoy's limits: no backend, no credentials, no shell, no
  callbacks, and it must never shadow a scored service.

## Reset

```bash
./ctfctl decoy stop
rm -f captures/decoy-*.jsonl     # generated, git-ignored
```

Answers and expected values: `drills/answers.md`.
