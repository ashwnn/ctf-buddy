# Competition automation template (optional, bounded, mock-first)

**Use this only if the event rules permit automation.** It is a template, not an
event integration: it is disabled by default, it refuses any endpoint that is not
explicitly allowlisted, and the shipped configuration points at a local mock
server. No organizer URL is hardcoded anywhere in this repository.

## Files

| File | Purpose |
|---|---|
| `submit.py` | reads candidate flags from a file, deduplicates, rate-limits and submits to the configured endpoint |
| `mock_server.py` | a loopback-only rehearsal endpoint that says what it would accept |
| `config.example.json` | dry-run config you copy and edit deliberately |

## Rehearse offline

```bash
cp templates/competition-automation/config.example.json /tmp/submit.json
python templates/competition-automation/mock_server.py --port 8099 &

printf 'FLAG{practice_one}\nFLAG{practice_two}\nFLAG{practice_one}\n' > /tmp/candidates.txt
python templates/competition-automation/submit.py --config /tmp/submit.json \
    --flags-file /tmp/candidates.txt --dry-run
```

Then remove `--dry-run` (and set `"dry_run": false` in the config) to send to the
mock endpoint. The mock logs every request, so you can confirm the exact payload,
the order and the dedup behavior before any real endpoint exists.

## Bounds, by construction

| Control | Behavior |
|---|---|
| Endpoint allowlist | `allow_hosts` must contain the URL host or the config is refused |
| Fail-safe default | `dry_run: true` sends nothing until you change it deliberately |
| Flag format | `flag_regex` must compile; candidates are extracted from free text |
| Deduplication | sha256 of every flag is written to `state_file`; repeats are skipped |
| Rate limit | at most `max_per_minute` submissions in any 60 second window |
| Timeouts | per-request `timeout_seconds`; bounded body read (64 KiB) |
| Retries | at most `max_attempts`, with short bounded backoff; HTTP 4xx is not retried |
| State | one JSON line per attempt in the state file; never committed (`state/` is ignored) |

## Rules checklist before enabling

* Does the event allow automated flag submission at all? If the rules are silent,
  assume no and keep `dry_run: true`.
* Is the endpoint stable, and is it the team's own submission path (not a shared
  or opponent system)?
* Is there a per-team rate limit? Set `max_per_minute` below it.
* Who owns the dedup state, and does the team agree on one submission path? Two
  people running two copies will duplicate work.
* Does the checker score on first submission only? If so, dedup matters more than
  speed.

## What this template will not do

* It never scans, targets, or interacts with opponent hosts.
* It does not poll a scoreboard, brute-force a flag format, or bypass a rate
  limit. If the mock rejects, you fix your input, not the endpoint.
* It does not automate exploitation; it only carries already-captured flags.
