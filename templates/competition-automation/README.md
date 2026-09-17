# Competition automation template (optional, bounded, mock-first)

**Use this only if the event rules permit automation.** It is a template, not an
event integration: it is disabled by default, it refuses any endpoint that is not
explicitly allowlisted, and the shipped configuration points at a local mock
server. No organizer URL is hardcoded anywhere in this repository.

## Files

| File | Purpose |
|---|---|
| `submit.py` | reads candidate flags from a file, tracks outcomes durably, deduplicates, rate-limits and submits to the configured endpoint |
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

## Outcome model

Every send is recorded in the state file as one of four outcomes. Only the two
terminal outcomes suppress future attempts:

| Outcome | Meaning | Retried later? |
|---|---|---|
| `pending` | written before the request is sent; a crash leaves this record behind | yes |
| `accepted` | the response body confirmed `accepted: true` | no |
| `rejected-final` | the response body explicitly rejected the flag | no |
| `retryable` | connection error, timeout, 429/5xx, or any 2xx/4xx whose body has no explicit boolean rejection | yes |

A 2xx response is not acceptance by itself: only `accepted: true` decides, and an
ambiguous response is reported as unconfirmed. Only `accepted: false` or
`rejected: true` are terminal rejections; status/result strings such as
`denied` or `invalid`, and bare 401/403 responses, are retryable and
unconfirmed. Retries within a run are bounded by `max_attempts`; a
`Retry-After` header is honored but capped at 30 seconds.
The state file is append-only JSONL, fsynced per line, an interrupted final line
is ignored on load, and a lock file (`<state_file>.lock`) serializes writers.
Legacy records migrate in memory only: `rejected` -> `rejected-final`,
`failed` -> `retryable`, and `submitted` -> `retryable` and unconfirmed, because
the old writer marked every non-rejected 2xx as `submitted` and so never proved
acceptance. A legacy `submitted` flag may therefore be submitted again: check
the scoreboard before rerunning so an already-scored flag is not duplicated. No
record is ever rewritten.

## Bounds, by construction

| Control | Behavior |
|---|---|
| Endpoint allowlist | `allow_hosts` must contain the URL host or the config is refused |
| Fail-safe default | `dry_run: true` sends nothing until you change it deliberately |
| Flag format | `flag_regex` must compile; candidates are extracted from free text |
| Deduplication | sha256 of every flag is written to `state_file`; only `accepted` and `rejected-final` records skip a flag, so `pending`/`retryable` are retried |
| Rate limit | at most `max_per_minute` submissions in any 60 second window |
| Timeouts | per-request `timeout_seconds`; bounded body read (64 KiB) |
| Retries | at most `max_attempts`; connection errors, timeouts, 429/5xx and ambiguous 2xx/4xx bodies are retried with bounded backoff, `Retry-After` is honored up to 30 seconds, and only an explicit boolean rejection (`accepted: false` / `rejected: true`) is final |
| State | one fsynced JSON line per state change in the state file; torn lines are ignored on load; never committed (`state/` is ignored) |

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
