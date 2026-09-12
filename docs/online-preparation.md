# Online preparation (`ctfctl prep-online`)

`prep-online` is the **only** command in this repository that may use the
network. Run it before the event, on a trusted network, never during
event-time discovery, planning or hardening.

## What it does

```bash
./ctfctl prep-online --json                 # capability + tool report
./ctfctl prep-online --require-tools rg tcpdump tshark docker
./ctfctl prep-online --check-sources        # re-verify source URLs still resolve
./ctfctl prep-online --check-sources --all  # include already-verified sources
```

* `--require-tools` exits non-zero if a named tool is missing, so a setup script
  can fail early instead of failing under time pressure.
* `--check-sources` performs HEAD/GET requests against `canonical_url` values in
  `sources/verified-index.jsonl` and records what resolved, with timestamps. It
  does not crawl, does not follow arbitrary links and does not bypass paywalls.
* The command never installs packages and never builds or pulls container
  images implicitly. Use your normal package manager and `docker pull` /
  `docker compose build` explicitly.

## What it does not do

* No fetching during event-time commands. `doctor`, `discover`, `plan`, `apply`,
  `verify`, `rollback`, `watch`, `decoy`, `kb` and `files` are offline.
* No credentials. There is no account, token or API key anywhere in this
  repository; the online step only checks public URLs.
* No third-party installs into this repository. It is stdlib-only by design.

## Remote mode is separate

`ctfctl remote ...` uses SSH to reach a declared team-owned host. That is a
deliberate, operator-initiated connection to *your own box*, not a dependency
fetch. It does not require Internet access (a LAN address works), it never
installs anything, and it is gated by `state/targets.json`. See
`docs/remote-mode.md`.

## Pre-event checklist

```bash
./ctfctl doctor                       # everything offline that should work
./ctfctl kb index                     # build the search index once
./ctfctl prep-online --require-tools rg tcpdump tshark
./ctfctl prep-online --check-sources  # refresh source provenance dates
./ctfctl profiles validate            # profiles parse and pass the closed checks
./ctfctl doctor                       # confirm the index and corpus counts
```
