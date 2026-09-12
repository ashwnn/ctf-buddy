# Drill 03 — Unknown VM inventory

**Time:** 15-20 minutes. **Track:** attack/defend reconnaissance.
**Targets:** Track A is your own machine (always available). Track B is the
disposable `p2` fixture if Docker is available. Both are read-only exercises.

## Goal

Produce a defensible inventory of an unfamiliar host without guessing: what is
listening, what is exposed beyond loopback, what evidence supports each stack
hypothesis, what is missing, and what you would refuse to touch before the
checker contract is understood.

## Setup

Track A (no Docker needed):

```bash
./ctfctl discover --save --json > captures/drill03-local.json
```

Track B (Docker):

```bash
cd fixtures/p2-php-compose
docker compose up -d --build
curl -sS "http://127.0.0.1:8081/api.php?action=healthz"
cd ../..
./ctfctl discover --save --json > captures/drill03-fixture.json
```

## Tasks

1. From the inventory, list every listener that is **not** bound to loopback.
2. For each listener, separate two things:
   * evidence (the socket, the owning process, a unit, a container);
   * candidates (the `stack_candidates` list). Explain why a port number alone
     is never a confirmed stack.
3. Name the application root candidates and where that evidence came from.
4. List at least three gaps the inventory reports, and say what extra evidence
   (root, a package, a config file) would close each one.
5. For Track B, run `./ctfctl plan --profile web-php-apache-compose --verbose`
   and point at the exact facts that connect the container, the published port,
   the file on disk and the profile.
6. Write the one-line target declaration you would need before any mutation, and
   say what rule must be confirmed first.

## Expected evidence

* A listener table with address, port, exposure and confidence.
* The `confidence_legend` applied correctly: medium/low findings are marked as
  candidates, not conclusions.
* A written list of gaps with a concrete way to close each.
* No file changed on the host, and no `apply` command was run.

## Success criteria

* Every claim in your inventory cites an evidence field from the JSON.
* You can explain the difference between "port 80 is open" and "nginx serves a
  PHP application", and you do not cross that line without evidence.
* You know the exact declaration command and the unknown it depends on (patch
  permission / event rules).

## Reset

```bash
cd fixtures/p2-php-compose && ./reset.sh   # only if you started it
rm -f captures/drill03-*.json              # generated, git-ignored
```

Answers and expected values: `drills/answers.md`.
