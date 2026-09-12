# Rank routes by what they can read, not by how interesting the bug class sounds

**First useful action.** For each confirmed flaw, ask which route would let you read the flag store or
another team's stored data, and work that one first.

```bash
rg -n --no-config -e 'flag|FLAG|secret|token|store|spool|/var/lib|data_dir|DATA_DIR|STORE' \
  <SERVICE_SRC>/ | head -n 80
```

Expected: a short list of paths and constants pointing at where the secret lives. Pair each with the route
that reads it. If the flag path is not visible in source, look at the service's working directory, its
config, and the process environment before guessing.

## Symptoms

- Several candidate vulnerabilities exist and the tick is short.
- One flaw gives code execution but nothing to read; another gives a data read from the right place.
- The team is debating bug classes rather than deciding what to attack.

## Prerequisites and assumptions

- A confirmed or strongly-indicated primitive, and a rough idea where secrets are stored.
- The event's rules on what may be read from a service (`AGENTS.md` scope rules apply).
- Stack/version: stack-agnostic; the flag-placement model is event-specific and frequently *not*
  documented for a given event (`research/01-event-and-team-operations.md` records this uncertainty for
  Raymond James explicitly).

## Diagnostic sequence

1. Locate the secret's storage: source constant, config key, environment variable, or a mounted path.
   → The target of a read primitive.
2. Locate every route that can read or return that location. → Rank by "one request, no precondition".
3. Check whether the flag is per-tick and per-team. → If identifiers rotate, the primitive must be
   re-usable, not a one-shot.
4. Confirm the primitive against your own instance first. → Never test a data-read primitive against a
   peer before it works locally.
5. Only then decide whether to spend the tick on a harder bug class with broader reach.

If the flag path cannot be found at all, the placement model is probably dynamic (written per tick by the
checker). Look at the write path, not the read path.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `rg -n 'FLAG\|flag_path\|flagstore' <SVC>` | a constant or config key | Direct read target. |
| `rg -n 'open(\|read_text\|readFile' near a flag name | file read reaching the flag | Candidate read primitive. |
| route list + one route returning stored user data | data-returning route | Likely shares the storage layer with the flag. |
| `ls -la <SERVICE_WORKDIR>` on the team's own instance | data files/directories | Where runtime state actually lives. |

## Exploit → patch pair

- **Flaw:** not a single flaw. This card decides *which* flaw to spend the tick on, and therefore which
  patch matters.
- **Reproduce on the isolated fixture:** `fixtures/d1-switchboard` and `fixtures/d2-notehub-diagnose`
  (planned in `research/06-drills-and-validation.md`) both contain a seeded "secret-equivalent" record
  whose value must be reachable only through a legitimate owner-scoped path (not yet run here).
- **Narrow patch:** the patch for whichever read path you selected; the invariant is that the secret is
  reachable only through authorized legitimate flows.
- **Legitimate functionality that must keep working:** the checker's own flag store/retrieve path, which
  is by definition legitimate traffic.
- **Verify:** the unauthorized read fails and the checker still stores and retrieves successfully.

## Failure modes and things teams stopped doing

- Chasing the most exotic bug class first. Availability-scored events reward the *first working* read of
  another team's data, not the most elegant bug (`src-enowars-checker-tenets-bf4b0ac7` describes checkers exercising
  legitimate service functionality, including placement and later retrieval of values).
- Assuming a flag path from another event. `research/01-event-and-team-operations.md` documents materially
  different flag lifetimes and models across FAUST, saarCTF, and RuCTFE and warns against importing any
  of them; the ENOWARS play documentation is indexed as the general-availability model, not as a rule set
  for our event (`src-enowars-general-docs-5c2a697e`).
- Spending the whole tick on one hard service. Keep the Jeopardy lane and the other services alive;
  a single exploited service rarely outweighs losing the whole board.
- Reporting "we found an RCE" without showing what it reads. In a scored game, the value is the data
  retrieved, not the class name (the saarCTF 2025 services/checkers repository is indexed as the
  reference for how checkers place and retrieve data: `src-saarsec-saarctf2025-a6-3e109202`).
- Guessing the flag format and building a scanner around it. `research/01-event-and-team-operations.md`
  keeps the flag format explicitly unknown for our event; do not encode a guess into a tool.

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No source was searched and no secret path was identified in this
  session.
- **Our adaptation vs the source:** the flag-store/checker model is drawn from the FAUST gameserver
  (`src-faust-gameserver-readme-4e7460fe`), the ENOWARS service/checker tenets (`src-enowars-checker-tenets-bf4b0ac7`), the
  ENOWARS general play documentation (`src-enowars-general-docs-5c2a697e`), and the saarCTF 2025
  services/checkers repository (`src-saarsec-saarctf2025-a6-3e109202`). The triage rule ("rank by what a path can
  read") is our synthesis for a hybrid event with limited time.

## Sources

- `src-faust-gameserver-readme-4e7460fe` — gameserver/checker architecture and how flags are placed and retrieved.
- `src-enowars-checker-tenets-bf4b0ac7` — service/checker design: checkers exercise legitimate functionality.
- `src-enowars-general-docs-5c2a697e` — general attack-defend availability model.
- `src-saarsec-saarctf2025-a6-3e109202` — per-service checkers that place and retrieve flags.
- `src-maplebacon-ad-primer-23bd534f` — attack-defend primer used for prioritisation framing.
