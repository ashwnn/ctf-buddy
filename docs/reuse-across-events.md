# Reuse this kit across CTFs

This repository is the reusable core. An event profile is a short, human-readable record of the rules, scope, scoring, team roles and available tools for **one** competition. It is not a new CLI mode. The event's current rules take precedence over any example command in this repository.

## Start with the event, then select tools

1. Read the organizer's current rules and briefing. Record what is confirmed, what is assumed and what remains unknown in a copy of `events/_template.md`.
2. Select a small set of relevant cheat sheets and drills. Run `./ctfctl doctor`, `./ctfctl kb cheat`, and the appropriate local fixture before the event.
3. During the event, use search, notes and read-only analysis first. Use a mutation, remote operation, decoy, scan or automation only when the event rules and exact target scope authorize it.
4. After the event, promote a technique to the shared `kb/` only if it is reusable, accurate, source-linked and searchable. Keep flags, challenge answers, captures, credentials, private organizer material and team state out of Git.

The presence of a command is not permission to use it. For example, `remote auto`, `apply`, `lockdown`, and `honeypot` are aimed at a declared, team-owned attack/defend host. They are irrelevant to a file-based puzzle and may violate another event's rules. A challenge involving a service also does not by itself authorize scanning or attacking the organizer's platform.

## Repository boundaries

| Location | Include | Exclude |
| --- | --- | --- |
| `tools/ctfctl/`, `profiles/`, `fixtures/`, `drills/` | Rehearsed, broadly useful workflows | One-off challenge-specific automation |
| `kb/` | Short cards that can be found and used under time pressure | A giant speculative corpus or copied proprietary material |
| `events/<event>/` | Public or team-authorized event profile, checklist and links | Live flags, solutions, private email/PDF text, target details |
| Separate optional package | Specialized analyzers with their own tests and dependencies | A second copy of generic case, search and reporting code |
| Ignored local state | Cases, captures, hashes, targets, notes, tokens | Anything that belongs in the tracked repository |

`ctfctl` remains the general CLI. Specialized analyzers can keep their own entry point while they mature. Do not merge two CLIs just to make a monorepo look uniform. When a module has worked in two events, decide whether to share its parser and case model; move it with tests, then remove the duplicate implementation. Generated SQLite indexes stay generated and are rebuilt locally.

## Migration from existing repositories

- **`ashwnn/ctf-buddy`:** keep as the initial core and preserve its history. Its attack/defend and remote features are opt-in, never the default event workflow.
- **`ashwnn/ctf-airplanes`:** retain the source and history. First link its tested aviation-specific analyzers and cards from a local event profile. Move only broadly useful file/PCAP/EVTX/RSA handling after comparing it with existing core capabilities. Keep aviation-specific ARINC/CAN/ATC material in an optional package or event folder. Review licensing and privacy before copying any organizer material into this public repository.
- **Team repository:** inspect access, ownership, existing work and team preferences before moving files. A team-owned repo may remain a coordination space even if each person uses the same field kit.

Migration is complete when one checkout gives a teammate a concise start page, event rules and the relevant tested tools offline, with no duplicated generic commands. It does **not** require merging every historical note or deleting old repos. Archive an old repo only after a teammate can reproduce its useful workflow from the new checkout.

## Time budget

Before an event, prioritize one 30-minute end-to-end drill per likely challenge family and a team handoff drill. Cap new tooling work when it displaces hands-on practice. A useful field kit should be easy to ignore during a challenge that calls for direct reasoning or a familiar tool.
