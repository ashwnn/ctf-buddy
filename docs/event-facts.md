# Event facts, assumptions and unknowns

This file is the single source of truth for **what we know** about the event.
It separates four very different kinds of statement, because treating a guess as
a fact is how a first-time team loses points it did not have to lose.

| Class | Meaning | How it may be used |
|---|---|---|
| **Brief** | Stated in the supplied preparation brief (`docs/raymond-james-ctf-2026-prep.md`) | Plan around it, but do not treat the numbers as official rules |
| **Verified** | Confirmed by an organiser publication, rule page or checker we can read | Safe to rely on |
| **Assumption** | Our engineering decision, made explicit so it can be wrong out loud | Must be re-checked at kickoff |
| **Unknown** | Nobody on the team has evidence | Must be answered before it can change behaviour |

Nothing in this repository copies another competition's answers into this event's
configuration. Other events appear in the corpus only as *technique* evidence, and
every card that does so names the event it came from.

---

## 1. What the brief states (unverified)

| # | Statement | Consequence if true | Consequence if false |
|---|---|---|---|
| B1 | Hybrid format: mini-Jeopardy challenges **and** live attack/defend | Two parallel workstreams must be staffed, not one | Re-plan roles at kickoff |
| B2 | Historically red-heavy with some blue | Offence is where points have come from; defence protects them | A blue-heavier event needs the defensive lane staffed from minute zero |
| B3 | ~18 teams | A crowded scoreboard: small mistakes are visible but recoverable | Scoring density changes; nothing technical changes |
| B4 | One CTF-connected device per member | Each person is an independent operator; no implied shared server | If a shared server is allowed, coordination gets easier |
| B5 | Internet may be limited | Everything must work offline from the first minute | Online references are a bonus, never a dependency |
| B6 | Priority areas: web, PCAP/forensics, attack/defend, RE, scripting, crypto, misc | Corpus and drills are weighted accordingly (see `kb/`) | Corpus is broader than strictly needed; harmless |

**These are brief statements, not official rules.** They are consistent with
public Raymond James coverage of previous years' events (ninth annual event, 2025)
but that coverage does not confirm the 2026 format.

## 2. What is verified

| # | Fact | Source |
|---|---|---|
| V1 | Raymond James has run this event multiple years (ninth annual in 2025) and describes it as a cybersecurity competition with university teams | Raymond James public event coverage, 2025 |
| V2 | The public coverage does **not** publish ticks, scoring weights, checker behaviour, flag formats, network ranges or patch rules | Same source, read for this purpose |
| V3 | Mature attack/defend events differ materially on exactly these parameters — e.g. flag lifetime, tick length, filtering permission and automation permission differ between FAUST, saarCTF, RuCTFE and ENOWARS | Organiser rule pages and event specifications, cited in `sources/manifest.jsonl` |

V3 is the reason this repository refuses to hardcode a tick model: the parameters
that decide how fast a patch must be deployed are event-specific, and guessing
them is worse than measuring them.

## 3. Design assumptions (ours, re-check at kickoff)

| # | Assumption | Why we chose it | How to re-check |
|---|---|---|---|
| A1 | The target hosts are Linux | The brief's toolset (`ss`, `journalctl`, `lsof`, `systemctl`, `iptables`/`nftables`, `diff`) is Linux-oriented | Look at the target at kickoff; `ctfctl discover` reports `os_id` |
| A2 | Services are reachable over TCP from our devices | Standard for attack/defend | `ctfctl discover` listener inventory |
| A3 | We may patch the services we are given | "Patch your own service without breaking it" is in the brief | Confirm in the rules; if patching is restricted, `apply` must not be used |
| A4 | The checker exercises *legitimate* service behaviour, not just liveness | This is the norm for A/D checkers (ENOWARS service/checker tenets, FAUST guidance) | Watch the traffic once ticks start |
| A5 | Our devices can run Python 3.9+ | The toolkit is standard-library Python | `ctfctl doctor` |
| A6 | No API credentials or cloud services are available | Brief says Internet may be limited; credentials are not mentioned | `ctfctl doctor` shows what is missing |
| A7 | Docker is *optional* for the event, required only for our own fixtures | Container inventory is a bonus; fixtures use Compose | `ctfctl doctor` |
| A8 | Two service stacks would cover the realistic middle of a first A/D box: a Python web service behind a proxy, and a PHP web service | Both are common, both have narrow, testable patch shapes | Detection is broader than mutation; see `docs/support-matrix.md` |

## 4. Unknowns to resolve on the day (and how)

Each item below is a question that changes what we do. Until it is answered, the
toolkit stays on the conservative side of it.

| # | Unknown | If unanswered, we do | How to answer it, fast |
|---|---|---|---|
| U1 | **Scoring model**: points for offence, defence, availability (SLA)? Weights? | Assume availability matters; never trade availability for a speculative hardening step | Read the rules/scoreboard page; watch whether our service loses points while up and correct |
| U2 | **Tick length** and checker cadence | Do not time anything to a guessed tick; verify after every change instead | Time two consecutive checker observations |
| U3 | **Flag lifetime** and whether "attack info" (captured flags) is exposed | Do not assume a flag stays valid; re-collect after each tick | Observe where flags appear in our own service and how long submitted ones stay valid |
| U4 | **Checker contract**: which endpoints, which state transitions, whether it writes data | Verify with our own create/read/delete workflow rather than assuming the checker's | Capture checker traffic; diff it against normal traffic (`kb/attack-defend/`) |
| U5 | **Target ranges**: our own hosts, opponent hosts, whether cross-team traffic is in scope | Only ever touch team-owned hosts; opponent interaction stops until ranges are confirmed | Rules page + kickoff briefing; write the answers into `state/targets.json` |
| U6 | **Reset policy**: does the environment reset, when, and does it discard patches? | Keep every patch in Git so it can be replayed; do not rely on a reset | Ask organisers; observe whether a patch survives a tick |
| U7 | **Flag retention** after a service restart or a reset | Assume a restart may lose in-memory flags; prefer patches that do not restart unrelated services | Restart one fixture service and watch what happens to state |
| U8 | **Patch restrictions**: must we patch in place? is a Git-based deploy allowed? is a WAF allowed? | Do only narrow in-place source patches; no filters, no proxies added to scored ports | Rules page; ask explicitly |
| U9 | **Network restrictions**: egress filtering, port scans, exploit automation, rate limits | No scanning, no automation until permitted; observation is read-only and local | Rules page; if a scan is forbidden, discovery stays passive |
| U10 | **AI / external help rules** | Do not use external assistance to solve challenges unless explicitly permitted | Rules page; the offline toolkit is designed so this is not needed |
| U11 | **Decoys / honeypots**: permitted, and on which unused ports/paths | Decoys stay **disabled** | Rules page; `ctfctl decoy enable --ack-rules` requires a named unused port |
| U12 | **"One connected device per member"**: may a member run a local VM? may we use a shared team server? | Assume each member is independent and offline-capable; no shared server | Kickoff briefing — see `docs/team-operations.md` for both cases |
| U13 | **Whether a checker contacts an upstream port directly** (which would make binding it to loopback fatal) | Binding an upstream port to loopback is always `review-only`, never automatic | Capture checker traffic; check whether it ever connects to the upstream port |
| U14 | **Whether the database port is a scored endpoint** | Never remove a database port publication automatically | Same as U13 |

## 5. Standing rules for this repository

1. **Scope.** Tools and drills run only against local fixtures in `fixtures/` and
   targets a teammate has declared in `state/targets.json`. The event name is not
   an authorization scope, and neither is "it looked like ours".
2. **Unknown rule ⇒ dry run.** `ctfctl plan` always works; `ctfctl apply` refuses
   when the target is undeclared or the policy is unacknowledged.
3. **Read-only never needs permission.** Discovery, search, planning and drills
   are unrestricted, so an unanswered question never blocks preparation.
4. **No blanket actions.** No package upgrades, no mass password rotation, no
   firewall flushes, no default-deny, no disabling unknown services, no deleting
   files, no recursive permission changes. See `docs/support-matrix.md` for the
   exact list of what is *not* implemented, and why.
5. **Report honestly.** Tests not run are reported as not run
   (`docs/validation.md`), and container checks never stand in for host firewall
   or SSH validation.
