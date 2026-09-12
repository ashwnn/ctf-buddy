# CTF Offline Corpus and Knowledge Cards

Retrieval date: 2026-09-11

## Scope and normalization rules

This corpus is optimized for a first-time hybrid mini-Jeopardy plus live attack/defend team. The supplied Raymond James preparation brief prioritizes web exploitation, PCAP/forensics, attack/defend service exploitation and patching, then reverse engineering/malware, scripting, crypto/encoding, and unusual challenges. It also assumes Internet access may be limited, so the output is deliberately searchable offline.

Normalization rules used here:

- Primary-source preference: original team/organizer writeups and original maintainer documentation or repository files. Copies/mirrors are not counted separately.
- Unknown reuse rights default to an original summary plus exact link. Public accessibility alone is not redistribution permission.
- GitHub repository-file records use the Git blob SHA returned by GitHub when available. This is not represented as a locally downloaded SHA-256 snapshot. Ordinary web pages therefore have `content_hash: null`.
- Event-specific rules, score weights, flag lifetimes, network layouts, and attack-info APIs stay explicitly event-specific.
- Commands are labeled as `fixture-verified`, `source-reported`, `documentation-derived`, or `operator-derived`. “Fixture-verified” means the command shape was actually exercised in the local build fixture.
- Negative knowledge is retained: failed exploits, partial patches, Docker/VM mismatches, unavailable tools, and unsafe team-specific infrastructure choices are indexed instead of silently removed.

## Local fixture evidence

Fixture-verified in this build environment: `file`, `strings`, `readelf`, `objdump`, strict Base64 decoding, hex decoding, XOR round-trip, Git initial snapshot, removing mutable state from tracking, commit-based patch history, rollback inspection, and `ss -ltnp` syntax.

Not locally available: `tcpdump` and `tshark`. Packet-capture CLI examples are therefore documentation-derived or source-reported, never marked fixture-verified. A local Python HTTP-server bind attempt also failed in this sandbox, so port-to-PID-to-source tracing was not claimed as an end-to-end fixture success.

## Source index

| ID | Source | Author/team | Event/year | Topics | Reuse | Version/stale note |
|---|---|---|---|---|---|---|
| S001 | [Attack/Defense for Beginners](https://2026.faustctf.net/information/attackdefense-for-beginners/) | FAUST organizers | FAUST CTF / 2026 | attack-defend, ticks, SLA, vulnbox | original_summary_and_link (unknown) | FAUST-specific network, preparation period, scoring, and flag mechanics are not assumed for Raymond James. |
| S002 | [Rules](https://2024.faustctf.net/information/rules/) | FAUST organizers | FAUST CTF / 2024 | attack-defend, scoring, SLA, first blood | original_summary_and_link (unknown) | Historical FAUST rules. Scoring weights and mechanics are event-specific and not transplanted. |
| S003 | [CTF Gameserver README](https://github.com/fausecteam/ctf-gameserver/blob/master/README.md) | FAUST CTF gameserver maintainers | FAUST CTF / reusable A/D infrastructure | checker, flags, ticks, service health | permitted_full_text_snapshot (permissive) | The master branch is mutable; pin the recorded blob SHA if snapshotted. Checker semantics are framework-specific. |
| S004 | [[FAUST 2024] Patching infrastructure for attack-defense CTFs](https://maplebacon.org/2024/09/faustctf-patcher/) | JJ / Maple Bacon | FAUST CTF / 2024 | patching, git, rollback, deployment | original_summary_and_link (unknown) | Team-specific workflow. Running a Git account as UID 0 and evaluating push options is intentionally risky and should not be copied blindly. |
| S005 | [A primer on Attack Defense CTFs](https://maplebacon.org/2025/09/maple-attack-defense-primer/) | Aditya Adiraju / Maple Bacon | General A/D primer with FAUST/ENOWARS examples / 2025 | attack-defend, traffic analysis, throwers, patchers | original_summary_and_link (unknown) | General primer mixes common patterns with competition-dependent features such as attack-info APIs and score states. |
| S006 | [ENOWARS 8 Writeup: Attack and Defense](https://jp.security.ntt/insights_resources/tech_blog/enowars-8-writeup-attack-and-defense/) | NTT Security / Team Enu | ENOWARS 8 / 2024 | attack-defend, team operations, service analysis, defense | original_summary_and_link (unknown) | Team Enu experience at ENOWARS 8. Workflow transfers better than exact infrastructure assumptions. |
| S007 | [Welcome to the New Order: A DEF CON 2018 Retrospective](https://dttw.tech/posts/Hka91N-IQ) | Down to the Wire | DEF CON CTF Finals / 2018 | attack-defend, retrospective, services, patching | original_summary_and_link (unknown) | DEF CON finals format was bespoke. Preserve lessons about workload and service reasoning, not its exact scoring or infrastructure. |
| S008 | [Hacking from the Pool: A DEF CON 2021 Retrospective](https://dttw.tech/posts/ByGpq5bgt) | Down to the Wire | DEF CON CTF Finals / 2021 | attack-defend, binary services, retrospective, team workflow | original_summary_and_link (unknown) | DEF CON service and binary-access assumptions are not generic A/D rules. |
| S009 | [I-Hack 2024 Semi-Final Writeup](https://vicevirus.github.io/posts/ihack-2024-semi-final-writeup/) | Vicevirus / Team Kena Paksa | Siber Siaga I-Hack Semi-Final / 2024 | attack-defend, logs, payload recovery, patching | original_summary_and_link (unknown) | Some tactics relied on that event exposing Apache access logs and on time-limited competition conditions. |
| S010 | [Mars University - FAUST CTF 2020 Writeup](https://fluix.one/blog/faust-ctf-2020-marsu/) | Fluix | FAUST CTF / 2020 | web, attack-defend, Django, flags | original_summary_and_link (unknown) | Older Django/service implementation; keep the trust-boundary reasoning, revalidate framework/version details. |
| S011 | [FAUST CTF 2024 - Todo List Writeup](https://czechcyberteam.github.io/posts/faust2024-todolist-writeup/) | Greenscreener / Czech Cyber Team (TeamCalabria) | FAUST CTF / 2024 | web, user-id collision, deserialization, patching | original_summary_and_link (unknown) | Vulnerabilities are service-specific. Generalize the identity-collision and unsafe deserialization patterns, not exploit constants. |
| S012 | [Writeup: SaarCTF 2025 - Routerploit](https://www.thomasweigold.de/blog/2025/writeup-saarctf/) | Thomas Weigold / Squareroots | SaarCTF / 2025 | web, IDOR, predictable token, patching | original_summary_and_link (unknown) | Specific PHP parameters and PRNG construction are service-specific. The “change seed” patch is retained as an event example, not recommended cryptography. |
| S013 | [FAUST CTF 2025](https://oneman.party/blog/20250927_faustctf/) | OneManParty | FAUST CTF / 2025 | attack-defend, pcap analyzer, automation, parallelism | original_summary_and_link (unknown) | Solo-player tooling and Cera behavior reflect one participant’s setup and may not transfer directly to a team environment. |
| S014 | [home_r00ter](https://molteniluca.github.io/posts/homerooter/) | Luca Molteni with Kien Tuong Truong | CyberChallenge.IT A/D / 2020 | physical, router, command injection, reverse engineering | original_summary_and_link (unknown) | Hardware/router environment is unusual and event-specific; preserve scope-splitting and physical/service debugging lessons. |
| S015 | [ENOWARS9](https://stoffregen.io/posts/enowars9/) | Stoffregen / ENOFLAG service author | ENOWARS 9 / 2025 | organizer, service design, attack-defend, AI service | original_summary_and_link (unknown) | Organizer/service-author perspective for one ENOWARS9 service. Vulnerability prevalence is not a universal difficulty ranking. |
| S016 | [Service & Checker Tenets](https://github.com/enowars/specification/blob/main/service_checker_tenets.md) | ENOFLAG / ENOWARS maintainers | ENOWARS infrastructure specification | checker, service health, flags, patchability | permitted_full_text_snapshot (permissive) | Specification can evolve. Pin the blob SHA and treat MUST/SHOULD requirements as ENOWARS design requirements. |
| S017 | [EnoEngine README](https://github.com/enowars/EnoEngine/blob/master/README.md) | ENOFLAG / ENOWARS maintainers | ENOWARS infrastructure | rounds, flag validity, checker API, scoreboard | permitted_full_text_snapshot (permissive) | README references older .NET SDK details and is framework-specific. Pin blob SHA; do not assume port 1337 or statuses elsewhere. |
| S018 | [CyberAlchemist README](https://github.com/enowars/enowars3-service-cyber-alchemist/blob/master/README.md) | ENOFLAG / CyberAlchemist service authors | ENOWARS 3 / 2019 | web, RCE, pickle, dynamic dispatch | permitted_full_text_snapshot (permissive) | Python/Flask/Gunicorn service from ENOWARS 3. Patterns remain useful; exact endpoints and exploit behavior are historical. |
| S019 | [Buggy service README](https://github.com/enowars/enowars4-service-buggy/blob/master/README.md) | ENOFLAG / Buggy service authors | ENOWARS 4 / 2020 | web, predictable token, auth logic, flags | permitted_excerpt (permissive) | Go/MySQL service is historical; exact “48 hashes” behavior and patches are challenge-specific. |
| S020 | [saarCTF 2024 README](https://github.com/saarsec/saarctf-2024/blob/master/README.md) | saarsec | saarCTF / 2024 | checkers, services, exploits, environment mismatch | original_summary_and_link (unknown) | Demo checker/exploit instructions are challenge-specific. Notably, one Rent-a-Printer exploit requires the full VM because cups-browsed does not start in Docker. |
| S021 | [Stay ~/ CTF 2022 README](https://github.com/C4T-BuT-S4D/stay-home-ctf-2022/blob/master/README.md) | C4T BuT S4D | Stay ~/ CTF / 2022 | attack-defend, services, checkers, sploits | permitted_full_text_snapshot (permissive) | Historical services span Rust/Go/C++/Python/Node/Java/Bash. Use as breadth seed rather than assuming modern framework behavior. |
| S022 | [Insecure direct object references (IDOR)](https://portswigger.net/web-security/access-control/idor) | PortSwigger Web Security Academy | maintainer docs | web, IDOR, access control, object references | original_summary_and_link (unknown) | Training examples explain the class, not event-specific endpoints. Browser/lab UI may change. |
| S023 | [Path traversal](https://portswigger.net/web-security/file-path-traversal) | PortSwigger Web Security Academy | maintainer docs | web, path traversal, file read, canonicalization | original_summary_and_link (unknown) | Use techniques only in authorized CTF targets. Framework/platform path semantics vary. |
| S024 | [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) | PortSwigger Web Security Academy | maintainer docs | web, SSRF, internal services, trust boundary | original_summary_and_link (unknown) | Cloud metadata and URL-parser behaviors vary; do not hard-code historical bypasses as universal. |
| S025 | [OS command injection](https://portswigger.net/web-security/os-command-injection) | PortSwigger Web Security Academy | maintainer docs | web, command injection, blind injection, OS commands | original_summary_and_link (unknown) | Command separators and shell behavior depend on target OS/shell. Authorized CTF context only. |
| S026 | [Following Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html) | Wireshark project | Wireshark User’s Guide | pcap, TCP, HTTP, stream reconstruction | original_summary_and_link (unknown) | UI labels and supported stream types vary by Wireshark version; keep CLI alternatives indexed. |
| S027 | [Exporting Objects](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html) | Wireshark project | Wireshark User’s Guide | pcap, object export, HTTP, file recovery | original_summary_and_link (unknown) | Object-export support is protocol/dissector dependent and does not guarantee byte-identical original files in every capture. |
| S028 | [tshark(1) Manual Page](https://www.wireshark.org/docs/man-pages/tshark.html) | Wireshark project | TShark documentation | pcap, CLI, follow stream, fields | original_summary_and_link (unknown) | Option set changes across Wireshark/TShark releases. Pin local tool version in event kit. |
| S029 | [File Analysis Framework](https://docs.zeek.org/en/v8.1.1/frameworks/file-analysis.html) | Zeek project | Zeek documentation | pcap, file analysis, hashing, extraction | original_summary_and_link (unknown) | Version-pinned to Zeek 8.1.1. Event laptop may ship an older Zeek; test scripts locally. |
| S030 | [ss(8) - another utility to investigate sockets](https://man7.org/linux/man-pages/man8/ss.8.html) | iproute2 maintainers; rendered by man7.org | iproute2 manual | linux, ports, sockets, process discovery | original_summary_and_link (unknown) | Process display requires permissions and kernel/process visibility. Exact output columns vary by iproute2 version. |
| S031 | [Introduction to Ghidra Student Guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html) | NSA Ghidra project | Ghidra training documentation | reverse engineering, strings, xrefs, decompiler | permitted_excerpt (permissive) | UI details can change between Ghidra releases. Index concepts and hot paths, not screenshots. |
| S032 | [Examining Memory](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory.html) | GNU GDB project | GDB documentation | reverse engineering, debugging, memory, x command | original_summary_and_link (unknown) | Target architecture and GDB build affect formats, sizes, and available features. |
| S033 | [olevba](https://github.com/decalage2/oletools/wiki/olevba) | Philippe Lagadec / oletools | oletools documentation | malware, VBA, macros, IOC extraction | original_summary_and_link (permissive) | Macro heuristics and supported formats evolve. Prefer installed `olevba --help` for exact flags. |
| S034 | [oleobj](https://github.com/decalage2/oletools/wiki/oleobj) | Philippe Lagadec / oletools | oletools documentation | malware, OLE, embedded objects, file extraction | original_summary_and_link (permissive) | Embedded-object support and output names can change across oletools versions. |
| S035 | [CyberChef Magic operation source](https://github.com/gchq/CyberChef/blob/master/src/core/operations/Magic.mjs) | GCHQ CyberChef maintainers | maintainer docs | encoding, triage, XOR, file type | permitted_full_text_snapshot (permissive) | Magic is heuristic/speculative execution, not a proof of encoding or encryption. Master is mutable; pin blob SHA. |
| S036 | [Flash CTF - Key Evidence](https://metactf.com/blog/flash-ctf-key-evidence/) | MetaCTF | Flash CTF / 2026 | pcap, USB HID, keyboard, forensics | original_summary_and_link (unknown) | Challenge writeup assumes a particular USB keyboard report structure. Keep field-extraction logic conditional on descriptor/layout. |
| S037 | [ordinary-keyboard - snakeCTF 2024 Quals Writeup](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard) | snakeCTF organizers | snakeCTF 2024 Quals / 2024 | USB HID, nonstandard descriptor, pcap, base32 | original_summary_and_link (unknown) | The challenge deliberately used a non-standard HID report descriptor; standard keyboard decoders can fail by design. |
| S038 | [CryptoHack Introduction course](https://www.cryptohack.org/courses/intro/) | CryptoHack maintainers | CryptoHack | crypto, encoding, hex, base64 | original_summary_and_link (unknown) | Educational exercises teach primitives, not a classifier for arbitrary blobs. Do not treat every opaque string as crypto. |

## Knowledge cards

64 normalized cards. Search aliases intentionally include terse phrases a teammate might type under time pressure.

### AD-001 - Identify the tick, checker, flag-validity and SLA model before optimizing
- Category: `attack-defend`
- Tags: `ticks`, `SLA`, `scoring`, `flags`
- Search aliases: how do ticks work, flag lifetime, sla rules, what loses points
- Symptoms: You have a live service and flags but do not yet know what “healthy”, “old”, or “scoreable” means.
- Stack assumptions: A/D games usually have periodic checks and short-lived flags, but exact states, lifetimes, and score weights are event-specific.
- Prerequisites: Organizer rules, scoreboard/status page, attack-info/flag-submission documentation if provided.
- First action: Write a one-screen event facts note: tick length, checker states, flag lifetime, submission interface, downtime penalty, and whether attack-info exists. Mark every unknown.
- Command placeholders / evidence: none required.
- Expected output / interpretation: The team can distinguish universal workflow from event rules and will not design automation around FAUST/ENOWARS-specific assumptions.
- Failure branch: If organizer material is incomplete, observe one or two ticks and record behavior rather than borrowing another event’s rules.
- Impact / rollback: Low operational risk; prevents scoring-model mistakes.
- Sources / reuse: [S001], [S002], [S017]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized; no commands

### AD-002 - Snapshot the service before the first edit
- Category: `attack-defend`
- Tags: `baseline`, `rollback`, `source-review`
- Search aliases: save original service, baseline before patch, snapshot vulnbox
- Symptoms: Service code has just been released or mounted and teammates are about to patch it.
- Stack assumptions: You can read the service tree and have enough local storage for a source/config snapshot.
- Prerequisites: Know which paths contain mutable runtime data, secrets, databases, uploads, or logs.
- First action: Capture file list, hashes where cheap, listening ports, process tree, and an initial Git commit of code/config only. Exclude mutable data before normal work begins.
- Command placeholders / evidence:
  - `git init && git add . && git commit -m "initial commit"` - fixture-verified command shape
  - `git rm -r --cached <mutable-dir>/ && printf "%s/\n" <mutable-dir> >> .gitignore` - fixture-verified command shape
- Expected output / interpretation: You have a known-good code baseline and a fast path to compare or revert later.
- Failure branch: If Git sees constant dirty state, identify generated/runtime paths and untrack them before using push-based patching.
- Impact / rollback: Do not commit secrets or live flag databases into a shared repo.
- Sources / reuse: [S004]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: local fixture verified Git baseline/untrack pattern

### AD-003 - Map a listening port to the owning process and source route
- Category: `attack-defend`
- Tags: `enumeration`, `linux`, `ports`, `process`
- Search aliases: what owns port 8080, find process behind port, port to source code, service route behind port
- Symptoms: A checker or scan exposes a TCP/UDP port, but the service directory/entrypoint is unclear.
- Stack assumptions: Linux vulnbox; process metadata is visible to your user/root.
- Prerequisites: Shell access to your own authorized vulnbox.
- First action: Start at socket -> PID/program -> command line -> cwd/executable -> unit/container -> config/routes. Do not grep the whole filesystem first.
- Command placeholders / evidence:
  - `ss -ltnp` - fixture-verified syntax; process mapping not fully reproduced in fixture
  - `tr "\0" " " < /proc/<pid>/cmdline; readlink /proc/<pid>/cwd; readlink /proc/<pid>/exe` - operator-derived, not locally end-to-end verified
  - `systemctl status <unit> || docker ps --no-trunc` - operator-derived
- Expected output / interpretation: Within minutes you should know what binary/interpreter accepts the port and where its source/config lives.
- Failure branch: If `ss -p` omits process data, rerun with appropriate privileges, inspect containers/net namespaces, or use `lsof -i :<port>` if available.
- Impact / rollback: Read-only enumeration. Avoid restarting anything until the checker baseline is understood.
- Sources / reuse: [S030], [S003]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: ss syntax fixture-verified; remaining chain operator-derived

### AD-004 - Read the checker before broad patching when it is available
- Category: `attack-defend`
- Tags: `checker`, `SLA`, `source-review`
- Search aliases: checker code, what does sla test, service health tests
- Symptoms: You found a vulnerability but do not know which behavior must remain intact.
- Stack assumptions: Checker source/demo checker is provided, or a local checker can be run.
- Prerequisites: Ability to read or execute the checker against your local/service instance.
- First action: Trace putflag/getflag and havoc/noise or equivalent paths. Extract required routes, expected state transitions, persistence duration, and timeouts before changing behavior.
- Command placeholders / evidence:
  - `PYTHONPATH=.. python3 <service-checker>.py <ip>` - source-reported shape from saarCTF; adapt to event
- Expected output / interpretation: A small contract list: features the checker touches, required persistence, and obvious filter/timeout constraints.
- Failure branch: If checker source is hidden, infer contract by baseline traffic/logs and controlled local requests; label it inferred.
- Impact / rollback: Read-only unless you run a local checker. Never modify organizer checker code as a “fix”.
- Sources / reuse: [S016], [S020], [S003]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-reported and source-synthesized

### AD-005 - Keep mutable service state out of the patch repository
- Category: `attack-defend`
- Tags: `git`, `patching`, `state`
- Search aliases: git remote rejected, uncommitted database, patch repo dirty, mutable data git
- Symptoms: Every tick/request changes files, Git is always dirty, or pushes to a working-tree remote are rejected.
- Stack assumptions: Patch workflow tracks the live service tree with Git.
- Prerequisites: Baseline repository and list of runtime state directories/files.
- First action: Untrack databases/uploads/cache/log state while preserving them on disk. Commit ignore rules separately from code patches.
- Command placeholders / evidence:
  - `git rm -r --cached data/ && printf "data/\n" >> .gitignore && git add .gitignore && git commit -m "do not track mutable data"` - fixture-verified; source concept S004
- Expected output / interpretation: `git status` reflects code/config edits rather than normal service activity.
- Failure branch: If the runtime writes inside the source tree unpredictably, isolate only known generated paths; do not blanket-ignore directories containing executable code.
- Impact / rollback: Incorrect ignores can hide attacker modifications; inspect ignore rules during incident review.
- Sources / reuse: [S004]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: fixture-verified

### AD-006 - Patch the narrow trust-boundary check, not the whole feature
- Category: `attack-defend`
- Tags: `patching`, `authorization`, `SLA`
- Search aliases: smallest patch, patch without breaking sla, narrow fix
- Symptoms: A route accepts attacker-controlled identity/path/action data that crosses a trust boundary.
- Stack assumptions: You know the concrete vulnerable comparison or sink and the checker-required behavior.
- Prerequisites: One reproducible exploit and one normal checker/user flow.
- First action: Change the smallest condition that re-establishes server-side authority, then immediately run both exploit and normal-flow tests.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Exploit fails for the original reason; legitimate behavior still passes. Diff remains reviewable under pressure.
- Failure branch: If the checker fails, revert and refine. Avoid “disable endpoint”, blanket deny, or schema changes unless the checker contract permits them.
- Impact / rollback: A narrow patch lowers regression risk but may miss alternate paths; continue traffic/code review after deployment.
- Sources / reuse: [S012], [S016], [S019]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### AD-007 - Prove a patch with the checker, not with one curl request
- Category: `attack-defend`
- Tags: `regression`, `checker`, `SLA`
- Search aliases: patch works but checker down, mumble after patch, prove service still works
- Symptoms: Your exploit stopped working, but service score/health is unknown.
- Stack assumptions: Checker or equivalent functional tests can be run, and some flags/state span multiple rounds.
- Prerequisites: Known pre-patch baseline and the patch commit.
- First action: Run checker/functional tests after patch; include store/retrieve and old-state retrieval where the game requires it. Record result before deploying broadly.
- Command placeholders / evidence:
  - `<checker command> <local-or-vulnbox-ip>` - event-specific/source-reported template
- Expected output / interpretation: Exploit is denied while core features, persistence, and prior flags remain retrievable.
- Failure branch: If current-round checks pass but old data fails, investigate migrations/state deletion/restart behavior before keeping the patch.
- Impact / rollback: Checker failures can cost SLA/defense. Roll back quickly if functional loss outweighs temporary exposure.
- Sources / reuse: [S016], [S017], [S020], [S005]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized; checker command event-specific

### AD-008 - Rollback a bad patch by commit, not by memory
- Category: `attack-defend`
- Tags: `rollback`, `git`, `patching`
- Search aliases: undo patch fast, revert broken service, bad patch rollback
- Symptoms: Service goes OFFLINE/FAULTY/MUMBLE immediately after a patch.
- Stack assumptions: Each patch was committed independently and runtime state is not tracked.
- Prerequisites: Known-good commit and deployment/restart command.
- First action: Revert/reset to the last known-good code commit, redeploy, re-run checker, then investigate the failed diff offline.
- Command placeholders / evidence:
  - `git log --oneline -n 5; git diff <good>..<bad>` - operator-derived
  - `git revert <bad-commit>` - operator-derived safe history-preserving option
  - `git show HEAD^:app.txt` - fixture-verified rollback inspection pattern
- Expected output / interpretation: Service health returns without reconstructing edits by hand.
- Failure branch: If state/schema changed, code rollback alone may not recover data; restore only from a known event-allowed state backup.
- Impact / rollback: Avoid destructive `reset --hard` on live state unless you have deliberately isolated tracked code from data.
- Sources / reuse: [S004]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: Git rollback inspection fixture-verified; deployment event-specific

### AD-009 - Turn a confirmed exploit into a tick-aware thrower only after correctness
- Category: `attack-defend`
- Tags: `automation`, `thrower`, `flags`
- Search aliases: run exploit every tick, attack all teams, flag submit loop
- Symptoms: A manual exploit reliably retrieves fresh flags from one target.
- Stack assumptions: Event rules allow automated attacks and provide target/team/attack-info data.
- Prerequisites: Manual exploit is deterministic, bounded, and logs target/result without destructive side effects.
- First action: Separate target enumeration, exploit execution, flag validation/dedup, and submission. Add per-target timeout and a kill switch before parallelism.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Automation can rerun within the flag-validity window without wedging on one target or resubmitting the same result endlessly.
- Failure branch: If flag lifetime/attack-info semantics are unknown, keep manual or dry-run mode until confirmed. Do not infer ENOWARS/FAUST endpoints.
- Impact / rollback: High traffic can break services or violate rules; bound concurrency and requests.
- Sources / reuse: [S005], [S017], [S013]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized; no event endpoint assumed

### AD-010 - Treat flag lifetime and attack-info as event data, not universal A/D behavior
- Category: `attack-defend`
- Tags: `flags`, `attack-info`, `event-specific`
- Search aliases: where are flag ids, attack info json, old flag rejected
- Symptoms: An exploit needs per-team/per-tick identifiers or starts returning stale/old flags.
- Stack assumptions: Some games expose attack info and finite flag validity; others do not.
- Prerequisites: Organizer-provided API/docs or observed submission responses.
- First action: Cache only the minimum required identifier history and tag each value with team, service/store, and tick. Expire it using confirmed event rules.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Exploit inputs match the flag store/tick they target; stale data is not mistaken for a broken exploit.
- Failure branch: If no attack-info endpoint exists, derive identifiers from public service behavior/source rather than inventing one.
- Impact / rollback: Wrong assumptions waste offense time and can flood services.
- Sources / reuse: [S005], [S017]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized with explicit event-specific caveat

### AD-011 - Capture inbound service traffic continuously when rules permit
- Category: `attack-defend`
- Tags: `pcap`, `monitoring`, `traffic`
- Search aliases: capture attacks, watch incoming exploits, pcap defense
- Symptoms: Other teams are attacking but logs/source review are not revealing the vector.
- Stack assumptions: Rules permit capture on your vulnbox/interface and traffic is visible before encryption terminates elsewhere.
- Prerequisites: Disk budget and interface/port list.
- First action: Capture bounded rotating PCAPs per service/tick or use organizer-provided captures. Preserve timestamps and service mapping.
- Command placeholders / evidence:
  - `tcpdump -n -i <iface> -s0 -w <service>-<tick>.pcap <filter>` - source/doc-derived; tcpdump unavailable in local fixture
- Expected output / interpretation: You can correlate a suspicious request to the relevant service and replay/analyze it later.
- Failure branch: If traffic is TLS-encrypted and keys are unavailable, pivot to reverse-proxy/app logs, metadata, or service-side instrumentation.
- Impact / rollback: Captures may contain flags/secrets; keep them team-private and rotate/delete per event policy.
- Sources / reuse: [S005], [S007]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized; capture command not locally tested

### AD-012 - Reconstruct an observed HTTP exploit from a capture
- Category: `attack-defend`
- Tags: `pcap`, `HTTP`, `replay`
- Search aliases: rebuild request from pcap, copy exploit from traffic, http request from capture
- Symptoms: A suspicious PCAP contains an HTTP transaction that differs from normal checker traffic.
- Stack assumptions: HTTP is visible or decrypted and request boundaries can be reconstructed.
- Prerequisites: PCAP, target route, and a safe local copy of the service if possible.
- First action: Follow the conversation, recover method/path/query/headers/cookies/body in order, then reproduce against your own service with the smallest client possible.
- Command placeholders / evidence:
  - `tshark -r <pcap> -Y "http.request" -T fields -e frame.number -e ip.src -e tcp.stream -e http.request.method -e http.host -e http.request.uri` - doc-derived; tshark unavailable in fixture
  - `tshark -r <pcap> -q -z follow,http,ascii,<stream>` - doc-derived from TShark follow support; exact local version untested
- Expected output / interpretation: A replayable request demonstrates the same unauthorized behavior/flag access on your controlled service.
- Failure branch: If the app is not decoded as HTTP, follow TCP bytes and inspect framing manually; HTTP/2, WebSockets, compression, or custom protocols need protocol-specific handling.
- Impact / rollback: Never replay destructive traffic against third parties outside the CTF game network.
- Sources / reuse: [S026], [S028], [S005], [S007]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: doc-derived, not locally tested

### AD-013 - Replay suspicious traffic against a local/owned instance before reflecting it
- Category: `attack-defend`
- Tags: `replay`, `validation`, `traffic`
- Search aliases: test captured exploit, replay pcap, confirm attack payload
- Symptoms: Traffic looks exploit-like but intent/effect is uncertain.
- Stack assumptions: You have an owned test/vulnbox instance and rules permit replay internally.
- Prerequisites: Reconstructed application request plus baseline state.
- First action: Replay once on a controlled instance, compare response/state/logs, and only then label it exploit, scanner noise, checker, or failed attempt.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Evidence ties request to a concrete security effect rather than a suspicious string alone.
- Failure branch: If exact state is required, clone minimal prerequisite state or instrument the vulnerable function instead of mutating production flags.
- Impact / rollback: Avoid automatic reflection until semantics and event rules are understood.
- Sources / reuse: [S007], [S005]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### AD-014 - Diff suspicious traffic against normal checker traffic
- Category: `attack-defend`
- Tags: `pcap`, `diff`, `checker`
- Search aliases: attack vs checker, which request is exploit, pcap anomaly
- Symptoms: Hundreds of requests per tick make manual inspection impractical.
- Stack assumptions: You can identify at least some normal checker/user conversations.
- Prerequisites: Normalized requests grouped by service/route or protocol message type.
- First action: Cluster by route/message shape, then rank rare parameter names, lengths, methods, bodies, status changes, and state effects. Use rarity to triage, not to prove maliciousness.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A short list of conversations worth source-code tracing, with clear baseline differences.
- Failure branch: If checker deliberately uses unusual/malicious-looking inputs, whitelist by behavior/source rather than payload string.
- Impact / rollback: Overaggressive anomaly filters can hide slow/common-looking exploits.
- Sources / reuse: [S007], [S016], [S005]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### AD-015 - Use traffic to detect patch bypasses
- Category: `attack-defend`
- Tags: `patch-bypass`, `pcap`, `defense`
- Search aliases: they bypassed patch, exploit still works, new payload after patch
- Symptoms: Defense score drops after a patch that blocked the original PoC.
- Stack assumptions: Inbound traffic is captured and patch deployment time is known.
- Prerequisites: Pre-patch exploit signature and post-patch captures.
- First action: Compare new successful/suspicious requests to the original exploit. Trace changed parameter, encoding, alternate route, or sink to source before making another patch.
- Command placeholders / evidence: none required.
- Expected output / interpretation: You learn whether attackers found an alternate path or simply re-encoded the same trust-boundary failure.
- Failure branch: If no suspicious traffic is visible, consider a second vulnerability/flag store or checker/state failure before patching again.
- Impact / rollback: Do not stack speculative patches; keep each diff attributable and reversible.
- Sources / reuse: [S005], [S007]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### AD-016 - Mine service logs for attacker payloads when packet capture is absent
- Category: `attack-defend`
- Tags: `logs`, `payload recovery`, `web`
- Search aliases: find exploit in apache log, recover attacker command, payload from logs
- Symptoms: You were exploited but have web/server logs rather than PCAP.
- Stack assumptions: Requests or relevant parameters are logged without destructive truncation/escaping.
- Prerequisites: Access/application logs and timestamp of suspected attack.
- First action: Filter around the score-loss/timestamp; compare rare routes/status/lengths; preserve the raw log before decoding URL/base encodings.
- Command placeholders / evidence:
  - `grep -nE "<route|status|marker>" <access-log>` - operator-derived; source reports log recovery concept
- Expected output / interpretation: A concrete request/payload can be traced to the vulnerable code path or replayed on an owned instance.
- Failure branch: If logs encode/truncate bodies, pivot to reverse-proxy logs, application debug logs, or captures. Do not assume source IP attribution is stable behind game proxies.
- Impact / rollback: Logs may contain flags and attacker payloads. Keep private.
- Sources / reuse: [S009]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-reported concept; command operator-derived

### AD-017 - Recognize client-supplied identity overriding session identity
- Category: `attack-defend`
- Tags: `IDOR`, `identity`, `trust-boundary`
- Search aliases: user_guid override, id parameter shows other user, invoice idor
- Symptoms: Authenticated route accepts `user_id`, `user_guid`, username, account ID, or similar and returns another user’s object.
- Stack assumptions: Server has an authenticated identity but also trusts an object-owner identity from the request.
- Prerequisites: Two test accounts or source code showing both identity sources.
- First action: Change only the client-supplied identity while keeping the same session. If ownership changes, trace where the request value overrides/competes with session identity.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A minimal proof shows session A reading object B by changing one identifier.
- Failure branch: If the identifier merely selects a public object, confirm expected authorization semantics before calling it IDOR.
- Impact / rollback: Patch should bind object authorization to server-side session identity, not hide the parameter.
- Sources / reuse: [S012], [S022]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific example plus general class

### AD-018 - Spot predictable authorization codes built from weakly seeded PRNGs
- Category: `attack-defend`
- Tags: `PRNG`, `token`, `auth`
- Search aliases: predict auth code, same token after restart, weak random
- Symptoms: Authorization codes repeat, form a small space, or can be predicted after observing related output.
- Stack assumptions: Security decision depends on deterministic/predictable pseudo-random output rather than a cryptographic generator.
- Prerequisites: Source or enough samples to identify seed/state relationship.
- First action: Trace generator initialization and every exposed output. Model predictability locally before spending time brute forcing network endpoints.
- Command placeholders / evidence: none required.
- Expected output / interpretation: You can explain which observed value reveals or constrains future authorization material.
- Failure branch: Do not “fix” by changing a constant seed. Replace the security-token construction with a cryptographically secure primitive if checker compatibility permits.
- Impact / rollback: Changing token semantics can break stored state/checker expectations; regression-test first.
- Sources / reuse: [S012], [S018]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific patterns

### AD-019 - Treat identity collisions as an authorization primitive failure
- Category: `attack-defend`
- Tags: `collision`, `user-id`, `authorization`
- Search aliases: same user id, account collision, todo list flags
- Symptoms: Different registrations can receive the same/overlapping internal identifier or attacker can influence identifier derivation.
- Stack assumptions: Object access is keyed by that identifier and ownership checks assume uniqueness.
- Prerequisites: Registration path, ID derivation, and object lookup code.
- First action: Determine collision domain and whether attacker-controlled inputs reduce it. Create two controlled identities that collide, then inspect cross-account object access.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Collision, not password compromise, explains the data leak.
- Failure branch: If collision only affects display/cache keys, confirm it reaches an authorization/data lookup boundary before prioritizing.
- Impact / rollback: Patching ID generation may not repair already-colliding records; checker/state migration risk exists.
- Sources / reuse: [S011]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-020 - Flag unsafe polymorphic deserialization in service code
- Category: `attack-defend`
- Tags: `deserialization`, `.NET`, `RCE`
- Search aliases: TypeNameHandling, newtonsoft rce, deserialize attacker json
- Symptoms: Service deserializes attacker-controlled structured data with type metadata/polymorphism enabled.
- Stack assumptions: Runtime can instantiate attacker-selected types or invoke dangerous object graphs.
- Prerequisites: Source/config showing serializer settings and input boundary.
- First action: Trace from request body to deserializer. Identify whether allowed types are constrained. Prefer disabling type-name-driven construction or explicit allowlisting compatible data models.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Untrusted input can no longer select arbitrary runtime types while legitimate serialized objects still parse.
- Failure branch: A superficial content-type or string filter is fragile. If checker submits polymorphic legitimate data, build a precise allowlist.
- Impact / rollback: Deserializer changes may break persisted objects; test old-state retrieval.
- Sources / reuse: [S011]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-021 - Look for empty/default user objects after failed database operations
- Category: `attack-defend`
- Tags: `auth`, `logic`, `Go`
- Search aliases: empty user authenticated, failed insert still true, all users leak
- Symptoms: Authentication succeeds after failed registration/insert, or session user fields are empty/default.
- Stack assumptions: Application treats operation success boolean/result incorrectly and later authorization logic special-cases empty identity.
- Prerequisites: Registration/login code, DB return values, and protected handler.
- First action: Force a controlled failure path and inspect whether a session is still created. Trace default values into authorization comparisons.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A failed DB operation can be tied to an authenticated/default identity that widens access.
- Failure branch: If failure path cannot be safely triggered, reason from source and unit-test the function locally.
- Impact / rollback: Fix error propagation first; then simplify authorization condition. Run checker and normal login tests.
- Sources / reuse: [S019]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-022 - Recognize timestamp-derived or tiny-space object hashes
- Category: `attack-defend`
- Tags: `hash`, `predictable-id`, `bruteforce`
- Search aliases: guess ticket hash, order hash timestamp, small token space
- Symptoms: Object URLs use hashes/tokens that appear unique but are built from public username/time or a tiny variant set.
- Stack assumptions: Hash input entropy is low and attacker can bound creation time or enumerate related usernames.
- Prerequisites: Source for token construction or sample tokens with known creation times.
- First action: Recreate the hash function locally across a bounded time window; do not network brute-force until the model matches known samples.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Candidate generation reproduces a known token and reveals a feasible object enumeration path.
- Failure branch: If unknown salt/server secret is involved, stop treating it as predictable and move to another hypothesis.
- Impact / rollback: Patch token construction with random unguessable identifiers while preserving lookup behavior expected by checker.
- Sources / reuse: [S019]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-023 - Find dynamic function dispatch crossing from strings to executable callables
- Category: `attack-defend`
- Tags: `RCE`, `dynamic-dispatch`, `Python`
- Search aliases: getattr globals rce, function name from request, dynamic method exploit
- Symptoms: Service accepts operation/module/method names from users and dynamically resolves/calls them.
- Stack assumptions: Resolution reaches broad namespaces/objects rather than a fixed registry of intended operations.
- Prerequisites: Source search for `getattr`, `globals`, reflection, dynamic import, or equivalent.
- First action: Trace allowed input to resolved callable. Replace broad namespace lookup with an explicit mapping/allowlist of intended functions.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Unexpected functions/classes are no longer reachable through user-provided names; intended recipe/actions still run.
- Failure branch: If dynamic behavior is core to checker functionality, allowlist at the narrowest semantic layer rather than disabling recipes/plugins.
- Impact / rollback: RCE risk is high; patch promptly but regression-test complex workflows.
- Sources / reuse: [S018]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-024 - Treat untrusted pickle import as code execution, not data parsing
- Category: `attack-defend`
- Tags: `pickle`, `RCE`, `Python`
- Search aliases: pickle upload rce, unsafe import recipe, deserialize file
- Symptoms: Python service accepts uploaded/imported pickle data from untrusted users.
- Stack assumptions: Standard pickle semantics can execute constructors/reducers during unpickling.
- Prerequisites: Source path from upload/import to `pickle.load(s)`.
- First action: Remove untrusted pickle as an interchange format or enforce a safe explicit schema. In CTF patching, first identify the minimum checker-required fields and replace the import path narrowly.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Malicious object construction path disappears while required imported data still works.
- Failure branch: Filtering byte patterns/classes is not a robust generic pickle sandbox. If format cannot change mid-game, isolate/disable only the untrusted import feature if checker allows.
- Impact / rollback: Potential RCE; validate checker before deployment.
- Sources / reuse: [S018]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-025 - Treat exposed PRNG state as future-secret disclosure
- Category: `attack-defend`
- Tags: `PRNG`, `state-leak`, `prediction`
- Search aliases: random getstate leak, predict names, python random state
- Symptoms: Endpoint/debug feature exposes internal pseudo-random generator state or enough raw output to recover it.
- Stack assumptions: Future security-relevant identifiers use the same deterministic generator.
- Prerequisites: Source linking exposed state/output to identifier generation.
- First action: Reproduce the generator locally, set/recover state from controlled output, and predict a known subsequent identifier before targeting flags.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Prediction matches server-generated names/tokens, proving state linkage.
- Failure branch: If identifiers use a separate cryptographic generator, state leak may be irrelevant; map generator instances precisely.
- Impact / rollback: Fix by separating non-security randomness from secret/token generation and removing state exposure.
- Sources / reuse: [S018]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-specific pattern

### AD-026 - Preserve failed and partial techniques as negative knowledge
- Category: `attack-defend`
- Tags: `failure`, `triage`, `retrospective`
- Search aliases: did not work, dead end, event-specific exploit
- Symptoms: Team is repeating an approach another team/writeup already found ineffective or environment-dependent.
- Stack assumptions: Failure conditions are documented with enough context to recognize them.
- Prerequisites: Corpus card has explicit assumptions and failure branch.
- First action: Index failure terms alongside success terms: “no one exploited”, “partial patch”, “Docker exploit fails/full VM works”, “backdoor not executed in time”.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Search results explain not just what to try but when to stop or change environment.
- Failure branch: Do not convert one team’s failure into impossibility; label confidence and event context.
- Impact / rollback: Low risk; saves time and prevents folklore from becoming universal advice.
- Sources / reuse: [S004], [S009], [S020]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized from documented failures

### WEB-001 - Test IDOR with two identities and one object
- Category: `web`
- Tags: `IDOR`, `access-control`
- Search aliases: idor, change id get other user, object id auth
- Symptoms: Authenticated endpoint references an object by ID/filename/key in URL/body.
- Stack assumptions: Object is supposed to be user/role-scoped.
- Prerequisites: Two test users or one user plus known foreign object ID.
- First action: Request your object, then change only the object reference to the other controlled user’s object while retaining the same session.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Unauthorized object data/action succeeds with no credential change.
- Failure branch: If response differs only because object is public/shared, inspect intended policy before escalating.
- Impact / rollback: Patch authorization on the server-side object lookup, not by obscuring identifiers.
- Sources / reuse: [S022], [S012]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-002 - Identify competing sources of authority in one request
- Category: `web`
- Tags: `trust-boundary`, `auth`, `IDOR`
- Search aliases: session vs parameter, who is the user, authority mismatch
- Symptoms: Handler has session identity plus request-supplied user/account/tenant fields.
- Stack assumptions: Developer may use the wrong identity at lookup or authorization time.
- Prerequisites: Route source and one authenticated request.
- First action: Mark each identity-bearing value as server-derived, session-derived, database-derived, or attacker-controlled. Follow which one reaches the resource lookup and final authorization check.
- Command placeholders / evidence: none required.
- Expected output / interpretation: You can point to a specific boundary where attacker-controlled authority replaces trusted identity.
- Failure branch: If request identity is merely a filter and final authorization is server-side, downgrade the hypothesis.
- Impact / rollback: This is a reasoning shortcut, not an exploit by itself.
- Sources / reuse: [S012], [S022]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-003 - Use path traversal first for configuration/source recovery, not random file fishing
- Category: `web`
- Tags: `path-traversal`, `LFI`, `source`
- Search aliases: ../, read source file, download config, etc passwd
- Symptoms: Download/view endpoint maps a request value to filesystem path without robust confinement.
- Stack assumptions: Service filesystem contains source/config likely to reveal credentials, routes, or flag-store logic.
- Prerequisites: Known legitimate file path and platform separator/working directory clues.
- First action: Prove escape with a harmless readable target, then prioritize app config/source, process/service definitions, and known flag-store metadata over indiscriminate host files.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Traversal yields material that accelerates service understanding or directly crosses confidentiality boundary.
- Failure branch: If normalization blocks simple `../`, inspect decode/canonicalization order rather than cycling encodings indefinitely.
- Impact / rollback: Authorized CTF scope only. Avoid destructive special files/devices.
- Sources / reuse: [S023]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-004 - Model SSRF as a server-side trust-boundary pivot
- Category: `web`
- Tags: `SSRF`, `internal-services`
- Search aliases: ssrf localhost, server fetch url, internal api from web
- Symptoms: Application fetches user-supplied URL/resource server-side.
- Stack assumptions: Server has network access or identity not available to external client.
- Prerequisites: Controllable URL and an observable response/timing effect.
- First action: Confirm server-side fetch to an owned endpoint, then map only event-relevant internal services/ports revealed by source/config; do not start with huge blind scans.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Request reaches a destination from server context and returns/changes observable data.
- Failure branch: If URL is fetched client-side, via allowlisted proxy, or response is fully opaque, adjust hypothesis before brute forcing parser bypasses.
- Impact / rollback: Keep internal scanning bounded to competition scope.
- Sources / reuse: [S024], [S004]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-005 - Trace command injection from parameter to shell boundary
- Category: `web`
- Tags: `command-injection`, `source-review`
- Search aliases: shell injection, os command, subprocess shell true
- Symptoms: Route invokes system utility using user-controlled string.
- Stack assumptions: Input reaches shell parsing or command construction without structured argument separation.
- Prerequisites: Source or a benign controlled marker test.
- First action: Find the exact sink (`system`, shell invocation, command string); replace shell string composition with fixed executable + argument array or strict semantic validation.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Benign metacharacter payload no longer changes command structure; legitimate operation still works.
- Failure branch: If process API already passes an argument vector with no shell, metacharacters alone do not prove injection; inspect downstream program semantics.
- Impact / rollback: High-impact RCE class. Patch sink, not individual separators.
- Sources / reuse: [S025], [S014]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-006 - Use response timing/output only to confirm blind command execution after a sink exists
- Category: `web`
- Tags: `blind-command-injection`, `timing`
- Search aliases: blind rce, no output command injection, sleep payload
- Symptoms: Source/behavior strongly indicates shell execution but response does not include command output.
- Stack assumptions: Authorized CTF endpoint and bounded timing/OAST mechanism permitted by rules.
- Prerequisites: Identified command sink; baseline latency distribution.
- First action: Use one low-impact side effect/timing differential to confirm execution, then stop probing and patch/exploit the identified sink.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Repeatable differential tied to the injected command, not random service latency.
- Failure branch: If timing noise overlaps baseline, use a deterministic local artifact on your own service rather than increasing delays.
- Impact / rollback: Avoid long sleeps or resource-heavy commands that damage SLA.
- Sources / reuse: [S025]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-007 - Search source for high-yield trust-boundary sinks before reading every line
- Category: `web`
- Tags: `source-review`, `sinks`
- Search aliases: grep vuln source, quick code audit, where to look first
- Symptoms: Large service source tree and limited opening minutes.
- Stack assumptions: Languages/frameworks are at least roughly known.
- Prerequisites: Local grep/ripgrep and source tree.
- First action: Search for auth/session/object IDs; filesystem joins/open; HTTP clients/URL fetch; subprocess/shell; deserialization/reflection; raw SQL; upload/extract; randomness/token generation. Then trace backward to attacker input.
- Command placeholders / evidence:
  - `rg -n "(subprocess|os\.system|exec\(|pickle|deserialize|getattr|globals\(|requests\.|http\.|open\(|join\(|session|user_id|guid|token|random)" <src>` - operator-derived heuristic; adapt per language
- Expected output / interpretation: A prioritized list of dataflows crossing security boundaries.
- Failure branch: Keyword absence is not evidence of safety; framework helpers and indirect calls need semantic review.
- Impact / rollback: Read-only triage.
- Sources / reuse: [S018], [S019], [S011], [S012]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: operator synthesis from source-specific failures

### WEB-008 - Rebuild the smallest HTTP request that preserves exploit semantics
- Category: `web`
- Tags: `HTTP`, `replay`, `minimization`
- Search aliases: curl from pcap, minimal exploit request, copy burp request
- Symptoms: Captured/Burp request works but contains many irrelevant headers/cookies.
- Stack assumptions: You can replay against owned service and reset state if needed.
- Prerequisites: Full working request.
- First action: Remove one class at a time: browser headers, unrelated cookies, optional fields. Keep method/path/query, auth state, content type, body, and any anti-CSRF/session values until proven unnecessary.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A short deterministic request suitable for exploit automation and patch regression.
- Failure branch: If minimization breaks behavior, restore last removed element and mark it required rather than guessing.
- Impact / rollback: Avoid minimizing against opponents if request mutates state.
- Sources / reuse: [S026], [S028], [S012]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### WEB-009 - Prove both security and availability with a two-request regression pair
- Category: `web`
- Tags: `patching`, `regression`
- Search aliases: test patch route, normal request still works, security regression
- Symptoms: You changed one web authorization/input-validation branch.
- Stack assumptions: One exploit request and one legitimate request exercise the same route/feature.
- Prerequisites: Known expected status/body/state for both.
- First action: Run exploit first against controlled state, then the normal request. Record status, response invariant, and state change. Add checker afterward if available.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Exploit fails specifically; normal flow and checker pass.
- Failure branch: If both fail, patch is overbroad. If both pass, patch missed boundary. If exploit gets different error but still leaks state, inspect side effects.
- Impact / rollback: Small regression pair is faster than broad ad-hoc clicking but does not replace checker coverage.
- Sources / reuse: [S016], [S012], [S019]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### PCAP-001 - Use conversations to find the service and dominant flows before packet-by-packet reading
- Category: `pcap`
- Tags: `Wireshark`, `conversations`, `triage`
- Search aliases: top talkers, which stream matters, pcap ports
- Symptoms: Large capture with unknown relevant host/port.
- Stack assumptions: IP/TCP/UDP metadata is intact.
- Prerequisites: Capture file and rough time/service scope.
- First action: Open protocol conversations/endpoints; sort by bytes/packets/time and isolate flows to the service port or unusual peers before following streams.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A handful of candidate conversations replace thousands of packets.
- Failure branch: If traffic is highly multiplexed/NATed, pivot to stream IDs, SNI/Host, timing, or application fields.
- Impact / rollback: Read-only analysis.
- Sources / reuse: [S026]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: documentation-derived

### PCAP-002 - Follow one TCP/application stream to reconstruct a conversation
- Category: `pcap`
- Tags: `Wireshark`, `TCP`, `follow-stream`
- Search aliases: follow tcp stream, reassemble conversation, see request response
- Symptoms: Packets are interleaved and application request/response is hard to read.
- Stack assumptions: Protocol rides a stream Wireshark can follow/reassemble.
- Prerequisites: Select a packet from candidate flow.
- First action: Use Follow Stream and switch representation (ASCII/hex/raw) based on protocol. Record stream index so CLI filters can reproduce it.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Ordered client/server payload exposes request framing, credentials, object IDs, or exploit bytes.
- Failure branch: If stream is encrypted or custom-framed, reassembly still helps delimit transport data but content may need keys/custom parser.
- Impact / rollback: Read-only.
- Sources / reuse: [S026]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: documentation-derived

### PCAP-003 - Use TShark follow output for scriptable stream extraction
- Category: `pcap`
- Tags: `tshark`, `CLI`, `stream`
- Search aliases: tshark follow stream, extract tcp stream CLI, pcap grep
- Symptoms: Need repeatable extraction across many captures without GUI.
- Stack assumptions: Local TShark version supports follow statistic for target protocol.
- Prerequisites: Known stream/filter selector.
- First action: Use TShark follow output and store the exact tool version/command with extracted artifact.
- Command placeholders / evidence:
  - `tshark -r <pcap> -q -z follow,tcp,ascii,<stream>` - doc-derived; local tshark unavailable
- Expected output / interpretation: Deterministic stream transcript suitable for diffing/indexing.
- Failure branch: If the installed syntax differs, consult `tshark -z help`/local man page; do not assume online-current options.
- Impact / rollback: Read-only.
- Sources / reuse: [S028]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: documentation-derived, not locally tested

### PCAP-004 - Export reassembled HTTP objects before manual carving
- Category: `pcap`
- Tags: `Wireshark`, `file-carving`, `HTTP`
- Search aliases: export http files, recover download from pcap, save objects
- Symptoms: Capture contains file downloads/uploads or responses likely to be useful artifacts.
- Stack assumptions: Supported application dissector can identify complete/reassembled objects.
- Prerequisites: Relevant capture and protocol decoded correctly.
- First action: Try protocol object export first, then hash/file-type triage each artifact before resorting to raw stream carving.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Recovered objects get names/content types/sizes and can be triaged independently.
- Failure branch: If export is empty/incomplete, capture may be truncated, encrypted, chunked unusually, or protocol unsupported; fall back to streams/Zeek/manual carving.
- Impact / rollback: Treat exported files as untrusted. Do not execute them on host.
- Sources / reuse: [S027], [S029]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: documentation-derived

### PCAP-005 - Use Zeek file analysis to inventory hashes/types before extraction
- Category: `pcap`
- Tags: `Zeek`, `files`, `hashes`
- Search aliases: zeek extract files, files.log, hash pcap files
- Symptoms: Many application-layer files cross the capture and you need metadata at scale.
- Stack assumptions: Zeek supports the protocol/file handle and local version matches scripts.
- Prerequisites: PCAP and Zeek 8.1.1-compatible workflow or adapted local docs.
- First action: Generate file-analysis logs, then prioritize by MIME/type, size, source/destination, and hashes. Extract only selected artifacts when possible.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A searchable inventory connects file artifacts to network context before opening them.
- Failure branch: Unsupported protocol or incomplete stream may produce no file handle. Use Wireshark streams/manual extraction as fallback.
- Impact / rollback: Extracted payloads are untrusted; sandbox static/dynamic analysis.
- Sources / reuse: [S029]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: documentation-derived

### PCAP-006 - Correlate recovered file artifacts back to the connection that carried them
- Category: `pcap`
- Tags: `Zeek`, `correlation`, `forensics`
- Search aliases: which request downloaded file, file to connection, artifact provenance
- Symptoms: You have an extracted/hash-identified file but need the request/user/peer that transferred it.
- Stack assumptions: File-analysis metadata preserves connection/protocol identifiers.
- Prerequisites: Zeek logs or equivalent flow metadata.
- First action: Join file identifier/connection UID to protocol log and then to connection log; retain timestamps and endpoint tuple with artifact hash.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Artifact provenance includes who transferred it, over which protocol/session, and when.
- Failure branch: If IDs are missing because artifact was manually carved, use timestamp/stream/byte-offset notes from extraction.
- Impact / rollback: Read-only correlation.
- Sources / reuse: [S029]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: documentation-derived

### PCAP-007 - Stream a remote capture over SSH only when the environment permits it
- Category: `pcap`
- Tags: `tcpdump`, `Wireshark`, `remote-capture`
- Search aliases: remote wireshark ssh, pipe tcpdump wireshark, capture vulnbox live
- Symptoms: You want live Wireshark analysis without writing large PCAPs on the vulnbox.
- Stack assumptions: SSH access, tcpdump privileges, sufficient bandwidth, and event rules permit remote capture.
- Prerequisites: Interface/filter and trusted analysis host.
- First action: Pipe pcap bytes from remote tcpdump to local Wireshark; exclude the SSH control flow to avoid self-capture noise.
- Command placeholders / evidence:
  - `ssh root@$REMOTE_SRV tcpdump -n -i $INTERFACE -U -s0 -w - | wireshark -k -i -` - source-reported by Thomas Weigold; not locally tested
  - `ssh root@$REMOTE_SRV tcpdump -n -i $INTERFACE -U -s0 -w - 'not port 22' | wireshark -k -i -` - source-reported variant; not locally tested
- Expected output / interpretation: Local Wireshark receives live packets without a remote capture file.
- Failure branch: If event VPN/SSH shares service interface, filters can hide needed traffic or create loops. Prefer organizer PCAPs/rotating local capture when uncertain.
- Impact / rollback: Root capture and live flag traffic are sensitive; team-private only.
- Sources / reuse: [S012]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-reported only; tcpdump/Wireshark absent in fixture

### PCAP-008 - Decode standard USB keyboard HID reports from capture fields
- Category: `pcap`
- Tags: `USB`, `HID`, `keyboard`
- Search aliases: usb keyboard pcap, keystrokes pcap, hid data tshark
- Symptoms: USB capture contains interrupt transfers from a keyboard-like device.
- Stack assumptions: Device uses a conventional keyboard report layout or Wireshark exposes report bytes consistently.
- Prerequisites: USB PCAP and HID usage-code mapping/script.
- First action: Filter keyboard interrupt data, extract report bytes, map modifiers + keycodes, then reconstruct key-down transitions rather than blindly converting every packet.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Recovered keystroke sequence produces coherent text/commands or challenge material.
- Failure branch: If decoded text is nonsense, inspect HID report descriptor before assuming wrong key map or encoding.
- Impact / rollback: Read-only forensic recovery.
- Sources / reuse: [S036], [S037]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-derived; exact field names/version must be checked locally

### PCAP-009 - When keyboard decoding is nonsense, inspect the HID report descriptor
- Category: `pcap`
- Tags: `USB`, `HID`, `descriptor`, `dead-end`
- Search aliases: weird usb keyboard, nonstandard hid, keycodes wrong
- Symptoms: Standard keyboard script produces garbage or misses a second keyboard/device.
- Stack assumptions: Challenge/device may define custom report structure.
- Prerequisites: USB descriptors and endpoint/device IDs.
- First action: Parse report descriptor, determine bit/byte layout and usages for the specific device, then write a decoder for that layout before applying any downstream encoding such as Base32.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Raw reports align with descriptor and produce structured values; only then should you decode higher-level text.
- Failure branch: Do not keep swapping keyboard layouts/encodings when report framing itself is wrong.
- Impact / rollback: Read-only; high value for deliberately unusual challenges.
- Sources / reuse: [S037]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: organizer-writeup-derived

### REV-001 - Run `file` and targeted `strings` before opening a binary in a heavy tool
- Category: `reverse`
- Tags: `triage`, `ELF`, `strings`
- Search aliases: what is this binary, strings first, quick rev triage
- Symptoms: Unknown executable/library/artifact and only minutes to orient.
- Stack assumptions: Local static tools available.
- Prerequisites: Copy of artifact; never execute unknown file.
- First action: Identify format/arch/linking first, then scan strings for routes, file paths, error messages, flags, commands, URLs, crypto constants, and function/library names.
- Command placeholders / evidence:
  - `file <artifact>` - fixture-verified on /bin/true
  - `strings -a -n 8 <artifact> | less` - fixture-verified command shape on /bin/true
- Expected output / interpretation: You know architecture/format and have anchors to search in disassembler/decompiler.
- Failure branch: Stripped/packed binaries may yield little. Move to headers/imports/entropy/decompiler instead of running broad `strings` forever.
- Impact / rollback: Static-only; safe if parser/tool is trusted.
- Sources / reuse: [S031]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: fixture-verified command shapes

### REV-002 - Use ELF headers before guessing architecture or entry behavior
- Category: `reverse`
- Tags: `ELF`, `readelf`, `objdump`
- Search aliases: readelf header, objdump file format, elf architecture
- Symptoms: `file` says ELF or binary behavior depends on architecture/linking.
- Stack assumptions: ELF artifact.
- Prerequisites: readelf/objdump installed.
- First action: Inspect ELF header, program/section headers, dynamic dependencies/imports as needed before choosing debugger/decompiler settings.
- Command placeholders / evidence:
  - `readelf -h <artifact>` - fixture-verified on /bin/true
  - `objdump -f <artifact>` - fixture-verified on /bin/true
- Expected output / interpretation: Class, endianness, machine, type, and entrypoint/file format are explicit.
- Failure branch: Non-ELF or packed/custom loaders require format-specific tooling.
- Impact / rollback: Static read-only.
- Sources / reuse: [S031]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: fixture-verified

### REV-003 - Pivot from a useful string to references and callers in Ghidra
- Category: `reverse`
- Tags: `Ghidra`, `xrefs`, `strings`
- Search aliases: ghidra find xref, string to function, where used string
- Symptoms: Binary contains a distinctive route, error, filename, command, or protocol literal.
- Stack assumptions: Ghidra analysis completed enough to build references.
- Prerequisites: Imported project and useful string.
- First action: Locate string -> show references -> inspect referencing function in decompiler/disassembly -> climb callers until attacker-controlled input or security decision is visible.
- Command placeholders / evidence: none required.
- Expected output / interpretation: A semantic anchor lands you in the relevant parser/auth/handler instead of reversing from entrypoint.
- Failure branch: If no xref exists, string may be constructed/encoded or referenced indirectly; search nearby data/functions or runtime memory.
- Impact / rollback: Read-only.
- Sources / reuse: [S031]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: official documentation-derived

### REV-004 - Rename variables around trust boundaries before understanding the whole function
- Category: `reverse`
- Tags: `Ghidra`, `decompiler`, `dataflow`
- Search aliases: rename ghidra vars, understand decompiler, trust boundary reverse
- Symptoms: Decompiler output has `param_1`, `local_28`, and nested comparisons obscuring security logic.
- Stack assumptions: You have identified input, session/state, resource lookup, or sensitive sink.
- Prerequisites: Decompiler view and references.
- First action: Rename only semantically proven values: `req_user`, `session_user`, `path`, `token`, `cmd`, `flag_ptr`. Retype structures/functions when evidence supports it. Follow one dataflow to the sink.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Authorization/input-validation logic becomes readable enough to formulate an exploit/patch hypothesis.
- Failure branch: Do not overcommit guesses as names; suffix uncertain names with `maybe_` or keep notes until confirmed.
- Impact / rollback: Analysis-only.
- Sources / reuse: [S031], [S008]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### REV-005 - Use GDB `x/nfu` to inspect the exact memory representation you need
- Category: `reverse`
- Tags: `GDB`, `memory`
- Search aliases: gdb examine memory, x/16gx, dump bytes gdb
- Symptoms: Need to inspect buffer, pointer target, stack/heap data, or decoded structure during controlled debugging.
- Stack assumptions: You can run the challenge binary safely in an isolated CTF lab.
- Prerequisites: Breakpoint at relevant code and known address/expression.
- First action: Choose count/format/unit explicitly instead of dumping huge memory regions. Re-run at before/after points to compare state.
- Command placeholders / evidence:
  - `x/<count><format><unit> <address-or-expression>` - official GDB documentation pattern; not locally exercised
- Expected output / interpretation: Memory bytes/words/string/instructions match the representation needed for the hypothesis.
- Failure branch: If address is invalid or optimized code moves data, inspect registers/symbols and breakpoint timing rather than widening dump blindly.
- Impact / rollback: Dynamic execution only in isolated authorized target.
- Sources / reuse: [S032]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: official documentation-derived

### REV-006 - Triage Office macros with olevba before manual VBA reading
- Category: `reverse`
- Tags: `malware`, `VBA`, `olevba`
- Search aliases: macro malware, extract vba, office document triage
- Symptoms: DOC/XLS/PowerPoint/OOXML artifact may contain VBA or macro-driven behavior.
- Stack assumptions: oletools installed; artifact handled as untrusted.
- Prerequisites: Static copy of document.
- First action: Run macro extraction/analysis; prioritize auto-execution hooks, shell/process/network calls, obfuscation/encoded strings, and IOCs. Then open only relevant modules.
- Command placeholders / evidence:
  - `olevba <document>` - tool-maintainer documented command family; exact local flags untested
- Expected output / interpretation: You know whether macros exist and have a short list of suspicious functions/decoded indicators.
- Failure branch: No VBA does not rule out embedded objects, DDE, XLM, scripts, or exploits; pivot based on file type.
- Impact / rollback: Static only; do not open active content in Office on host.
- Sources / reuse: [S033]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: maintainer documentation-derived

### REV-007 - Extract embedded OLE objects as artifacts, then triage each independently
- Category: `reverse`
- Tags: `malware`, `OLE`, `embedded-object`
- Search aliases: oleobj extract, embedded exe office, extract object doc
- Symptoms: Office/OLE document contains embedded packages/objects or macro references to embedded content.
- Stack assumptions: oleobj supports the container format.
- Prerequisites: Static copy and isolated output directory.
- First action: List/extract embedded objects, hash them, run `file`/strings, and preserve parent-document provenance.
- Command placeholders / evidence:
  - `oleobj <document>` - tool-maintainer documented command family; exact local flags/output untested
- Expected output / interpretation: Embedded payloads become standalone artifacts linked back to the parent file.
- Failure branch: If extraction fails, inspect archive/container structure manually or use alternate format-specific parser.
- Impact / rollback: Do not execute extracted files; treat as hostile.
- Sources / reuse: [S034], [S033]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: maintainer documentation-derived

### CRYPTO-001 - Decode hex only when structure supports it
- Category: `crypto`
- Tags: `hex`, `encoding`, `triage`
- Search aliases: is this hex, decode hex, hex string
- Symptoms: String consists mostly/exclusively of hex digits with plausible even length.
- Stack assumptions: It is text representing bytes, not an integer/hash identifier.
- Prerequisites: Copy of value and expected context.
- First action: Check even length and decode once; inspect resulting bytes with `file`, printable ratio, magic bytes, or next obvious layer.
- Command placeholders / evidence:
  - `python3 -c "print(bytes.fromhex('<hex>'))"` - fixture-verified primitive; placeholder must be replaced safely
- Expected output / interpretation: Decoded bytes reveal text, file signature, or a clearly different next layer.
- Failure branch: If result is random-looking and original could be a digest/key/ID, stop recursive decoding without evidence.
- Impact / rollback: Read-only.
- Sources / reuse: [S038]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: fixture-verified hex roundtrip

### CRYPTO-002 - Use strict Base64 decoding to avoid false positives
- Category: `crypto`
- Tags: `base64`, `encoding`
- Search aliases: is this base64, decode b64, base64 garbage
- Symptoms: Text matches Base64 alphabet/padding and length is plausible.
- Stack assumptions: String is intended as encoded bytes rather than arbitrary identifier.
- Prerequisites: Python/offline decoder.
- First action: Decode with validation enabled, then inspect byte structure. Accept URL-safe alphabet only when context supports it.
- Command placeholders / evidence:
  - `python3 -c "import base64; print(base64.b64decode('<value>', validate=True))"` - fixture-verified primitive; placeholder only
- Expected output / interpretation: Successful strict decode plus meaningful structure supports the hypothesis.
- Failure branch: If validation fails, do not keep adding padding blindly unless the producer/format suggests omitted padding or URL-safe Base64.
- Impact / rollback: Read-only.
- Sources / reuse: [S038]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: fixture-verified strict Base64

### CRYPTO-003 - Use known flag/file prefixes as XOR cribs
- Category: `crypto`
- Tags: `XOR`, `known-plaintext`
- Search aliases: xor flag prefix, known plaintext xor, crib xor
- Symptoms: Ciphertext-like bytes and suspected repeating/single-byte XOR; expected plaintext prefix such as flag format or file magic exists.
- Stack assumptions: XOR model is plausible from challenge/source/context.
- Prerequisites: Ciphertext bytes and known plaintext bytes at aligned position.
- First action: XOR ciphertext prefix with known plaintext to derive candidate key bytes; test repetition across the rest before brute force.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Derived key reproduces readable structure beyond the crib.
- Failure branch: If candidate key only explains the crib and nowhere else, discard rather than force it.
- Impact / rollback: Offline computation.
- Sources / reuse: [S038], [S035]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### CRYPTO-004 - Brute-force single-byte XOR offline and rank outputs
- Category: `crypto`
- Tags: `XOR`, `bruteforce`
- Search aliases: single byte xor, xor 256 keys, favorite byte
- Symptoms: Same XOR byte likely applied to entire short ciphertext.
- Stack assumptions: Keyspace is exactly one byte or evidence strongly suggests it.
- Prerequisites: Ciphertext bytes.
- First action: Evaluate all 256 keys locally; rank by printable/expected-language/flag-regex score, then inspect top candidates.
- Command placeholders / evidence: none required.
- Expected output / interpretation: One candidate has coherent structure and not merely a few printable characters.
- Failure branch: If no candidate is coherent, stop. Move to repeating-key/other transform only with evidence.
- Impact / rollback: Offline, negligible cost.
- Sources / reuse: [S038], [S035]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### CRYPTO-005 - Exploit XOR cancellation before attacking a key
- Category: `crypto`
- Tags: `XOR`, `algebra`
- Search aliases: xor cancel, xor properties, known xor components
- Symptoms: Challenge combines values with XOR and exposes overlapping combinations.
- Stack assumptions: Values are aligned equal-length byte strings and no additional nonlinear transform intervenes.
- Prerequisites: Equations/data from challenge.
- First action: Write XOR equations symbolically; cancel repeated terms before guessing keys or brute forcing.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Unknown value isolates algebraically or key bytes become directly derivable.
- Failure branch: If lengths/encodings differ, normalize to bytes first. Do not XOR ASCII hex characters unless the format actually does.
- Impact / rollback: Offline.
- Sources / reuse: [S038]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: educational primitive

### CRYPTO-006 - Use CyberChef Magic as a hypothesis generator, never as proof
- Category: `crypto`
- Tags: `CyberChef`, `Magic`, `triage`
- Search aliases: cyberchef magic, what encoding is this, auto decode
- Symptoms: Unknown blob/string could be layered encoding/compression/XOR/file data.
- Stack assumptions: Offline CyberChef version includes Magic; sensitive challenge data can stay local.
- Prerequisites: Raw bytes/text and, when known, a crib such as flag regex.
- First action: Run Magic at shallow depth first. Treat suggested operations, file magic, entropy, language scores, and crib matches as leads; manually verify each transform.
- Command placeholders / evidence: none required.
- Expected output / interpretation: One suggested chain produces structurally valid output that survives independent validation.
- Failure branch: No result means “heuristic found nothing,” not “encrypted.” Intensive mode brute-forces only bounded data and can create plausible false positives.
- Impact / rollback: Offline. Pin the local CyberChef build for event reproducibility.
- Sources / reuse: [S035]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source code directly documents heuristic/speculative behavior

### CRYPTO-007 - Stop recursive decoding when each layer stops increasing structure
- Category: `crypto`
- Tags: `dead-end`, `encoding`, `triage`
- Search aliases: encoding rabbit hole, base64 forever, is it encrypted
- Symptoms: You can repeatedly apply Base64/hex/URL/rot-like transforms but outputs are not becoming more interpretable.
- Stack assumptions: No challenge/source clue mandates a fixed number of layers.
- Prerequisites: Ability to measure validity: magic bytes, syntax, printable text, checksum, known prefix, parse success.
- First action: Require each transform to increase evidence: valid decoder, meaningful header/text/grammar, or known crib. After one or two structure-free layers, branch to file type/entropy/source clues instead of continuing.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Time is spent on transformations with objective evidence rather than aesthetic plausibility.
- Failure branch: Compressed/encrypted data can remain high entropy after a correct decode; use context/magic/metadata, not printable ratio alone.
- Impact / rollback: Offline.
- Sources / reuse: [S035], [S038]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized stop rule

### CRYPTO-008 - Distinguish an encoding from a cryptographic identifier before decoding
- Category: `crypto`
- Tags: `hash`, `encoding`, `classification`
- Search aliases: hash or base64, is this ciphertext, random token
- Symptoms: Opaque token could be digest, random ID, ciphertext, compressed bytes, or encoding.
- Stack assumptions: Context such as field name, length stability, source code, equality behavior, or known input/output exists.
- Prerequisites: Multiple samples if possible.
- First action: Classify by production/usage: compared for equality -> likely identifier/digest; reversible parse path -> encoding; nonce/IV/tag structure -> encryption. Decode only when syntax plus context supports reversibility.
- Command placeholders / evidence: none required.
- Expected output / interpretation: You avoid wasting time “decoding” a hash/random identifier and instead attack generation/authorization logic if relevant.
- Failure branch: Length/alphabet alone is weak evidence; many token formats look alike.
- Impact / rollback: Read-only reasoning.
- Sources / reuse: [S019], [S035], [S038]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### MISC-001 - Split a physical/router challenge into device, transport, and service layers
- Category: `misc`
- Tags: `physical`, `router`, `scope`
- Search aliases: router challenge, hardware ctf, physical service
- Symptoms: Challenge involves physical network gear plus a software service/protocol.
- Stack assumptions: You have authorized access to event hardware/network.
- Prerequisites: Basic topology and interfaces.
- First action: Write three columns: physical/device state, network transport, application/service. Test reachability and trust boundaries at each layer separately before mixing hypotheses.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Failures localize to cabling/device config, protocol reachability, or application logic instead of “router is broken”.
- Failure branch: Race conditions and reset behavior can cross layers; record timing and device state for reproducibility.
- Impact / rollback: Avoid destructive firmware/config changes unless explicitly allowed.
- Sources / reuse: [S014]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized from physical A/D experience

### MISC-002 - Treat a non-standard HID report descriptor as the protocol specification
- Category: `misc`
- Tags: `USB`, `HID`, `descriptor`
- Search aliases: custom keyboard descriptor, hid report weird, usb custom protocol
- Symptoms: USB device identifies as HID but normal keycode decoding fails.
- Stack assumptions: Descriptor capture is available.
- Prerequisites: USB PCAP/descriptor parser.
- First action: Decode descriptor first: report IDs, field widths/counts, usages, logical ranges. Build decoder from those fields, then map to higher-level symbols.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Byte/bit offsets are justified by descriptor, not guessed from standard keyboard layout.
- Failure branch: If descriptor changes mid-capture or multiple interfaces exist, key decoder by device/interface/report ID.
- Impact / rollback: Read-only.
- Sources / reuse: [S037]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: organizer-writeup-derived

### MISC-003 - Treat container-vs-VM behavior mismatch as a first-class failure mode
- Category: `misc`
- Tags: `environment`, `Docker`, `VM`
- Search aliases: works in vm not docker, exploit fails container, cups port conflict
- Symptoms: Official/demo exploit fails locally in Docker while service otherwise appears present.
- Stack assumptions: Challenge documentation notes host services, privileged daemons, namespaces, devices, or VM-only components.
- Prerequisites: Compare process list, ports, privileges, mounts, system services between environments.
- First action: Before rewriting exploit, confirm environment parity. Reproduce against the full event VM when docs say a dependency does not start in container.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Failure is attributed to missing environment component, not incorrectly to patched vulnerability or bad exploit.
- Failure branch: Local host daemons can also steal ports (saarCTF example: CUPS/631). Check listeners before modifying service config.
- Impact / rollback: Do not disable unrelated host services on competition infrastructure without understanding impact.
- Sources / reuse: [S020]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-reported negative knowledge

### MISC-004 - Use multi-language service repositories as pattern drills, not as copy-paste exploit banks
- Category: `misc`
- Tags: `practice`, `services`, `breadth`
- Search aliases: attack defense practice repo, service source examples, old ctf services
- Symptoms: Team wants offline examples across Rust/Go/C++/Python/Node/Java/Bash.
- Stack assumptions: Historical source/checkers/sploits are available.
- Prerequisites: Local snapshot with license/reuse status respected.
- First action: For each old service, extract only: trust boundary, flag store, checker contract, exploit prerequisite, patch invariant, and one failure/stale assumption. Re-implement small fixtures instead of copying full exploit code into the KB.
- Command placeholders / evidence: none required.
- Expected output / interpretation: Corpus gains transferable patterns without becoming a duplicate archive of old solutions.
- Failure branch: Old dependencies/frameworks may be insecure in unrelated ways; distinguish intended vulnerabilities from incidental CVEs.
- Impact / rollback: Practice only in local authorized fixtures.
- Sources / reuse: [S021], [S020]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized

### MISC-005 - Recover useful artifacts before solving the whole challenge
- Category: `misc`
- Tags: `forensics`, `artifact-recovery`, `triage`
- Search aliases: what can i extract first, recover files pcap, useful artifacts
- Symptoms: A challenge combines capture, document, binary, or unusual protocol and full understanding will take time.
- Stack assumptions: At least one artifact boundary can be extracted safely.
- Prerequisites: Hashing/file-type tools and isolated workspace.
- First action: Prioritize concrete artifacts: exported HTTP files, embedded OLE objects, reconstructed keyboard text, binaries/configs, URLs/credentials/IDs. Hash and label provenance, then hand off each artifact to the relevant specialist/card path.
- Command placeholders / evidence:
  - `file <artifact>; sha256sum <artifact>` - file command fixture-verified; sha256sum standard but not separately fixture-recorded
- Expected output / interpretation: Team can parallelize on real evidence while one person continues protocol reconstruction.
- Failure branch: If extraction changes bytes/metadata, record method and retain original capture/container for re-extraction.
- Impact / rollback: Never execute recovered artifacts directly.
- Sources / reuse: [S027], [S029], [S034], [S036]. Follow each source record’s reuse policy; card text is an original normalization, not copied full text.
- Evidence status: source-synthesized; partial fixture verification

## Source-to-topic expansion map

The current corpus has 64 cards. The 36 distinct expansions below take it to exactly 100 cards without duplicating the existing advice. Each candidate names a narrower operational question rather than a generic category recap.

| Expansion ID | Source | Proposed card |
|---|---|---|
| EXP-001 | S001 | Build a tick observation worksheet from unknown organizer rules |
| EXP-002 | S002 | Compare score tradeoffs: downtime vs exposure without hard-coded weights |
| EXP-003 | S003 | Interpret checker states and alert transitions from gameserver architecture |
| EXP-004 | S004 | Safe patch transport alternative that avoids UID-0 Git and eval push-options |
| EXP-005 | S005 | Design a minimal thrower state machine with dry-run and kill switch |
| EXP-006 | S006 | First-time A/D service ownership and handoff pattern from Team Enu |
| EXP-007 | S007 | Rank high-volume packet conversations for human review |
| EXP-008 | S008 | Binary-only service triage when source is absent |
| EXP-009 | S009 | When a recovered attacker payload is useful but too late to operationalize |
| EXP-010 | S010 | Django route/model/flag-store mapping drill |
| EXP-011 | S011 | Newtonsoft deserialization patch regression checklist |
| EXP-012 | S012 | Predictable token modeling worksheet with known samples |
| EXP-013 | S013 | PCAP-to-exploit script generation pipeline with human validation |
| EXP-014 | S014 | Race-condition evidence capture across physical/network/application layers |
| EXP-015 | S015 | Service-author view: intended vulnerability vs unintended vulnerability triage |
| EXP-016 | S016 | Checker-aware firewall/filter testing using pseudo-malicious checker input |
| EXP-017 | S017 | Parse scoreboard/checker result states into team alerts |
| EXP-018 | S018 | Safe dynamic-dispatch allowlist patch patterns in Python |
| EXP-019 | S019 | Authorization boolean simplification: default-value edge cases |
| EXP-020 | S020 | Host-port conflict triage before blaming the service |
| EXP-021 | S021 | Cross-language source-review sink keywords by runtime |
| EXP-022 | S022 | IDOR mutation matrix: path/query/body/GraphQL/object filename |
| EXP-023 | S023 | Canonicalization-order tests for path traversal |
| EXP-024 | S024 | SSRF parser/redirect/DNS assumptions to verify before bypass work |
| EXP-025 | S025 | Command-injection sink taxonomy: shell string vs argv vs interpreter |
| EXP-026 | S026 | Follow UDP/TLS/HTTP2/QUIC streams: when stream reconstruction differs |
| EXP-027 | S027 | Object-export validation: compare content length/hash to stream bytes |
| EXP-028 | S028 | TShark fields-first extraction templates for HTTP/DNS/TLS |
| EXP-029 | S029 | Zeek file hash and MIME triage script pinned to local version |
| EXP-030 | S030 | Socket -> namespace/container mapping when PID is hidden |
| EXP-031 | S031 | Ghidra imports/call-tree triage after strings fail |
| EXP-032 | S032 | GDB before/after memory snapshots for parser state |
| EXP-033 | S033 | VBA autoexec/network/process IOC priority matrix |
| EXP-034 | S034 | OLE embedded-object provenance manifest |
| EXP-035 | S035 | CyberChef Magic false-positive validation checklist |
| EXP-036 | S036 | USB HID modifier/key-down de-duplication decoder fixture |

Additional mappings already represented heavily in current cards:

- S037 -> PCAP-009,MISC-002: Non-standard HID descriptor and post-extraction Base32 workflow.
- S038 -> CRYPTO-001..008: Encoding/XOR primitives and stop rules.

## Corpus gaps

- Raymond James 2026 public participant rules/checker/scoring material is still absent from this corpus. The brief says live attack/defend is expected, but another event’s score model must not be substituted.
- Binary exploitation/pwn coverage is intentionally thinner than web/PCAP because the supplied brief prioritizes web + network/forensics + A/D. Add modern heap/pwn cards only after event-specific service style is known.
- Windows memory/disk forensics lacks a primary-source tool-maintainer set here. Add Volatility 3, Windows event-artifact, registry, and NTFS timelines if organizers signal host forensics.
- DNS/QUIC/HTTP2/custom-protocol PCAP cards are only expansion candidates. Current cards focus on the highest-yield request/response and artifact-recovery paths.
- Mobile/APK tooling (`jadx`, `apktool`) is listed in the prep brief but not yet normalized into cards.
- Steganography is not covered beyond generic artifact triage because a good primary-source set was not collected in this pass. Do not fill this with duplicated “try zsteg/binwalk” folklore.
- No Raymond James-specific physical/magstripe source was verified here. Keep those as unanswered event questions rather than importing unrelated rules.

## Proposed prioritization toward 100 cards

1. Add `EXP-001` through `EXP-009` first: they reduce live A/D operational mistakes and improve first-response traffic triage.
2. Add `EXP-010` through `EXP-021`: these deepen service source review, checker-aware patching, and cross-language vulnerability recognition.
3. Add `EXP-022` through `EXP-030`: these turn web/PCAP/Linux triage into repeatable lookup cards and close common “what do I do next?” gaps.
4. Add `EXP-031` through `EXP-036`: these strengthen binary, debugger, macro, CyberChef, and USB edge cases.
5. Only then widen into pwn, Windows forensics, steg, mobile, and additional crypto. This keeps the first 100 aligned to the brief instead of maximizing topic count.

## 20 realistic search queries

| Query typed under pressure | Expected card IDs |
|---|---|
| `what process owns port 8080` | AD-003 |
| `find source code behind listening port` | AD-003, WEB-007 |
| `patch works but checker says faulty` | AD-007, WEB-009 |
| `rollback broken patch fast` | AD-008 |
| `git remote rejected vulnbox mutable data` | AD-005 |
| `rebuild http request from pcap` | AD-012, WEB-008, PCAP-002, PCAP-003 |
| `other team bypassed my patch` | AD-015, AD-014 |
| `recover exploit payload from apache logs` | AD-016 |
| `user_guid lets me see another invoice` | AD-017, WEB-001, WEB-002 |
| `predictable auth code after restart` | AD-018, AD-025 |
| `timestamp hash ticket brute force` | AD-022 |
| `pickle upload rce` | AD-024 |
| `getattr globals function name from request` | AD-023 |
| `export files from http pcap` | PCAP-004, PCAP-005, MISC-005 |
| `usb keyboard pcap keystrokes` | PCAP-008 |
| `usb keyboard decoder gives garbage` | PCAP-009, MISC-002 |
| `ghidra string xrefs to function` | REV-003 |
| `office macro suspicious commands` | REV-006, REV-007 |
| `base64 or random hash dead end` | CRYPTO-002, CRYPTO-007, CRYPTO-008 |
| `cyberchef magic found xor is it real` | CRYPTO-006, CRYPTO-003, CRYPTO-004 |

## Source-record field notes

`02-sources.jsonl` is the machine-readable provenance index. `content_hash` is `null` for ordinary web pages because no byte-for-byte local snapshot was downloaded. GitHub file records may instead contain a `git-blob-sha1` supplied by GitHub. `intended_use` is conservative: unknown web rights are `original_summary_and_link`; a permissive project license may allow an excerpt or snapshot only when the license evidence applies to that file/document.

## Safety and event-boundary note

These cards are intended for the authorized CTF environment described by the supplied brief. Automation, replay, exploit loops, packet capture, and service modification must remain inside organizer-provided systems and rules. The corpus deliberately does not turn another competition’s mechanics into assumed Raymond James permissions.
