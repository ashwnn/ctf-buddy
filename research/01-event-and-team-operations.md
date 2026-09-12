# Raymond James CTF 2026 - Event and Team Operations

Research date: 2026-09-11

## Bottom line

No publicly indexed official Raymond James 2026 participant rulebook, scoring specification, network policy, or organizer page was found during this research. The team preparation brief is therefore the only current source for the claimed 2026 hybrid format, 18-team estimate, and one-CTF-connected-device-per-member constraint. Those details should be treated as planning inputs, not independently verified organizer rules.

What is independently verified is the event family and organizer history. Raymond James publicly describes hosting its annual collegiate Capture the Flag competition, and its December 2025 article says the ninth annual event was held at Raymond James' St. Petersburg headquarters with 14 university teams. Raymond James also confirms that BCIT participated in the 2022 edition as the first non-US university invited to the event. This makes continuity into a 2026 Raymond James CTF plausible, but the exact 2026 date, location, format, scoring model, and technical rules remain unverified publicly.

Until the 2026 rules are obtained, the safe operating model is:

1. Prepare aggressively offline.
2. Inspect only systems and artifacts explicitly assigned to the team.
3. Keep cross-team traffic, automated exploitation, flag submission, filtering, decoys, cloud AI, and state-changing defensive controls disabled until the organizer explicitly permits them.
4. Treat service correctness and recoverability as first-class concerns, because multiple mature attack-defense formats score service availability as well as offense and defense. That lesson transfers; their exact scoring formulas do not.

## 1. Raymond James 2026 evidence status

| Statement | Classification | Evidence | Confidence | Operational consequence |
|---|---|---|---|---|
| The event is referred to as "Raymond James CTF 2026." | Brief statement | Team preparation brief. | High that this is the team's intended event; not independently verified as the official 2026 title. | Use as internal event identifier only. |
| The event is expected to combine mini-Jeopardy questions with live attack-defend. | Brief statement | Team preparation brief. | Unverified externally. | Prepare for both lanes, but do not assume classic A/D flag mechanics. |
| About 18 teams are expected. | Brief statement | Team preparation brief. | Unverified externally. | Useful only for rough workload assumptions. |
| One CTF-connected device is allowed per team member. | Brief statement | Team preparation brief. | Unverified externally and underspecified. | Do not design around extra connected laptops, cloud workers, or shared team servers until clarified. |
| Attack-defend is especially important for 2026. | Brief statement | Team preparation brief. | Unverified externally. | Prioritize service ownership, patching, availability, monitoring, and exploit scripting in practice. |
| Internet access may be limited or unavailable. | Preparation assumption | Team preparation brief says to assume this for readiness. | Not an organizer rule. | Cache tools, docs, packages, wordlists, and references locally. |
| Raymond James has an annual collegiate CTF program. | Independently verified fact | Raymond James official 2022 and 2025 publications. | High. | Confirms the event family is genuine and recurring. |
| Raymond James hosted the ninth annual CTF at its St. Petersburg headquarters in 2025. | Independently verified fact | Raymond James official article dated 2025-12-18. | High for 2025 only. | Do not automatically carry the location into 2026. |
| The 2025 event had 14 university teams. | Independently verified fact | Raymond James official 2025 article. | High for 2025 only. | Does not verify the brief's 18-team 2026 estimate. |
| BCIT has previously participated. | Independently verified fact | Raymond James official 2022 article names BCIT as the first non-US university at that edition. | High. | Supports continuity between BCIT and the Raymond James event. |
| Raymond James historically uses financial-sector threat scenarios. | Independently verified historical fact | Raymond James official 2022 article. | High historically. | Useful for thematic practice, not proof of 2026 challenge categories. |
| The exact 2026 venue and date are public. | Unanswered question | No official 2026 event page located. | Unknown. | Confirm from invitation or organizer. |
| Exact offense, defense, availability, and Jeopardy scoring are public. | Unanswered question | No official 2026 rulebook located. | Unknown. | Do not optimize red-vs-blue staffing against a guessed formula. |
| Flags rotate on ticks and have a fixed lifetime. | Assumption if classic A/D | Common in FAUST, saarCTF, RuCTFE and similar formats, but not confirmed for Raymond James. | Unknown for this event. | Flag schedulers and expiry logic remain disabled until confirmed. |
| Network filtering, WAFs, decoys, or honeypots are allowed. | Unanswered question | Other A/D events differ materially. | Unknown. | Prepare configurations but do not deploy them. |
| Automated scanning, exploitation, submission, or AI assistance is allowed. | Unanswered question | No 2026 Raymond James public policy found. A recent unrelated A/D final explicitly prohibited AI. | Unknown. | Automation stays in dry-run/local mode until clarified. |

### Public-event verification note

The latest official Raymond James publication found is about the 2025 ninth annual event. It identifies Raymond James as host and its St. Petersburg headquarters as that year's venue. No indexed official 2026 Raymond James participant rules were located. This document therefore does not import FAUST, ENOWARS, saarCTF, RuCTFE, or iCTF rules into the Raymond James event.

## 2. Source and evidence table

The attack-defense sources below are deliberately a mix of organizer documentation and first-hand team retrospectives. A retrospective is evidence that a team experienced a problem or used a workflow. It is not evidence that the workflow was optimal or caused its final placement.

| ID | Source | Type | Evidence used here | Transfer boundary |
|---|---|---|---|---|
| RJ1 | Raymond James, "Future cybersecurity leaders shine at ninth annual Raymond James Capture the Flag event," 2025 | Official organizer publication | Ninth annual event, St. Petersburg headquarters, 14 university teams. | Verifies 2025 only, not 2026 format or rules. |
| RJ2 | Raymond James, "Raymond James hosts next-generation cybersecurity talent at annual Capture the Flag event," 2022 | Official organizer publication | Sixth annual event, BCIT participation, financial-sector threat scenarios. | Historical context only. |
| AD1 | FAUST CTF 2025, "Attack/Defense for Beginners" | Organizer guide | Gameserver exercises intended service behavior; breaking legitimate behavior harms SLA; services must remain reachable. | Concepts transfer if Raymond James has availability checking. Exact architecture does not. |
| AD2 | FAUST CTF 2024 Rules | Organizer rules | One-hour prep, three-minute ticks, five-tick flag validity, offense + defense + SLA. | Strong evidence that cadence and scoring matter, but these exact numbers do not transfer. |
| AD3 | saarCTF 2025 Rules | Organizer rules | One-hour prep, 2-3 minute ticks, ten-tick flag validity, target and DoS restrictions. | Demonstrates that even similar A/D formats use different flag lifetimes and restrictions. |
| AD4 | RuCTFE 2020 Rules | Organizer rules | One-hour closed-network prep, availability-sensitive scoring, 15-round flag lifetime, filtering restrictions. | Another materially different model. Never assume Raymond James copies it. |
| AD5 | ENOWARS documentation, "General" | Organizer guide | Prep window is for getting the box running and analyzing services; easy vulnerabilities can be exploited immediately after network opening. | Opening discipline transfers. Exact one-hour window and network design do not. |
| AD6 | iCTF history and background | Organizer material | Traditional A/D requires keeping services available while compromising identical opponent services. | High-level model transfers only if Raymond James uses classic A/D. |
| TR1 | Maple Bacon, "FAUST 2024: Patching infrastructure for attack-defense CTFs" | Team retrospective | Manual SSH edits were painful; Git gave rollback/version history; team built a push-to-deploy patch workflow. | Supports reproducible patching, not a claim that this caused competitive success. |
| TR2 | NTT Security Japan, ENOWARS 8 retrospective | Team retrospective | Automated recurring exploit loop; then precise defense because checkers exercised service functionality; binary patch had to preserve behavior. | Supports exploit reproducibility and minimal patches. Automation depends on Raymond James rules. |
| TR3 | D0GL0V3R, "My First Attack-Defense CTF Experience - UMCS 2026" | First-time team retrospective | Wrong interface monitoring missed container traffic; patching before understanding the exploit failed; WAF consumed all 8 GB RAM. | Directly useful failure modes for another first-time team. UMCS rules, AI ban, and scoring do not transfer. |
| TR4 | #misec RuCTFE 2019 writeup | Team retrospective | Code reading and division of exploit/patch work; shared source; context switching and weak awareness of ownership caused coordination problems. | Strong operations lesson. Network and target details remain RuCTFE-specific. |

### Source URLs

- RJ1: https://www.raymondjames.com/about-us/our-stories/our-business/2025/12/18/future-cybersecurity-leaders-shine-at-ninth-annual-raymond-james-capture-the-flag-event
- RJ2: https://www.raymondjames.com/careers/all-access/campus-recruiting/capture-the-flag-event
- AD1: https://2025.faustctf.net/information/attackdefense-for-beginners/
- AD2: https://2024.faustctf.net/information/rules/
- AD3: https://ctf.saarland/rules
- AD4: https://ructfe.org/rules
- AD5: https://enowars.github.io/docs/play/general/
- AD6: https://ictf.cs.ucsb.edu/
- TR1: https://maplebacon.org/2024/09/faustctf-patcher/
- TR2: https://jp.security.ntt/insights_resources/tech_blog/enowars-8-writeup-attack-and-defense/
- TR3: https://d0gl0v3r.github.io/2026/05/16/UMCS-2026-First-Attack-Defense-CTF-Experience.html
- TR4: https://duchyoftaco.net/2019/11/23/misec-ructfe-2019.html

## 3. Lessons that transfer, and lessons that do not

### High-confidence transferable lessons

1. **Get every assigned service into a known-good state before clever work.** A broken service prevents useful testing and, in availability-scored formats, directly costs points. [AD1, AD5]
2. **Assign explicit service ownership.** One person is accountable for the current state and handoff of each service even when analysis, exploitation, and patching are shared. This addresses the coordination failures described by #misec. [TR4]
3. **Snapshot before changing.** Track source/configuration in version control where practical, record baseline hashes, and keep a known rollback path. [TR1]
4. **Read the actual service.** Generic scanner output is secondary to understanding the code, binary, protocol, trust boundaries, state, and flag path. [TR4, TR2]
5. **Reproduce before patching.** A working local reproduction provides evidence that the bug exists and becomes a regression test for the patch. [TR2, TR3]
6. **Make the smallest patch that closes the vulnerability without changing legitimate behavior.** Aggressive rewrites, blanket filters, or protocol changes can break checkers. [AD1, TR2]
7. **Verify monitoring at the layer where traffic actually flows.** A packet capture on the wrong interface can create false confidence. [TR3]
8. **Separate mutable state from deployable code.** Databases, uploads, flag stores, and runtime data should not be overwritten by a patch deployment. [TR1]
9. **Shared state beats verbal memory.** Maintain one service board with owner, state, exploit, patch, checker/health status, rollback, and next action. [TR4]
10. **Automate repetition only after one manual path is correct and the rules allow it.** A reliable exploit can then become a loop; a broken one merely fails faster. [TR2]

### Event-specific lessons that must not be imported blindly

| Decision | Why it is event-specific |
|---|---|
| Defense-first versus offense-first | Depends on offense/defense/SLA/Jeopardy weights, first-blood bonuses, and flag cadence. |
| How much downtime a patch can tolerate | Depends on checker cadence, recovering states, retry behavior, and downtime penalties. |
| How often to run exploits | FAUST used three-minute ticks in 2024, saarCTF 2025 used 2-3 minute ticks, and RuCTFE 2020 used roughly one-minute rounds. |
| How long stolen flags remain valuable | FAUST 2024 allowed five ticks, saarCTF 2025 ten ticks, and RuCTFE 2020 fifteen rounds. |
| Whether filtering is legal | saarCTF constrains target scope and DoS; RuCTFE 2020 explicitly prohibited filtering traffic from other teams. Raymond James is unknown. |
| Whether source IP identifies an attacker | Some A/D networks use NAT or game routers. Never build attribution logic before confirming topology. |
| Whether every opponent service is in scope | Scope varies and organizer infrastructure is commonly excluded. Obtain exact CIDRs/ports first. |
| Whether automated exploit loops are acceptable | Common in some A/D events, but Raymond James automation policy is unknown. |
| Whether cloud AI is allowed | UMCS 2026's A/D final prohibited AI entirely. This proves rules can be restrictive, not that Raymond James has the same rule. |
| Whether decoys or proxies are useful or legal | Depends on checker semantics, allowed network controls, and whether service behavior may be wrapped. |

## 4. Actionable KB cards

These cards are designed for full-text search during the event. Each is an operational default, not a substitute for organizer rules.

### KB-01 - Baseline before touching a service

**Trigger:** The team receives a VM, container, source tree, binary, or credentials.

**Action:** Record service name, ports, process/container, start/stop command, health behavior, state paths, baseline hashes, current listeners, and a rollback artifact before modifying anything.

**Evidence:** TR1, AD1.

**Rule gate:** Inspection must remain inside explicitly assigned team assets.

### KB-02 - One accountable owner per service

**Trigger:** Multiple people begin working on the same service.

**Action:** Put one current owner on the board. Others may analyze, exploit, or review, but deployment and handoff state flows through the owner.

**Evidence:** TR4.

**Why:** Prevents duplicate work, unknown changes, and "I thought someone else fixed it."

### KB-03 - Health check before security check

**Trigger:** A service is assigned or restarted.

**Action:** Prove the intended happy path works first. Save the exact request, expected response, and required state as a smoke test.

**Evidence:** AD1, AD5.

**Why:** You cannot distinguish a bad patch from a pre-existing broken service without a baseline.

### KB-04 - Reproduce the bug locally first

**Trigger:** A suspected vulnerability is found.

**Action:** Build the smallest reproducible input against your own local/assigned instance. Record precondition, request, observable effect, and whether it exposes flag-equivalent data.

**Evidence:** TR2, TR3, TR4.

**Why:** Reproduction gives both an exploit primitive and a regression test.

### KB-05 - Patch the vulnerable path, not the symptom

**Trigger:** A reproducible vulnerability exists.

**Action:** Fix the smallest code/data-flow defect that removes the primitive while preserving protocol and legitimate functionality. Avoid broad regex filters or rewrites unless the exact exploit requires them and checker behavior is known.

**Evidence:** TR2, TR3.

### KB-06 - Patch deployment is a transaction

**Trigger:** A patch is ready.

**Action:** Snapshot -> apply -> restart only if required -> run health test -> run exploit regression -> observe resource usage -> commit deployment state. If any step fails, rollback immediately.

**Evidence:** TR1, TR2.

### KB-07 - Restore beats debugging a dead service

**Trigger:** The service is down, wedged, checker-failing, or a patch has broken intended behavior.

**Action:** Return to the last known-good artifact first, verify health, then investigate the failed patch offline.

**Evidence:** AD1 plus TR3's experience spending effort keeping containers alive.

**Scoring caveat:** This priority is strongest when availability is scored. Confirm Raymond James scoring as soon as possible.

### KB-08 - Verify packet visibility with a known request

**Trigger:** Monitoring is configured.

**Action:** Send one known request through the same path as the checker/attacker and confirm that the chosen capture point sees it. If containerized, map bridges, veth pairs, namespaces, reverse proxies, and host ports before trusting a host-level capture.

**Evidence:** TR3.

### KB-09 - Logs are evidence, not guaranteed detection

**Trigger:** Application logs show nothing suspicious.

**Action:** Do not infer "no attack." Correlate access logs, process/container state, network traces, database/state changes, and checker/score changes.

**Evidence:** TR3.

### KB-10 - Keep mutable state out of the patch path

**Trigger:** Code is copied, committed, rebuilt, or redeployed.

**Action:** Explicitly exclude databases, uploads, flag/state stores, generated keys, caches, and runtime volumes from destructive sync or checkout behavior.

**Evidence:** TR1.

### KB-11 - Centralize service status, not every artifact

**Trigger:** Team communication starts fragmenting.

**Action:** Maintain one lightweight board containing owner, service health, suspected vuln, exploit status, patch status, telemetry location, rollback, and next action. Large traces and binaries can live elsewhere.

**Evidence:** TR4.

### KB-12 - Reduce analyst context switching

**Trigger:** A person is carrying several codebases or is being interrupted by multiple teammates.

**Action:** Handoff a service with the template in this document, then stop routing unrelated questions to that person until their current task checkpoint.

**Evidence:** TR4 describes exhaustion while juggling several codebases and concurrent conversations.

### KB-13 - Convert a successful exploit into a deterministic harness

**Trigger:** A manual exploit against your own service succeeds.

**Action:** Parameterize target, timeout, expected success condition, and flag extraction. Add bounded concurrency, structured output, and failure logging.

**Evidence:** TR2.

**Rule gate:** Cross-team execution and automation remain disabled until explicitly permitted.

### KB-14 - Never schedule around a guessed tick

**Trigger:** Someone wants a cron/systemd loop for exploit or submission.

**Action:** Wait for documented checker cadence and flag validity. Record issue time, service, target, capture time, submit time, and expiry if the event exposes those semantics.

**Evidence:** AD2, AD3, AD4 demonstrate materially different cadences and lifetimes.

### KB-15 - Do not block traffic until filtering rules are known

**Trigger:** A teammate proposes iptables/nftables/WAF blocking.

**Action:** Prepare the rule offline and identify exactly what it would match. Do not activate it until organizers confirm filtering is permitted and checker traffic will remain valid.

**Evidence:** AD4 explicitly prohibited filtering other teams in RuCTFE 2020; other formats differ.

### KB-16 - Separate containment from patching

**Trigger:** Active exploitation is suspected.

**Action:** Record whether the proposed response is temporary containment, root-cause patch, or restore. Give each a rollback and health test. Do not allow an emergency rule to become an undocumented permanent change.

**Evidence:** TR3.

### KB-17 - Keep a Jeopardy lane alive

**Trigger:** The hybrid event has both challenge and live-service scoring active.

**Action:** Maintain a visible queue of low-cost/high-confidence Jeopardy tasks so the whole team does not disappear into one hard service problem. Reallocate only after the actual scoring weights are known.

**Evidence:** Hybrid format comes from the team brief. Staffing priority is a recommendation, not an organizer rule.

### KB-18 - Unknown rule means dry-run

**Trigger:** An operation affects another team, the shared network, flag submission, filtering, decoys, automation, AI, or additional connected infrastructure and the rule is not explicit.

**Action:** Keep it local/read-only/dry-run. Ask the organizer. Record the answer with timestamp and source.

**Why:** Mature A/D events differ sharply on exactly these points. [AD2, AD3, AD4]

## 5. Opening plan

The timer below starts when the team receives the competition image/source/credentials or is told the event has begun. If Raymond James provides a separate closed-network preparation period, use the same sequence inside that period.

### First 5 minutes

**Objective: establish control and a known-good baseline.**

- Coordinator opens the official rules/announcement channel and records last-minute changes.
- Mark every unanswered rule field in Section 10 as `UNKNOWN`. No teammate converts an unknown to an assumption silently.
- Inventory all assigned services: host/container, listener, protocol, state location, start method, source/binary availability.
- Capture baseline health for each service before modifications.
- Put service files/configuration under local version control or create a timestamped snapshot if Git is unsuitable.
- Record processes, listeners, containers, mounts/volumes, and obvious service dependencies.
- Assign one current owner to each service. Ownership may change later.
- Start the Jeopardy queue if that portion is open.
- Keep opponent-directed scanning, exploitation, automated submissions, filtering, decoys, and cloud AI disabled until rules are known.

**Exit condition:** every service has an owner, health state, rollback path, and location on the shared board.

### By 15 minutes

**Objective: know what the services are doing and where the highest-risk paths are.**

For each service:

- Read routes/handlers/protocol parser, authentication/session logic, storage calls, subprocess execution, serialization/deserialization, path/file operations, and any code that returns stored secrets or user-controlled records.
- Map inbound traffic to the actual process/container/network namespace.
- Build or record a minimal legitimate health request.
- Identify mutable state that must survive patch deployment.
- Create candidate vulnerability notes with evidence, not guesses.
- If a plausible vulnerability exists, reproduce it against the team's own instance or an offline clone.
- Identify the smallest possible correction, but do not deploy broad filters as a substitute for understanding.
- Keep shared status current: `HEALTHY`, `INVESTIGATING`, `EXPLOIT-REPRODUCED`, `PATCH-STAGED`, `PATCHED`, `BROKEN`, `RESTORING`.

**Exit condition:** each active service has a happy-path test, visibility point, state map, and either a concrete vulnerability hypothesis or a deliberate "still investigating" status.

### By 30 minutes

**Objective: turn understanding into tested defensive and offensive primitives without sacrificing recoverability.**

- For any reproduced vulnerability, create a deterministic local exploit harness.
- Create the minimal patch on a separate branch/copy.
- Test in this order: legitimate health -> exploit regression -> resource sanity -> restart behavior -> persistence/state sanity.
- Deploy only after rollback is immediate and the event permits the modification.
- If cross-team attack is explicitly permitted, test one bounded opponent request manually before enabling wider automation.
- If automated exploitation is explicitly permitted, wrap the proven exploit with target enumeration, timeouts, bounded concurrency, deduplication, and logging.
- If flag mechanics are documented, add exact validity/expiry behavior to submission logic. Otherwise, keep the submission scheduler disabled.
- Review the service board and move spare capacity to the highest-value unresolved item based on actual scoring.
- Preserve a Jeopardy worker/queue unless the published weighting makes doing so irrational.

**Exit condition:** no change exists only in someone's terminal history; every deployed patch and every working exploit has an owner, reproducible procedure, evidence, and rollback/disable path.

## 6. First-time-team role allocation without assuming team size

Do not begin with a permanent "half red, half blue" split. A first-time team benefits more from explicit functional hats and service ownership. One person may carry several hats and several people may share a hat. The invariant is accountability, not headcount.

| Functional hat | Accountable for | Must not become |
|---|---|---|
| Coordinator / rules keeper | Official announcements, scope/rule answers, service board, prioritization, conflict resolution. | A bottleneck approving every technical command. |
| Service owner | Current known state of one service, vulnerability notes, patch, health test, rollback, handoff. | The only person allowed to understand the service. |
| Offense runner | Turns reproduced flaws into bounded exploit harnesses and, if allowed, cross-team execution/submission. | A blind scanner operator disconnected from service owners. |
| Defender / observer | Visibility, incoming attack evidence, flag-loss/checker correlation, containment proposals. | A dashboard watcher who cannot identify the real traffic path. |
| Platform / restore | VM/container lifecycle, snapshots, version control, deploys, resource health, emergency restore. | A full-time infrastructure project during the event. |
| Jeopardy solver | Maintains progress on mini-Jeopardy points and hands off solved techniques/artifacts. | Permanently isolated from live-service status. |

### Allocation algorithm

1. Name one person as the current coordinator, even if that role is only part-time.
2. Assign every live service exactly one current owner and a backup/contact if capacity permits.
3. Ensure someone is always capable of restoring a broken service. This can be a service owner.
4. Keep one explicit Jeopardy queue and assign from available capacity based on real scoring.
5. Add offense runners only after a service owner has produced a concrete exploit hypothesis or reproduction.
6. Add dedicated monitoring only where telemetry has been proven useful. Do not spend a teammate on dashboards that do not answer an operational question.
7. Rotate ownership deliberately through the handoff template, not by saying "can someone look at this?"

This model scales down by combining hats and scales up by assigning more service owners/runners without changing the workflow.

## 7. Service handoff template

Copy one block per service.

```yaml
service:
  name:
  owner:
  backup_or_next_owner:
  last_updated:

runtime:
  host_or_container:
  listen_addresses_ports:
  protocol:
  process_or_unit:
  start_command:
  stop_command:
  restart_command:
  dependencies:
  state_paths_or_volumes:

baseline:
  status: HEALTHY | DEGRADED | DOWN | UNKNOWN
  baseline_hash_or_commit:
  snapshot_or_rollback_location:
  legitimate_health_test:
  expected_health_result:

visibility:
  confirmed_capture_point:
  access_log:
  app_log:
  other_signal:
  known_visibility_gaps:

vulnerability:
  status: NONE_KNOWN | HYPOTHESIS | REPRODUCED | ACTIVE_EXPLOIT_SEEN
  location:
  root_cause:
  prerequisites:
  local_reproducer:
  evidence:
  flag_or_sensitive_data_path:

offense:
  exploit_status: NONE | MANUAL | SCRIPTED | DISABLED_BY_RULE
  script_or_command:
  success_condition:
  safety_bounds:
  cross_team_execution_allowed: UNKNOWN
  automation_allowed: UNKNOWN

defense:
  patch_status: NONE | STAGED | DEPLOYED | ROLLED_BACK
  patch_commit_or_diff:
  regression_test:
  health_after_patch:
  resource_impact:
  deployment_time:
  rollback_command:

checker_and_scoring:
  checker_status:
  last_known_good:
  last_failure:
  flag_loss_or_score_change:
  cadence_if_known:
  notes:

next:
  highest_priority_action:
  blocker:
  handoff_notes:
```

### Minimum verbal handoff

If time is too short for the full template, say five things:

1. "Service and current health."
2. "What I proved, not what I suspect."
3. "What changed and the exact rollback."
4. "Where the exploit/patch/test lives."
5. "The next highest-value action."

## 8. Patch vs investigate vs exploit vs restore triage

Use evidence and service state rather than instinct.

### Decision order

**1. RESTORE when availability is not known-good.**

Choose restore first when any of these are true:

- Service is down, wedged, crash-looping, or no longer performs the known legitimate request.
- A recent patch correlates with checker/health failure.
- Resource exhaustion threatens the whole assigned host.
- The team cannot tell whether current behavior is pre-existing or self-inflicted and a known-good snapshot exists.

After restore, preserve the failed artifact and investigate offline. If Raymond James does not score availability, the scoring priority may change, but recoverability still enables testing.

**2. PATCH when the vulnerability is reproduced and the fix is small/testable.**

Patch when:

- Root cause is understood.
- A reproducer demonstrates the vulnerable behavior.
- The proposed change is narrow and reversible.
- Legitimate health behavior passes after the change.
- The reproducer fails after the change.
- Resource and state effects are acceptable.
- The modification is permitted by the rules.

If active exploitation is visible, this path moves up in priority.

**3. EXPLOIT when the primitive is proven, your service is stable, and offense is legal.**

Exploit when:

- The bug has a deterministic local reproduction.
- Opponent targets and ports are explicitly in scope.
- The exploit is non-destructive and respects traffic/rate limits.
- Cross-team exploitation is open.
- Automation level is permitted.
- A failed offensive run cannot damage your own service or shared infrastructure.

A strong workflow is often `reproduce -> package exploit -> patch`, with offense packaging and patching proceeding in parallel if staffing allows. Do not delay an urgent safe patch solely to perfect an offensive script.

**4. INVESTIGATE when evidence is insufficient.**

Investigate when:

- There is a score/checker change but no confirmed cause.
- Logs suggest an attack but no exploitable path is known.
- A vulnerability is only speculative.
- A patch would be broad or checker-risky.
- Monitoring may be pointed at the wrong layer.
- The service is healthy and there is no confirmed offensive primitive.

### Tie-break table

| Situation | Default action | Reason |
|---|---|---|
| Broken after own change | RESTORE | Stop compounding self-inflicted downtime. |
| Healthy + confirmed active exploit + safe minimal fix | PATCH | Stops ongoing loss while preserving service. |
| Healthy + confirmed vuln + no evidence of active attacks + offense allowed | EXPLOIT and PATCH in parallel if possible | Same understanding supports both sides. |
| Healthy + suspected vuln only | INVESTIGATE | Avoid random defensive changes. |
| Checker failing, root cause unknown | RESTORE then INVESTIGATE | Re-establish baseline first. |
| Exploit works but target/scope/automation rule unknown | Do not cross-team execute | Rule uncertainty overrides offensive opportunity. |
| Patch works locally but breaks legitimate health | Do not deploy | A "secure" broken service is not operationally correct. |
| WAF/filter is proposed without exploit evidence | INVESTIGATE | TR3 shows how blind filtering can consume time/resources without fixing cause. |

### Scoring adjustment after rules arrive

Once the Raymond James scoring model is known, add four numbers to every service board:

- `availability_cost_per_failed_check`
- `defense_cost_per_stolen_flag`
- `offense_value_per_valid_capture`
- `jeopardy_opportunity_value`

Use those values to break ties. Before they are known, do not invent them.

## 9. Organizer questions - maximum-value set

Ask these before the live portion. Ten questions cover the major operational gates without turning the organizer briefing into an interview.

1. **Automation and AI:** What automation is permitted: scanners, exploit loops, flag harvesting/submission, local LLMs, cloud AI assistants, coding agents, and organizer/API scraping? Are any rate limits or human-in-the-loop requirements imposed?
2. **Exact attack scope:** What IPs/CIDRs, ports, services, accounts, and protocols may teams target, and what organizer, checker, VPN, scoreboard, participant-device, or other infrastructure is explicitly out of scope?
3. **One-device rule:** What exactly counts as a "CTF-connected device"? Do local VMs/containers on that device count separately? Are offline second devices, USB transfer, LAN sharing, a team server, tethering, or cloud/VPS resources prohibited?
4. **Scoring:** What are the relative weights/mechanics for mini-Jeopardy, offense, defense, service availability/correctness, first blood, and penalties? Does a failed checker cost points immediately or after retries?
5. **Checkers:** How often are services checked, what legitimate functionality must remain intact, are checker source addresses identifiable, and what do service states such as down/recovering mean if exposed?
6. **Patching:** What modifications are allowed on our assigned systems: source edits, binary patches, package installs, service restarts, reverse proxies, WAFs, firewall rules, permission changes, credential changes, or replacing a service implementation?
7. **Flags:** What is the flag format, placement model, refresh cadence, lifetime/expiry, submission interface, deduplication behavior, and are historical/current flag IDs or retrieval tokens provided?
8. **Reset/recovery:** Can a team reset/reimage/restore its assigned VM or service? What state is preserved, what credentials change, how long does it take, and is there a scoring penalty?
9. **Network controls:** May teams filter/rate-limit/block peer traffic? Is traffic NATed/proxied such that source IP does not identify an opponent? Are passive PCAP/IDS tools on our assigned interfaces allowed?
10. **Decoys and redirection:** Are honeypots, decoy services, fake flags/data, transparent proxies, or traffic redirection allowed, and must any such layer continue to satisfy checker semantics?

Record answers verbatim with organizer name/channel and timestamp.

## 10. Rules configuration schema

Populate this file from official instructions. Keep `UNKNOWN` literal until answered.

```yaml
rules:
  provenance:
    event_brief: "raymond-james-ctf-2026-prep.md"
    official_2026_rulebook_url: UNKNOWN
    official_announcement_channel: UNKNOWN
    last_verified_at: UNKNOWN

  event:
    internal_name: "Raymond James CTF 2026"
    organizer_event_family: "Raymond James"  # verified historically
    organizer_2026_confirmed: UNKNOWN
    date: UNKNOWN
    venue: UNKNOWN
    expected_teams_from_brief: 18
    expected_teams_official: UNKNOWN

  format:
    hybrid_from_brief: true
    mini_jeopardy_from_brief: true
    live_attack_defend_from_brief: true
    official_format_confirmed: UNKNOWN
    preparation_window_minutes: UNKNOWN
    live_window_minutes: UNKNOWN

  devices:
    connected_devices_per_member_from_brief: 1
    official_limit_confirmed: UNKNOWN
    what_counts_as_connected_device: UNKNOWN
    local_vms_allowed: UNKNOWN
    local_containers_allowed: UNKNOWN
    offline_second_device_allowed: UNKNOWN
    usb_transfer_allowed: UNKNOWN
    team_lan_or_share_allowed: UNKNOWN
    cloud_vps_allowed: UNKNOWN

  scope:
    target_cidrs: UNKNOWN
    target_ports: UNKNOWN
    target_services: UNKNOWN
    participant_devices_in_scope: UNKNOWN
    organizer_infrastructure_out_of_scope: UNKNOWN
    checker_infrastructure_out_of_scope: UNKNOWN
    scoreboard_infrastructure_out_of_scope: UNKNOWN
    internet_targets_out_of_scope: UNKNOWN
    traffic_rate_limits: UNKNOWN
    dos_policy: UNKNOWN

  automation:
    port_scanning_allowed: UNKNOWN
    vuln_scanning_allowed: UNKNOWN
    exploit_automation_allowed: UNKNOWN
    flag_harvesting_allowed: UNKNOWN
    flag_submission_automation_allowed: UNKNOWN
    local_ai_allowed: UNKNOWN
    cloud_ai_allowed: UNKNOWN
    coding_agents_allowed: UNKNOWN

  service_modification:
    source_provided: UNKNOWN
    binary_only_services_possible: UNKNOWN
    source_edits_allowed: UNKNOWN
    binary_patches_allowed: UNKNOWN
    package_install_allowed: UNKNOWN
    service_restart_allowed: UNKNOWN
    credential_changes_allowed: UNKNOWN
    reverse_proxy_allowed: UNKNOWN
    waf_allowed: UNKNOWN
    firewall_allowed: UNKNOWN
    service_reimplementation_allowed: UNKNOWN
    decoys_allowed: UNKNOWN
    honeypots_allowed: UNKNOWN
    fake_flags_or_data_allowed: UNKNOWN

  checker:
    exists: UNKNOWN
    cadence_seconds: UNKNOWN
    retries: UNKNOWN
    required_functionality: UNKNOWN
    source_addresses_known: UNKNOWN
    service_states: UNKNOWN
    recovering_behavior: UNKNOWN

  flags:
    exists: UNKNOWN
    format_regex: UNKNOWN
    placement_model: UNKNOWN
    flags_per_service_per_tick: UNKNOWN
    refresh_cadence_seconds: UNKNOWN
    validity_seconds_or_ticks: UNKNOWN
    identifiers_or_tokens_provided: UNKNOWN
    submission_endpoint: UNKNOWN
    duplicate_submission_behavior: UNKNOWN
    late_submission_behavior: UNKNOWN

  scoring:
    jeopardy_weight: UNKNOWN
    offense_weight: UNKNOWN
    defense_weight: UNKNOWN
    availability_weight: UNKNOWN
    checker_failure_penalty: UNKNOWN
    stolen_flag_penalty: UNKNOWN
    first_blood_bonus: UNKNOWN
    penalties: UNKNOWN

  recovery:
    reset_available: UNKNOWN
    reset_method: UNKNOWN
    reset_duration: UNKNOWN
    reset_penalty: UNKNOWN
    state_preserved: UNKNOWN
    credentials_after_reset: UNKNOWN

  network:
    peer_source_ips_stable: UNKNOWN
    source_nat_or_proxy: UNKNOWN
    peer_filtering_allowed: UNKNOWN
    rate_limiting_allowed: UNKNOWN
    passive_capture_allowed: UNKNOWN
    ids_allowed: UNKNOWN
```

### Operations that remain read-only while rules are unknown

The following preparation can proceed without sending attack traffic or altering shared competition behavior, provided it is performed only on assets the organizers have assigned to the team:

- Read supplied source code, binaries, configuration, documentation, and challenge material.
- Hash/copy/diff supplied files.
- Inventory processes, listeners, containers, routes, mounts, and local configuration on the team's assigned system if shell access itself is authorized.
- Inspect local logs and service state.
- Perform static source and binary analysis.
- Build a local service map and data-flow notes.
- Create patches in a local copy without deploying them.
- Create exploit proof-of-concepts against an offline/local clone or the team's own expressly assigned test instance.
- Prepare scripts with cross-team network execution disabled.
- Prepare firewall/WAF/decoy rules without activating them.
- Prepare local dashboards/parsers using already collected team-local data.
- Build the service board, handoffs, runbooks, aliases, and local tool cache.

Keep these operations disabled until rules answer the relevant gate:

- Connecting to another team's hosts or services.
- Broad peer scanning or service discovery across the competition network.
- Automated exploitation.
- Automated flag harvesting or submission.
- Network filtering, blocking, WAF enforcement, or rate limiting that changes traffic.
- Honeypots, decoys, transparent proxies, or fake data visible to other teams/checkers.
- Cloud/VPS workers or extra connected devices.
- Cloud AI or coding agents if AI/tool policy is unknown.
- Any attack against organizers, checkers, scoreboard, VPN, other participant devices, or the public Internet.

"Read-only" is not a claim that all local inspection is always permitted. Official organizer instructions remain authoritative. It is the default posture for avoiding state-changing or opponent-directed behavior while policy is unresolved.

## 11. Three sourced mistakes to avoid

### Mistake 1 - Monitoring the wrong network layer

**What happened:** In a first-time UMCS 2026 A/D retrospective, the team listened on the host VPN interface while the vulnerable services ran inside Docker. The author later learned that relevant traffic was flowing through Docker virtual networking, so the monitoring setup missed the activity they cared about. [TR3]

**Avoidance:**

- Map the actual request path before relying on telemetry.
- For containers, record published ports, bridge/network, veth/namespace path, reverse proxies, and service process.
- Send a known health request and prove it appears in the chosen capture/log source.
- If it is not observable, move the sensor instead of assuming the attack is invisible.

**KB link:** KB-08.

### Mistake 2 - Patching before understanding, then exhausting the host

**What happened:** The same UMCS team says it implemented a WAF before understanding the exploit or payload. Their WAF ultimately consumed all 8 GB of RAM on the target machine. [TR3]

**Avoidance:**

- Reproduce first.
- Patch the root cause before adding generic filtering.
- Measure CPU/RSS/latency before and after a defensive control.
- Add a rollback command before deployment.
- Treat a resource-heavy defensive layer as a service outage risk, not automatically as protection.

**KB links:** KB-04, KB-05, KB-06.

### Mistake 3 - Weak ownership and excessive context switching

**What happened:** In #misec's RuCTFE 2019 retrospective, one contributor described holding several codebases in mind while talking to many teammates and eventually burning out. The retrospective also says internal communication and awareness of who was doing what were weaker than desired, leaving the team unsure whether work had been duplicated or complementary findings had failed to meet. [TR4]

**Avoidance:**

- Give every service a current owner.
- Use a shared status board with one-line next actions.
- Require explicit handoffs when ownership changes.
- Route exploit development and patch review through the service owner instead of interrupting every analyst.
- Check board state at short checkpoints rather than continuously broadcasting questions.

**KB links:** KB-02, KB-11, KB-12.

## 12. Practical operating doctrine for this team

For a first attack-defense event, optimize for recoverability and shared understanding before sophistication.

**Default loop per service:**

`BASELINE -> UNDERSTAND -> REPRODUCE -> SCRIPT -> PATCH -> HEALTH TEST -> REGRESSION TEST -> DEPLOY -> OBSERVE -> HANDOFF`

If the service becomes unhealthy at any point:

`ROLLBACK/RESTORE -> HEALTH TEST -> INVESTIGATE OFFLINE`

If a cross-team or state-changing action reaches an `UNKNOWN` rule field:

`DRY-RUN -> ASK ORGANIZER -> RECORD ANSWER -> ENABLE ONLY IF PERMITTED`

This is intentionally more conservative than a mature A/D team's workflow. The point is to avoid the two failure classes that repeatedly appear in retrospectives: self-inflicted service damage and team coordination collapse.

## 13. Pre-event artifacts to have ready

The preparation brief already emphasizes web, network/forensics, attack-defend, Python/Bash automation, and a local toolset. The operations work above turns that technical preparation into a team system.

Have these files available locally before arrival:

```text
research/
  01-event-and-team-operations.md

ops/
  rules.yaml
  organizer-answers.md
  service-board.md
  service-handoff-template.md
  restore-runbook.md

scripts/
  baseline.sh
  health/
  exploits/
  telemetry/
  submit/
```

Recommended behavior before organizer answers:

- `baseline.sh`: local/assigned-system inventory only.
- `health/`: legitimate own-service checks.
- `exploits/`: target defaults to localhost/team-owned test instance; cross-team mode requires an explicit flag.
- `telemetry/`: passive team-owned interfaces only.
- `submit/`: disabled until flag endpoint, format, validity, and automation policy are official.

## 14. Evidence-based preparation priorities from the team brief

The supplied preparation brief identifies web exploitation and PCAP/forensics as high-priority areas and calls attack-defend "very important for 2026." It specifically expects rapid service enumeration, exploitation of opposing services, vulnerable-code-path identification, patching without breakage, availability, and monitoring. It also emphasizes short Python/Bash automation and recommends keeping tools and references local in case Internet access is limited.

Operationally, that means the highest-value rehearsal is not another standalone Jeopardy box. Run a timed mini A/D drill where the team receives two or three unfamiliar local services and must:

1. inventory and health-check them;
2. assign ownership;
3. reproduce one vulnerability;
4. turn it into a local exploit harness;
5. patch it without changing legitimate behavior;
6. verify traffic visibility;
7. deliberately deploy one broken patch and practice restoring it;
8. hand the service to a teammate using the template above.

Measure time to baseline, time to reproduction, time to safe patch, time to rollback, and whether another teammate can continue from the written handoff. Those metrics are scoring-system independent and directly target the failure modes found in the sourced retrospectives.
