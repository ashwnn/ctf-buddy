# Write the event facts sheet before automating or hardening anything

**First useful action.** Create one screen-sized facts file, fill only fields you can trace to organizer material, and leave everything else literally `UNKNOWN` — then count the unknowns; that count is your organizer question list.

```bash
mkdir -p <WORKDIR> && cat > <WORKDIR>/event-facts.md <<'EOF'
tick_or_round_seconds: UNKNOWN
prep_window_minutes: UNKNOWN
checker_interval_seconds: UNKNOWN
checker_states: UNKNOWN
flag_lifetime: UNKNOWN
flags_per_service_per_tick: UNKNOWN
flag_submission_endpoint: UNKNOWN
attack_info_api_or_ids: UNKNOWN
downtime_penalty: UNKNOWN
availability_weight: UNKNOWN
offense_weight: UNKNOWN
defense_weight: UNKNOWN
first_blood_bonus: UNKNOWN
peer_filtering_allowed: UNKNOWN
automation_allowed: UNKNOWN
source_of_each_answer: UNKNOWN
EOF
grep -c 'UNKNOWN' <WORKDIR>/event-facts.md
```

Expected: a non-zero count printed. If it prints `0` on your very first pass you are probably importing another event's rulebook instead of this one's. If the file does not appear, the heredoc was blocked by a read-only workspace — write it somewhere you own.

## Symptoms

- A service is running and flags exist, but nobody can define "healthy", "stale", or "scoreable" for it.
- A teammate proposes a cron loop, a firewall rule, or a WAF while the tick length is still unknown.
- Two teammates disagree about how long a captured flag stays valid and both are guessing.

## Prerequisites and assumptions

- Organizer announcement channel, rules page, scoreboard/status page — or an explicit statement that none was published.
- Stack-agnostic. Nothing needed beyond a shell and a text file.
- State this aloud: periodic checks and short-lived flags are typical of attack/defense, but cadence, lifetime, and weights differ per event and do not transfer between events.

## Diagnostic sequence

1. Search the organizer material for the vocabulary that defines the game (`tick`, `round`, `checker`, `flag`, `SLA`, `availability`, `downtime`) → each hit either answers a field verbatim or is a dead end.
2. For every field still `UNKNOWN`, ask whether it is *observable*: watch one or two cycles and record when your own service's checker-visible state or flag value changes → an observation, not a rule; label it as observation in the file.
3. Anything still unknown when the live window opens is a gate, not a guess → go to `card-ad-unknown-rule-dry-run` before enabling anything that touches peers, filters, submission, or automation.

If cadence is observable but lifetime is not, keep automation off for one more cycle and keep observing. If neither is observable, ask the organizer and record the answer with a timestamp and a channel name.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -inE 'tick\|round\|flag\|checker\|sla\|availab\|downtime' <RULES_FILE>` | matching lines with numbers | the only authoritative statements you have; anything unmatched is genuinely unspecified |
| `date -u +%s; <SELF_HEALTH_PROBE>; sleep <SUSPECTED_TICK_SECONDS>; date -u +%s` | start/end epoch plus two results | if the results differ, one cycle elapsed inside the window — narrow it, do not yet call it the tick |
| `grep -c 'UNKNOWN' <WORKDIR>/event-facts.md` | decreasing integer | your remaining risk surface; drive it to zero before enabling cross-team behaviour |

## Failure modes and things teams stopped doing

- Hard-coding a cadence from another event is a documented failure mode, not a hypothetical. FAUST's published 2024 rules describe three-minute ticks with a five-tick flag lifetime; saarCTF's published rules describe 2–3 minute ticks with a ten-tick lifetime; RuCTFE's published 2020 rules describe roughly one-minute rounds with a fifteen-round lifetime. Identical-sounding formats, materially different clocks. [src-faust-rules-2024-7fc6a296] [src-saarctf-rules-a45fdf6b] [src-ructfe-rules-95d7c601]
- Teams stopped treating the preparation window as free time. Organizer guidance describes that window as the period for getting assigned boxes running and analysing services, because easy vulnerabilities become exploitable the moment the network opens. Spend it on facts, not on tuning a loop. [src-enowars-general-docs-5c2a697e]
- Teams stopped inferring a penalty formula from the existence of availability scoring. That the component exists is strong prior evidence that correctness matters; its arithmetic is not transferable. [src-faust-rules-2024-7fc6a296] [src-ictf-history-d702df2b]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No command on this card was executed. The heredoc and `grep -c` shape are ordinary shell but were not exercised here.
- **Our adaptation vs the source:** the worksheet is our synthesis. FAUST, saarCTF, RuCTFE, ENOWARS and iCTF material is used only to justify *which fields exist*, and to demonstrate how much they vary. No event's numbers are adopted.

## Sources

- `src-faust-ad-beginners-779c0a5e` — organizer description of what the gameserver exercises and why breaking legitimate behaviour is costly.
- `src-faust-rules-2024-7fc6a296` — ticks, flag validity, availability/offense/defense components.
- `src-saarctf-rules-a45fdf6b` — a different cadence, a different flag lifetime, scope and DoS restrictions.
- `src-ructfe-rules-95d7c601` — a third cadence/lifetime plus an explicit traffic-filtering restriction.
- `src-enowars-general-docs-5c2a697e` — purpose of the preparation window.
- `src-ictf-history-d702df2b` — the high-level attack/defense model.
- `src-faust-gameserver-readme-4e7460fe` — checker/flag/tick terminology from a real gameserver implementation.
- `src-enowars-engine-readme-7933cf37` — framework-level concepts of rounds, flag validity, and checker API.
