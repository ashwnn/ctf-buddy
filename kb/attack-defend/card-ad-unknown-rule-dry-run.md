# When a rule is not written down, the answer is dry-run plus a question

**First useful action.** Keep a literal list of unresolved rule answers and make every cross-team or state-changing script default to dry-run until its gate is answered.

```bash
grep -n 'UNKNOWN' <WORKDIR>/event-facts.md | tee -a <WORKDIR>/organizer-questions.md && \
  grep -nE 'DRY_RUN|dry_run|--dry-run' <SCRIPTS_DIR>/*.py <SCRIPTS_DIR>/*.sh 2>/dev/null | head -n 20
```

Expected: two lists — fields you still cannot source, and the scripts that need a dry-run default for each of those fields. A script with no dry-run flag and no confirmation gate is the one that ends the run early.

## Symptoms

- Someone says "other events allow it, so it must be fine here".
- A script sends traffic, blocks traffic, or submits results while the relevant rule is still `UNKNOWN`.
- The team cannot quote where a permission came from — only that "someone said".

## Prerequisites and assumptions

- The facts worksheet from `card-ad-event-facts-tick-model`, however incomplete.
- Working scripts for exploits, telemetry, and submission.
- Assumption: mature formats genuinely differ on these points, so precedent from another event proves only that rules *can* differ.

## Diagnostic sequence

1. For each `UNKNOWN` field, ask "which of my actions depends on this answer?" → actions with no dependency can proceed; actions with a dependency gate to dry-run.
2. Check whether the question is answerable from material you already have (rules page, scoreboard page, announcements) before asking → asking twenty questions wastes the organizer channel.
3. Ask the highest-value subset (automation and AI policy, exact attack scope, what counts as a connected device, scoring weights, checker behaviour, allowed service modifications, flag mechanics, reset/recovery, network controls, decoys) and record each answer verbatim with who said it and when.
4. Re-run the dry-run scripts with the answer applied, one at a time, on one target.

If the answer is "permitted", un-gate exactly one script and watch your own availability. If the answer is "not permitted" or absent, leave it gated and put the capability on the board as unavailable so nobody re-litigates it at minute 90.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| `grep -n 'UNKNOWN' <WORKDIR>/event-facts.md` | field list | the exact set of questions still standing between you and safe action |
| `grep -nE 'DRY_RUN\|--dry-run' <SCRIPTS_DIR>/*` | file and line of the gate | how many scripts are actually safe by default |
| `<SUBMISSION_SCRIPT> --dry-run` | planned submissions with no network write | the submission path is inspectable without spending a flag |
| `<FIREWALL_PREP_SCRIPT> --print` | would-be rules, not installed | a containment plan can be reviewed without risking checker traffic |

## State-changing actions

- **Impact:** the dangerous version of this card is installing prepared controls. Installing a filter, WAF, proxy, or decoy changes graded traffic and can itself violate the rules.
- **Preconditions:** a written rule answer naming the layer (may we filter? rate-limit? block peers?) and confirmation that checker traffic will still reach the service.
- **Health check before:** availability watch running and flat, with the legitimate smoke test passing.
- **Apply:** install only the prepared artefact for which you have a written answer; install it for the narrowest stated purpose, never "the whole network".
- **Health check after:** legitimate smoke test unchanged, your own watch flat, and one deliberately permitted peer path still behaves as before. Regression probe: the peer-side behaviour you claim to have preserved.
- **Rollback:** remove the rule (`<FIREWALL_REMOVE_COMMAND>` / `--flush` on your own chain) and re-verify the smoke test. It becomes unsafe to add the rule back if the organizer later clarifies that filtering is prohibited.

## Failure modes and things teams stopped doing

- Teams stopped importing permissions from other events. FAUST, saarCTF, and RuCTFE publish materially different rules on cadence, flag lifetime, and — for RuCTFE 2020 — peer filtering; identical-looking formats, different permissions. [src-faust-rules-2024-7fc6a296] [src-saarctf-rules-a45fdf6b] [src-ructfe-rules-95d7c601]
- Teams stopped assuming an AI/automation ban cannot exist. A recent A/D final explicitly prohibited AI, which is evidence that automation policy can be restrictive, not evidence that any particular event restricts it. [src-d0gl0v3r-umcs2026-c85f0c19]
- Teams stopped spending the live window on questions they could have asked in the preparation period. Organizer guidance treats the preparation window as the time to get boxes running and services analysed; rule questions belong there too. [src-enowars-general-docs-5c2a697e]

## Evidence status

- **Status:** source-supported but untested
- **What we actually ran:** nothing. No filtering rule, proxy, or decoy was prepared or installed in this session.
- **Our adaptation vs the source:** the gate/dry-run discipline is ours. The question list is derived from differences between published rules; the specific ten questions are our prioritisation, not an organizer checklist.

## Sources

- `src-ructfe-rules-95d7c601` — an explicit restriction on filtering peer traffic.
- `src-saarctf-rules-a45fdf6b` — target-scope and DoS restrictions.
- `src-faust-rules-2024-7fc6a296` — an example of a rules page that states cadence, lifetime, and scoring explicitly.
- `src-d0gl0v3r-umcs2026-c85f0c19` — an event final that banned AI, and a team that ignored a permission gate implicitly.
- `src-enowars-general-docs-5c2a697e` — purpose of the preparation window.
- `src-faust-gameserver-readme-4e7460fe` — what a gameserver expects from services it checks.
