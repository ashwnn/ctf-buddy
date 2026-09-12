# Make the automation challenge correct once before making it parallel

**First useful action.** Get a single correct answer for the smallest input, then generalize — never the
reverse.

```bash
python3 <SOLVER.py> --input <SMALLEST_SAMPLE_INPUT> --verbose 2>&1 | tail -n 20
```

Expected: one correct, printed answer for one sample, with enough logging that you can see the path
taken. If the first sample is wrong, no amount of concurrency will help; stop and fix correctness.

## Symptoms

- A challenge asks you to process many inputs, run a simulation, or write a solver against a large
  dataset with a time limit.
- A teammate proposes spinning up many workers immediately.
- Your solver works on one example and produces nonsense on the batch.

## Prerequisites and assumptions

- The smallest valid input and its expected answer (from the challenge statement or a probe).
- A local file or fixture to run against. Any action against a shared or event system stays dry-run until
  the rules are confirmed — automation permission is event-specific and the corpus records that primer
  patterns (attack-info APIs, scheduling) do not transfer between events.
- A time budget and a stop condition, not just a goal.

## Diagnostic sequence

1. Solve one instance by hand or with a trivial script. Record the exact expected output.
2. Implement the general solver and run it on the smallest sample, then on a second, slightly harder
   sample. Two successful general cases is the minimum evidence that the model generalizes.
3. Add logging and structured output (input id, answer, elapsed) before adding parallelism. You cannot
   debug worker output you never recorded.
4. Only now parallelize, with bounded concurrency, a per-item timeout, and a global kill switch. Run the
   batch on the full dataset only after a small subset matches known answers.
5. Sanity-check the aggregate: partial results, failure counts, and runtime versus the remaining clock.
   A fast wrong answer is worse than a slow right one.

If the solver fails on the second sample → your model is overfitted to sample one; fix it before any
performance work. If the solver is correct but too slow → optimize the algorithm and measure, rather than
adding workers to a slow kernel. If correctness is unknown because no expected answers exist → keep
logging and comparisons explicit, and label the result as unverified.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| one-sample run with `--verbose` | correct answer + path | Correctness baseline established |
| two-sample run | both correct | Generalization evidence; proceed to scale |
| batch subset vs known answers | all matching | Ready for the full dataset |
| failure counts in structured output | some items errored | Handle before scaling; timeouts may be masking logic bugs |
| elapsed time vs remaining clock | margin | Whether to optimize or to stop and bank the partial result |

## Failure modes and things teams stopped doing

- Parallelizing a wrong solver. It fails faster and makes the failure harder to read; the log-noise
  version of this is what makes debugging expensive under time pressure.
- Copying a solo participant's automation design into a team run. The corpus records one solo player's
  tooling and behaviour as setup-specific; team coordination, ownership, and shared state change the
  requirements (see the service-board discipline in the operations research).
- Enabling external automation because "the script works". Rules on scanning and automation are
  event-specific and often unknown; the repository's operating doctrine is dry-run plus a written
  question to the organizer.
- Skipping logging because the answer is what matters. Without per-item records you cannot tell a wrong
  answer from a missing answer, and you cannot re-run only the failures.
- Optimizing before measuring. Choose the algorithm with a measurement, then the concurrency.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing. No solver or benchmark was executed in this session; the workflow is
  a rewrite of repository draft MISC-004/automation material, and the "solo setup may not transfer" caveat
  comes from the source notes recorded in the repository index.
- **Our adaptation vs the source:** the two-sample generalization gate, the structured-output-before-
  parallelism rule, and the partial-result banking branch are our additions.

## Sources

- `src-onemanparty-faustctf2025-6368aeaf` — first-hand account of solo tooling, a packet-capture analyser, and
  parallel automation in an attack/defend event; the repository index specifically warns that this setup
  may not transfer to a team environment.
- `src-maplebacon-ad-primer-23bd534f` — primer material that mixes transferable patterns with
  competition-dependent features such as automation APIs and scoring, hence the rule gate on external
  automation.
- `src-dttw-defcon2021-retro-14eb5491` — team-level evidence of how workload and coordination change
  what automation is actually useful.
