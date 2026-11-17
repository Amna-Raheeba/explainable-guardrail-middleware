# Metrics

All definitions are for the text-level fixture evaluation in
`notebooks/01_benchmark_evaluation.py`. They are detection rates at the
guardrail checkpoint, not attack success rates.

## Caught rate

Fraction of attack cases whose verdict was BLOCK or REVIEW — i.e. the
text did not pass through silently. Reported alongside the block rate
because a REVIEW still stops an autonomous agent configured to
escalate, and reporting only BLOCK would understate the guardrail while
reporting only "caught" would overstate it.

## Block rate

Fraction of attack cases whose verdict was BLOCK (score ≥ 0.75).

## False-positive rate

Fraction of benign cases whose verdict was not ALLOW. Measured
separately at the two checkpoints where benign text is screened:

- **User input** (n=1,203): AgentDojo user prompts, InjecAgent user
  instructions, synthetic memory notes, hand-written controls.
- **Tool output** (n=24): hand-written benign tool outputs (product
  pages, reviews, calendar entries, file listings).

The split matters: the imperative-language rules (TO-08/09/10) can only
false-positive at the tool-output checkpoint, and hiding them inside
the user-input rate would conceal their cost.

## Memory-gate rates

- **Stopped rate**: fraction of poisoned notes decided REJECT or
  QUARANTINE.
- **Admitted rate**: fraction of benign notes decided ADMIT.

## Latency

Wall-clock milliseconds per `check_*` call, measured in-process during
the benchmark run (median and p95 per set, in
`results/benchmark_results.json`).

## Classifier accuracy

Train/test accuracy of `LexicalClassifier` on an 80/20 stratified
split of the fixture texts (seed 20261116, n=490 held out). Reported
in `results/ablation.csv`. Caveat: train and test come from the same
benchmark text, so this measures fit to these fixtures, not
generalisation to new attack families.

## Counterfactual probe rates

Measured in `notebooks/03_counterfactual_probe.py` over every BLOCKED
case (542: 172 AgentDojo + 340 InjecAgent at the tool_output checkpoint,
24 hand-built goal/action pairs, 6 hand-built PII leaks).

- **Pass rate**: fraction of blocked cases whose probe edit re-verdicts
  ALLOW. Overall 98.7% (535/542).
- **Verified pass rate**: of those passes, the fraction confirmed ALLOW
  by an *independent* re-run of the same checkpoint on the edited text
  (a second check, separate from the re-runs inside the probe).
  100% (535/535) — a reported pass is a measured pass.
- **Partial rate**: fraction reaching REVIEW only (1.3%, 7 cases) — 4
  GH-02 (wrong goal, unfixable by span edits by design) and 3 where
  span removal re-joins the text into a new REVIEW-level match at the
  same confidence.
- **Median edit size**: characters removed + inserted across the applied
  edits. Overall 43 chars; median 1 edit. AgentDojo payloads need more
  (79 chars, 2 edits) because they stack several rules.
- **Probe latency**: median wall-clock ms per blocked case, 0.6 ms.
