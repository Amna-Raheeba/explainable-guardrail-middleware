# Changelog

## 0.2.0 — 2026-11-17

- **New: counterfactual pass probe.** For a BLOCKED verdict,
  `Guardrail.probe_pass(text, checkpoint)` finds the minimal span-level
  edit that lets it pass — remove the matched span, redact PII to a
  typed placeholder (`[EMAIL]`, `[IBAN]`, `[CARD]`), or re-route a
  GH-01 destination to one the user's goal mentions — verified by
  re-running the checkpoint on the edited text. GH-02 has no edit by
  design (its span is the whole action). Measured on all 542 blocked
  cases (notebook 03, `results/probe_results.json`): 535 reach ALLOW
  (98.7%), 100% of passes verified on an independent re-run; 7 partial
  (1.3%); median edit 43 chars, median 1 edit, median probe latency
  0.6 ms. CLI: `guardrail probe "…" [--checkpoint …] [--goal …]`.
  Dashboard Check-text tab shows the minimal safe alternative for
  every BLOCK.
- Audit fixes: removed 8 dead-code findings (unused imports, unused
  variable, f-strings without placeholders) across the core, examples,
  notebooks, and scripts; added `tests/test_dashboard_app.py` pinning
  the Streamlit app with AppTest (0 exceptions).
- 107 pytest tests, all passing; GitHub Actions CI (Python
  3.10/3.11/3.12) now also runs notebook 03.

## 0.1.0 — 2026-11-16

First release.

- Glass-box guardrail: five checkpoints (user input, tool output, model
  output, proposed action, memory write), every verdict with a reason
  trace (rule id, matched span, confidence).
- Detectors: prompt injection (PI-01…PI-18), tool-output injection
  (TO-01…TO-10), goal hijack (GH-01, GH-02), PII leakage with IBAN
  mod-97 and card Luhn verification (PII-01…PII-06), memory-write
  admission with provenance (MG-01…MG-03), optional lexical log-odds
  classifier (capped, opt-in).
- Hash-chained JSONL audit log with `verify()`; log stores input
  SHA-256 and a PII-redacted excerpt, never raw input.
- Benchmark evaluation on real fixtures: AgentDojo subset (230 cases
  from 46 goals × 5 renderings) and the complete InjecAgent base set
  (1,054 cases), plus synthetic memory-poison (25) and benign sets.
  Measured: AgentDojo 90.9% caught / 74.8% blocked; InjecAgent 83.6%
  caught / 32.3% blocked; benign user-input FPR 0.0%; benign
  tool-output FPR 16.7% (REVIEW only); memory poison 15/15 stopped.
- Streamlit dashboard over the real pipeline (check text, memory gate,
  benchmarks, audit log), verified with AppTest.
- 85 pytest tests, all passing; GitHub Actions CI (Python 3.10/3.11/3.12).
