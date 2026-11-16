# Changelog

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
