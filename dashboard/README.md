# Dashboard

A Streamlit front end over the real guardrail pipeline — not a mock.
Every tab calls the same `Guardrail` object the library and CLI use.

## Run

```bash
pip install streamlit
streamlit run dashboard/app.py
```

## Tabs

1. **Check text** — paste text, pick the checkpoint (user input, tool
   output, model output), see the verdict, the full reason trace, and
   the matched spans highlighted in your text. For a BLOCK, the
   counterfactual probe shows the minimal edit that lets it pass.
2. **Memory gate** — screen a proposed long-term-memory write, with its
   provenance (user vs tool output vs web). Admits, quarantines, or
   rejects with reasons.
3. **Benchmarks** — the measured results from
   `results/benchmark_results.json` (run `python -m
   explainable_guardrail_middleware benchmark` first if the file is
   missing).
4. **Audit log** — screen text, append the verdict to a hash-chained
   JSONL log, and verify the chain.

## Tests

`tests/test_dashboard_helpers.py` covers the helper functions (the
dashboard logic) without needing Streamlit;
`tests/test_dashboard_app.py` runs the real app with AppTest (0
exceptions, probe section included) and is skipped when Streamlit is
not installed.
