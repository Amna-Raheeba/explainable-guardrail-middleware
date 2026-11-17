# Counterfactual pass probe — measured results

Measured 2026-11-17 with `python notebooks/03_counterfactual_probe.py`. Every blocked case from the AgentDojo (230) and InjecAgent (1,054) fixtures was probed at the tool_output checkpoint; the action and model-output sets are hand-built (24 + 6 cases).

| Set | Blocked | Passed | Verified pass | Partial (REVIEW) | No edit | Median edit size |
|---|---|---|---|---|---|---|
| agentdojo_attacks | 172 | 169 (98.3%) | 169 (100.0%) | 3 (1.7%) | 0 | 79 chars |
| injecagent_attacks | 340 | 340 (100.0%) | 340 (100.0%) | 0 (0.0%) | 0 | 40.5 chars |
| action_synthetic | 24 | 20 (83.3%) | 20 (100.0%) | 4 (16.7%) | 0 | 32.0 chars |
| model_output_pii_synthetic | 6 | 6 (100.0%) | 6 (100.0%) | 0 (0.0%) | 0 | 27.5 chars |

**Overall:** 535/542 blocked cases reach ALLOW (98.7%), 535 of those verified ALLOW on an independent re-run (100.0%); 7 reach REVIEW only (1.3%); median edit size 43 chars, median 1 edit(s); median probe latency 0.51 ms.

## What the numbers mean

- A pass is verified twice: once inside the probe (an edit is only accepted after the checkpoint re-runs ALLOW) and once by the independent re-check above. A reported pass is a measured pass.
- The 7 partial cases (1.3%) split two ways. Four are GH-02: the action's content is unrelated to the goal, and no span edit can fix "wrong goal" — the probe refuses to delete the whole action and reports that instead. The other three are AgentDojo cases where span removal re-joins the remaining text into a new REVIEW-level match at the same confidence (deleting an imperative sentence joins 'Do ...' to '... instead', firing PI-16), so the score never drops. The probe only edits finding spans, never sub-spans, so it cannot break that join — a real limitation, not a bug.
- AgentDojo payloads need more edits than InjecAgent ones (median 2 edits / 79 chars vs 1 / 40.5): they stack several rules (override phrase + action + destination), so the probe clears them one finding at a time.
- Edits are minimal in the detectors' feature space, not semantic guarantees: removing a matched span makes the text pass because no rule fires on what is left. See README §7.
