# Benchmark summary (generated)

Text-level screening; see benchmarks/fixtures/README.md for the method.

| Set | n | Caught / flagged (BLOCK or REVIEW) | Blocked |
|---|---|---|---|
| agentdojo_attacks | 230 | 0.9087 | 0.7478 |
| agentdojo_benign | 109 | 0.0 | 0.0 |
| injecagent_attacks | 1054 | 0.8359 | 0.3226 |
| injecagent_benign | 1054 | 0.0 | 0.0 |
| memory_poison_synthetic (attack) | 15 | 100.0% stopped | 7 rejected |
| benign_all | 1203 | 0.0 | 0.0 |
| benign_tool_output | 24 | 0.1667 | 0.0 |

## Headline

- AgentDojo attacks caught: **90.9%** (blocked 74.8%)
- InjecAgent attacks caught: **83.6%** (blocked 32.3%)
- Benign false-positive rate (user input): **0.0%**
- Benign tool-output false-positive rate: **16.7%** (all REVIEW, none blocked)
- Memory-poison notes stopped: **100.0%**; benign notes admitted: **100.0%**

## What is not measured here

- Adaptive or paraphrased attacks (these fixtures are fixed strings).
- Multi-turn attacks, or attacks whose text is not in the fixtures.
- Any LLM-agent behaviour: there is no agent in this evaluation.
