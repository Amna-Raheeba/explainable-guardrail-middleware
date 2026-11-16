# Benchmark fixtures — provenance and method

## What these files are

Text-level fixture subsets extracted from two public benchmarks, plus two
hand-written sets. They let the guardrail be measured without an LLM
agent, a model key, or any network access.

| File | Cases | Source |
|---|---|---|
| `agentdojo_subset.jsonl` | 230 attack | AgentDojo: 46 unique attacker GOAL strings from the injection-task definitions, each rendered through the four canonical attack templates (`important_instructions`, `ignore_previous`, `system_message`, `direct`) plus the bare goal. Templates copied verbatim from `src/agentdojo/attacks/*.py`. |
| `agentdojo_benign.jsonl` | 109 benign | AgentDojo: the PROMPT strings of the user tasks. |
| `injecagent_subset.jsonl` | 1,054 attack | InjecAgent base test cases (510 direct-harm + 544 data-stealing): the verbatim `Tool Response` field, which embeds the attacker instruction inside a tool output. |
| `injecagent_benign.jsonl` | 1,054 benign | InjecAgent: the `User Instruction` field of the same cases. |
| `memory_poison_synthetic.jsonl` | 15 attack, 10 benign | Hand-written by the author, labelled SYNTHETIC. Attack notes follow the AgentPoison (NeurIPS 2024) and MINJA (NeurIPS 2025) shapes: persistence directives, conditional triggers, and standing exfiltration instructions. |
| `benign_controls.jsonl` | 30 benign | Hand-written by the author, labelled SYNTHETIC. Ordinary agent text, including user-authored action requests ("Send a message to Sara...") that must NOT be flagged — the user is allowed to instruct their own agent. |

## Source provenance

- AgentDojo — github.com/ethz-spylab/agentdojo, commit
  `089ed468cf3ed0322acc66b0211f26d9d90dbf60`, MIT licence.
  Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate
  Prompt Injection Attacks and Defenses for LLM Agents", NeurIPS 2024.
  Full benchmark: 97 user tasks, 629 security cases.
- InjecAgent — github.com/uiuc-kang-lab/InjecAgent, commit
  `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`.
  Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections in
  Tool-Integrated Large Language Model Agents", arXiv:2403.02691.
  Full benchmark: 1,054 test cases, 17 user tools, 62 attacker tools.

Extraction is reproducible: `scripts/extract_benchmark_fixtures.py`
regenerates all four benchmark-derived files from local clones.

## Method — read this before quoting any number

This is a **text-level screening evaluation, not a full agent replay**.
The guardrail screens the attack payload text at the checkpoint where a
real agent would meet it (tool output for AgentDojo/InjecAgent payloads,
the memory gate for memory notes). There is no LLM agent, no tool
execution, and no environment state, so these numbers are **detection
rates at the guardrail checkpoint**, not attack success rates and not
comparable to the ASR figures in the benchmark papers.

- "Caught" = verdict BLOCK or REVIEW (the text did not pass silently).
- "Blocked" = verdict BLOCK alone. Both are always reported.
- Benign false-positive rate is measured on the benign sets at the
  `user_input` checkpoint, because that is where benign user text is
  screened in a real deployment.

## Why a subset, not the full benchmarks

AgentDojo's full 629 cases need an LLM agent running its environment;
InjecAgent's full evaluation needs tool execution. What can be measured
honestly offline is the text the attacker plants. The subset is every
unique attacker goal in AgentDojo (46) and every base InjecAgent case
(1,054 — the complete base set, not a sample). What is *not* measured
here: adaptive attacks, paraphrased injections, multi-turn attacks, and
any attack family whose text is not in these files. Those limits are
stated in the README and the experiment log, not hidden.
