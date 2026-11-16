"""Text-level benchmark evaluation on the bundled fixtures.

What this is, precisely: the guardrail screens the *text* of benchmark
attack payloads (AgentDojo attack strings rendered through the four
canonical templates; InjecAgent tool responses verbatim) at the
checkpoint where a real agent would meet them (tool output). It is NOT
a full agent replay — there is no LLM agent here, no tool execution, and
no environment state — so the numbers are detection rates at the
guardrail checkpoint, not attack success rates. The fixture README
states the provenance and the exact counts.

"Caught" means the verdict was BLOCK or REVIEW (the text did not pass
through silently). "Blocked" means BLOCK alone. Both are reported,
because a REVIEW still stops an autonomous agent that is configured to
escalate — and because conflating the two would inflate the headline.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from pathlib import Path

from .guardrail import Guardrail


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _evaluate(
    guardrail: Guardrail, cases: list[dict], checkpoint: str
) -> dict:
    check = {
        "tool_output": guardrail.check_tool_output,
        "user_input": guardrail.check_user_input,
    }[checkpoint]
    decisions: Counter[str] = Counter()
    latencies: list[float] = []
    by_group: dict[str, Counter[str]] = defaultdict(Counter)
    for case in cases:
        started = time.perf_counter()
        verdict = check(case["text"])
        latencies.append((time.perf_counter() - started) * 1000.0)
        decisions[verdict.decision.value] += 1
        group = case.get("attack_template") or case.get("attack_type") or "all"
        by_group[group][verdict.decision.value] += 1
    n = len(cases)
    caught = decisions["block"] + decisions["review"]
    latencies.sort()
    return {
        "n": n,
        "decisions": dict(decisions),
        "caught": caught,
        "caught_rate": round(caught / n, 4) if n else None,
        "block_rate": round(decisions["block"] / n, 4) if n else None,
        "miss_rate": round(decisions["allow"] / n, 4) if n else None,
        "latency_ms_median": round(latencies[len(latencies) // 2], 2) if latencies else None,
        "latency_ms_p95": round(latencies[int(len(latencies) * 0.95)], 2) if latencies else None,
        "by_group": {
            group: {
                "n": sum(counts.values()),
                "caught_rate": round(
                    (counts["block"] + counts["review"]) / sum(counts.values()), 4
                ),
                "block_rate": round(counts["block"] / sum(counts.values()), 4),
            }
            for group, counts in sorted(by_group.items())
        },
    }


def run_all(fixtures_dir: Path) -> dict:
    """Run every bundled fixture set; returns the full results dict."""
    guardrail = Guardrail()
    results: dict = {"method": "text-level screening at the tool_output checkpoint; "
                     "no LLM agent, no tool execution (see benchmarks/fixtures/README.md)",
                     "sets": {}}

    ad_attack = _load(fixtures_dir / "agentdojo_subset.jsonl")
    ad_benign = _load(fixtures_dir / "agentdojo_benign.jsonl")
    ia_attack = _load(fixtures_dir / "injecagent_subset.jsonl")
    ia_benign = _load(fixtures_dir / "injecagent_benign.jsonl")
    mem = _load(fixtures_dir / "memory_poison_synthetic.jsonl")
    benign_extra = _load(fixtures_dir / "benign_controls.jsonl")

    results["sets"]["agentdojo_attacks"] = _evaluate(guardrail, ad_attack, "tool_output")
    results["sets"]["agentdojo_benign"] = _evaluate(guardrail, ad_benign, "user_input")
    results["sets"]["injecagent_attacks"] = _evaluate(guardrail, ia_attack, "tool_output")
    results["sets"]["injecagent_benign"] = _evaluate(guardrail, ia_benign, "user_input")

    mem_attack = [c for c in mem if c["label"] == "attack"]
    mem_benign = [c for c in mem if c["label"] == "benign"]
    mem_results: dict = {}
    for label, cases in (("attack", mem_attack), ("benign", mem_benign)):
        counts: Counter[str] = Counter()
        for case in cases:
            screen = guardrail.check_memory_write(
                case["text"], source=case.get("source", "unknown")
            )
            counts[screen.decision.value] += 1
        n = len(cases)
        mem_results[label] = {
            "n": n,
            "decisions": dict(counts),
            "rejected_or_quarantined_rate": round(
                (counts["reject"] + counts["quarantine"]) / n, 4
            ) if n else None,
        }
    results["sets"]["memory_poison_synthetic"] = mem_results

    benign_all = ad_benign + ia_benign + mem_benign + benign_extra
    results["sets"]["benign_all"] = _evaluate(guardrail, benign_all, "user_input")

    # Benign tool output is screened at the tool_output checkpoint, where
    # the imperative-language rules (TO-08/09/10) can false-positive.
    # It is reported separately so a tool-output false alarm is never
    # hidden inside the user-input false-positive rate.
    benign_tool = _load(fixtures_dir / "benign_tool_output.jsonl")
    results["sets"]["benign_tool_output"] = _evaluate(guardrail, benign_tool, "tool_output")

    summary = {
        "agentdojo_attacks_caught": results["sets"]["agentdojo_attacks"]["caught_rate"],
        "agentdojo_attacks_blocked": results["sets"]["agentdojo_attacks"]["block_rate"],
        "injecagent_attacks_caught": results["sets"]["injecagent_attacks"]["caught_rate"],
        "injecagent_attacks_blocked": results["sets"]["injecagent_attacks"]["block_rate"],
        "benign_false_positive_rate": round(
            1 - results["sets"]["benign_all"]["decisions"].get("allow", 0)
            / results["sets"]["benign_all"]["n"], 4
        ),
        "benign_tool_output_false_positive_rate": round(
            1 - results["sets"]["benign_tool_output"]["decisions"].get("allow", 0)
            / results["sets"]["benign_tool_output"]["n"], 4
        ),
        "memory_poison_stopped": mem_results["attack"]["rejected_or_quarantined_rate"],
        "memory_benign_admitted": round(
            mem_results["benign"]["decisions"].get("admit", 0) / mem_results["benign"]["n"], 4
        ),
    }
    results["summary"] = summary
    return results
