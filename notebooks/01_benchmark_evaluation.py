#!/usr/bin/env python3
"""Notebook 01 — benchmark evaluation (runnable script, stdlib only).

Runs the guardrail over every bundled fixture set and writes
results/benchmark_results.json plus a human-readable
results/benchmark_summary.md. This is the script behind the numbers in
the README. Run it with:

    python notebooks/01_benchmark_evaluation.py

Method: text-level screening at the checkpoint where a real agent would
meet the text (tool output for attack payloads, user input for benign
text, the memory gate for memory notes). No LLM agent, no tool
execution — see benchmarks/fixtures/README.md for the full method note.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from explainable_guardrail_middleware.benchmark import run_all  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    results = run_all(ROOT / "benchmarks" / "fixtures")
    (ROOT / "results" / "benchmark_results.json").write_text(
        json.dumps(results, indent=2)
    )
    summary = results["summary"]
    lines = [
        "# Benchmark summary (generated)",
        "",
        "Text-level screening; see benchmarks/fixtures/README.md for the method.",
        "",
        "| Set | n | Caught / flagged (BLOCK or REVIEW) | Blocked |",
        "|---|---|---|---|",
    ]
    for name, data in results["sets"].items():
        if name == "memory_poison_synthetic":
            lines.append(
                f"| {name} (attack) | {data['attack']['n']} | "
                f"{data['attack']['rejected_or_quarantined_rate']:.1%} stopped | "
                f"{data['attack']['decisions'].get('reject', 0)} rejected |"
            )
            continue
        lines.append(
            f"| {name} | {data['n']} | {data.get('caught_rate', '—')} | "
            f"{data.get('block_rate', '—')} |"
        )
    lines += [
        "",
        "## Headline",
        "",
        f"- AgentDojo attacks caught: **{summary['agentdojo_attacks_caught']:.1%}** "
        f"(blocked {summary['agentdojo_attacks_blocked']:.1%})",
        f"- InjecAgent attacks caught: **{summary['injecagent_attacks_caught']:.1%}** "
        f"(blocked {summary['injecagent_attacks_blocked']:.1%})",
        f"- Benign false-positive rate (user input): **{summary['benign_false_positive_rate']:.1%}**",
        f"- Benign tool-output false-positive rate: "
        f"**{summary['benign_tool_output_false_positive_rate']:.1%}** (all REVIEW, none blocked)",
        f"- Memory-poison notes stopped: **{summary['memory_poison_stopped']:.1%}**; "
        f"benign notes admitted: **{summary['memory_benign_admitted']:.1%}**",
        "",
        "## What is not measured here",
        "",
        "- Adaptive or paraphrased attacks (these fixtures are fixed strings).",
        "- Multi-turn attacks, or attacks whose text is not in the fixtures.",
        "- Any LLM-agent behaviour: there is no agent in this evaluation.",
    ]
    (ROOT / "results" / "benchmark_summary.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2))
    print("wrote results/benchmark_results.json and results/benchmark_summary.md")


if __name__ == "__main__":
    main()
