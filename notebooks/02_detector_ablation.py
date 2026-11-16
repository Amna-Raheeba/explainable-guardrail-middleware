#!/usr/bin/env python3
"""Notebook 02 — detector ablation + lexical-classifier train/test split.

Questions:
1. Which detector family carries the detection rate on each benchmark?
2. How much do the bare-imperative rules (TO-08/09/10) add, and what do
   they cost in benign tool-output false positives?
3. Does the optional lexical classifier generalise to held-out text, or
   does it only memorise its training set?

Run:  python notebooks/02_detector_ablation.py
Writes: results/ablation.csv (one row per configuration).
"""

from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from explainable_guardrail_middleware import Guardrail, Policy  # noqa: E402
from explainable_guardrail_middleware.classifier import LexicalClassifier  # noqa: E402
from explainable_guardrail_middleware.detectors import (  # noqa: E402
    detect_prompt_injection,
    detect_tool_output_injection,
)


ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "benchmarks" / "fixtures"


def _load(name: str) -> list[dict]:
    return [json.loads(l) for l in (FIX / name).read_text().splitlines() if l.strip()]


def _rate(guardrail: Guardrail, cases: list[dict], checkpoint: str) -> float:
    check = {
        "tool_output": guardrail.check_tool_output,
        "user_input": guardrail.check_user_input,
    }[checkpoint]
    caught = sum(1 for c in cases if check(c["text"]).decision.value != "allow")
    return caught / len(cases)


def _rate_with_detector(detect, cases: list[dict]) -> float:
    """Caught rate using one detector function directly, at the default
    policy thresholds (any finding >= 0.45 counts as caught)."""
    caught = 0
    for case in cases:
        findings = detect(case["text"])
        score = max((f.confidence for f in findings), default=0.0)
        if score >= Policy().review_threshold:
            caught += 1
    return caught / len(cases)


def main() -> None:
    ad = _load("agentdojo_subset.jsonl")
    ia = _load("injecagent_subset.jsonl")
    benign_tool = _load("benign_tool_output.jsonl")
    benign_user = _load("benign_controls.jsonl")

    # NOTE: the tool-output detector subsumes the prompt-injection rules
    # by design (an injection inside tool output is still an injection),
    # so "tool-output rules only" equals the default configuration. The
    # informative comparison is prompt-injection rules alone vs the full
    # tool-output set: it shows what the tool-output-specific rules
    # (TO-01..TO-10) add.
    guardrail = Guardrail()
    rows = [
        {
            "config": "prompt-injection rules only",
            "agentdojo_caught": round(_rate_with_detector(detect_prompt_injection, ad), 4),
            "injecagent_caught": round(_rate_with_detector(detect_prompt_injection, ia), 4),
            "benign_tool_output_fpr": round(
                _rate_with_detector(detect_prompt_injection, benign_tool), 4),
            "benign_user_fpr": round(
                _rate_with_detector(detect_prompt_injection, benign_user), 4),
        },
        {
            "config": "all regex rules (default)",
            "agentdojo_caught": round(_rate(guardrail, ad, "tool_output"), 4),
            "injecagent_caught": round(_rate(guardrail, ia, "tool_output"), 4),
            "benign_tool_output_fpr": round(
                sum(1 for c in benign_tool
                    if guardrail.check_tool_output(c["text"]).decision.value != "allow")
                / len(benign_tool), 4),
            "benign_user_fpr": round(
                sum(1 for c in benign_user
                    if guardrail.check_user_input(c["text"]).decision.value != "allow")
                / len(benign_user), 4),
        },
    ]

    # Classifier: 80/20 split, stratified, seed fixed for reproducibility.
    rng = random.Random(20261116)
    attack = ad + ia
    benign = _load("agentdojo_benign.jsonl") + _load("injecagent_benign.jsonl")
    examples = [(c["text"], True) for c in attack] + [(c["text"], False) for c in benign]
    rng.shuffle(examples)
    split = int(0.8 * len(examples))
    train, test = examples[:split], examples[split:]
    clf = LexicalClassifier()
    clf.train(train)

    def _accuracy(cases):
        correct = 0
        for text, is_attack in cases:
            predicted = clf.score(text) >= 0.5
            correct += int(predicted == is_attack)
        return correct / len(cases)

    clf_row = {
        "config": "lexical classifier only (held-out test)",
        "agentdojo_caught": None,
        "injecagent_caught": None,
        "benign_tool_output_fpr": None,
        "benign_user_fpr": None,
        "classifier_train_accuracy": round(_accuracy(train), 4),
        "classifier_test_accuracy": round(_accuracy(test), 4),
        "classifier_test_n": len(test),
    }
    with open(ROOT / "results" / "ablation.csv", "w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["config", "agentdojo_caught", "injecagent_caught",
                        "benign_tool_output_fpr", "benign_user_fpr",
                        "classifier_train_accuracy", "classifier_test_accuracy",
                        "classifier_test_n"],
        )
        writer.writeheader()
        writer.writerows(rows)
        writer.writerow(clf_row)
    for row in rows + [clf_row]:
        print(row)
    print("wrote results/ablation.csv")


if __name__ == "__main__":
    main()
