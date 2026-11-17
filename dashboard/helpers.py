"""Dashboard helpers: pure functions, no Streamlit import.

Kept separate from app.py so the logic is unit-tested (see
tests/test_dashboard_helpers.py) and the dashboard is a thin view over
the real pipeline, not a second implementation of it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Usable from the repo root and from inside dashboard/ alike.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from explainable_guardrail_middleware import Guardrail
from explainable_guardrail_middleware.audit import AuditLog
from explainable_guardrail_middleware.memory_gate import MemoryDecision
from explainable_guardrail_middleware.pii import redact

ROOT = Path(__file__).resolve().parent.parent


def screen_text(text: str, checkpoint: str) -> dict:
    """Run one checkpoint and return a JSON-safe verdict dict."""
    guardrail = Guardrail()
    check = {
        "user_input": guardrail.check_user_input,
        "tool_output": guardrail.check_tool_output,
        "model_output": guardrail.check_model_output,
    }[checkpoint]
    verdict = check(text)
    return verdict.to_dict()


def probe_text(text: str, checkpoint: str, user_goal: str = "") -> dict:
    """Probe a blocked verdict for the minimal edit that lets it pass.

    Returns the probe as a JSON-safe dict (see counterfactual.PassProbe).
    """
    guardrail = Guardrail()
    probe = guardrail.probe_pass(text, checkpoint, user_goal=user_goal)
    return probe.to_dict()


def screen_memory(note: str, source: str) -> dict:
    """Screen a memory write; returns decision + findings as plain data."""
    guardrail = Guardrail()
    screen = guardrail.check_memory_write(note, source=source)
    return {
        "decision": screen.decision.value,
        "explanation": screen.explain(),
        "findings": [
            {
                "rule_id": f.rule_id,
                "detector": f.detector,
                "confidence": round(f.confidence, 2),
                "explanation": f.explanation,
                "span": f.span,
            }
            for f in screen.findings
        ],
    }


def load_benchmark_results(path: str | Path | None = None) -> dict | None:
    """Load results/benchmark_results.json if it exists, else None."""
    path = Path(path) if path else ROOT / "results" / "benchmark_results.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def benchmark_table(results: dict) -> list[dict]:
    """One row per evaluated set, for display."""
    rows = []
    for name, data in results.get("sets", {}).items():
        if name == "memory_poison_synthetic":
            rows.append({
                "set": name,
                "n": data["attack"]["n"] + data["benign"]["n"],
                "caught / stopped": data["attack"]["rejected_or_quarantined_rate"],
                "blocked": None,
                "false positives": 1 - data["benign"]["decisions"].get("admit", 0) / data["benign"]["n"],
            })
            continue
        n = data["n"]
        decisions = data["decisions"]
        rows.append({
            "set": name,
            "n": n,
            "caught / stopped": data.get("caught_rate"),
            "blocked": data.get("block_rate"),
            "false positives": round(1 - decisions.get("allow", 0) / n, 4) if name.startswith("benign") else None,
        })
    return rows


def highlight_spans(text: str, findings: list[dict]) -> str:
    """Wrap matched spans in <mark> tags for display (HTML-escaped)."""
    import html

    spans = sorted(
        {(f.get("span_start", -1), f.get("span_end", -1)) for f in findings
         if f.get("span_start", -1) >= 0},
    )
    if not spans:
        return html.escape(text)
    out: list[str] = []
    pos = 0
    for start, end in spans:
        if start < pos:
            continue
        out.append(html.escape(text[pos:start]))
        out.append("<mark>" + html.escape(text[start:end]) + "</mark>")
        pos = end
    out.append(html.escape(text[pos:]))
    return "".join(out)


def verify_audit_log(path: str | Path) -> tuple[bool, str]:
    return AuditLog(path).verify()


def redacted(text: str) -> str:
    return redact(text)


def memory_decision_label(decision: str) -> str:
    return {
        MemoryDecision.ADMIT.value: "Admit — write it to memory",
        MemoryDecision.QUARANTINE.value: "Quarantine — hold for human review",
        MemoryDecision.REJECT.value: "Reject — do not write",
    }[decision]
