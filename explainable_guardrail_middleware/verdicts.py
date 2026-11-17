"""Verdict types: every decision ships with its reason trace.

The design point of this package: a guardrail verdict is not a boolean.
It is a decision *plus* the evidence that produced it, so a human (or an
audit) can replay exactly why a message was allowed, escalated, or
blocked. Nothing here is a black box.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    """The three outcomes a guardrail check can produce."""

    ALLOW = "allow"  # No finding reached the review threshold.
    REVIEW = "review"  # Something suspicious; a human (or a stricter policy) decides.
    BLOCK = "block"  # A finding reached the block threshold. Fail closed.


@dataclass(frozen=True)
class Finding:
    """One piece of evidence behind a verdict.

    Every finding names the exact rule that fired, the text span it fired
    on, and a confidence in [0, 1]. A verdict with no findings is an
    ALLOW with an empty reason trace — which is itself informative.
    """

    rule_id: str  # e.g. "PI-01", stable across versions
    detector: str  # e.g. "prompt_injection"
    category: str  # e.g. "prompt_injection", "pii", "memory_write"
    span: str  # the matched text (truncated to 160 chars)
    span_start: int  # character offset of the match, -1 if not positional
    span_end: int
    confidence: float  # 0..1
    explanation: str  # one plain sentence a human can read

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "detector": self.detector,
            "category": self.category,
            "span": self.span,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "confidence": round(self.confidence, 3),
            "explanation": self.explanation,
        }


@dataclass
class ReasonTrace:
    """The human-readable explanation of a verdict."""

    decision: Decision
    score: float  # highest finding confidence, 0.0 when no findings
    findings: list[Finding] = field(default_factory=list)
    policy_version: str = "1.0.0"

    def lines(self) -> list[str]:
        """One plain-English line per finding, most confident first."""
        if not self.findings:
            return [
                "ALLOW (score 0.00): no detector fired; "
                "nothing in the text matched any rule."
            ]
        out = [
            f"{self.decision.value.upper()} (score {self.score:.2f}): "
            f"{len(self.findings)} finding(s)."
        ]
        for f in sorted(self.findings, key=lambda x: -x.confidence):
            span = f.span.replace("\n", " ")
            out.append(
                f"  [{f.rule_id}] {f.detector} "
                f"(confidence {f.confidence:.2f}): {f.explanation} "
                f"Matched: \"{span}\""
            )
        return out

    def text(self) -> str:
        return "\n".join(self.lines())


@dataclass
class Verdict:
    """The complete result of one guardrail check."""

    decision: Decision
    score: float
    findings: list[Finding] = field(default_factory=list)
    policy_version: str = "1.0.0"
    input_sha256: str = ""
    audit_id: str = ""  # sequence number in the audit log, "" when not logged

    @property
    def trace(self) -> ReasonTrace:
        return ReasonTrace(
            decision=self.decision,
            score=self.score,
            findings=self.findings,
            policy_version=self.policy_version,
        )

    def explain(self) -> str:
        return self.trace.text()

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "score": round(self.score, 3),
            "policy_version": self.policy_version,
            "input_sha256": self.input_sha256,
            "audit_id": self.audit_id,
            "findings": [f.to_dict() for f in self.findings],
        }

    @staticmethod
    def input_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
