"""Memory-write admission: the screen in front of long-term memory.

The threat (AgentPoison, NeurIPS 2024; MINJA, NeurIPS 2025): an agent
that writes its own memory can be tricked into storing an attacker's
instruction, which is then retrieved and obeyed in later sessions —
possibly by a different user. Google's Agent Anomaly Detection
benchmark (12 Nov 2026) caught only 4 of 18 such cases after the fact.

This gate runs *before* the write. A memory write is admitted only if
it is clean, or quarantined for a human to review, or rejected outright.
Provenance — where the note came from — is part of the decision: a note
the user wrote is trusted more than one summarised from tool output,
because tool output is attacker-controlled data.

Decisions: ADMIT (write it), QUARANTINE (hold for human review),
REJECT (do not write, log it).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .detectors import detect_prompt_injection, detect_tool_output_injection
from .pii import detect_pii
from .verdicts import Finding

_PERSISTENCE = re.compile(
    r"\b(always|never|from now on|remember to|make sure to|in all future|every time)\b.{0,60}",
    re.IGNORECASE,
)
_TRIGGER = re.compile(
    r"\b(when|whenever|if)\b[^.\n]{0,40}?\b(ask\w*|mention\w*|talk about|request\w*|say\w*)\b[^.\n]{0,60}?\b(then|do|send|tell|share|reveal|forward)\b",
    re.IGNORECASE,
)
_EXFIL = re.compile(
    r"(send|email|share|forward|post|reveal|leak)\s+.{0,40}?\s+to\s+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?://\S+)",
    re.IGNORECASE,
)
_TRUSTED_SOURCES = {"user", "developer", "system"}


class MemoryDecision(str, Enum):
    ADMIT = "admit"
    QUARANTINE = "quarantine"
    REJECT = "reject"


@dataclass
class MemoryScreen:
    decision: MemoryDecision
    findings: list[Finding] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)

    def explain(self) -> str:
        if not self.findings:
            return (
                f"{self.decision.value.upper()}: the note is clean — no embedded "
                f"instructions, no persistence directive, no exfiltration target, "
                f"no PII. Source: {self.provenance.get('source', 'unknown')}."
            )
        lines = [f"{self.decision.value.upper()}: {len(self.findings)} finding(s)."]
        for f in sorted(self.findings, key=lambda x: -x.confidence):
            lines.append(
                f"  [{f.rule_id}] {f.detector} ({f.confidence:.2f}): "
                f"{f.explanation} Matched: \"{f.span.replace(chr(10), ' ')}\""
            )
        return "\n".join(lines)


def screen_memory_write(
    note: str,
    source: str = "unknown",
    author: str = "unknown",
    session_id: str = "",
) -> MemoryScreen:
    """Decide whether `note` may be written to long-term memory.

    `source` is where the note's content came from: "user" (typed by the
    user), "tool_output" (summarised from something a tool returned),
    "web" / "document" (retrieved content), or "unknown".
    """
    provenance = {"source": source, "author": author, "session_id": session_id}
    findings: list[Finding] = []

    trusted = source in _TRUSTED_SOURCES
    if trusted:
        injection = detect_prompt_injection(note)
        # A user writing their own note may legitimately quote instructions;
        # only high-confidence, explicit override phrasing counts against it.
        injection = [f for f in injection if f.confidence >= 0.90]
    else:
        injection = detect_tool_output_injection(note)
    findings.extend(injection)

    for match in _EXFIL.finditer(note):
        findings.append(
            Finding(
                rule_id="MG-01",
                detector="memory_gate",
                category="memory_write",
                span=match.group(0)[:160],
                span_start=match.start(),
                span_end=match.end(),
                confidence=0.95,
                explanation=(
                    "The note tells a future session to send data to an outside "
                    "address. A standing exfiltration instruction in memory is "
                    "exactly how a poisoned memory pays off."
                ),
            )
        )
    for match in _PERSISTENCE.finditer(note):
        findings.append(
            Finding(
                rule_id="MG-02",
                detector="memory_gate",
                category="memory_write",
                span=match.group(0)[:160],
                span_start=match.start(),
                span_end=match.end(),
                confidence=0.60,
                explanation=(
                    "Persistence directive ('always'/'never'/'from now on'): the "
                    "note tries to change the agent's behaviour in all future sessions."
                ),
            )
        )
    for match in _TRIGGER.finditer(note):
        findings.append(
            Finding(
                rule_id="MG-03",
                detector="memory_gate",
                category="memory_write",
                span=match.group(0)[:160],
                span_start=match.start(),
                span_end=match.end(),
                confidence=0.70,
                explanation=(
                    "Conditional trigger: 'when the user asks about X, do Y'. "
                    "This is the AgentPoison shape — a dormant instruction that "
                    "fires only when its trigger appears."
                ),
            )
        )
    for f in detect_pii(note):
        findings.append(
            Finding(
                rule_id=f.rule_id,
                detector="memory_gate",
                category="memory_write",
                span=f.span,
                span_start=f.span_start,
                span_end=f.span_end,
                confidence=min(f.confidence, 0.70),
                explanation="The note would store personal data in long-term memory: " + f.explanation,
            )
        )

    if not findings:
        return MemoryScreen(MemoryDecision.ADMIT, [], provenance)
    top = max(f.confidence for f in findings)
    if top >= 0.85:
        decision = MemoryDecision.REJECT
    else:
        decision = MemoryDecision.QUARANTINE
    return MemoryScreen(decision, findings, provenance)
