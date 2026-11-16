"""Explainable Guardrail Middleware — a glass-box guardrail for agents.

Every verdict ships with a reason trace: which rule fired, on what span,
with what confidence. See README.md for the design and the measured
results on AgentDojo / InjecAgent fixture subsets.
"""

from .audit import AuditLog
from .classifier import LexicalClassifier
from .guardrail import Guardrail, Policy
from .memory_gate import MemoryDecision, MemoryScreen, screen_memory_write
from .pii import detect_pii, redact
from .verdicts import Decision, Finding, ReasonTrace, Verdict

__version__ = "0.1.0"
__all__ = [
    "AuditLog",
    "Decision",
    "Finding",
    "Guardrail",
    "LexicalClassifier",
    "MemoryDecision",
    "MemoryScreen",
    "Policy",
    "ReasonTrace",
    "Verdict",
    "detect_pii",
    "redact",
    "screen_memory_write",
]
