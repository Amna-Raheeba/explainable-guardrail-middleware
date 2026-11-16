"""Detectors: regex/lexical rules with a confidence and a span each.

Every detector returns a list of Findings. A detector never decides
anything on its own — scoring lives in guardrail.py, so the rules stay
auditable and the policy stays changeable without touching detection.

Confidence is a per-rule constant, set when the rule was written from
how specific the pattern is (a literal "ignore all previous
instructions" is 0.95; a bare imperative verb is 0.55). It is not a
calibrated probability; the experiment notebook measures how these
constants behave on real benchmark text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .verdicts import Finding

MAX_SPAN = 160


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: str  # regex, matched case-insensitively unless noted
    confidence: float
    explanation: str
    flags: int = re.IGNORECASE | re.DOTALL


def _find(rule: Rule, detector: str, category: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(rule.pattern, text, flags=rule.flags):
        span = match.group(0)
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                detector=detector,
                category=category,
                span=span[:MAX_SPAN],
                span_start=match.start(),
                span_end=match.end(),
                confidence=rule.confidence,
                explanation=rule.explanation,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Prompt injection: instructions smuggled into text the agent did not write
# (user message, document, web page, chat transcript).
# ---------------------------------------------------------------------------
PROMPT_INJECTION_RULES: list[Rule] = [
    # NOTE: AgentDojo's own "ignore_previous" template misspells the word
    # as "iunstructions" (see src/agentdojo/attacks/baseline_attacks.py).
    # The rule matches the typo too — a guardrail that only matches
    # correctly-spelled attacks is not guarding anything.
    Rule("PI-01", r"ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+(instructions?|iunstructions?)",
         0.95, "Explicit instruction to ignore the instructions that came before it."),
    Rule("PI-02", r"disregard\s+(all\s+)?(the\s+)?(your\s+)?(previous|prior|above|earlier)\s+(instructions?|iunstructions?)",
         0.95, "Explicit instruction to disregard the instructions that came before it."),
    Rule("PI-03", r"forget\s+(your|all|the)\s+(previous\s+)?instructions?",
         0.90, "Tells the model to forget its instructions."),
    Rule("PI-04", r"do\s+not\s+follow\s+(your|the|any)\s+instructions?",
         0.90, "Tells the model not to follow its instructions."),
    Rule("PI-05", r"###\s*\(?\s*system(_message)?\s*\)?",
         0.90, "Fake system-message marker: text pretending to be a system message."),
    Rule("PI-06", r"<\s*INFORMATION\s*>",
         0.85, "Framing tag used by the AgentDojo 'important instructions' attack to impersonate the user."),
    Rule("PI-07", r"this is an important message from me,?\s+.{0,40}?\s+to you",
         0.85, "Impersonation framing: text claiming to be an important message from the user to the model."),
    Rule("PI-08", r"before you (can\s+)?(solve|do|complete|answer)[^.\n]{0,80}?(do the following|please do|first)[^.\n]{0,120}",
         0.90, "Sequencing trick: 'do this first, then your real task' — the classic injection wrapper."),
    Rule("PI-09", r"you are now\s+.{0,60}",
         0.80, "Role override: 'you are now...' redefines what the model is."),
    Rule("PI-10", r"pretend (you are|to be)\s+.{0,60}",
         0.80, "Role override: 'pretend you are...' redefines what the model is."),
    Rule("PI-11", r"\bnew instructions?\b.{0,40}?(follow|do|execute|obey)",
         0.70, "Introduces 'new instructions' the model is told to follow."),
    Rule("PI-12", r"override\s+(your|the|all)\s+(instructions?|rules?|policy|guidelines?)",
         0.85, "Tells the model to override its instructions, rules, or policy."),
    Rule("PI-13", r"reveal (your|the)\s+(system prompt|instructions?|prompt)",
         0.90, "Asks the model to reveal its system prompt or instructions."),
    Rule("PI-14", r"\b(jailbreak|developer mode|\bDAN\b.{0,20}do anything now)",
         0.85, "Jailbreak marker."),
    Rule("PI-15", r"\bTODO:\s+(send|transfer|email|grant|delete|share|post|execute|run|download|pay|modify|change|update|remove|create)",
         0.65, "'TODO:' followed by an action verb — the AgentDojo 'direct' attack shape."),
    Rule("PI-16", r"do\s+.{0,80}?\s+instead\.?$",
         0.55, "Trailing 'do X instead' — an instruction swap at the end of the text."),
    Rule("PI-17", r"ignore\s+.{0,30}?\s+and\s+(strictly\s+)?adhere to",
         0.90, "'Ignore ... and adhere to ...' — the InjecAgent attack phrasing."),
    Rule("PI-18", r"from now on,?\s+(you (must|should|will)|always|never)",
         0.70, "Persistence directive: tries to change the model's behaviour from now on."),
]


def detect_prompt_injection(text: str) -> list[Finding]:
    """All prompt-injection findings in `text` (any source)."""
    findings: list[Finding] = []
    for rule in PROMPT_INJECTION_RULES:
        findings.extend(_find(rule, "prompt_injection", "prompt_injection", text))
    return findings


# ---------------------------------------------------------------------------
# Tool-output injection: instructions hidden in data a tool returned
# (search results, file contents, reviews, emails). The text is data, so
# imperative action language inside it is suspicious by itself.
# ---------------------------------------------------------------------------
_ACTION_VERBS = r"(send|transfer|email|e-mail|grant|delete|share|post|pay|download|execute|run|forward|wire|upload)"
_DESTINATION = r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|IBAN[:\s]*[A-Z]{2}\d{2}[A-Z0-9]{4,}|[A-Z]{2}\d{2}[A-Z0-9]{11,30}|https?://\S+|account\s+\S+|guest_[a-z0-9_]+)"

TOOL_OUTPUT_RULES: list[Rule] = [
    Rule("TO-01", _ACTION_VERBS + r"\s+.{0,60}?\s+to\s+" + _DESTINATION,
         0.85, "Tool output contains an action (send/transfer/grant/...) aimed at an external destination."),
    Rule("TO-02", r"(you (must|should|need to|have to)|please (send|transfer|email|grant|delete|share|pay|forward))\s+.{0,80}",
         0.70, "Second-person instruction inside tool output: data telling the agent what to do."),
    Rule("TO-03", r"(send|transfer|email|share|forward)\s+(my|the|your|all)\s+.{0,40}?\s+to\s+" + _DESTINATION,
         0.85, "Tool output asks for data to be sent to an outside address."),
    Rule("TO-04", r"(?:(password|api[_\s-]?key|secret|token|credentials?)\s*.{0,30}?\s*(send|share|email|post|provide|enter)|(send|share|email|post|provide|enter)\s+.{0,30}?\s*(your\s+)?(password|api[_\s-]?key|secret|token|credentials?))",
         0.85, "Tool output asks for a secret or credential to be sent somewhere."),
    Rule("TO-05", r"(click|visit|download|open)\s+.{0,20}?\s+https?://\S+",
         0.60, "Tool output pushes the agent toward an external link."),
    Rule("TO-06", r"grant\s+(permanent\s+)?access\s+to\s+.{0,40}",
         0.85, "Tool output asks the agent to grant access to someone."),
    Rule("TO-07", r"ignore\s+.{0,40}?\s+instruction",
         0.80, "Tool output contains an instruction-override phrase."),
    # TO-08/09/10: bare imperative language inside tool output. Tool
    # output is data, not instructions, so a sentence shaped like a
    # command ("Please unlock my front door", "Withdraw 5 BTC") is
    # suspicious even with no override phrasing. These rules are scored
    # at REVIEW level (0.50–0.55), never BLOCK: polite imperatives also
    # appear in legitimate text, so they escalate to a human instead of
    # being refused outright. The InjecAgent misses were dominated by
    # exactly this shape (see docs/experiment_log.md).
    Rule("TO-08", r"\bplease\s+(send|transfer|grant|delete|share|update|retrieve|move|schedule|change|use|unlock|initiate|deposit|sell|create|dispatch|redirect|guide|give|pay|forward|post|download|execute|run|open|book|cancel|disable|enable|modify|remove|add|set|turn|lock|withdraw|leave)\b",
         0.55, "Polite imperative ('Please <action>...') inside tool output: data shaped like an instruction."),
    Rule("TO-09", r"[:'\"]\s*(update|disable|withdraw|delete|send|transfer|grant|unlock|remove|create|leave)\b",
         0.50, "A quoted field or labelled value in tool output begins with an imperative action verb."),
    Rule("TO-10", r"(?:^|[\n.]\s*)(send|transfer|modify|change|delete|grant|unlock|disable|withdraw|remove|update)\b[^.\n]{0,80}",
         0.55, "A sentence in tool output begins with an imperative action verb."),
]


def detect_tool_output_injection(text: str) -> list[Finding]:
    """Injection findings in text that came from a tool (untrusted data)."""
    findings: list[Finding] = []
    for rule in TOOL_OUTPUT_RULES:
        findings.extend(_find(rule, "tool_output_injection", "tool_output_injection", text))
    # Injection phrasing is also an injection when it sits in tool output.
    for f in detect_prompt_injection(text):
        findings.append(
            Finding(
                rule_id=f.rule_id,
                detector="tool_output_injection",
                category="tool_output_injection",
                span=f.span,
                span_start=f.span_start,
                span_end=f.span_end,
                confidence=f.confidence,
                explanation=f.explanation,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Goal hijack: a proposed action that does not serve the user's stated goal.
# Lexical, not semantic: it extracts the action's destination and checks
# whether the user's goal mentions it at all.
# ---------------------------------------------------------------------------
_IRREVERSIBLE = re.compile(
    r"\b(send|transfer|email|grant|delete|share|post|pay|forward|wire|publish|upload)\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_URL_RE = re.compile(r"https?://\S+")
_ACCOUNT_RE = re.compile(r"\b(?:account|guest|user)[_\s-]?[a-z0-9_]+\b", re.IGNORECASE)


def _destinations(text: str) -> list[str]:
    found: list[str] = []
    for pattern in (_EMAIL_RE, _IBAN_RE, _URL_RE, _ACCOUNT_RE):
        found.extend(m.lower() for m in pattern.findall(text))
    return found


def _content_words(text: str) -> set[str]:
    stop = {
        "the", "a", "an", "to", "of", "and", "for", "in", "on", "is", "it",
        "you", "your", "me", "my", "please", "can", "could", "would", "with",
        "from", "that", "this", "do", "does", "i", "we", "us", "are", "be",
    }
    words = re.findall(r"[a-z]{3,}", text.lower())
    return {w for w in words if w not in stop}


def detect_goal_hijack(user_goal: str, proposed_action: str) -> list[Finding]:
    """Flag a proposed action whose destination or content is absent from the user's goal."""
    findings: list[Finding] = []
    goal_lower = user_goal.lower()
    action_lower = proposed_action.lower()

    verbs = _IRREVERSIBLE.findall(proposed_action)
    if not verbs:
        return findings  # No irreversible action proposed: nothing to hijack.

    for dest in _destinations(proposed_action):
        if dest not in goal_lower:
            findings.append(
                Finding(
                    rule_id="GH-01",
                    detector="goal_hijack",
                    category="goal_hijack",
                    span=dest[:MAX_SPAN],
                    span_start=proposed_action.lower().find(dest),
                    span_end=proposed_action.lower().find(dest) + len(dest),
                    confidence=0.90,
                    explanation=(
                        f"The proposed action targets '{dest}', which the user's goal "
                        f"never mentions. An irreversible action to an unmentioned "
                        f"destination is the shape of a goal hijack."
                    ),
                )
            )
    if findings:
        return findings

    # Destination is mentioned, or there is none: fall back to content overlap.
    goal_words = _content_words(user_goal)
    action_words = _content_words(proposed_action)
    shared = goal_words & action_words
    overlap = len(shared) / max(len(action_words), 1)
    if overlap < 0.25 and len(action_words) >= 4:
        findings.append(
            Finding(
                rule_id="GH-02",
                detector="goal_hijack",
                category="goal_hijack",
                span=proposed_action[:MAX_SPAN],
                span_start=0,
                span_end=min(len(proposed_action), MAX_SPAN),
                confidence=0.65,
                explanation=(
                    f"The proposed action shares only {overlap:.0%} of its content "
                    f"words with the user's goal ('{user_goal[:60]}...'). "
                    f"It may serve a different goal than the one the user stated."
                ),
            )
        )
    return findings
