"""The Guardrail: one object that screens text at every agent checkpoint.

Checkpoints (one call each):
- ``check_user_input(text)`` — what the user typed.
- ``check_tool_output(text)`` — what a tool returned (untrusted data).
- ``check_model_output(text, user_input="")`` — what the model is about
  to say; PII here is a leak only if it was not in the user's own input.
- ``check_action(user_goal, proposed_action)`` — a tool call the agent
  is about to make; screened for goal hijack.
- ``screen_memory_write(...)`` — a note the agent wants to remember.

Scoring policy (v1.0.0, in ``Policy``):
- highest finding confidence >= block_threshold (0.75) -> BLOCK
- >= review_threshold (0.45) -> REVIEW
- otherwise -> ALLOW
- The optional lexical classifier can only add a finding capped at
  0.70, so it can escalate to REVIEW but never BLOCK on its own.
- Fail closed: an empty string is ALLOW (nothing to screen); a detector
  error is never swallowed — it raises, so a broken guardrail cannot
  silently pass traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .classifier import LexicalClassifier
from .detectors import (
    detect_goal_hijack,
    detect_prompt_injection,
    detect_tool_output_injection,
)
from .memory_gate import MemoryScreen, screen_memory_write
from .pii import detect_pii
from .verdicts import Decision, Finding, Verdict

POLICY_VERSION = "1.0.0"
_CLASSIFIER_CAP = 0.70


@dataclass
class Policy:
    block_threshold: float = 0.75
    review_threshold: float = 0.45
    enable_prompt_injection: bool = True
    enable_tool_output_injection: bool = True
    enable_goal_hijack: bool = True
    enable_pii: bool = True
    enable_classifier: bool = False  # opt-in; see classifier.py limits
    version: str = POLICY_VERSION


@dataclass
class Guardrail:
    policy: Policy = field(default_factory=Policy)
    classifier: LexicalClassifier | None = None

    # -- internal ---------------------------------------------------------
    def _decide(self, findings: list[Finding], text: str) -> Verdict:
        score = max((f.confidence for f in findings), default=0.0)
        if score >= self.policy.block_threshold:
            decision = Decision.BLOCK
        elif score >= self.policy.review_threshold:
            decision = Decision.REVIEW
        else:
            decision = Decision.ALLOW
        return Verdict(
            decision=decision,
            score=score,
            findings=sorted(findings, key=lambda f: -f.confidence),
            policy_version=self.policy.version,
            input_sha256=Verdict.input_hash(text),
        )

    def _classifier_finding(self, text: str) -> list[Finding]:
        if not self.policy.enable_classifier or self.classifier is None:
            return []
        if not self.classifier.trained:
            return []
        score = self.classifier.score(text)
        if score < 0.80:
            return []
        return [
            Finding(
                rule_id="CL-01",
                detector="lexical_classifier",
                category="prompt_injection",
                span=text[:160],
                span_start=0,
                span_end=min(len(text), 160),
                confidence=min(score, _CLASSIFIER_CAP),
                explanation=(
                    f"The lexical classifier scores this text {score:.2f} "
                    f"likely to be an attack (word patterns learned from labelled "
                    f"examples). Capped at {_CLASSIFIER_CAP:.2f}: a learned score "
                    f"alone never blocks."
                ),
            )
        ]

    # -- checkpoints ------------------------------------------------------
    def check_user_input(self, text: str) -> Verdict:
        findings: list[Finding] = []
        if self.policy.enable_prompt_injection:
            findings.extend(detect_prompt_injection(text))
        findings.extend(self._classifier_finding(text))
        return self._decide(findings, text)

    def check_tool_output(self, text: str) -> Verdict:
        findings: list[Finding] = []
        if self.policy.enable_tool_output_injection:
            findings.extend(detect_tool_output_injection(text))
        findings.extend(self._classifier_finding(text))
        return self._decide(findings, text)

    def check_model_output(self, text: str, user_input: str = "") -> Verdict:
        """Screen a reply before it reaches the user.

        PII counts as a leak only when it was not already in the user's
        own input — echoing back an address the user just gave is not a
        leak; volunteering one the user never mentioned is.
        """
        findings: list[Finding] = []
        if self.policy.enable_prompt_injection:
            findings.extend(detect_prompt_injection(text))
        if self.policy.enable_pii:
            for f in detect_pii(text):
                if f.span in user_input:
                    continue  # user-supplied PII, echoed back: not a leak
                findings.append(f)
        findings.extend(self._classifier_finding(text))
        return self._decide(findings, text)

    def check_action(self, user_goal: str, proposed_action: str) -> Verdict:
        """Screen a tool call the agent is about to make."""
        findings: list[Finding] = []
        if self.policy.enable_goal_hijack:
            findings.extend(detect_goal_hijack(user_goal, proposed_action))
        # The action text is the agent's own proposal, not tool output, so
        # tool-output rules must NOT run on it: "email the report to Sara"
        # is a legitimate action, and TO-01 would block it. Only
        # prompt-injection phrasing is screened here, in case the action
        # text was lifted verbatim from untrusted data.
        if self.policy.enable_prompt_injection:
            findings.extend(detect_prompt_injection(proposed_action))
        return self._decide(findings, proposed_action)

    def check_memory_write(
        self,
        note: str,
        source: str = "unknown",
        author: str = "unknown",
        session_id: str = "",
    ) -> MemoryScreen:
        return screen_memory_write(note, source=source, author=author, session_id=session_id)

    def probe_pass(
        self,
        text: str,
        checkpoint: str = "user_input",
        *,
        user_goal: str = "",
        user_input: str = "",
        max_edits: int = 8,
    ):
        """Probe a BLOCKED verdict for the minimal edit that lets it pass.

        See ``counterfactual.probe_pass``: for a blocked verdict it finds
        the smallest span-level edit (remove, redact, or re-route a
        destination) that makes the same checkpoint re-verdict ALLOW,
        verified by re-running the checkpoint on the edited text.
        """
        from .counterfactual import probe_pass as _probe

        return _probe(
            self,
            text,
            checkpoint,
            user_goal=user_goal,
            user_input=user_input,
            max_edits=max_edits,
        )
