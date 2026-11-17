"""Counterfactual pass probe: the minimal safe alternative to a block.

Every guardrail library I could find returns a verdict and stops there.
None answers the question a developer (or an agent) asks next: *what
would I have to change for this to pass?* This probe answers it, with
evidence: for a BLOCKED verdict it searches for the smallest edit to
the text — or, for a goal hijack, to the action's destination — that
makes the same checkpoint re-verdict ALLOW, and it verifies the edit by
actually re-running the checkpoint on the edited text. An edit is only
reported if the re-run passes.

How it searches (deterministic, stdlib-only, offline):
- Greedy, one finding at a time, highest-confidence finding first,
  and it keeps going past REVIEW until the text re-verdicts ALLOW —
  stopping at REVIEW would report a partial result for cases a span
  removal would have fixed. For that finding it tries the smallest
  neutralisation that fits the finding's kind, in this order:
    1. PII (PII-01…PII-06): redact the span to a typed placeholder
       ("[EMAIL]", "[IBAN]", "[CARD]") — the sentence stays readable.
    2. Goal hijack GH-01 (destination the goal never mentions):
       replace the destination with one the user's goal *does*
       mention ("what if it had gone to Sara instead of the attacker").
       If the goal mentions no destination, remove the destination.
    3. Everything else (injection phrasing, imperative language):
       remove the finding's matched span.
- If no single-span edit lowers the verdict score, it removes all
  flagged spans at once as one combined edit step.
- It stops at ALLOW, when the remaining finding is GH-02 (see below),
  when no edit lowers the score, or at `max_edits` edit steps. A
  REVIEW-only result is reported as partial — better than BLOCK, not
  a pass.
- GH-02 (action content unrelated to the goal, no destination to fix)
  has no span edit at all: its span is the whole action, and deleting
  the action is not a fix, it is deleting the subject. The probe
  refuses that edit and reports the case honestly instead of
  inventing one — the fix there is a human decision (amend the goal
  explicitly), not a text edit.

Minimality is span-level, not character-level: the probe finds the
smallest *set of findings* to neutralise, and for each finding the
smallest span that clears it. It does not rewrite sentences and it
does not paraphrase — a paraphrase could change meaning in ways the
detectors cannot see, so the probe never proposes one.

Honest limits (also in README §7 and docs/experiment_log.md):
- An edit is minimal in the *detectors' feature space*, not a semantic
  guarantee. Removing "Ignore all previous instructions" makes the
  text pass because no rule fires on what is left — it says nothing
  about what the remaining text means.
- For GH-02 (action content unrelated to the goal, no destination to
  fix) there is no safe edit inside the action: the action itself
  serves a different goal. The probe reports that honestly instead of
  inventing one — the fix there is a human decision (amend the goal
  explicitly), not a text edit.
- For a text that is *entirely* an attack, the minimal edit is
  essentially the whole text. The probe still reports it: "keep the
  benign framing, drop the injected instruction" is the useful answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .verdicts import Decision, Finding, Verdict

# Typed placeholders for PII redaction (cleaner than the generic tags in
# pii.redact, which are built for log excerpts).
_PII_PLACEHOLDER = {
    "PII-01": "[EMAIL]",
    "PII-02": "[PHONE]",
    "PII-03": "[SSN]",
    "PII-04": "[API_KEY]",
    "PII-05": "[IBAN]",
    "PII-06": "[CARD]",
}

# Destination patterns, mirroring detectors._destinations (kept local so
# the probe does not depend on a private helper).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_URL_RE = re.compile(r"https?://\S+")
_ACCOUNT_RE = re.compile(r"\b(?:account|guest|user)[_\s-]?[a-z0-9_]+\b", re.IGNORECASE)


def _destinations(text: str) -> list[str]:
    found: list[str] = []
    for pattern in (_EMAIL_RE, _IBAN_RE, _URL_RE, _ACCOUNT_RE):
        found.extend(m.lower() for m in pattern.findall(text))
    return found


@dataclass(frozen=True)
class ProbeEdit:
    """One applied edit: what changed, where, and why."""

    kind: str  # "remove_span" | "redact_span" | "replace_destination" | "remove_spans"
    rule_id: str
    span_start: int  # -1 for a combined multi-span edit
    span_end: int
    original: str  # the text that was removed or replaced
    replacement: str  # "" for a removal
    description: str  # one plain sentence

    @property
    def edit_cost(self) -> int:
        """Characters changed: removed + inserted. The size measure."""
        return len(self.original) + len(self.replacement)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "rule_id": self.rule_id,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "original": self.original,
            "replacement": self.replacement,
            "description": self.description,
            "edit_cost": self.edit_cost,
        }


@dataclass
class PassProbe:
    """The result of probing one blocked verdict for a way through."""

    checkpoint: str
    original_text: str
    original_decision: Decision
    original_score: float
    edited_text: str | None  # None when nothing was probed / no edit found
    edited_decision: Decision | None
    edited_score: float | None
    edits: list[ProbeEdit] = field(default_factory=list)
    attempts: int = 0  # checkpoint re-runs spent searching
    note: str = ""

    @property
    def edit_size(self) -> int:
        """Total characters changed across the applied edits."""
        return sum(e.edit_cost for e in self.edits)

    @property
    def passed(self) -> bool:
        """The edited text re-verdicts ALLOW (verified by re-running)."""
        return self.edited_decision == Decision.ALLOW

    @property
    def partial(self) -> bool:
        """The edited text re-verdicts REVIEW: better than BLOCK, not a pass."""
        return self.edited_decision == Decision.REVIEW

    def explain(self) -> str:
        """One plain-English account of the probe, for humans and logs."""
        head = (
            f"{self.original_decision.value.upper()} (score {self.original_score:.2f})"
        )
        if self.original_decision != Decision.BLOCK:
            return f"{head}: not blocked — nothing to probe."
        if not self.edits:
            note = self.note or "No single-span edit lowered the score."
            return f"{head}: no minimal edit found. {note}"
        tail = (
            f"-> {self.edited_decision.value.upper()} "
            f"(score {self.edited_score:.2f}) with {len(self.edits)} edit(s), "
            f"{self.edit_size} chars changed."
        )
        lines = [f"{head} {tail}"]
        for i, edit in enumerate(self.edits, 1):
            lines.append(f"  {i}. [{edit.rule_id}] {edit.description}")
        if self.edited_text is not None:
            lines.append(f"  Edited text: {self.edited_text!r}")
        if self.note:
            lines.append(f"  Note: {self.note}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "checkpoint": self.checkpoint,
            "original_decision": self.original_decision.value,
            "original_score": round(self.original_score, 3),
            "edited_text": self.edited_text,
            "edited_decision": self.edited_decision.value if self.edited_decision else None,
            "edited_score": round(self.edited_score, 3) if self.edited_score is not None else None,
            "edits": [e.to_dict() for e in self.edits],
            "edit_size": self.edit_size,
            "passed": self.passed,
            "partial": self.partial,
            "attempts": self.attempts,
            "note": self.note,
        }


def _locate(finding: Finding, text: str) -> tuple[int, int] | None:
    """Character span of a finding in `text`, or None if unlocatable."""
    if 0 <= finding.span_start < finding.span_end <= len(text):
        if text[finding.span_start:finding.span_end] == finding.span:
            return finding.span_start, finding.span_end
    at = text.find(finding.span)
    if at >= 0:
        return at, at + len(finding.span)
    return None


def _candidates(
    finding: Finding, text: str, user_goal: str
) -> list[ProbeEdit]:
    """Edit candidates for one finding, smallest / most useful first.

    GH-02 has no candidates: its span is the whole action, and deleting
    the action is not a fix. See the module docstring.
    """
    if finding.rule_id == "GH-02":
        return []
    located = _locate(finding, text)
    if located is None:
        return []
    start, end = located
    span = text[start:end]
    if finding.detector == "pii":
        tag = _PII_PLACEHOLDER.get(finding.rule_id, "[REDACTED]")
        label = {
            "PII-01": "email address",
            "PII-02": "phone number",
            "PII-03": "Social Security number",
            "PII-04": "API key / token",
            "PII-05": "IBAN",
            "PII-06": "card number",
        }.get(finding.rule_id, "PII")
        return [
            ProbeEdit(
                kind="redact_span",
                rule_id=finding.rule_id,
                span_start=start,
                span_end=end,
                original=span,
                replacement=tag,
                description=f"Redacted the {label} to {tag}.",
            ),
            ProbeEdit(
                kind="remove_span",
                rule_id=finding.rule_id,
                span_start=start,
                span_end=end,
                original=span,
                replacement="",
                description=f"Removed the {label}.",
            ),
        ]
    if finding.rule_id == "GH-01":
        goal_dests = _destinations(user_goal)
        if goal_dests:
            replacement = goal_dests[0]
            return [
                ProbeEdit(
                    kind="replace_destination",
                    rule_id=finding.rule_id,
                    span_start=start,
                    span_end=end,
                    original=span,
                    replacement=replacement,
                    description=(
                        f"Re-routed the action from '{span}' to '{replacement}', "
                        f"a destination the user's goal mentions."
                    ),
                ),
                ProbeEdit(
                    kind="remove_span",
                    rule_id=finding.rule_id,
                    span_start=start,
                    span_end=end,
                    original=span,
                    replacement="",
                    description=(
                        f"Removed the unmentioned destination '{span}' from the action."
                    ),
                ),
            ]
        return [
            ProbeEdit(
                kind="remove_span",
                rule_id=finding.rule_id,
                span_start=start,
                span_end=end,
                original=span,
                replacement="",
                description=(
                    f"Removed the unmentioned destination '{span}' from the action."
                ),
            )
        ]
    return [
        ProbeEdit(
            kind="remove_span",
            rule_id=finding.rule_id,
            span_start=start,
            span_end=end,
            original=span,
            replacement="",
            description=f"Removed the matched span: {span!r}.",
        )
    ]


def _remove_spans(text: str, findings: list[Finding]) -> tuple[str, list[ProbeEdit]]:
    """Remove every locatable finding span at once; returns new text + edits."""
    spans = sorted(
        (_locate(f, text) for f in findings),
        key=lambda s: s[0] if s else -1,
    )
    spans = [s for s in spans if s is not None]
    if not spans:
        return text, []
    out: list[str] = []
    pos = 0
    removed: list[str] = []
    for start, end in spans:
        if start < pos:
            continue
        out.append(text[pos:start])
        removed.append(text[start:end])
        pos = end
    out.append(text[pos:])
    return "".join(out), [
        ProbeEdit(
            kind="remove_spans",
            rule_id=",".join(sorted({f.rule_id for f in findings})),
            span_start=-1,
            span_end=-1,
            original=" | ".join(removed),
            replacement="",
            description=(
                f"Removed {len(removed)} blocking span(s) at once; no "
                f"single-span edit lowered the score."
            ),
        )
    ]


def probe_pass(
    guardrail,
    text: str,
    checkpoint: str = "user_input",
    *,
    user_goal: str = "",
    user_input: str = "",
    max_edits: int = 8,
) -> PassProbe:
    """Probe a BLOCKED verdict for the minimal edit that lets it pass.

    `checkpoint` is one of "user_input", "tool_output", "model_output",
    "action" (the last needs `user_goal`). A non-BLOCKED verdict returns
    a probe with no edits and a note — there is nothing to fix.
    """
    checks = {
        "user_input": lambda t: guardrail.check_user_input(t),
        "tool_output": lambda t: guardrail.check_tool_output(t),
        "model_output": lambda t: guardrail.check_model_output(t, user_input=user_input),
        "action": lambda t: guardrail.check_action(user_goal, t),
    }
    if checkpoint not in checks:
        raise ValueError(f"unknown checkpoint: {checkpoint!r}")
    check = checks[checkpoint]

    verdict: Verdict = check(text)
    probe = PassProbe(
        checkpoint=checkpoint,
        original_text=text,
        original_decision=verdict.decision,
        original_score=verdict.score,
        edited_text=None,
        edited_decision=None,
        edited_score=None,
    )
    if verdict.decision != Decision.BLOCK:
        probe.note = "Not blocked — nothing to probe."
        return probe

    current = text
    edits: list[ProbeEdit] = []
    attempts = 0
    # Keep going past REVIEW until ALLOW: a REVIEW-level finding (a
    # trailing "do X instead", a sentence starting with an imperative
    # verb) is still a removable span, and stopping at REVIEW would
    # report a partial result for a case a span removal would fix.
    # The one finding that stops the search is GH-02: no span edit can
    # fix "wrong goal", and deleting the whole action is not a fix.
    while verdict.decision != Decision.ALLOW and len(edits) < max_edits:
        if not verdict.findings:
            break
        top = max(verdict.findings, key=lambda f: f.confidence)
        if top.rule_id == "GH-02":
            break
        progressed = False
        for candidate in _candidates(top, current, user_goal):
            attempts += 1
            new_text = (
                current[:candidate.span_start]
                + candidate.replacement
                + current[candidate.span_end:]
            )
            new_verdict = check(new_text)
            if new_verdict.score < verdict.score:
                edits.append(candidate)
                current, verdict = new_text, new_verdict
                progressed = True
                break
        if progressed:
            continue
        # No single-span edit on the top finding helped: remove every
        # flagged span at once (except GH-02, which is never removable)
        # and see if the score moves.
        removable = [f for f in verdict.findings if f.rule_id != "GH-02"]
        new_text, combined = _remove_spans(current, removable)
        attempts += 1
        if not combined or new_text == current:
            break
        new_verdict = check(new_text)
        if new_verdict.score < verdict.score:
            edits.extend(combined)
            current, verdict = new_text, new_verdict
        else:
            break

    probe.edits = edits
    probe.attempts = attempts
    if edits:
        probe.edited_text = current
        probe.edited_decision = verdict.decision
        probe.edited_score = verdict.score
    if not edits:
        if any(f.rule_id == "GH-02" for f in verdict.findings):
            probe.note = (
                "No safe edit inside the action: the top finding is GH-02 — "
                "the action's content is unrelated to the user's goal, with "
                "no destination to fix. The fix is a human decision (amend "
                "the goal explicitly), not a text edit."
            )
        else:
            probe.note = "No single-span or combined edit lowered the score."
    elif verdict.decision == Decision.REVIEW and verdict.findings:
        remaining = max(verdict.findings, key=lambda f: f.confidence)
        if remaining.rule_id == "GH-02":
            probe.note = (
                "Reached REVIEW only: GH-02 still fires — the action's content "
                "is unrelated to the user's goal, and no span edit can fix "
                "\"wrong goal\". The fix is a human decision (amend the goal "
                "explicitly), not a text edit."
            )
        else:
            probe.note = (
                f"Reached REVIEW only: {remaining.rule_id} still fires at "
                f"{remaining.confidence:.2f} and no span edit cleared it."
            )
    elif verdict.decision == Decision.BLOCK:
        probe.note = (
            "Still BLOCK after the edit budget ran out "
            f"({max_edits} edits) — no further span edit lowered the score."
        )
    return probe
