# API

Core library: `explainable_guardrail_middleware`. Stdlib only.

## Guardrail

```python
from explainable_guardrail_middleware import Guardrail, Policy

guardrail = Guardrail()                       # default policy v1.0.0
guardrail = Guardrail(Policy(block_threshold=0.8, review_threshold=0.5))

verdict = guardrail.check_user_input(text)    # what the user typed
verdict = guardrail.check_tool_output(text)   # what a tool returned
verdict = guardrail.check_model_output(text, user_input="...")  # reply before sending
verdict = guardrail.check_action(user_goal, proposed_action)    # tool call about to happen
screen  = guardrail.check_memory_write(note, source="tool_output")  # memory write

verdict.decision        # Decision.ALLOW / REVIEW / BLOCK
verdict.score           # highest finding confidence (0.0 when no findings)
verdict.findings        # list[Finding], most confident first
verdict.explain()       # plain-English reason trace
verdict.to_dict()       # JSON-safe dict
```

`check_model_output` treats PII as a leak only when it was not in the
user's own input. `check_action` runs goal-hijack and prompt-injection
rules only (see `docs/architecture.md` §2 for why tool-output rules do
not run on the agent's own proposal).

## Memory gate

```python
from explainable_guardrail_middleware import screen_memory_write

screen = screen_memory_write(note, source="web", author="agent", session_id="s-1")
screen.decision   # MemoryDecision.ADMIT / QUARANTINE / REJECT
screen.findings   # list[Finding]
screen.explain()  # plain-English reason trace
```

`source` is one of `"user"`, `"developer"`, `"system"` (trusted),
`"tool_output"`, `"web"`, `"document"`, `"unknown"` (untrusted).
Trusted sources are screened more leniently: only high-confidence
override phrasing counts against a user-written note.

## PII

```python
from explainable_guardrail_middleware import detect_pii, redact

detect_pii("My IBAN is GB29NWBK60161331926819.")  # list[Finding], mod-97 verified
redact("Email amna@example.com")                  # "Email [EMAIL_ADDRESS]"
```

## Audit log

```python
from explainable_guardrail_middleware import AuditLog

log = AuditLog("audit.jsonl")
record = log.append(verdict, text, context="tool_output")
ok, message = log.verify()   # (True, "chain intact: N record(s) verified")
```

The log stores the input SHA-256 and a PII-redacted excerpt (max 200
chars), never the raw input.

## Classifier (optional)

```python
from explainable_guardrail_middleware import LexicalClassifier

clf = LexicalClassifier()
clf.train([(text, is_attack), ...])   # needs both classes
clf.score(text)                        # float in [0, 1]
clf.top_words(15)                      # most attack-indicative words

guardrail = Guardrail(Policy(enable_classifier=True), classifier=clf)
```

Classifier findings are capped at 0.70: they can escalate to REVIEW
but never BLOCK alone.

## CLI

```bash
python -m explainable_guardrail_middleware check "text" [--checkpoint user_input|tool_output|model_output] [--audit-log audit.jsonl]
python -m explainable_guardrail_middleware demo
python -m explainable_guardrail_middleware memory "note" [--source web] [--author agent]
python -m explainable_guardrail_middleware benchmark [--fixtures benchmarks/fixtures] [--out results/benchmark_results.json]
```

`check` exits 0 on ALLOW, 1 otherwise. `memory` exits 0 on ADMIT, 1 otherwise.
