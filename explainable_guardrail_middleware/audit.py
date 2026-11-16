"""Immutable audit log: a hash chain over verdicts.

Each record contains the hash of the previous record, so any edit to an
earlier record breaks every hash after it. `verify()` replays the chain
and reports the first broken link, if any. The log stores the input's
SHA-256 and a PII-redacted excerpt — never the raw input — so the audit
trail itself cannot leak what the guardrail blocked.

This is the piece that makes a blocked decision defensible afterwards:
"on this date, this input, these rules fired, this was the verdict, and
nobody has altered the record since."
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .pii import redact
from .verdicts import Verdict


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _hash(record: dict) -> str:
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only JSONL audit log with a hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._prev_hash = "GENESIS"
        self._seq = 0
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                self._prev_hash = record["hash"]
                self._seq = record["seq"]

    def append(self, verdict: Verdict, text: str, context: str = "") -> dict:
        """Append one verdict; returns the record (including its hash)."""
        self._seq += 1
        record = {
            "seq": self._seq,
            "prev_hash": self._prev_hash,
            "decision": verdict.decision.value,
            "score": round(verdict.score, 3),
            "policy_version": verdict.policy_version,
            "input_sha256": verdict.input_sha256 or Verdict.input_hash(text),
            "excerpt": redact(text)[:200],
            "context": context,
            "rules": sorted({f.rule_id for f in verdict.findings}),
        }
        record["hash"] = _hash({k: v for k, v in record.items()})
        with open(self.path, "a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._prev_hash = record["hash"]
        verdict.audit_id = str(self._seq)
        return record

    def verify(self) -> tuple[bool, str]:
        """Replay the chain. Returns (ok, message)."""
        prev = "GENESIS"
        expected_seq = 0
        if not self.path.exists():
            return True, "log file does not exist yet; nothing to verify"
        for line_no, line in enumerate(self.path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            expected_seq += 1
            if record["seq"] != expected_seq:
                return False, f"line {line_no}: sequence break (expected {expected_seq}, found {record['seq']})"
            if record["prev_hash"] != prev:
                return False, f"line {line_no}: prev_hash does not match the previous record"
            claimed = record.pop("hash")
            if _hash(record) != claimed:
                return False, f"line {line_no}: record hash mismatch — this record was altered after it was written"
            record["hash"] = claimed
            prev = claimed
        return True, f"chain intact: {expected_seq} record(s) verified"
