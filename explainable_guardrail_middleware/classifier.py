"""Optional lexical classifier: a small bag-of-words log-odds scorer.

Stdlib only. It learns, from labelled example texts, which words appear
more often in attacks than in benign text, and scores a new text by the
sum of its words' log-odds. It is deliberately *not* the primary
detector: regex rules are auditable and stable, while a learned scorer
can drift with its training data. In the Guardrail it is opt-in and its
finding is capped so it can escalate to REVIEW but never BLOCK alone.

Honest limits, stated up front:
- It is a word counter. Paraphrase it and it misses; feed it a new
  attack family and it has no opinion.
- Its accuracy is only meaningful on the data it was trained on; the
  benchmark notebook reports train/test accuracy with a held-out split
  so the number is not a training-set artefact.
"""

from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{2,}")


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class LexicalClassifier:
    """Log-odds word scorer trained on (text, is_attack) pairs."""

    def __init__(self) -> None:
        self.log_odds: dict[str, float] = {}
        self.bias: float = 0.0
        self.trained: bool = False

    def train(self, examples: list[tuple[str, bool]]) -> None:
        attack_counts: Counter[str] = Counter()
        benign_counts: Counter[str] = Counter()
        n_attack = n_benign = 0
        for text, is_attack in examples:
            words = set(_tokens(text))
            if is_attack:
                n_attack += 1
                attack_counts.update(words)
            else:
                n_benign += 1
                benign_counts.update(words)
        if n_attack == 0 or n_benign == 0:
            raise ValueError("need both attack and benign examples to train")
        vocab = set(attack_counts) | set(benign_counts)
        # Laplace smoothing (alpha=1) on document frequencies.
        for word in vocab:
            p_attack = (attack_counts[word] + 1) / (n_attack + 2)
            p_benign = (benign_counts[word] + 1) / (n_benign + 2)
            self.log_odds[word] = math.log(p_attack / p_benign)
        self.bias = math.log(n_attack / n_benign)
        self.trained = True

    def score(self, text: str) -> float:
        """Probability-like score in [0, 1] that `text` is an attack."""
        if not self.trained:
            raise RuntimeError("classifier has not been trained yet")
        total = self.bias
        for word in set(_tokens(text)):
            total += self.log_odds.get(word, 0.0)
        # Sigmoid, clamped so a long text cannot saturate to exactly 1.
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, total))))

    def top_words(self, n: int = 15) -> list[tuple[str, float]]:
        """Most attack-indicative words, for inspection (not for production)."""
        return sorted(self.log_odds.items(), key=lambda kv: -kv[1])[:n]
