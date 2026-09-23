"""
sentinel/metrics.py
-------------------
Pure precision/recall/F1 math, with NO heavy imports.

Why its own file? The metrics are simple arithmetic that deserve fast, dependency-
free unit tests. When this lived inside evaluation.py, importing Metrics dragged in
the whole LLM stack (litellm and its 40+ transitive packages) just to check that
2*p*r/(p+r) is right. Splitting the pure math out means the logic tests run with
nothing installed but pytest -- and the coupling that forced otherwise is gone.

Definitions:
  True Positive  (TP): a CONFIRMED finding that matches a known real vulnerability.
  False Positive (FP): a CONFIRMED finding that matches no known vulnerability.
  False Negative (FN): a known vulnerability Sentinel did NOT confirm.

  Precision = TP / (TP + FP)   -- of what we confirmed, how much was real
  Recall    = TP / (TP + FN)   -- of what was real, how much we caught
  F1        = harmonic mean of the two
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def __add__(self, other: "Metrics") -> "Metrics":
        return Metrics(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class TieredMetrics:
    """Scores computed at two readings of "confirmed".

    `permissive` counts any finding whose exploit printed the success marker --
    what a marker-only scanner reports, and what Sentinel v1 reported.

    `strict` counts only findings whose reported LINE was observed to execute
    during the exploit.

    Reporting both is the point: the gap between them is exactly the quantity of
    evidence that a marker-only check silently overstates. A single "precision"
    figure hides it.
    """

    permissive: Metrics
    strict: Metrics

    @property
    def overstatement(self) -> float:
        """How much precision the marker-only reading claims but cannot support."""
        return self.permissive.precision - self.strict.precision

    def to_dict(self) -> dict:
        return {
            "permissive": self.permissive.to_dict(),
            "strict": self.strict.to_dict(),
            "precision_overstatement": round(self.overstatement, 4),
        }
