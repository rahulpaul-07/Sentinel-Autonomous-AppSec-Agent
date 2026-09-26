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

from dataclasses import dataclass, field


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    # A ratio with a zero denominator is undefined, and is reported as None. It
    # used to be 1.0, so a run that confirmed nothing printed "Precision: 100%".
    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def f1(self) -> float | None:
        # 2TP / (2TP + FP + FN): equal to the harmonic mean of precision and recall
        # wherever both exist, and still defined (as 0) when nothing was confirmed.
        denom = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / denom if denom else None

    def __add__(self, other: Metrics) -> Metrics:
        return Metrics(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": _round(self.precision),
            "recall": _round(self.recall),
            "f1": _round(self.f1),
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
    # How every candidate was graded, and the sandbox image the exploits ran in.
    # Without these, "nothing was tested" and "the model missed everything" print
    # the same score.
    tiers: dict = field(default_factory=dict)
    environment: dict | None = None
    hunter: dict | None = None

    @property
    def overstatement(self) -> float | None:
        """How much precision the marker-only reading claims but cannot support."""
        p, s = self.permissive.precision, self.strict.precision
        return None if p is None or s is None else p - s

    def to_dict(self) -> dict:
        return {
            "permissive": self.permissive.to_dict(),
            "strict": self.strict.to_dict(),
            "precision_overstatement": _round(self.overstatement),
            "tiers": self.tiers,
            "environment": self.environment,
            "hunter": self.hunter,
        }
