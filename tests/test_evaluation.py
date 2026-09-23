"""Unit tests for the metrics math. Fast, deterministic, no LLM needed."""

from sentinel.metrics import Metrics


def test_precision_recall_f1():
    m = Metrics(tp=3, fp=1, fn=1)
    assert round(m.precision, 2) == 0.75
    assert round(m.recall, 2) == 0.75
    assert round(m.f1, 2) == 0.75


def test_perfect_scores():
    m = Metrics(tp=2, fp=0, fn=0)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0


def test_metrics_add():
    total = Metrics(1, 1, 0) + Metrics(2, 0, 1)
    assert (total.tp, total.fp, total.fn) == (3, 1, 1)