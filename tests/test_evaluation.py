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

# --- class matching: decides what counts as a true positive ---------------------

import pytest

from sentinel.evaluation import _class_matches


@pytest.mark.parametrize("a, b", [
    ("SQL Injection", "SQL injection via f-string"),
    ("SQL Injection", "SQLi in login query"),
    ("Path Traversal", "Directory Traversal"),
    ("Command Injection", "OS command injection"),
    ("Insecure Deserialization", "Unsafe deserialization of untrusted data"),
    ("Hardcoded Secret", "Hard-coded credentials"),
    ("Cross-Site Scripting", "XSS"),
    ("Server-Side Request Forgery", "SSRF"),
])
def test_same_class_phrased_differently_matches(a, b):
    assert _class_matches(a, b)
    assert _class_matches(b, a)


@pytest.mark.parametrize("a, b", [
    ("SQL Injection", "Command Injection"),       # regression: shared only "injection"
    ("Command Injection", "Code Injection"),
    ("SQL injection via f-string", "Command injection via f-string"),
    ("Insecure Deserialization", "Insecure Direct Object Reference"),
    ("Remote Code Execution", "Remote Command Execution"),
    ("Path Traversal", "SQL Injection"),
])
def test_different_classes_never_match(a, b):
    assert not _class_matches(a, b)
    assert not _class_matches(b, a)
