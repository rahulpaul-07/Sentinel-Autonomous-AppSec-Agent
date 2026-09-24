"""
The evaluator must not be able to print a flattering number about a run that
tested nothing.

What happened: Docker was not running, every exploit failed to start and was graded
UNPROVEN, and `sentinel-eval` printed "Precision: 100%, Recall: 0%" three times. A
model that found nothing, a sandbox that never started, and a dependency image that
never built all printed the same line. These tests pin the three changes that make
them distinguishable.
"""

from __future__ import annotations

import pytest

import evaluate
from sentinel import evaluation
from sentinel.environment import Environment
from sentinel.evidence import Evidence
from sentinel.hunter import Finding
from sentinel.metrics import Metrics, TieredMetrics
from sentinel.sandbox import SandboxUnavailable
from sentinel.scanner import ScannedFinding, ScanReport


# --- undefined is not 100% -----------------------------------------------------

def test_precision_with_nothing_confirmed_is_undefined_not_perfect():
    m = Metrics(tp=0, fp=0, fn=5)
    assert m.precision is None
    assert m.recall == 0.0
    assert m.f1 == 0.0


def test_recall_with_no_ground_truth_is_undefined():
    assert Metrics(tp=0, fp=2, fn=0).recall is None


def test_all_zero_has_no_f1():
    assert Metrics().f1 is None


def test_f1_matches_the_harmonic_mean_where_both_exist():
    m = Metrics(tp=3, fp=1, fn=2)
    p, r = m.precision, m.recall
    assert m.f1 == pytest.approx(2 * p * r / (p + r))


def test_undefined_values_serialise_as_null():
    d = TieredMetrics(Metrics(0, 0, 5), Metrics(0, 0, 5)).to_dict()
    assert d["strict"]["precision"] is None
    assert d["precision_overstatement"] is None


# --- no Docker, no run ----------------------------------------------------------

def test_eval_refuses_to_run_without_docker(monkeypatch, capsys):
    def no_docker():
        raise SandboxUnavailable("Cannot connect to the Docker daemon")

    def must_not_run(*a, **k):
        raise AssertionError("scored a target without a sandbox")

    monkeypatch.setattr(evaluate.Sandbox, "preflight", staticmethod(no_docker))
    monkeypatch.setattr(evaluate, "evaluate_target_tiered", must_not_run)
    monkeypatch.setattr(evaluate, "LLMClient", must_not_run)
    monkeypatch.setattr("sys.argv", ["sentinel-eval", "--runs", "3"])

    assert evaluate.main() == 3
    err = capsys.readouterr().err
    assert "Docker" in err and "No model calls were made" in err


# --- what a run prints ------------------------------------------------------------

def _tiered(strict, permissive, tiers, status="built"):
    return TieredMetrics(strict, permissive, tiers=tiers,
                         environment={"image": "sentinel-env:abc", "status": status})


CLEAN = {"started_at": "2026-09-24T00:00:00+00:00", "model": "stub/model",
         "sentinel": {"commit": "a" * 40, "dirty": False}}


def _run_main(monkeypatch, capsys, per_target, argv=(), provenance=CLEAN):
    calls = iter(per_target)
    monkeypatch.setattr(evaluate.Sandbox, "preflight", staticmethod(lambda: None))
    monkeypatch.setattr(evaluate, "LLMClient", lambda: object())
    # Pinned, so the test does not depend on the state of the checkout it runs in.
    monkeypatch.setattr(evaluate, "stamp", lambda model: dict(provenance))
    monkeypatch.setattr(evaluate, "evaluate_target_tiered",
                        lambda llm, target, build_env: next(calls))
    monkeypatch.setattr("sys.argv", ["sentinel-eval", *argv])
    assert evaluate.main() == 0
    return capsys.readouterr().out


def test_every_target_shows_its_image_and_how_each_candidate_was_graded(monkeypatch, capsys):
    out = _run_main(monkeypatch, capsys, [
        _tiered(Metrics(2, 0, 1), Metrics(3, 0, 0), {"line_proven": 2, "class_only": 1}),
        _tiered(Metrics(0, 0, 0), Metrics(0, 0, 0), {"unreachable": 2}),
        _tiered(Metrics(1, 0, 0), Metrics(1, 0, 0), {"line_proven": 1}),
        _tiered(Metrics(0, 0, 1), Metrics(0, 0, 1), {"unproven": 1}),
    ])

    assert "sentinel-env:abc (built)" in out
    assert "line-proven 2, class-only 1" in out
    assert "gated out 2" in out
    assert "strict (line-proven):" in out and "permissive (marker only):" in out
    assert "WARNING" not in out


def test_a_run_that_confirmed_nothing_says_so(monkeypatch, capsys):
    """The failing run, replayed: every candidate unproven, nothing confirmed."""
    nothing = _tiered(Metrics(0, 0, 1), Metrics(0, 0, 1), {"unproven": 2})
    control = _tiered(Metrics(0, 0, 0), Metrics(0, 0, 0), {"unproven": 1})
    out = _run_main(monkeypatch, capsys, [nothing, control, nothing, nothing])

    assert "P=100%" not in out and "Precision: 100%" not in out
    assert "P=n/a" in out
    assert "n/a (undefined in every run" in out
    assert "unproven 2" in out


def test_failed_image_build_and_untestable_findings_are_warned(monkeypatch, capsys):
    out = _run_main(monkeypatch, capsys, [
        _tiered(Metrics(0, 0, 3), Metrics(0, 0, 3), {"env_incomplete": 3}, "build_failed"),
        _tiered(Metrics(0, 0, 0), Metrics(0, 0, 0), {}),
        _tiered(Metrics(0, 0, 1), Metrics(0, 0, 1), {}),
        _tiered(Metrics(0, 0, 1), Metrics(0, 0, 1), {}),
    ])

    assert "WARNING: targets/vulnerable_app: dependency image failed to build" in out
    assert "WARNING: targets/vulnerable_app: 3 finding(s) not testable" in out
    assert "measure the environment, not the method" in out


# --- the evaluator reads tiers from the real report ------------------------------------

def test_tiered_evaluation_counts_every_candidate_and_records_the_image(monkeypatch):
    def entry(line, cls, ev):
        return ScannedFinding(Finding(cls, "app.py", line, "high", "d", 0.9),
                              confirmed=ev.is_confirmed, evidence=ev)

    class FakeScanner:
        def __init__(self, llm, target, build_env=False):
            pass

        def scan(self, patch=True):
            report = ScanReport(target="t", scanned=[
                entry(33, "SQL Injection", Evidence.LINE_PROVEN),
                entry(18, "Hardcoded Secret", Evidence.CLASS_ONLY),
                entry(45, "Command Injection", Evidence.ENV_INCOMPLETE),
                entry(50, "Command Injection", Evidence.UNREACHABLE),
            ])
            report.environment = Environment(image="sentinel-env:x", status="cached")
            return report

    monkeypatch.setattr(evaluation, "Scanner", FakeScanner)
    m = evaluation.evaluate_target_tiered(object(), "targets/vulnerable_app")

    assert m.tiers == {"line_proven": 1, "class_only": 1, "env_incomplete": 1,
                       "unreachable": 1}
    assert m.environment["status"] == "cached"
    assert m.strict.tp == 1           # SQLi at 33 matches ground truth
    assert m.permissive.tp == 2       # plus the class-only secret at 18


# --- provenance and unreadable hunter replies -----------------------------------------

def _quiet():
    return _tiered(Metrics(0, 0, 1), Metrics(0, 0, 1), {})


def test_results_file_records_model_commit_and_dirty_flag(monkeypatch, capsys, tmp_path):
    import json
    out_file = tmp_path / "r.json"
    _run_main(monkeypatch, capsys, [_quiet()] * 4, argv=["--json", str(out_file)])

    record = json.loads(out_file.read_text(encoding="utf-8"))
    assert record["model"] == "stub/model"
    assert record["sentinel"] == {"commit": "a" * 40, "dirty": False}
    assert record["build_env"] is True
    assert len(record["runs"]) == 1 and "strict" in record["runs"][0]


def test_uncommitted_changes_are_flagged(monkeypatch, capsys):
    dirty = dict(CLEAN, sentinel={"commit": "b" * 40, "dirty": True})
    out = _run_main(monkeypatch, capsys, [_quiet()] * 4, provenance=dirty)
    assert "UNCOMMITTED CHANGES" in out
    assert "cannot be tied to it" in out


def test_no_candidates_says_whether_the_reply_was_read(monkeypatch, capsys):
    unreadable = _quiet()
    unreadable.hunter = {"unreadable_files": ["app.py"], "dropped_entries": 0}
    read_fine = _quiet()
    read_fine.hunter = {"unreadable_files": [], "dropped_entries": 0}

    out = _run_main(monkeypatch, capsys, [unreadable, read_fine, _quiet(), _quiet()])

    assert "no candidates (hunter reply unreadable)" in out
    assert "no candidates (model reported none)" in out
    assert "WARNING: targets/vulnerable_app: hunter reply unreadable for app.py" in out
