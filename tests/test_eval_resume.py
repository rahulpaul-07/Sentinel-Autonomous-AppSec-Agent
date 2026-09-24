"""
An evaluation must survive a provider's usage limit without losing finished runs.

Twice, a three-run evaluation hit Groq's daily token limit on its last run. The
results were written only at the end, so two finished runs were lost each time.
These tests pin what replaced that: every finished run is on disk before the next
starts, a limit stops the run cleanly, and --resume finishes the same measurement
later -- but only on the same code, model and settings, since otherwise the runs
would not be one measurement.
"""

from __future__ import annotations

import json

import pytest

import evaluate
from sentinel.llm import QuotaExhausted
from sentinel.metrics import Metrics, TieredMetrics

COMMIT = "a" * 40


def _stamp(commit=COMMIT, dirty=False, model="stub/model"):
    return {"started_at": "2026-09-25T00:00:00+00:00", "model": model,
            "sentinel": {"commit": commit, "dirty": dirty}}


def _target(tp=1, fn=0):
    return TieredMetrics(Metrics(tp, 0, fn), Metrics(tp, 0, fn), tiers={"line_proven": tp},
                         environment={"image": "sentinel-env:x", "status": "cached"},
                         hunter={"unreadable_files": [], "details": {},
                                 "retried_files": [], "dropped_entries": 0})


class MeteredLLM:
    """Stands in for LLMClient. Each target evaluated costs 1000 tokens."""

    model = "stub/model"

    def __init__(self):
        self.tokens = 0

    def usage(self):
        return {"calls": self.tokens // 1000, "prompt_tokens": self.tokens,
                "completion_tokens": 0, "total_tokens": self.tokens}


@pytest.fixture
def run(monkeypatch, capsys):
    """Run sentinel-eval with a scripted sequence of per-target outcomes."""

    def go(argv, outcomes, provenance=None, model="stub/model"):
        llm = MeteredLLM()
        llm.model = model
        script = iter(outcomes)
        calls = []

        def evaluate_target_tiered(llm_, target, build_env):
            calls.append(target)
            outcome = next(script)
            if isinstance(outcome, Exception):
                raise outcome
            if callable(outcome):
                return outcome()
            llm.tokens += 1000
            return outcome

        monkeypatch.setattr(evaluate.Sandbox, "preflight", staticmethod(lambda: None))
        monkeypatch.setattr(evaluate, "LLMClient", lambda: llm)
        monkeypatch.setattr(evaluate, "stamp", lambda m: dict(provenance or _stamp(model=m)))
        monkeypatch.setattr(evaluate, "evaluate_target_tiered", evaluate_target_tiered)
        monkeypatch.setattr("sys.argv", ["sentinel-eval", *argv])
        code = evaluate.main()
        out = capsys.readouterr()
        return code, out.out + out.err, calls

    return go


def _limit():
    return QuotaExhausted("stub/model", 971.5, "tokens per day (TPD)")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- a limit mid-evaluation -----------------------------------------------------------

def test_a_limit_keeps_every_finished_run_and_says_how_to_resume(run, tmp_path):
    out_file = tmp_path / "r.json"
    code, out, calls = run(["--runs", "3", "--json", str(out_file)],
                           [_target()] * 4 + [_target(), _limit()])

    assert code == 4
    record = _read(out_file)
    assert len(record["runs"]) == 1                      # the finished run
    assert record["complete"] is False and record["runs_requested"] == 3
    assert "try again in 16m" in record["stopped"]
    assert "--resume" in out and "1 of 3 runs saved" in out
    assert "Traceback" not in out


def test_each_run_is_on_disk_before_the_next_one_starts(run, tmp_path):
    out_file = tmp_path / "r.json"
    seen = {}

    def peek_then_score():
        seen["runs_on_disk"] = len(_read(out_file)["runs"])
        return _target()

    run(["--runs", "2", "--json", str(out_file)],
        [_target()] * 4 + [peek_then_score] + [_target()] * 3)

    assert seen["runs_on_disk"] == 1
    assert _read(out_file)["complete"] is True


def test_a_limit_without_a_results_file_still_stops_cleanly(run):
    code, out, _ = run(["--runs", "2"], [_limit()])
    assert code == 4 and "Traceback" not in out and "try again in 16m" in out


# --- resuming ----------------------------------------------------------------------------

def _stopped_after_one_run(run, out_file):
    run(["--runs", "3", "--json", str(out_file)], [_target(tp=0, fn=1)] * 4 + [_limit()])


def test_resume_finishes_the_measurement_and_scores_every_run(run, tmp_path):
    out_file = tmp_path / "r.json"
    _stopped_after_one_run(run, out_file)

    code, out, calls = run(["--runs", "3", "--json", str(out_file), "--resume"],
                           [_target()] * 8)

    assert code == 0
    assert len(calls) == 8                                # only the two missing runs
    record = _read(out_file)
    assert len(record["runs"]) == 3 and record["complete"] is True
    assert record["stopped"] is None
    assert len(record["resumed_at"]) == 1
    # The summary covers the saved run too: its 0% recall is in the range.
    assert "range 0%-100%" in out


@pytest.mark.parametrize("provenance, reason", [
    (_stamp(commit="b" * 40), "commit"),
    (_stamp(dirty=True), "uncommitted"),
    (_stamp(model="other/model"), "model"),
])
def test_resume_refuses_anything_but_the_same_code_and_model(run, tmp_path, provenance, reason):
    out_file = tmp_path / "r.json"
    _stopped_after_one_run(run, out_file)
    before = out_file.read_text(encoding="utf-8")

    code, out, calls = run(["--runs", "3", "--json", str(out_file), "--resume"],
                           [_target()] * 8, provenance=provenance,
                           model=provenance["model"])

    assert code == 2 and calls == []
    assert reason in out.lower()
    assert out_file.read_text(encoding="utf-8") == before


def test_resume_refuses_different_settings(run, tmp_path):
    out_file = tmp_path / "r.json"
    _stopped_after_one_run(run, out_file)
    code, out, calls = run(["--runs", "3", "--json", str(out_file), "--resume",
                            "--no-build-env"], [_target()] * 8)
    assert code == 2 and calls == [] and "build" in out.lower()


def test_resuming_a_complete_file_makes_no_calls(run, tmp_path):
    out_file = tmp_path / "r.json"
    run(["--runs", "1", "--json", str(out_file)], [_target()] * 4)
    code, out, calls = run(["--runs", "1", "--json", str(out_file), "--resume"], [])
    assert code == 0 and calls == [] and "already complete" in out.lower()


def test_an_existing_results_file_is_never_overwritten(run, tmp_path):
    out_file = tmp_path / "r.json"
    out_file.write_text('{"keep": true}', encoding="utf-8")

    code, out, calls = run(["--runs", "1", "--json", str(out_file)], [_target()] * 4)

    assert code == 2 and calls == []
    assert _read(out_file) == {"keep": True}
    assert "--resume" in out


# --- cost -------------------------------------------------------------------------------

def test_each_run_records_the_tokens_it_used(run, tmp_path):
    out_file = tmp_path / "r.json"
    run(["--runs", "2", "--json", str(out_file)], [_target()] * 8)
    runs = _read(out_file)["runs"]
    assert [r["tokens"]["total_tokens"] for r in runs] == [4000, 4000]
    assert all(r["started_at"] for r in runs)
