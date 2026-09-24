"""
Tests for the CVE benchmark harness.

The numbers this produces are only as honest as its rules, so the rules are what
is tested: which finding counts as the labelled bug, which tier wins, what each
ratio divides by, and that the runner scans exactly the commit it was told to,
in the image it was told to, with dependencies read from the repo root.

Checkout runs real git against a local repository. The scanner is faked, and the
fake records how it was CALLED.
"""

from __future__ import annotations

import copy
import subprocess
from pathlib import Path

import pytest

from sentinel.cve_benchmark import (
    CaseResult,
    ManifestError,
    aggregate,
    checkout,
    load_manifest,
    matches_sink,
    parse_manifest,
    run_benchmark,
    score_fixed,
    score_vulnerable,
    spread,
)
from sentinel.evaluation import LINE_TOLERANCE
from sentinel.evidence import Evidence
from sentinel.hunter import Finding
from sentinel.scanner import ScannedFinding, ScanReport

SHA_A = "a" * 40
SHA_B = "b" * 40

GOOD = {
    "id": "CVE-2099-0001",
    "repo": "https://example.invalid/proj.git",
    "vulnerable_commit": SHA_A,
    "fixed_commit": SHA_B,
    "vuln_class": "SQL Injection",
    "cwe": "CWE-89",
    "sink": {"file": "src/proj/db.py", "line": 40},
    "sink_rationale": "query is built by string concatenation and executed on line 40",
    "scan_path": "src",
    "python": "3.11",
    "published": "2099-01-02",
}


def _manifest(*cases):
    return {"schema": 1, "cases": list(cases)}


def _case(**overrides):
    raw = copy.deepcopy(GOOD)
    raw.update(overrides)
    return parse_manifest(_manifest(raw))[0]


# --- manifest validation --------------------------------------------------------

def test_valid_case_parses():
    case = _case()
    assert case.sink_file == "src/proj/db.py" and case.sink_line == 40
    assert case.image == "python:3.11-slim"


def test_the_shipped_manifest_is_valid():
    assert load_manifest("benchmarks/cves/manifest.json") is not None


@pytest.mark.parametrize("overrides, expected", [
    ({"vulnerable_commit": "abc123"}, "full 40-character"),
    ({"fixed_commit": SHA_A}, "are the same"),
    ({"sink": {"file": "src/proj/db.py", "line": 0}}, "positive integer"),
    ({"sink": {"file": "src/proj/db.txt", "line": 4}}, ".py path"),
    ({"sink": {"file": "lib/db.py", "line": 4}}, "outside scan_path"),
    ({"sink": {"file": "../db.py", "line": 4}, "scan_path": ""}, "without '..'"),
    ({"sink_rationale": "it is here"}, "why this line"),
    ({"python": "3"}, "3.12"),
    ({"published": "Jan 2 2099"}, "YYYY-MM-DD"),
])
def test_invalid_fields_are_rejected(overrides, expected):
    with pytest.raises(ManifestError) as exc:
        _case(**overrides)
    assert any(expected in p for p in exc.value.problems), exc.value.problems


def test_every_problem_is_reported_at_once():
    bad = dict(GOOD, vulnerable_commit="x", published="soon")
    missing = {"id": "CVE-2099-0002"}
    with pytest.raises(ManifestError) as exc:
        parse_manifest(_manifest(bad, missing))
    text = "\n".join(exc.value.problems)
    assert "40-character" in text and "YYYY-MM-DD" in text and "missing" in text


def test_duplicate_ids_are_rejected():
    with pytest.raises(ManifestError, match="duplicate id"):
        parse_manifest(_manifest(GOOD, GOOD))


def test_scan_path_empty_means_the_whole_repo():
    case = _case(scan_path="", sink={"file": "proj/db.py", "line": 3})
    assert case.scan_path == ""


# --- matching: the pre-registered rule -------------------------------------------

def _f(file="proj/db.py", line=40, cls="SQL Injection"):
    return Finding(cls, file, line, "high", "d", 0.9)


def test_finding_paths_are_relative_to_the_scan_root():
    case = _case()                                   # scan_path "src"
    assert matches_sink(case, _f("proj/db.py"))      # -> src/proj/db.py
    assert not matches_sink(case, _f("src/proj/db.py"))


def test_line_tolerance_boundary():
    case = _case()
    assert matches_sink(case, _f(line=40 + LINE_TOLERANCE))
    assert not matches_sink(case, _f(line=40 + LINE_TOLERANCE + 1))


def test_class_must_share_a_keyword():
    case = _case()
    assert matches_sink(case, _f(cls="SQL injection via f-string"))
    assert not matches_sink(case, _f(cls="Command Injection"))


def test_windows_separators_in_findings_match():
    assert matches_sink(_case(), _f("proj\\db.py"))


# --- scoring -----------------------------------------------------------------------

def _report(*entries):
    return ScanReport(target="t", scanned=[
        ScannedFinding(finding=f, confirmed=ev.is_confirmed, evidence=ev) for f, ev in entries
    ])


def test_strongest_matching_tier_wins():
    case, result = _case(), CaseResult("c", 1)
    score_vulnerable(case, _report(
        (_f(line=38), Evidence.CLASS_ONLY),
        (_f(line=41), Evidence.LINE_PROVEN),
        (_f(line=40), Evidence.ENV_INCOMPLETE),
    ), result)
    assert result.outcome == "line_proven"


def test_tested_and_failed_outranks_not_tested():
    case, result = _case(), CaseResult("c", 1)
    score_vulnerable(case, _report(
        (_f(), Evidence.ENV_INCOMPLETE), (_f(line=42), Evidence.UNPROVEN),
    ), result)
    assert result.outcome == "unproven"


def test_nothing_matching_is_not_reported():
    case, result = _case(), CaseResult("c", 1)
    score_vulnerable(case, _report((_f(file="proj/other.py"), Evidence.UNPROVEN)), result)
    assert result.outcome == "not_reported"


def test_line_proven_elsewhere_is_listed_for_review_not_counted():
    case, result = _case(), CaseResult("c", 1)
    score_vulnerable(case, _report(
        (_f(file="proj/views.py", line=12, cls="Path Traversal"), Evidence.LINE_PROVEN),
    ), result)
    assert result.outcome == "not_reported"
    assert result.unlabelled_line_proven == ["src/proj/views.py:12 Path Traversal"]


def test_fixed_version_line_proof_is_recorded_at_any_line():
    case, result = _case(), CaseResult("c", 1)
    score_fixed(case, _report(
        (_f(line=90), Evidence.LINE_PROVEN),
        (_f(line=41), Evidence.CLASS_ONLY),
        (_f(file="proj/views.py"), Evidence.LINE_PROVEN),     # other file: ignored
        (_f(cls="Command Injection"), Evidence.LINE_PROVEN),  # other class: ignored
    ), result)
    assert result.fixed_line_proven == ["src/proj/db.py:90"]
    assert result.fixed_class_only == 1


# --- denominators ---------------------------------------------------------------------

def _results(*outcomes, errors=0):
    rs = [CaseResult(f"c{i}", 1, outcome=o) for i, o in enumerate(outcomes)]
    rs += [CaseResult(f"e{i}", 1, error="boom") for i in range(errors)]
    return rs


def test_both_recall_readings_are_reported_with_their_denominators():
    agg = aggregate(_results("line_proven", "class_only", "env_incomplete", "unproven"))
    assert agg["cases_scored"] == 4
    assert agg["line_proven_recall"] == 1 / 4
    assert agg["line_proven_recall_of_testable"] == 1 / 3
    assert agg["permissive_recall"] == 2 / 4
    assert agg["class_only_share_of_confirmed"] == 1 / 2


def test_errored_cases_are_excluded_and_counted():
    agg = aggregate(_results("line_proven", errors=2))
    assert agg["cases_scored"] == 1 and agg["cases_errored"] == 2
    assert agg["line_proven_recall"] == 1.0


def test_ratios_with_no_denominator_are_none_not_zero():
    agg = aggregate(_results("env_incomplete"))
    assert agg["line_proven_recall_of_testable"] is None
    assert agg["class_only_share_of_confirmed"] is None


def test_spread_is_min_and_max_never_a_best_run():
    runs = [aggregate(_results("line_proven", "unproven")),
            aggregate(_results("unproven", "unproven"))]
    assert spread(runs)["line_proven_recall"] == {"min": 0.0, "max": 0.5}


# --- checkout: real git ------------------------------------------------------------------

def _git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def origin(tmp_path):
    repo = tmp_path / "origin"
    (repo / "src" / "proj").mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "src" / "proj" / "db.py").write_text("VULNERABLE = True\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "vulnerable")
    vulnerable = _git(repo, "rev-parse", "HEAD")
    (repo / "src" / "proj" / "db.py").write_text("VULNERABLE = False\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "fix")
    fixed = _git(repo, "rev-parse", "HEAD")
    return repo, vulnerable, fixed


def test_checkout_materialises_exactly_the_requested_commit(origin, tmp_path):
    repo, vulnerable, fixed = origin
    url = repo.as_uri()

    v = checkout(url, vulnerable, tmp_path / "v")
    f = checkout(url, fixed, tmp_path / "f")

    assert (v / "src/proj/db.py").read_text() == "VULNERABLE = True\n"
    assert (f / "src/proj/db.py").read_text() == "VULNERABLE = False\n"


def test_checkout_reuses_a_matching_cache_and_replaces_a_stale_one(origin, tmp_path):
    repo, vulnerable, fixed = origin
    dest = tmp_path / "c"
    checkout(repo.as_uri(), vulnerable, dest)
    checkout(repo.as_uri(), fixed, dest)            # same directory, different commit
    assert (dest / "src/proj/db.py").read_text() == "VULNERABLE = False\n"


def test_checkout_of_an_unknown_commit_fails_loudly(origin, tmp_path):
    repo, _, _ = origin
    with pytest.raises(RuntimeError):
        checkout(repo.as_uri(), "c" * 40, tmp_path / "x")


# --- the runner: assert on how the scanner is CALLED ----------------------------------------

class _Env:
    def to_dict(self):
        return {"image": "sentinel-env:x", "status": "built"}


class RecordingScanner:
    calls: list = []

    def __init__(self, llm, target, **kwargs):
        RecordingScanner.calls.append({"target": target, **kwargs})
        self.target = target

    def scan(self, patch=True):
        assert patch is False, "the benchmark must never generate patches"
        vulnerable = (Path(self.target) / "proj" / "db.py").read_text().startswith("VULNERABLE = True")
        ev = Evidence.LINE_PROVEN if vulnerable else Evidence.UNPROVEN
        report = _report((_f(line=1), ev))
        report.environment = _Env()
        return report


class _LLM:
    model = "stub/model"


def test_runner_scans_both_commits_in_the_case_image_with_repo_root_deps(origin, tmp_path):
    repo, vulnerable, fixed = origin
    case = _case(repo=repo.as_uri(), vulnerable_commit=vulnerable, fixed_commit=fixed,
                 sink={"file": "src/proj/db.py", "line": 1})
    RecordingScanner.calls = []

    record = run_benchmark([case], _LLM(), runs=2, cache_dir=tmp_path / "cache",
                           scanner_factory=RecordingScanner)

    assert len(RecordingScanner.calls) == 4                    # 2 runs x 2 commits
    for call in RecordingScanner.calls:
        assert call["build_env"] is True
        assert call["image"] == "python:3.11-slim"
        assert Path(call["target"]) == Path(call["env_root"]) / "src"
    roots = {Path(c["env_root"]).name for c in RecordingScanner.calls}
    assert roots == {"vulnerable", "fixed"}

    first = record["results"][0]
    assert first["outcome"] == "line_proven"
    assert first["fixed_line_proven"] == []
    assert first["environment_vulnerable"]["image"] == "sentinel-env:x"
    assert record["model"] == "stub/model" and record["runs"] == 2
    assert record["spread"]["line_proven_recall"] == {"min": 1.0, "max": 1.0}
    assert "commit" in record["sentinel"]


def test_one_broken_case_does_not_end_the_run(origin, tmp_path):
    repo, vulnerable, fixed = origin
    good = _case(repo=repo.as_uri(), vulnerable_commit=vulnerable, fixed_commit=fixed,
                 sink={"file": "src/proj/db.py", "line": 1})
    broken = _case(id="CVE-2099-0009", repo=repo.as_uri(),
                   vulnerable_commit="c" * 40, fixed_commit=fixed)
    RecordingScanner.calls = []

    record = run_benchmark([broken, good], _LLM(), runs=1, cache_dir=tmp_path / "cache",
                           scanner_factory=RecordingScanner)

    by_id = {r["case_id"]: r for r in record["results"]}
    assert by_id["CVE-2099-0009"]["error"].startswith("checkout failed")
    assert by_id[good.id]["outcome"] == "line_proven"
    assert record["per_run"][0]["cases_errored"] == 1


# --- the CLI refuses to produce a number from nothing ---------------------------------

def test_cli_refuses_an_empty_manifest(tmp_path, monkeypatch, capsys):
    import benchmark_cves
    m = tmp_path / "m.json"
    m.write_text('{"schema": 1, "cases": []}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["sentinel-cve", "--manifest", str(m)])

    assert benchmark_cves.main() == 2
    assert "No cases" in capsys.readouterr().err


def test_cli_reports_every_manifest_problem(tmp_path, monkeypatch, capsys):
    import benchmark_cves
    m = tmp_path / "m.json"
    m.write_text('{"schema": 1, "cases": [{"id": "x"}]}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["sentinel-cve", "--manifest", str(m)])

    assert benchmark_cves.main() == 2
    assert "missing" in capsys.readouterr().err


def test_runner_drives_the_real_scanner_with_the_case_image(origin, tmp_path, monkeypatch):
    """Closes the gap the fake leaves: the real Scanner must accept what the runner passes."""
    from sentinel.environment import Environment
    from sentinel.llm import LLMResponse

    repo, vulnerable, fixed = origin
    sink = "import sqlite3\ndef q(name):\n    return sqlite3.connect(':memory:').execute(\"SELECT '\" + name + \"'\")\n"
    (repo / "src/proj/db.py").write_text(sink, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "sink")
    vulnerable = _git(repo, "rev-parse", "HEAD")

    class LLM:
        model = "stub/model"

        def complete(self, prompt, system=None):
            if "Analyze this Python file" in prompt:
                text = ('{"findings": [{"vuln_class": "SQL Injection", "line": 3,'
                        ' "severity": "high", "description": "d", "confidence": 0.9}]}')
            else:
                text = "print('SENTINEL_PWNED')"
            return LLMResponse(text=text, prompt_tokens=0, completion_tokens=0, cost_usd=0.0)

    built_from = []
    monkeypatch.setattr("sentinel.scanner.prepare_environment",
                        lambda root, base: built_from.append((root, base)) or Environment(image=base))
    docker_runs = []

    class _Proc:
        returncode, stdout, stderr = 0, "SENTINEL_PWNED\n", ""

    real_run = subprocess.run

    def fake_run(cmd, **kw):
        # `sentinel.sandbox.subprocess` is the global module, so git goes through
        # here too. Only docker is faked; everything else runs for real.
        if cmd[0] != "docker":
            return real_run(cmd, **kw)
        docker_runs.append(cmd)
        return _Proc()

    monkeypatch.setattr("sentinel.sandbox.subprocess.run", fake_run)

    case = _case(repo=repo.as_uri(), vulnerable_commit=vulnerable, fixed_commit=fixed,
                 sink={"file": "src/proj/db.py", "line": 3})
    record = run_benchmark([case], LLM(), runs=1, cache_dir=tmp_path / "cache")

    assert record["results"][0]["error"] == ""
    assert {Path(root).name for root, _ in built_from} == {"vulnerable", "fixed"}
    assert all(base == "python:3.11-slim" for _, base in built_from)
    assert docker_runs and all("python:3.11-slim" in cmd for cmd in docker_runs)
    # No witness record came back, so a marker alone is class-only, never line-proven.
    assert record["results"][0]["outcome"] == "class_only"
