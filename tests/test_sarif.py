"""SARIF export and the CI gate: only proven findings reach a dashboard or fail a build."""

import json

import pytest

import scan
from sentinel.evidence import Evidence
from sentinel.sarif import rule_id, to_sarif
from tests._fixtures import sample_report


def _sarif():
    report = sample_report()
    report.target = "targets/vulnerable_app"
    return report, to_sarif(report)


def test_document_has_the_required_sarif_shape():
    _, doc = _sarif()
    json.dumps(doc)                       # serializable
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Sentinel"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        assert not loc["artifactLocation"]["uri"].startswith("/")
        assert result["partialFingerprints"]["sentinelFinding/v1"]


def test_levels_follow_the_evidence_ladder_and_suspicions_stay_out():
    report, doc = _sarif()
    results = doc["runs"][0]["results"]
    by_tier = {r["properties"]["evidence"]: r["level"] for r in results}

    assert by_tier == {"line_proven": "error", "class_only": "warning"}
    exported = len(report.line_proven) + len(report.class_only)
    assert len(results) == exported < len(report.scanned)


def test_paths_are_relative_to_the_repository_root():
    _, doc = _sarif()
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]}
    assert uris == {"targets/vulnerable_app/app.py"}


def test_rule_carries_github_security_severity():
    _, doc = _sarif()
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert 0.0 < float(rule["properties"]["security-severity"]) <= 10.0


def test_rule_ids_are_stable_slugs():
    assert rule_id("SQL Injection") == "sentinel/sql-injection"
    assert rule_id("  Path  Traversal!! ") == "sentinel/path-traversal"


# --- --fail-on ------------------------------------------------------------------

@pytest.mark.parametrize("threshold,fails", [
    ("none", False), ("low", True), ("critical", True),
])
def test_fail_on_counts_only_line_proven_findings(threshold, fails):
    report = sample_report()
    assert bool(scan.should_fail(report, threshold)) is fails


def test_fail_on_ignores_class_only_findings_however_severe():
    report = sample_report()
    for s in report.scanned:
        if s.evidence is Evidence.LINE_PROVEN:
            s.finding.severity = "low"
        else:
            s.finding.severity = "critical"
    assert scan.should_fail(report, "high") == []


def test_unknown_severity_fails_closed():
    report = sample_report()
    for s in report.line_proven:
        s.finding.severity = "unknown"
    assert scan.should_fail(report, "critical")


@pytest.mark.parametrize("argv", [
    ["--min-confidence", "1.5"], ["--max-findings", "0"], ["--open"],
])
def test_bad_arguments_are_rejected_up_front(argv):
    with pytest.raises(SystemExit) as exc:
        scan._parse_args(["targets/vulnerable_app", *argv])
    assert exc.value.code == 2


def test_missing_model_configuration_is_a_clean_error(monkeypatch, capsys):
    monkeypatch.delenv("SENTINEL_MODEL", raising=False)
    monkeypatch.setattr("sentinel.llm._ensure_env", lambda: None)
    assert scan.main(["targets/vulnerable_app", "--no-validate"]) == scan.EXIT_USAGE
    assert "SENTINEL_MODEL" in capsys.readouterr().err
