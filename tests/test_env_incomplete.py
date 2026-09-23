"""
An untested claim must not be reported as a failed one.

The sandbox runs a minimal python image with no third-party packages. A target
that imports Flask therefore dies at its own import line, long before the exploit
can do anything. Grading that UNPROVEN would assert "we tried and the claim did
not hold" when in truth nothing was ever tested -- the same class of overstatement
the evidence ladder exists to prevent, pointing the other way.

Reproduces the real failure observed running against targets/vulnerable_app:

    File "/work/app.py", line 12, in <module>
      from flask import Flask, request
    ModuleNotFoundError: No module named 'flask'
"""

import json

from sentinel.evidence import Evidence
from sentinel.llm import LLMResponse
from sentinel.sandbox import SandboxResult
from sentinel.scanner import Scanner
from sentinel.report import render_html
from sentinel.validator import missing_dependency

FLASK_TRACEBACK = (
    'Traceback (most recent call last):\n'
    '  File "<sentinel-poc>", line 7, in <module>\n'
    '  File "/work/app.py", line 12, in <module>\n'
    '    from flask import Flask, request\n'
    "ModuleNotFoundError: No module named 'flask'\n"
)


# --- the discriminator ------------------------------------------------------


def test_third_party_module_is_an_environment_gap():
    assert missing_dependency(FLASK_TRACEBACK, "app") == "flask"


def test_missing_target_module_is_not_excused_as_an_environment_gap():
    """A missing target module means the mount broke -- our fault, not the image's.

    This must stay UNPROVEN so the infrastructure fault stays visible instead of
    being written off as a dependency the sandbox happened to lack.
    """
    out = "ModuleNotFoundError: No module named 'app'"
    assert missing_dependency(out, "app") is None


def test_submodule_is_reported_by_its_top_level_package():
    assert missing_dependency("No module named 'yaml.cyaml'", "app") == "yaml"


def test_clean_output_reports_no_missing_dependency():
    assert missing_dependency("SENTINEL_PWNED", "app") is None


# --- end to end through the scanner ----------------------------------------


class StubLLM:
    model = "stub/model"

    def complete(self, prompt, system=None):
        if "Analyze this Python file" in prompt:
            text = (
                '{"findings": [{"vuln_class": "Command Injection", "line": 45,'
                ' "severity": "critical", "description": "os.system with user input",'
                ' "confidence": 1.0}]}'
            )
        else:
            text = "import app\nprint('SENTINEL_PWNED')"
        return LLMResponse(text=text, prompt_tokens=1, completion_tokens=1, cost_usd=0.0)


def _sandbox_missing_flask(self, command, workdir=None):
    return SandboxResult(1, "", FLASK_TRACEBACK, False)


def test_scanner_grades_a_dependency_gap_as_not_testable(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox_missing_flask)

    report = Scanner(StubLLM(), "targets/vulnerable_app").scan(patch=False)

    assert len(report.not_testable) == 1
    assert report.not_testable[0].evidence is Evidence.ENV_INCOMPLETE
    assert report.confirmed == []
    assert report.line_proven == []
    # and it must NOT be lumped in with exploits that genuinely failed
    assert all(s.evidence is not Evidence.UNPROVEN for s in report.scanned)


def test_not_testable_is_serialized_with_the_missing_module(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox_missing_flask)

    d = Scanner(StubLLM(), "targets/vulnerable_app").scan(patch=False).to_dict()
    json.dumps(d)

    assert d["counts"]["not_testable"] == 1
    entry = [s for s in d["scanned"] if s["evidence"] == "env_incomplete"][0]
    assert entry["validation"]["missing_module"] == "flask"


def test_report_separates_not_testable_and_names_the_package(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox_missing_flask)

    html = render_html(Scanner(StubLLM(), "targets/vulnerable_app").scan(patch=False))

    assert "NOT TESTABLE" in html
    assert "Not testable" in html
    assert "Sandbox gap" in html
    assert "flask" in html
    # the reader must be told this is not a failed exploit
    assert "never tested" in html or "nothing was proven" in html.lower()


def test_dependency_gap_is_never_patched(monkeypatch):
    """We must not rewrite code whose vulnerability we could not even test."""
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox_missing_flask)

    report = Scanner(StubLLM(), "targets/vulnerable_app").scan(patch=True)
    assert report.patches == []


def test_not_testable_is_excluded_from_the_not_demonstrated_count(monkeypatch):
    """Regression: an untested claim must not inflate the failed-exploit count.

    `rejected` means "not confirmed", which includes untestable claims -- but those
    get their own section, so using it for the "Not demonstrated" header printed a
    count of 2 above a single card.
    """
    import re
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox_missing_flask)

    report = Scanner(StubLLM(), "targets/vulnerable_app").scan(patch=False)
    html = render_html(report)

    assert len(report.rejected) == 1          # not confirmed
    assert len(report.not_demonstrated) == 0  # but never actually tested

    headers = dict(
        re.findall(r'<h2 class="section[^"]*">([^<]+?)\s*<span class="count">(\d+)</span>', html)
    )
    assert int(headers["Not testable"]) == 1
    assert "Not demonstrated" not in headers  # no empty section rendered


def test_mixed_tiers_keep_their_counts_separate(monkeypatch):
    """The case both earlier tests missed: an untestable AND a failed claim together.

    With only one tier present, `rejected` and `not_demonstrated` coincide and a
    wrong header count is invisible. This renders both at once.
    """
    import re

    class TwoFindingLLM(StubLLM):
        def complete(self, prompt, system=None):
            if "Analyze this Python file" in prompt:
                text = (
                    '{"findings": ['
                    '{"vuln_class": "Command Injection", "line": 45, "severity": "critical",'
                    ' "description": "os.system", "confidence": 1.0},'
                    '{"vuln_class": "SQL Injection", "line": 33, "severity": "critical",'
                    ' "description": "sqli", "confidence": 1.0}]}'
                )
                return LLMResponse(text=text, prompt_tokens=1, completion_tokens=1, cost_usd=0.0)
            return LLMResponse(text="import app", prompt_tokens=1, completion_tokens=1, cost_usd=0.0)

    calls = {"n": 0}

    def mixed(self, command, workdir=None):
        # first finding: dependency gap; second: a genuinely failing exploit
        calls["n"] += 1
        if calls["n"] <= 3:
            return SandboxResult(1, "", FLASK_TRACEBACK, False)
        return SandboxResult(1, "", "AssertionError: payload had no effect", False)

    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", mixed)

    report = Scanner(TwoFindingLLM(), "targets/vulnerable_app").scan(patch=False)
    assert len(report.not_testable) == 1
    assert len(report.not_demonstrated) == 1
    assert len(report.rejected) == 2      # both, which is why rejected is the wrong header

    html = render_html(report)
    headers = dict(
        re.findall(r'<h2 class="section[^"]*">([^<]+?)\s*<span class="count">(\d+)</span>', html)
    )
    assert int(headers["Not testable"]) == 1
    assert int(headers["Not demonstrated"]) == 1, "untestable claim inflated the failed count"
