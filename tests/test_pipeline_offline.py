"""
End-to-end pipeline checks with the model and sandbox stubbed out.

This exercises the real wiring -- hunt -> gate -> validate -> witness -> patch ->
report/JSON -- without Docker or an API key, by replacing the two boundaries that
touch the outside world: the LLM (LLMClient.complete) and the container
(Sandbox.run). If any stage stops handing the right shape to the next, this fails.

The sandbox stub is where the interesting coverage lives: by choosing whether it
emits a witness record, the same pipeline can be driven to LINE_PROVEN or to
CLASS_ONLY, which is exactly the distinction the project exists to make.
"""

import json

from sentinel.evidence import Evidence
from sentinel.llm import LLMResponse
from sentinel.sandbox import SandboxResult
from sentinel.scanner import Scanner
from sentinel.report import render_html
from sentinel.witness import WITNESS_PREFIX

FINDINGS_JSON = (
    '{"findings": [{"vuln_class": "SQL Injection", "line": 33, "severity": "critical",'
    ' "description": "user input concatenated into SQL", "confidence": 0.95}]}'
)


class StubLLM:
    """Stands in for LLMClient: returns hunter JSON, a PoC, then a fixed file."""
    model = "stub/model"

    def __init__(self):
        self.calls = 0

    def complete(self, prompt, system=None):
        self.calls += 1
        if "Analyze this Python file" in prompt:
            text = FINDINGS_JSON
        elif "proof-of-concept" in prompt.lower() or "exploit" in prompt.lower():
            text = "import app\nprint('SENTINEL_PWNED')"
        else:  # patch request
            text = "# fixed file\n"
        return LLMResponse(text=text, prompt_tokens=1, completion_tokens=1, cost_usd=0.0)


def _sandbox(stdout):
    return lambda self, command, workdir=None: SandboxResult(0, stdout, "", False)


def _witness(line_executed, lines):
    record = {
        "available": True,
        "file_executed": bool(lines),
        "line_executed": line_executed,
        "executed_lines": lines,
        "error": "",
    }
    return "SENTINEL_PWNED\n" + WITNESS_PREFIX + json.dumps(record) + "\n"


def test_full_pipeline_line_proven(monkeypatch):
    """Marker + the reported line in the trace -> LINE_PROVEN, and it gets patched."""
    monkeypatch.setattr(
        "sentinel.sandbox.Sandbox.run", _sandbox(_witness(True, [31, 32, 33]))
    )

    scanner = Scanner(StubLLM(), "targets/vulnerable_app")
    report = scanner.scan()

    assert len(report.line_proven) == 1
    assert report.line_proven[0].finding.vuln_class == "SQL Injection"
    assert report.line_proven[0].evidence is Evidence.LINE_PROVEN
    assert len(report.patches) == 1  # only line-proven findings are patched

    d = report.to_dict()
    assert d["counts"]["line_proven"] == 1
    assert d["counts"]["class_only"] == 0
    html = render_html(report)
    assert "SQL Injection" in html and "SENTINEL_PWNED" in html


def test_full_pipeline_class_only_is_not_patched(monkeypatch):
    """Same marker, but the trace never reaches the line -> CLASS_ONLY, no patch.

    This is the regression guard for the project's central claim: an exploit that
    prints the marker without executing the reported code must NOT be promoted to
    a confirmed finding, and must never trigger a rewrite of that code.
    """
    monkeypatch.setattr(
        "sentinel.sandbox.Sandbox.run", _sandbox(_witness(False, []))
    )

    scanner = Scanner(StubLLM(), "targets/vulnerable_app")
    report = scanner.scan()

    assert len(report.class_only) == 1
    assert report.line_proven == []
    assert report.patches == []           # nothing proven at a line, nothing rewritten
    assert len(report.confirmed) == 1     # permissive reading still counts it

    html = render_html(report)
    assert "CLASS ONLY" in html


def test_missing_witness_degrades_to_class_only(monkeypatch):
    """No trace captured must never be read as proof of the line."""
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox("SENTINEL_PWNED\n"))

    report = Scanner(StubLLM(), "targets/vulnerable_app").scan()
    assert len(report.class_only) == 1
    assert report.line_proven == []


def test_unproven_when_marker_absent(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox("nothing happened\n"))

    report = Scanner(StubLLM(), "targets/vulnerable_app").scan()
    assert report.confirmed == []
    assert report.scanned[0].evidence is Evidence.UNPROVEN


def test_confidence_gate_skips_low_confidence(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox(_witness(True, [33])))
    # Hunter returns confidence 0.95; a 0.99 gate should skip validation entirely.
    scanner = Scanner(StubLLM(), "targets/vulnerable_app", min_confidence=0.99)
    report = scanner.scan()
    assert len(report.scanned) == 1
    assert report.confirmed == []  # skipped, never validated


def test_reachability_gate_blocks_before_any_model_call(monkeypatch):
    """A candidate with no attacker path must cost zero validation calls."""
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _sandbox(_witness(True, [26])))

    llm = StubLLM()
    # safe_app line 26 is a parameterized query -> the gate should reject it.
    scanner = Scanner(llm, "targets/safe_app")
    calls_before_validation = None

    class SafeStub(StubLLM):
        def complete(self, prompt, system=None):
            if "Analyze this Python file" in prompt:
                return LLMResponse(
                    text='{"findings": [{"vuln_class": "SQL Injection", "line": 26,'
                         ' "severity": "high", "description": "sqli", "confidence": 0.9}]}',
                    prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
                )
            raise AssertionError("gate should have rejected before any exploit call")

    scanner = Scanner(SafeStub(), "targets/safe_app")
    report = scanner.scan(patch=False)

    assert len(report.gated_out) == 1
    assert report.gated_out[0].evidence is Evidence.UNREACHABLE
    assert report.confirmed == []
