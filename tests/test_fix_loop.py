"""
Fixes are checked, not trusted.

Before: the patcher was handed only the FIRST proven finding in a file, so a file
with SQL injection and command injection got one of them fixed; whatever the model
returned -- empty, unparseable, unchanged -- was offered as a fix and written by
`--yes`; and nobody checked that a fix stopped the exploit.

Now every proven finding in a file goes into one fix, the fix must parse, and the
exploits that proved the findings are replayed against a patched copy of the tree.
"""

import json
from pathlib import Path

import pytest

import scan
from sentinel.evidence import Evidence
from sentinel.hunter import Finding
from sentinel.llm import LLMResponse
from sentinel.patcher import (
    INCONCLUSIVE, STILL_EXPLOITABLE, VERIFIED, Patcher,
)
from sentinel.sandbox import SandboxResult
from sentinel.scanner import Scanner
from sentinel.witness import WITNESS_PREFIX

TARGET = "targets/vulnerable_app"
NONCE = "fix-loop-nonce"
FIXED_FILE = "import os\n\ndef get_user(name):\n    return name\n"

HUNT = json.dumps({"findings": [
    {"vuln_class": "SQL Injection", "line": 34, "severity": "critical",
     "description": "sqli", "confidence": 0.9},
    {"vuln_class": "Command Injection", "line": 45, "severity": "high",
     "description": "cmdi", "confidence": 0.8},
]})


class StubLLM:
    model = "stub/model"

    def __init__(self, patch_reply=FIXED_FILE):
        self.patch_reply = patch_reply
        self.patch_prompts = []

    def complete(self, prompt, system=None):
        if "Analyze this Python file" in prompt:
            text = HUNT
        elif "proof-of-concept" in prompt.lower() or "exploit" in prompt.lower():
            text = "import app\nprint('SENTINEL_PWNED')"
        else:
            self.patch_prompts.append(prompt)
            text = self.patch_reply
        return LLMResponse(text=text, prompt_tokens=0, completion_tokens=0, cost_usd=0.0)


def _record(lines, line_executed):
    return WITNESS_PREFIX + json.dumps({
        "nonce": NONCE, "available": True, "file_executed": bool(lines),
        "line_executed": line_executed, "executed_lines": lines}) + "\n"


@pytest.fixture(autouse=True)
def _fixed_nonce(monkeypatch):
    monkeypatch.setattr("sentinel.validator.new_nonce", lambda: NONCE)


def _sandbox(monkeypatch, replay_stdout):
    """Validation runs against the target and proves both lines; replays differ."""
    replays = []

    def run(self, command, workdir=None):
        if Path(workdir).name == "vulnerable_app":
            return SandboxResult(0, "SENTINEL_PWNED\n" + _record([33, 34, 45], True), "", False)
        replays.append(Path(workdir))
        patched = (Path(workdir) / "app.py").read_text(encoding="utf-8")
        assert patched.strip() == FIXED_FILE.strip(), "replay did not run on the patched tree"
        return SandboxResult(0, replay_stdout, "", False)

    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", run)
    return replays


def _scan(llm=None):
    return Scanner(llm or StubLLM(), TARGET).scan()


def test_every_proven_finding_in_a_file_goes_into_one_fix(monkeypatch):
    _sandbox(monkeypatch, _record([3, 4], False))
    llm = StubLLM()
    report = Scanner(llm, TARGET).scan()

    assert len(report.line_proven) == 2
    assert len(report.patches) == 1
    assert {f.vuln_class for f in report.patches[0].findings} == {
        "SQL Injection", "Command Injection"}
    assert "SQL Injection at line 34" in llm.patch_prompts[0]
    assert "Command Injection at line 45" in llm.patch_prompts[0]


def test_fix_is_verified_when_patched_code_runs_and_no_exploit_succeeds(monkeypatch):
    replays = _sandbox(monkeypatch, _record([3, 4], False))
    patch = _scan().patches[0]

    assert len(replays) == 2                          # one replay per proven finding
    assert all(r.name == "target" for r in replays)  # a copy, never the real tree
    assert patch.verification == VERIFIED and patch.applicable
    assert "exploit failed" in patch.verification_detail


def test_fix_that_leaves_the_exploit_working_is_flagged(monkeypatch):
    _sandbox(monkeypatch, "SENTINEL_PWNED\n" + _record([3], False))
    patch = _scan().patches[0]
    assert patch.verification == STILL_EXPLOITABLE and not patch.applicable


def test_exploit_that_cannot_reach_the_patched_code_proves_nothing(monkeypatch):
    """A fix that breaks the import also stops the exploit. That is not a fix."""
    _sandbox(monkeypatch, "ModuleNotFoundError: No module named 'app'\n" + _record([], False))
    patch = _scan().patches[0]
    assert patch.verification == INCONCLUSIVE and not patch.applicable


def test_the_real_target_is_never_modified_by_verification(monkeypatch):
    before = Path(TARGET, "app.py").read_text(encoding="utf-8")
    _sandbox(monkeypatch, _record([3], False))
    _scan()
    assert Path(TARGET, "app.py").read_text(encoding="utf-8") == before


@pytest.mark.parametrize("reply,problem", [
    ("", "empty"),
    ("def broken(:\n", "does not parse"),
])
def test_an_invalid_fix_is_never_offered(reply, problem):
    finding = Finding("SQL Injection", "app.py", 3, "high", "d", 0.9)
    patch = Patcher(StubLLM(patch_reply=reply)).propose([finding], "x = 1\n")
    assert not patch.valid and problem in patch.problem


def test_an_unchanged_file_is_not_a_fix():
    original = "x = 1\n"
    patch = Patcher(StubLLM(patch_reply=original)).propose(
        [Finding("SQL Injection", "app.py", 1, "high", "d", 0.9)], original)
    assert not patch.valid and "unchanged" in patch.problem


def test_the_final_newline_survives_the_rewrite():
    patch = Patcher(StubLLM(patch_reply="```python\ny = 2\n```")).propose(
        [Finding("SQL Injection", "app.py", 1, "high", "d", 0.9)], "x = 1\n")
    assert patch.fixed_code == "y = 2\n"


# --- the CLI only auto-applies what was verified --------------------------------

class _Report:
    def __init__(self, patches):
        self.patches = patches


def _patch(verification, valid=True):
    finding = Finding("SQL Injection", "app.py", 1, "high", "d", 0.9)
    p = Patcher(StubLLM(patch_reply="y = 2\n")).propose([finding], "x = 1\n")
    p.valid, p.verification = valid, verification
    return p


@pytest.mark.parametrize("verification,applied", [
    (VERIFIED, True), (STILL_EXPLOITABLE, False), (INCONCLUSIVE, False), ("not_run", False),
])
def test_yes_applies_only_verified_fixes(tmp_path, verification, applied, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("--yes must not prompt"))
    scan._offer_patches(_Report([_patch(verification)]), str(tmp_path), auto_yes=True)
    assert ((tmp_path / "app.py").read_text() == "y = 2\n") is applied


def test_an_invalid_fix_is_not_applied_even_when_the_user_says_yes(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    scan._offer_patches(_Report([_patch(VERIFIED, valid=False)]), str(tmp_path), auto_yes=False)
    assert (tmp_path / "app.py").read_text() == "x = 1\n"


def test_evidence_is_unchanged_by_verification(monkeypatch):
    _sandbox(monkeypatch, "SENTINEL_PWNED\n" + _record([3], False))
    report = _scan()
    assert all(s.evidence is Evidence.LINE_PROVEN for s in report.line_proven)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_applying_a_fix_keeps_the_file_line_endings(tmp_path, ending):
    """Regression: on Windows an LF file came back CRLF, a diff on every line."""
    from sentinel.patcher import write_fixed

    path = tmp_path / "app.py"
    path.write_bytes(b"x = 1" + ending + b"y = 2" + ending)
    write_fixed(path, "x = 1\ny = 3\n")
    assert path.read_bytes() == b"x = 1" + ending + b"y = 3" + ending
