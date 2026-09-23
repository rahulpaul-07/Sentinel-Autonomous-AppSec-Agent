"""
The sandbox must receive the target directory to mount.

Regression guard for a bug that every other test missed. The validator wraps each
PoC in a harness that does `sys.path.insert(0, "/work")` and then imports the
module under test -- but it called `Sandbox.run(command)` without `workdir`, so no
`-v <target>:/work:ro` was ever added to the docker command. `/work` was empty,
every exploit died with ModuleNotFoundError, and nothing could ever be proven.

The existing tests all stub `Sandbox.run` and assert on its *return value*, so they
passed regardless of the arguments it was called with. These assert on the call
itself instead.
"""

from pathlib import Path

from sentinel.hunter import Finding
from sentinel.llm import LLMResponse
from sentinel.sandbox import SandboxResult, Sandbox
from sentinel.scanner import Scanner
from sentinel.validator import Validator, MOUNT


class StubLLM:
    model = "stub/model"

    def complete(self, prompt, system=None):
        if "Analyze this Python file" in prompt:
            text = (
                '{"findings": [{"vuln_class": "SQL Injection", "line": 33,'
                ' "severity": "critical", "description": "sqli", "confidence": 0.9}]}'
            )
        elif "proof-of-concept" in prompt.lower() or "exploit" in prompt.lower():
            text = "import app\nprint('SENTINEL_PWNED')"
        else:
            text = "# fixed\n"
        return LLMResponse(text=text, prompt_tokens=1, completion_tokens=1, cost_usd=0.0)


def _recorder(calls):
    def run(self, command, workdir=None):
        calls.append({"command": command, "workdir": workdir})
        return SandboxResult(0, "SENTINEL_PWNED\n", "", False)
    return run


def test_validator_mounts_the_target_directory(monkeypatch):
    calls = []
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _recorder(calls))

    finding = Finding("SQL Injection", "app.py", 33, "critical", "sqli", 0.9)
    validator = Validator(StubLLM(), Sandbox(), target="targets/vulnerable_app")
    validator.validate(finding, "source")

    assert calls, "the sandbox was never invoked"
    workdir = calls[0]["workdir"]
    assert workdir is not None, "no workdir passed -- the target would not be mounted"
    assert Path(workdir).name == "vulnerable_app"


def test_scanner_wires_its_target_into_the_validator(monkeypatch):
    calls = []
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", _recorder(calls))

    scanner = Scanner(StubLLM(), "targets/vulnerable_app")
    scanner.scan(patch=False)

    assert calls, "the sandbox was never invoked"
    assert calls[0]["workdir"] is not None
    assert Path(calls[0]["workdir"]).name == "vulnerable_app"


def test_harness_imports_from_the_mount_point():
    """The harness's sys.path entry must match where the sandbox mounts the code."""
    from sentinel.witness import build_harness

    harness = build_harness("import app", "app.py", 33, mount=MOUNT, workdir="/tmp")
    assert f"sys.path.insert(0, {MOUNT!r})" in harness
    # The PoC must run somewhere writable: /work is mounted read-only, so a PoC
    # that creates a scratch database would fail if it ran there.
    assert 'os.chdir(\'/tmp\')' in harness or 'os.chdir("/tmp")' in harness


def test_sandbox_builds_a_readonly_mount_flag(monkeypatch):
    """The docker command must actually contain the read-only bind mount."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("sentinel.sandbox.Sandbox.preflight", staticmethod(lambda: None))

    Sandbox().run("echo hi", workdir=Path("targets/vulnerable_app"))

    cmd = captured["cmd"]
    joined = " ".join(str(c) for c in cmd)
    assert "-v" in cmd
    assert f":{MOUNT}:ro" in joined, f"no read-only mount at {MOUNT} in: {joined}"
