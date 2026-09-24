"""
The sandbox and the evidence ladder, exercised against a real Docker daemon.

Every other test stubs `Sandbox.run`. That is how the mount bug survived: the stub
returned a good result regardless of how it was called. These tests stub only the
model -- the PoC text is fixed -- and let everything else run for real: the docker
CLI, the security flags, the read-only mount, the tracing harness inside the
container, and the grading of what comes back.

Each test names the bug it would catch. To confirm a test is load-bearing, revert
the thing it protects and watch it fail:

  * drop `workdir=self.target` in Validator.validate   -> the LINE_PROVEN test fails
  * drop `"--network", "none"` in Sandbox.run           -> the network test fails
  * drop `:ro` from the mount                           -> the read-only test fails

Run with:  pytest -m docker
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.evidence import Evidence
from sentinel.hunter import Finding
from sentinel.llm import LLMResponse
from sentinel.sandbox import Sandbox
from sentinel.validator import Validator

pytestmark = pytest.mark.docker

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TARGET = FIXTURES / "sandbox_target"
NEEDS_DEP = FIXTURES / "needs_dependency"


def _line_of(path: Path, needle: str) -> int:
    """Find a line by content, so editing the fixture's docstring can't break tests."""
    for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in text:
            return number
    raise AssertionError(f"{needle!r} not found in {path}")


SINK_LINE = _line_of(TARGET / "app.py", "query = ")
SECRET_LINE = _line_of(TARGET / "app.py", "API_TOKEN = ")
YAML_SINK_LINE = _line_of(NEEDS_DEP / "app.py", "yaml.load(")


class FixedPocLLM:
    """Stands in for the model only. Always returns the same exploit."""

    model = "fixed/poc"

    def __init__(self, poc: str) -> None:
        self.poc = poc

    def complete(self, prompt, system=None):
        return LLMResponse(text=self.poc, prompt_tokens=0, completion_tokens=0, cost_usd=0.0)


def _validate(poc: str, target: Path, file: str, line: int, vuln_class: str):
    finding = Finding(vuln_class, file, line, "high", "fixture", 1.0)
    validator = Validator(FixedPocLLM(poc), Sandbox(), target=target, max_attempts=1)
    return validator.validate(finding, (target / file).read_text(encoding="utf-8"))


# --- the evidence ladder, end to end -----------------------------------------

TARGETED_POC = """\
import app
conn = app.setup()
if app.login(conn, "' OR '1'='1"):
    print("SENTINEL_PWNED")
"""

GENERIC_POC = """\
import sqlite3
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE t (a TEXT)")
conn.execute("INSERT INTO t VALUES ('x')")
if conn.execute("SELECT * FROM t WHERE a = '' OR '1'='1'").fetchall():
    print("SENTINEL_PWNED")
"""


def test_exploit_that_drives_the_line_is_line_proven():
    """Catches: target not mounted, wrong mount path, tracer path mismatch."""
    result = _validate(TARGETED_POC, TARGET, "app.py", SINK_LINE, "SQL Injection")

    assert result.evidence is Evidence.LINE_PROVEN, result.output
    assert result.witness is not None and result.witness.available
    assert SINK_LINE in result.witness.driven_lines


def test_exploit_that_reproduces_the_pattern_is_class_only():
    """Catches: the witness collapsing into the marker check."""
    result = _validate(GENERIC_POC, TARGET, "app.py", SINK_LINE, "SQL Injection")

    assert result.evidence is Evidence.CLASS_ONLY
    assert result.witness is not None and not result.witness.file_executed


def test_import_only_exploit_is_class_only_on_a_module_level_line():
    """Catches: import-time execution counted as a witness, inside the container."""
    poc = "import app\nprint('SENTINEL_PWNED')\n"
    result = _validate(poc, TARGET, "app.py", SECRET_LINE, "Hardcoded Secret")

    assert result.evidence is Evidence.CLASS_ONLY
    assert SECRET_LINE in result.witness.import_only_lines


def test_missing_third_party_package_is_env_incomplete():
    """Catches: an untestable claim reported as a failed exploit."""
    poc = "import app\nprint('SENTINEL_PWNED' if app.load('a: 1') else '')\n"
    result = _validate(poc, NEEDS_DEP, "app.py", YAML_SINK_LINE, "Insecure Deserialization")

    assert result.evidence is Evidence.ENV_INCOMPLETE, result.output
    assert result.missing_module == "yaml"


# --- the cage ----------------------------------------------------------------

def test_container_has_no_network():
    """Catches: `--network none` removed or overridden."""
    probe = (
        "python3 -c \"import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
        "    print('CONNECTED')\n"
        "except OSError:\n"
        "    print('BLOCKED')\""
    )
    result = Sandbox().run(probe)

    assert "BLOCKED" in result.stdout, result.stdout + result.stderr
    assert "CONNECTED" not in result.stdout


def test_mounted_target_is_read_only():
    """Catches: the target mounted writable, so a PoC could alter the code it tests."""
    probe = (
        "python3 -c \"\n"
        "try:\n"
        "    open('/work/app.py', 'a').write('# tampered')\n"
        "    print('WROTE')\n"
        "except OSError:\n"
        "    print('WRITE_BLOCKED')\""
    )
    result = Sandbox().run(probe, workdir=TARGET)

    assert "WRITE_BLOCKED" in result.stdout, result.stdout + result.stderr
    assert "# tampered" not in (TARGET / "app.py").read_text(encoding="utf-8")


def test_runaway_exploit_is_killed():
    """Catches: the timeout path no longer firing."""
    result = Sandbox(timeout_seconds=5).run("sleep 60")

    assert result.timed_out
