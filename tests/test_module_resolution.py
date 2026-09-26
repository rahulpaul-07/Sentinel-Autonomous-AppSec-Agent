"""
The validator must import the target the way the project itself would.

Before this, the module name was the file's basename and only the mount root was
on sys.path. That works for a single `app.py`, and nothing else: `src/pkg/db.py`
became `import db`, which fails on any real package, and a relative import inside
the package fails even if you get past that. Every real-world target would die on
import and be graded UNPROVEN, which says "we tried and the exploit failed" about
code nobody ever ran.

The rule: walk up from the file while the directory is a package (has an
`__init__.py`). The first directory that is not a package is what goes on
sys.path, and the dotted path from there is the module name.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sentinel.hunter import Finding
from sentinel.llm import LLMResponse
from sentinel.sandbox import SandboxResult
from sentinel.validator import MOUNT, Validator, missing_dependency, resolve_import
from sentinel.witness import build_harness, parse_witness


def _write(root: Path, rel: str, text: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- resolution --------------------------------------------------------------

def test_flat_file_imports_by_its_stem(tmp_path):
    _write(tmp_path, "app.py")
    assert resolve_import(tmp_path, "app.py") == ("", "app")


def test_package_file_imports_by_dotted_path(tmp_path):
    _write(tmp_path, "pkg/__init__.py")
    _write(tmp_path, "pkg/db.py")
    assert resolve_import(tmp_path, "pkg/db.py") == ("", "pkg.db")


def test_src_layout_puts_src_on_the_path(tmp_path):
    _write(tmp_path, "src/pkg/__init__.py")
    _write(tmp_path, "src/pkg/sub/__init__.py")
    _write(tmp_path, "src/pkg/sub/db.py")
    assert resolve_import(tmp_path, "src/pkg/sub/db.py") == ("src", "pkg.sub.db")


def test_package_init_is_the_package_itself(tmp_path):
    _write(tmp_path, "pkg/__init__.py")
    assert resolve_import(tmp_path, "pkg/__init__.py") == ("", "pkg")


def test_directory_without_init_is_an_import_root(tmp_path):
    """No __init__.py: the file's own directory goes on sys.path, as a script would."""
    _write(tmp_path, "scripts/tool.py")
    assert resolve_import(tmp_path, "scripts/tool.py") == ("scripts", "tool")


def test_windows_separators_resolve_the_same(tmp_path):
    _write(tmp_path, "src/pkg/__init__.py")
    _write(tmp_path, "src/pkg/db.py")
    assert resolve_import(tmp_path, "src\\pkg\\db.py") == ("src", "pkg.db")


def test_resolution_never_walks_above_the_target(tmp_path):
    """An __init__.py above the scan root must not change the answer."""
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    inner = tmp_path / "project"
    _write(inner, "app.py")
    assert resolve_import(inner, "app.py") == ("", "app")


# --- the harness actually imports a package ----------------------------------

PKG_DB = textwrap.dedent('''
    import sqlite3
    from .config import TABLE

    def login(username):
        conn = sqlite3.connect(":memory:")
        conn.execute(f"CREATE TABLE {TABLE} (name TEXT)")
        conn.execute(f"INSERT INTO {TABLE} VALUES ('admin')")
        query = f"SELECT * FROM {TABLE} WHERE name = '" + username + "'"
        return conn.execute(query).fetchall()
''').lstrip()

SINK_LINE = 8   # query = ...


@pytest.fixture
def src_layout(tmp_path):
    _write(tmp_path, "src/shop/__init__.py")
    _write(tmp_path, "src/shop/config.py", 'TABLE = "users"\n')
    _write(tmp_path, "src/shop/db.py", PKG_DB)
    return tmp_path


def test_exploit_through_a_relative_import_is_line_proven(src_layout):
    root, module = resolve_import(src_layout, "src/shop/db.py")
    poc = f"from {module} import login\nif login(\"' OR '1'='1\"):\n    print('SENTINEL_PWNED')\n"
    harness = build_harness(poc, "src/shop/db.py", SINK_LINE, mount=str(src_layout),
                            workdir=str(src_layout), import_root=root, nonce="n")

    proc = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                          text=True, timeout=60)
    w = parse_witness(proc.stdout, "src/shop/db.py", SINK_LINE, nonce="n")

    assert "SENTINEL_PWNED" in proc.stdout, proc.stderr
    assert w.line_executed


# --- the validator: assert on what it SENDS -----------------------------------

class RecordingLLM:
    model = "stub/model"

    def __init__(self):
        self.prompts = []

    def complete(self, prompt, system=None):
        self.prompts.append(prompt)
        return LLMResponse(text="print('x')", prompt_tokens=0, completion_tokens=0,
                           cost_usd=0.0)


def test_validator_sends_the_dotted_module_and_the_import_root(monkeypatch, src_layout):
    commands = []

    def run(self, command, workdir=None):
        commands.append(command)
        return SandboxResult(1, "", "", False)

    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", run)
    llm = RecordingLLM()
    finding = Finding("SQL Injection", "src/shop/db.py", SINK_LINE, "high", "sqli", 0.9)

    from sentinel.sandbox import Sandbox
    Validator(llm, Sandbox(), target=src_layout, max_attempts=1).validate(finding, PKG_DB)

    assert "`shop.db`" in llm.prompts[0]
    import base64
    harness = base64.b64decode(commands[0].split()[1]).decode("utf-8")
    assert f"sys.path.insert(0, '{MOUNT}/src')" in harness


# --- a missing module that is part of the target is not an environment gap ----

def test_missing_top_level_package_of_the_target_is_not_env_incomplete():
    out = "ModuleNotFoundError: No module named 'shop'"
    assert missing_dependency(out, "shop.db") is None


def test_missing_sibling_module_of_the_target_is_not_env_incomplete():
    """If the target tree contains `utils`, failing to import it is our fault."""
    out = "ModuleNotFoundError: No module named 'utils'"
    assert missing_dependency(out, "app", local_modules={"utils", "app"}) is None


def test_missing_third_party_package_is_still_reported():
    out = "ModuleNotFoundError: No module named 'flask'"
    assert missing_dependency(out, "shop.db", local_modules={"shop"}) == "flask"


def test_retry_prompt_names_the_same_module(monkeypatch, src_layout):
    """A self-correcting retry must not fall back to guessing the import."""
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run",
                        lambda self, command, workdir=None: SandboxResult(1, "", "boom", False))
    llm = RecordingLLM()
    finding = Finding("SQL Injection", "src/shop/db.py", SINK_LINE, "high", "sqli", 0.9)

    from sentinel.sandbox import Sandbox
    Validator(llm, Sandbox(), target=src_layout, max_attempts=2).validate(finding, PKG_DB)

    assert len(llm.prompts) == 2
    assert "`import shop.db`" in llm.prompts[1]
