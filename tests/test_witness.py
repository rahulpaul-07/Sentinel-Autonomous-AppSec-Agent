"""
Tests for the execution witness.

The witness is the load-bearing part of the project's central claim, so it is
tested two ways:

  * unit  -- the harness builds and the record parses, including malformed input.
  * integration -- the harness is actually EXECUTED in a subprocess against a real
    target file, proving the tracer genuinely distinguishes an exploit that drives
    the target from one that merely reproduces the pattern.

The integration tests need no Docker and no API key: they run the same harness
source the sandbox would run, using the local interpreter.
"""

import subprocess
import sys
import textwrap

import pytest

from sentinel.witness import (
    build_harness,
    parse_witness,
    strip_witness,
    WitnessResult,
    WITNESS_PREFIX,
)

TARGET_SOURCE = textwrap.dedent('''
    import sqlite3

    def setup():
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (name TEXT, pw TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin', 's3cret')")
        return conn

    def login(conn, username):
        query = "SELECT * FROM users WHERE name = '" + username + "'"
        return conn.execute(query).fetchall()
''').lstrip()

# `query = ...` sits on line 11 of the file written by the fixture below.
SINK_LINE = 11


@pytest.fixture
def target_dir(tmp_path):
    (tmp_path / "app.py").write_text(TARGET_SOURCE, encoding="utf-8")
    return tmp_path


def _run_harness(poc, target_dir, line=SINK_LINE, file="app.py"):
    harness = build_harness(
        poc_code=poc, target_file=file, target_line=line,
        mount=str(target_dir), workdir=str(target_dir),
    )
    proc = subprocess.run(
        [sys.executable, "-c", harness], capture_output=True, text=True, timeout=60
    )
    return proc, parse_witness(proc.stdout, file, line)


# --- integration: the distinction the whole project rests on ---------------

GENERIC_POC = textwrap.dedent('''
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (a TEXT)")
    conn.execute("INSERT INTO t VALUES ('x')")
    q = "SELECT * FROM t WHERE a = '" + "' OR '1'='1" + "'"
    if conn.execute(q).fetchall():
        print("SENTINEL_PWNED")
''')

TARGETED_POC = textwrap.dedent('''
    import app
    conn = app.setup()
    if app.login(conn, "' OR '1'='1"):
        print("SENTINEL_PWNED")
''')


def test_generic_exploit_prints_marker_but_never_touches_the_target(target_dir):
    """The documented failure mode: a 'successful' exploit that proves nothing here.

    A marker-only check would call this CONFIRMED. The witness must show the
    target file never executed, so it can only be graded CLASS_ONLY.
    """
    proc, w = _run_harness(GENERIC_POC, target_dir)

    assert "SENTINEL_PWNED" in proc.stdout        # the shallow signal is satisfied
    assert w.available
    assert not w.file_executed                    # ...but nothing in app.py ran
    assert not w.line_executed
    assert "never executed any code" in w.explain()


def test_targeted_exploit_executes_the_reported_line(target_dir):
    """An exploit that imports and drives the real function must witness the line."""
    proc, w = _run_harness(TARGETED_POC, target_dir)

    assert "SENTINEL_PWNED" in proc.stdout
    assert w.available
    assert w.file_executed
    assert w.line_executed
    assert SINK_LINE in w.executed_lines
    assert f"app.py:{SINK_LINE} executed" in w.explain()


def test_exploit_reaching_the_file_but_not_the_line(target_dir):
    """Ran the module, never the reported line -> still only a class-level claim."""
    poc = "import app\nconn = app.setup()\nprint('SENTINEL_PWNED')\n"
    proc, w = _run_harness(poc, target_dir, line=SINK_LINE)

    assert w.available
    assert w.file_executed          # setup() ran
    assert not w.line_executed      # login()'s sink line did not
    assert "never reached line" in w.explain()


def test_crashing_poc_still_produces_a_witness(target_dir):
    """A PoC that raises is evidence too -- the harness must not swallow the run."""
    poc = "import app\nraise RuntimeError('boom')\n"
    proc, w = _run_harness(poc, target_dir)

    assert w.available              # record emitted despite the exception
    assert not w.line_executed
    assert "boom" in (proc.stdout + proc.stderr)


def test_harness_does_not_suppress_poc_stdout(target_dir):
    poc = "print('hello from the exploit')\n"
    proc, _ = _run_harness(poc, target_dir)
    assert "hello from the exploit" in proc.stdout


# --- unit: parsing contract ------------------------------------------------


def test_missing_record_is_unavailable_not_disproof():
    """No trace must never be readable as evidence AGAINST the finding."""
    w = parse_witness("just some exploit output\n", "app.py", 10)
    assert not w.available
    assert not w.line_executed
    assert "No execution trace" in w.explain()


def test_malformed_record_is_handled():
    w = parse_witness(WITNESS_PREFIX + "{not json}\n", "app.py", 10)
    assert not w.available


def test_last_record_wins_if_poc_prints_a_decoy():
    """A PoC could print a fake record; the harness's own trailing one must win."""
    fake = WITNESS_PREFIX + '{"available": true, "line_executed": true, "executed_lines": [1]}'
    real = WITNESS_PREFIX + '{"available": true, "line_executed": false, "executed_lines": []}'
    w = parse_witness(fake + "\n" + real + "\n", "app.py", 10)
    assert not w.line_executed


def test_strip_witness_removes_records_from_displayed_output():
    raw = "SENTINEL_PWNED\n" + WITNESS_PREFIX + '{"available": true}' + "\n"
    assert WITNESS_PREFIX not in strip_witness(raw)
    assert "SENTINEL_PWNED" in strip_witness(raw)


def test_nearest_line_reports_the_closest_executed_line():
    w = WitnessResult(
        available=True, file_executed=True, line_executed=False,
        executed_lines=[3, 8, 40], target_file="app.py", target_line=33,
    )
    assert w.nearest_line == 40


def test_witness_is_json_serializable():
    import json
    w = WitnessResult(available=True, file_executed=True, line_executed=True,
                      executed_lines=[1, 2], target_file="a.py", target_line=2)
    json.dumps(w.to_dict())


def test_bare_import_is_never_a_line_proof(target_dir):
    """Regression: importing a module must not witness a nearby sink.

    Importing executes every `def` and `class` header in the file. Those lines sit
    close to the code they introduce, so with a line window they would register as
    a hit -- letting a PoC that does nothing but `import app` be graded
    LINE_PROVEN. That is a false proof in the exact mechanism this project's main
    claim rests on, so it is pinned here.
    """
    proc, w = _run_harness("import app\nprint('SENTINEL_PWNED')\n", target_dir)

    assert "SENTINEL_PWNED" in proc.stdout
    assert w.available
    assert w.file_executed            # the def headers did run
    assert not w.line_executed        # but that is not proof of the sink


def test_import_time_lines_are_recorded_for_transparency(target_dir):
    """The ignored lines are reported, so the grading is auditable."""
    import json
    harness = build_harness(
        poc_code="import app\n", target_file="app.py", target_line=SINK_LINE,
        mount=str(target_dir), workdir=str(target_dir),
    )
    proc = subprocess.run(
        [sys.executable, "-c", harness], capture_output=True, text=True, timeout=60
    )
    payload = json.loads(proc.stdout.split(WITNESS_PREFIX)[-1].strip())
    # `def setup` (3) and `def login` (9) are import-time, not exploitation.
    assert 3 in payload["import_time_lines_ignored"]
    assert 9 in payload["import_time_lines_ignored"]


def test_same_named_dependency_file_cannot_forge_a_proof(tmp_path):
    """Regression: a dependency file with the same basename must not be traced.

    The tracer originally matched frames by basename. Real projects import
    libraries that ship common filenames -- flask/app.py being the obvious one --
    so tracing a target called app.py attributed hundreds of the library's lines
    to it and manufactured a LINE_PROVEN grade for a PoC that only did `import`.

    Here a fake package ships its own app.py with many lines. Executing it must
    contribute nothing to the witness for the real target.
    """
    target_dir = tmp_path / "project"
    target_dir.mkdir()
    (target_dir / "app.py").write_text(
        "def login(username):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
        "    return query\n",
        encoding="utf-8",
    )

    # A dependency that also contains an app.py, with a line at the sink number.
    dep = tmp_path / "site-packages" / "framework"
    dep.mkdir(parents=True)
    (dep / "__init__.py").write_text("from . import app\n", encoding="utf-8")
    (dep / "app.py").write_text("\n".join(f"X{i} = {i}" for i in range(1, 30)), encoding="utf-8")

    poc = (
        "import sys\n"
        f"sys.path.insert(0, {str(tmp_path / 'site-packages')!r})\n"
        "import framework\n"           # executes the OTHER app.py
        "print('SENTINEL_PWNED')\n"
    )
    harness = build_harness(
        poc_code=poc, target_file="app.py", target_line=2,
        mount=str(target_dir), workdir=str(target_dir),
    )
    proc = subprocess.run(
        [sys.executable, "-c", harness], capture_output=True, text=True, timeout=60
    )
    w = parse_witness(proc.stdout, "app.py", 2)

    assert "SENTINEL_PWNED" in proc.stdout   # the shallow signal is satisfied
    assert w.available
    assert not w.file_executed               # the real target never ran
    assert not w.line_executed               # so no line proof, despite the marker


# --- import-time execution is not exploitation ------------------------------
#
# Importing a module runs every top-level statement: imports, assignments,
# `app = Flask(...)`, and any function a module-level statement calls. None of
# that is the exploit doing anything. A PoC that only imports the target and
# prints the marker must never be LINE_PROVEN, wherever the reported line is.

MODULE_LEVEL_SOURCE = textwrap.dedent('''
    import sqlite3

    SECRET_KEY = "hunter2"

    def setup():
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (name TEXT)")
        return conn

    DEFAULT_CONN = setup()

    def login(conn, username):
        query = "SELECT * FROM users WHERE name = '" + username + "'"
        return conn.execute(query).fetchall()
''').lstrip()

SECRET_LINE = 3      # SECRET_KEY = ...
SETUP_BODY_LINE = 6  # conn = sqlite3.connect(...), run by `DEFAULT_CONN = setup()`


@pytest.fixture
def module_level_target(tmp_path):
    (tmp_path / "app.py").write_text(MODULE_LEVEL_SOURCE, encoding="utf-8")
    return tmp_path


def test_import_does_not_witness_a_module_level_line(module_level_target):
    """Regression: `import app` executes line 3, but that proves nothing about it."""
    proc, w = _run_harness(
        "import app\nprint('SENTINEL_PWNED')\n", module_level_target, line=SECRET_LINE
    )

    assert "SENTINEL_PWNED" in proc.stdout
    assert w.available
    assert SECRET_LINE in w.executed_lines      # it did run...
    assert not w.line_executed                  # ...but only because of the import


def test_function_called_during_import_does_not_witness(module_level_target):
    """A sink reached only because a module-level statement called it is import-time."""
    proc, w = _run_harness(
        "import app\nprint('SENTINEL_PWNED')\n", module_level_target, line=SETUP_BODY_LINE
    )

    assert "SENTINEL_PWNED" in proc.stdout
    assert not w.line_executed


def test_calling_the_function_after_import_does_witness(module_level_target):
    """The same line counts once the exploit itself drives it."""
    proc, w = _run_harness(
        "import app\napp.setup()\nprint('SENTINEL_PWNED')\n",
        module_level_target, line=SETUP_BODY_LINE,
    )

    assert w.line_executed


def test_import_only_run_is_explained_as_such(module_level_target):
    _, w = _run_harness("import app\n", module_level_target, line=SECRET_LINE)

    assert "import" in w.explain().lower()
    assert w.nearest_line is None   # no line the exploit itself drove
