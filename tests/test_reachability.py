"""
Unit tests for the static reachability gate.

The gate's contract has two halves, and both matter:
  1. It must NEVER reject a real vulnerability (that would cost recall, which is
     far more expensive than the validation call it saves).
  2. It must reject candidates where there is positive evidence of no attacker
     path, or where the call is made via a recognized safe idiom.

Anything it cannot analyze must fail open.
"""

import pytest

from sentinel.reachability import analyze, Verdict


# --- half 1: real vulnerabilities must survive the gate --------------------

VULNERABLE_SQL = '''
import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/u")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return str(cursor.fetchall())
'''

VULNERABLE_CMD = '''
import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    return "ok"
'''

VULNERABLE_FSTRING = '''
from flask import request
import subprocess

def run():
    name = request.args.get("name")
    subprocess.run(f"echo {name}", shell=True)
'''


def test_tainted_sql_sink_is_reachable():
    r = analyze(VULNERABLE_SQL, "SQL Injection", 12)
    assert r.verdict is Verdict.REACHABLE
    assert not r.blocks
    assert "execute" in r.sink


def test_tainted_command_sink_is_reachable():
    r = analyze(VULNERABLE_CMD, "Command Injection", 9)
    assert r.verdict is Verdict.REACHABLE
    assert not r.blocks


def test_taint_propagates_through_fstring_and_shell_true():
    """f-string interpolation must carry taint, and shell=True is not safe usage."""
    r = analyze(VULNERABLE_FSTRING, "Command Injection", 7)
    assert r.verdict is Verdict.REACHABLE
    assert not r.blocks


def test_taint_propagates_through_a_local_function_call():
    src = '''
from flask import request
import os

def execute_it(cmd):
    os.system(cmd)

def handler():
    user_input = request.args.get("c")
    execute_it(user_input)
'''
    r = analyze(src, "Command Injection", 6)
    assert r.verdict is Verdict.REACHABLE, r.reason


def test_hardcoded_secret_literal_is_reachable_without_any_taint():
    """Literal-based classes have no taint source; the literal IS the bug."""
    src = 'API_KEY = "sk-live-abcdef123456"\n'
    r = analyze(src, "Hardcoded Secret", 1)
    assert r.verdict is Verdict.REACHABLE
    assert not r.blocks


# --- half 2: unreachable and safely-used sinks must be rejected ------------

SAFE_PARAMETERIZED = '''
import sqlite3
from flask import request

def get_user():
    username = request.args.get("username", "")
    cursor = sqlite3.connect("app.db").cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
'''

SAFE_ARGV_SUBPROCESS = '''
import subprocess
from flask import request

def ping():
    host = request.args.get("host", "")
    subprocess.run(["ping", "-c", "1", host], capture_output=True)
'''


def test_parameterized_query_is_rejected_as_safe_usage():
    """The clean control's SQL is safe by HOW it is called, not by taint absence.

    Attacker data genuinely reaches cursor.execute here. A gate that modeled only
    taint would wave this through -- recognizing the parameterized idiom is what
    makes the gate useful on real code.
    """
    r = analyze(SAFE_PARAMETERIZED, "SQL Injection", 7)
    assert r.verdict is Verdict.SAFE_USAGE
    assert r.blocks
    assert "parameterized" in r.reason


def test_argument_vector_subprocess_is_rejected_as_safe_usage():
    r = analyze(SAFE_ARGV_SUBPROCESS, "Command Injection", 6)
    assert r.verdict is Verdict.SAFE_USAGE
    assert r.blocks
    assert "shell" in r.reason


def test_constant_argument_to_sink_has_no_taint_path():
    src = '''
import os
def housekeeping():
    os.system("ls -la /tmp")
'''
    r = analyze(src, "Command Injection", 4)
    assert r.verdict is Verdict.NO_TAINT_PATH
    assert r.blocks


def test_no_sink_of_that_class_in_the_file():
    src = '''
def add(a, b):
    return a + b
'''
    r = analyze(src, "SQL Injection", 3)
    assert r.verdict is Verdict.NO_SINK_AT_LINE
    assert r.blocks


def test_sanitizer_neutralizes_path_traversal():
    src = '''
import os
from flask import request

def read():
    name = request.args.get("f")
    with open(os.path.basename(name)) as fh:
        return fh.read()
'''
    r = analyze(src, "Path Traversal", 7)
    assert r.verdict is Verdict.SAFE_USAGE
    assert r.blocks


# --- fail-open contract ----------------------------------------------------


def test_unparseable_file_fails_open():
    r = analyze("def broken(:\n", "SQL Injection", 1)
    assert r.verdict is Verdict.NOT_ANALYZABLE
    assert not r.blocks


def test_unknown_vulnerability_class_fails_open():
    """A class we have no sink model for must never be rejected."""
    r = analyze(VULNERABLE_SQL, "Quantum Entanglement Overflow", 12)
    assert r.verdict is Verdict.NOT_ANALYZABLE
    assert not r.blocks


def test_secret_class_with_no_literal_fails_open():
    """An env-var read is not a literal -- the gate must not claim it is safe."""
    src = 'import os\nSECRET_KEY = os.environ.get("APP_SECRET_KEY", "")\n'
    r = analyze(src, "Hardcoded Secret", 2)
    assert r.verdict is Verdict.NOT_ANALYZABLE
    assert not r.blocks


@pytest.mark.parametrize("line", [10, 11, 12, 13, 14])
def test_line_drift_within_tolerance_still_matches(line):
    """Models routinely report a line or two off; that must not cause rejection."""
    r = analyze(VULNERABLE_SQL, "SQL Injection", line)
    assert not r.blocks, f"line {line} was wrongly blocked: {r.reason}"
