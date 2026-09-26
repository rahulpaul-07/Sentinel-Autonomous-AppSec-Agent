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


# --- the gate must not reject what it could not model ------------------------
#
# The gate may reject only on positive evidence. Two holes let it reject on
# ignorance instead: a sink called on a chained expression was invisible, so the
# gate reported "no sink anywhere"; and a sink fed by a function parameter was
# called unreachable, though in a library the parameter IS the attacker's input.

LIBRARY_SQLI = '''
import sqlite3

def find_user(conn, name):
    return conn.cursor().execute("SELECT * FROM users WHERE name = '" + name + "'")
'''


def test_sink_called_on_a_chained_expression_is_seen():
    r = analyze(LIBRARY_SQLI, "SQL Injection", 5)
    assert r.verdict is not Verdict.NO_SINK_AT_LINE, r.reason
    assert "execute" in r.sink


def test_function_parameter_reaching_a_sink_is_not_rejected():
    r = analyze(LIBRARY_SQLI, "SQL Injection", 5)
    assert not r.blocks, r.reason
    assert r.verdict is Verdict.NO_KNOWN_SOURCE


def test_variable_the_gate_cannot_resolve_fails_open():
    """Even a variable holding a constant proceeds: proving that needs def-use analysis."""
    src = '''
import os
def housekeeping():
    cmd = "ls -la /tmp"
    os.system(cmd)
'''
    assert not analyze(src, "Command Injection", 5).blocks


def test_an_unresolved_candidate_outweighs_a_safe_one_nearby():
    src = '''
import subprocess
from flask import request
def run():
    subprocess.run(["ls", request.args.get("d")])
def other(extra):
    subprocess.run("ls " + extra, shell=True)
'''
    r = analyze(src, "Command Injection", 5)
    assert not r.blocks, r.reason


# --- rejections that were unsound -----------------------------------------------
#
# Each of these is a real vulnerability the gate used to reject before any
# exploit was attempted -- the one failure its fail-open contract forbids.

REAL_BUGS_ONCE_REJECTED = {
    # realpath canonicalizes; it does not confine the path to BASE.
    "realpath-is-not-containment": ('''
import os
from flask import request
BASE = "/srv/files"
def dl():
    name = request.args.get("f")
    return open(os.path.realpath(os.path.join(BASE, name))).read()
''', "Path Traversal", 7),
    # A sanitizer on one value says nothing about the other.
    "quote-on-one-argument-only": ('''
import subprocess, shlex
from flask import request
def run():
    a = request.args.get("a"); b = request.args.get("b")
    subprocess.run(f"ls {shlex.quote(a)} {b}", shell=True)
''', "Command Injection", 6),
    # URL quoting is not shell quoting, even when both are called `quote`.
    "urllib-quote-is-not-shlex-quote": ('''
import os
from urllib.parse import quote
from flask import request
def run():
    os.system("curl " + quote(request.args.get("u"), safe=";|&$ "))
''', "Command Injection", 6),
    # An argument vector whose program is a shell is a shell command line.
    "argv-list-through-sh-c": ('''
import subprocess
from flask import request
def run():
    cmd = request.args.get("c")
    subprocess.run(["sh", "-c", cmd])
''', "Command Injection", 6),
    # shell=flag is not provably shell=False.
    "shell-from-a-variable": ('''
import subprocess
from flask import request
USE_SHELL = True
def run():
    subprocess.run([request.args.get("c")], shell=USE_SHELL)
''', "Command Injection", 6),
    # A sink the catalogue lacked was reported as "no sink".
    "subprocess-getoutput": ('''
import subprocess
from flask import request
def run():
    host = request.args.get("h")
    return subprocess.getoutput("ping -c 1 " + host)
''', "Command Injection", 6),
    # Imported under its bare name.
    "from-import-of-a-sink": ('''
from os import system
from flask import request
def run():
    system("ping " + request.args.get("h"))
''', "Command Injection", 5),
    # A call no catalogue lists, receiving attacker data, is not evidence of absence.
    "unmodelled-call-with-tainted-data": ('''
from flask import request
import mylib
def run():
    mylib.shell_out("ping " + request.args.get("h"))
''', "Command Injection", 5),
}


@pytest.mark.parametrize("src,cls,line", REAL_BUGS_ONCE_REJECTED.values(),
                         ids=REAL_BUGS_ONCE_REJECTED.keys())
def test_real_bug_is_never_rejected(src, cls, line):
    r = analyze(src, cls, line)
    assert not r.blocks, f"{r.verdict.value}: {r.reason}"


def test_quote_that_covers_every_tainted_value_is_safe():
    """The sanitizer rule still rejects when it genuinely applies, through a variable."""
    src = '''
import os, shlex
from flask import request
def run():
    safe = shlex.quote(request.args.get("h"))
    os.system("ping -c 1 " + safe)
'''
    r = analyze(src, "Command Injection", 6)
    assert r.verdict is Verdict.SAFE_USAGE, r.reason


def test_yaml_safe_loader_is_safe_usage():
    src = '''
import yaml
from flask import request
def load():
    return yaml.load(request.data, Loader=yaml.SafeLoader)
'''
    assert analyze(src, "Insecure Deserialization", 5).verdict is Verdict.SAFE_USAGE


def test_yaml_default_loader_is_reachable():
    src = '''
import yaml
from flask import request
def load():
    return yaml.load(request.data, Loader=yaml.Loader)
'''
    assert analyze(src, "Insecure Deserialization", 5).verdict is Verdict.REACHABLE
