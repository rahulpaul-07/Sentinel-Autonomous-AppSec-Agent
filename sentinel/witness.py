"""
sentinel/witness.py
-------------------
The execution witness: did the exploit actually run the line it claims to exploit?

The problem
-----------
An exploit that prints a success marker has proven something -- but not
necessarily what it says. The documented failure mode is an LLM writing a
self-contained demo that reproduces a vulnerability *pattern* and prints the
marker without ever touching the code under test. The marker is satisfied; the
claim is not. Recent work on Java PoC generation found that applying a post-hoc
check -- re-running with instrumentation and confirming the trace reaches the
vulnerable location -- invalidated roughly 44% of exploits that had passed a
marker-only check.

Those systems compare the trace against a *ground-truth* sink location supplied by
a labeled benchmark. That works for measuring a technique; it cannot work in the
field, where nobody knows the answer in advance.

The approach here
-----------------
Use the agent's own reported location as the witness target. The hunter asserts
"SQL injection at app.py:42". That assertion is checked against the trace of its
own exploit:

    marker printed  +  app.py:42 executed   ->  LINE_PROVEN
    marker printed  +  app.py:42 never ran  ->  CLASS_ONLY

No ground truth is needed, because the claim supplies its own target. That is what
makes the check deployable on unlabeled code rather than only on a benchmark.

Implementation
--------------
The PoC is wrapped in a harness that installs a `sys.settrace` line tracer, runs
the PoC, and emits a machine-readable record of which lines of the target file
executed. The harness is plain standard library, so it runs inside the same
network-off sandbox with nothing extra installed.

Honest limits
-------------
* Tracing records *that* a line ran, not that tainted data flowed through it. A
  line can execute with benign input. Combined with the static taint gate this is
  good evidence, but it is not a dataflow proof.
* `sys.settrace` does not see into C extensions, and conflicts with debuggers and
  coverage tools sharing the same hook.
* Lines that run while the target is being imported never count. Importing a
  module executes every top-level statement, so a finding on a module-level line
  (a hardcoded secret, for one) can never be LINE_PROVEN by execution alone --
  there is nothing for an exploit to drive. That is a real limit of execution
  evidence, and it is reported as such rather than papered over.
* A small line window absorbs the off-by-a-line drift that models routinely
  produce when reporting a multi-line statement.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Emitted by the harness, parsed back out of sandbox stdout.
WITNESS_PREFIX = "SENTINEL_WITNESS:"

# A reported line this far from an executed line still counts as a hit. Models
# commonly report the statement rather than the exact call, or vice versa.
LINE_WINDOW = 3

_WITNESS_RE = re.compile(rf"^{re.escape(WITNESS_PREFIX)}(\{{.*\}})\s*$", re.MULTILINE)


@dataclass
class WitnessResult:
    """What the tracer observed while the exploit ran."""

    available: bool = False          # did the harness emit a record at all?
    file_executed: bool = False      # did any line of the target file run?
    line_executed: bool = False      # did the reported line (within window) run?
    executed_lines: list[int] = field(default_factory=list)
    # Lines that ran only because the target was imported. Kept separate so the
    # report can say "it imported the file" rather than "it ran code there".
    import_only_lines: list[int] = field(default_factory=list)
    target_file: str = ""
    target_line: int = 0
    error: str = ""

    @property
    def driven_lines(self) -> list[int]:
        """Lines the exploit itself caused to run, after the import finished."""
        skip = set(self.import_only_lines)
        return [n for n in self.executed_lines if n not in skip]

    @property
    def nearest_line(self) -> int | None:
        lines = self.driven_lines
        if not lines:
            return None
        return min(lines, key=lambda n: abs(n - self.target_line))

    def explain(self) -> str:
        if not self.available:
            return "No execution trace was captured for this run."
        if self.line_executed:
            return (
                f"{self.target_file}:{self.target_line} executed while the exploit ran."
            )
        if self.file_executed and not self.driven_lines:
            return (
                f"The exploit imported {self.target_file}, but only code that runs on "
                f"import executed there. Import-time execution is not counted as "
                f"reaching line {self.target_line}."
            )
        if self.file_executed:
            near = self.nearest_line
            return (
                f"The exploit ran code in {self.target_file}, but never reached "
                f"line {self.target_line}"
                + (f" (nearest executed line: {near})." if near else ".")
            )
        return (
            f"The exploit never executed any code in {self.target_file} -- it "
            "demonstrated the vulnerability class in isolation."
        )

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "file_executed": self.file_executed,
            "line_executed": self.line_executed,
            "target_file": self.target_file,
            "target_line": self.target_line,
            "executed_lines": self.executed_lines[:200],
            "import_only_lines": self.import_only_lines[:200],
            "nearest_line": self.nearest_line,
            "error": self.error,
        }


HARNESS_TEMPLATE = '''\
import sys, os, json, ast, traceback

_TARGET_BASENAME = {target_basename!r}
_TARGET_PATH = {target_path!r}
_TARGET_LINE = {target_line!r}
_WITNESS_PREFIX = {prefix!r}
_hits = set()
_err = ""

# Resolve the target to an absolute real path and match traced frames against THAT.
# Matching on basename alone is unsafe: dependencies ship files with the same
# common names (flask/app.py, for one), so importing a library would attribute
# hundreds of its lines to the file under test and manufacture a proof.
try:
    _TARGET_REAL = os.path.realpath(_TARGET_PATH)
except Exception:
    _TARGET_REAL = _TARGET_PATH
_HAVE_REAL = os.path.isfile(_TARGET_REAL)

_target_cache = dict()

def _is_target(filename):
    if filename in _target_cache:
        return _target_cache[filename]
    _target_cache[filename] = result = _is_target_uncached(filename)
    return result

def _is_target_uncached(filename):
    if not filename:
        return False
    if _HAVE_REAL:
        try:
            return os.path.realpath(filename) == _TARGET_REAL
        except Exception:
            return False
    # Only if the target path could not be resolved do we fall back to basename,
    # and then we still require it not to live inside an installed package.
    if os.path.basename(filename) != _TARGET_BASENAME:
        return False
    return "site-packages" not in filename and "dist-packages" not in filename

# Lines that execute merely because a module is imported -- `def`/`class` headers
# and their decorators. Counting these as a witness would let a PoC that does
# nothing but `import target` appear to have reached a nearby sink.
_import_time_lines = set()
try:
    with open(_TARGET_REAL, "r", encoding="utf-8", errors="replace") as _fh:
        _tree = ast.parse(_fh.read())
    for _n in ast.walk(_tree):
        if isinstance(_n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _import_time_lines.add(_n.lineno)
            for _d in _n.decorator_list:
                _import_time_lines.add(_d.lineno)
except Exception:
    pass

# A line that runs while the target module is being imported is not the exploit
# doing anything: importing executes every top-level statement, and any function
# a top-level statement calls. We tell the two apart by looking up the call stack
# for the target's own module-level frame.
_runtime_hits = set()

def _during_target_import(frame):
    f = frame
    while f is not None:
        if f.f_code.co_name == "<module>" and _is_target(f.f_code.co_filename):
            return True
        f = f.f_back
    return False

def _tracer(frame, event, arg):
    if event == "line":
        if _is_target(frame.f_code.co_filename):
            _hits.add(frame.f_lineno)
            if not _during_target_import(frame):
                _runtime_hits.add(frame.f_lineno)
    return _tracer

_POC = {poc!r}

sys.path.insert(0, {mount!r})
os.chdir({workdir!r})

sys.settrace(_tracer)
try:
    exec(compile(_POC, "<sentinel-poc>", "exec"), {{"__name__": "__main__"}})
except SystemExit:
    pass
except BaseException:
    _err = traceback.format_exc()[-1500:]
finally:
    sys.settrace(None)

if _err:
    sys.stderr.write(_err + "\\n")

_lines = sorted(_hits)
# A line is a witness only if the exploit drove it after the import. A line that
# ran BOTH during the import and later by the exploit still counts: the later run
# is real, so we test membership in the runtime set, not absence from the import set.
_witness_lines = [n for n in sorted(_runtime_hits) if n not in _import_time_lines]
_record = {{
    "available": True,
    "file_executed": bool(_lines),
    "line_executed": any(abs(n - _TARGET_LINE) <= {window} for n in _witness_lines),
    "executed_lines": _lines[:200],
    "import_only_lines": sorted(_hits - _runtime_hits)[:200],
    "import_time_lines_ignored": sorted(_import_time_lines)[:200],
    "resolved_target": _TARGET_REAL if _HAVE_REAL else "",
    "error": _err[-400:],
}}
sys.stdout.write("\\n" + _WITNESS_PREFIX + json.dumps(_record) + "\\n")
sys.stdout.flush()
'''


def build_harness(
    poc_code: str,
    target_file: str,
    target_line: int,
    mount: str = "/target",
    workdir: str = "/tmp",
) -> str:
    """Wrap PoC source in a tracing harness.

    The harness puts the target's directory on `sys.path` so the PoC can import
    the module under test, runs the PoC with a line tracer installed, and prints a
    JSON witness record. It never fails the run: a PoC that raises still produces
    a record, because "it crashed" is itself evidence.
    """
    basename = target_file.replace("\\", "/").split("/")[-1]
    return HARNESS_TEMPLATE.format(
        target_basename=basename,
        target_path=f"{mount.rstrip('/')}/{target_file.replace(chr(92), '/')}",
        target_line=int(target_line or 0),
        prefix=WITNESS_PREFIX,
        poc=poc_code,
        mount=mount,
        workdir=workdir,
        window=LINE_WINDOW,
    )


def parse_witness(output: str, target_file: str = "", target_line: int = 0) -> WitnessResult:
    """Recover the witness record from sandbox output.

    Absence of a record is not a failure of the finding -- it means the trace is
    unavailable, and the caller must not treat that as disproof.
    """
    match = None
    for match in _WITNESS_RE.finditer(output or ""):
        pass  # keep the last record if the PoC somehow printed several
    if match is None:
        return WitnessResult(
            available=False, target_file=target_file, target_line=target_line
        )

    try:
        data = json.loads(match.group(1))
    except (ValueError, TypeError) as exc:
        return WitnessResult(
            available=False,
            target_file=target_file,
            target_line=target_line,
            error=f"malformed witness record: {exc}",
        )

    return WitnessResult(
        available=bool(data.get("available", True)),
        file_executed=bool(data.get("file_executed", False)),
        line_executed=bool(data.get("line_executed", False)),
        executed_lines=[int(n) for n in data.get("executed_lines", []) if isinstance(n, int)],
        import_only_lines=[
            int(n) for n in data.get("import_only_lines", []) if isinstance(n, int)
        ],
        target_file=target_file,
        target_line=target_line,
        error=str(data.get("error", "")),
    )


def strip_witness(output: str) -> str:
    """Remove witness records so report output shows only the exploit's own text."""
    return _WITNESS_RE.sub("", output or "").strip()
