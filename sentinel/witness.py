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

Integrity
---------
The PoC is untrusted code, written by a model that has read the target's source --
and that source can carry instructions. Three layers keep a PoC from grading itself:

* A per-run nonce. The harness's record carries a secret generated after the PoC
  was written; a record without it is ignored, and two records with it void the
  trace. This stops a PoC that prints a record and exits before the harness can.
* No reachable state. The tracer's hit sets live in function locals, not in the
  `__main__` module a PoC can import, and the record goes out through a file
  descriptor duplicated before the PoC starts, not through `sys.stdout`.
* A screen. `screen_poc` refuses, before execution, a PoC that touches the
  handles tampering would need: frame introspection, trace hooks, `os._exit`,
  `__main__`, `ctypes`, heap walking.

These defeat accidental and naively injected forgery. They do not make an
in-process tracer tamper-proof against a PoC engineered to evade the screen --
tracing from outside the interpreter would, and is on the roadmap.
"""

from __future__ import annotations

import ast
import hmac
import json
import re
import secrets
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


def new_nonce() -> str:
    """A fresh per-run secret that authenticates the harness's own record.

    The PoC is written by a model before the nonce exists, so a record the PoC
    prints from a template can never carry it. Tests replace this to get a
    predictable value.
    """
    return secrets.token_hex(16)


# All harness state lives in the locals of one function rather than in module
# globals. The PoC runs in the same interpreter, and `import __main__` used to hand
# it the hit sets directly: `__main__._runtime_hits.add(N)` graded a PoC that never
# touched the target as LINE_PROVEN. Reaching a function's locals takes frame
# introspection, which `screen_poc` refuses before the PoC ever runs.
#
# The record is written with os.write to a descriptor duplicated before the PoC
# starts. Writing through sys.stdout would pass the record, nonce included, through
# any object the PoC had put there -- one that could rewrite it on the way out.
HARNESS_TEMPLATE = '''\
import sys, os, json, ast, traceback, threading

def _sentinel_witness():
    target_basename = {target_basename!r}
    target_path = {target_path!r}
    target_line = {target_line!r}
    prefix = {prefix!r}
    nonce = {nonce!r}
    record_fd = os.dup(1)
    hits = set()
    runtime_hits = set()
    err = ""

    # Resolve the target to an absolute real path and match traced frames against
    # THAT. Matching on basename alone is unsafe: dependencies ship files with the
    # same common names (flask/app.py, for one), so importing a library would
    # attribute hundreds of its lines to the file under test and manufacture a proof.
    try:
        target_real = os.path.realpath(target_path)
    except Exception:
        target_real = target_path
    have_real = os.path.isfile(target_real)
    cache = dict()

    def is_target(filename):
        if filename in cache:
            return cache[filename]
        result = False
        if filename:
            if have_real:
                try:
                    result = os.path.realpath(filename) == target_real
                except Exception:
                    result = False
            # Only if the target path could not be resolved do we fall back to
            # basename, and then still refuse files inside an installed package.
            elif os.path.basename(filename) == target_basename:
                result = ("site-packages" not in filename
                          and "dist-packages" not in filename)
        cache[filename] = result
        return result

    # Lines that execute merely because a module is imported -- `def`/`class`
    # headers and their decorators. Counting these would let a PoC that does
    # nothing but `import target` appear to have reached a nearby sink.
    import_time_lines = set()
    try:
        with open(target_real, "r", encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read())
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                import_time_lines.add(n.lineno)
                for d in n.decorator_list:
                    import_time_lines.add(d.lineno)
    except Exception:
        pass

    # A line that runs while the target module is being imported is not the
    # exploit doing anything: importing executes every top-level statement, and
    # any function a top-level statement calls. We tell the two apart by looking
    # up the call stack for the target's own module-level frame.
    def during_target_import(frame):
        f = frame
        while f is not None:
            if f.f_code.co_name == "<module>" and is_target(f.f_code.co_filename):
                return True
            f = f.f_back
        return False

    def tracer(frame, event, arg):
        if event == "line" and is_target(frame.f_code.co_filename):
            hits.add(frame.f_lineno)
            if not during_target_import(frame):
                runtime_hits.add(frame.f_lineno)
        return tracer

    poc = {poc!r}

    sys.path.insert(0, {import_path!r})
    os.chdir({workdir!r})

    # Threads the PoC starts are traced too, so an exploit that drives the target
    # from a worker thread is not under-counted.
    threading.settrace(tracer)
    sys.settrace(tracer)
    try:
        exec(compile(poc, "<sentinel-poc>", "exec"), {{"__name__": "__main__"}})
    except SystemExit:
        pass
    except BaseException:
        err = traceback.format_exc()[-1500:]
    finally:
        sys.settrace(None)
        threading.settrace(None)

    if err:
        sys.stderr.write(err + "\\n")
    for stream in (sys.stdout, sys.__stdout__):
        try:
            stream.flush()
        except Exception:
            pass

    lines = sorted(hits)
    # A line is a witness only if the exploit drove it after the import. A line
    # that ran BOTH during the import and later by the exploit still counts: the
    # later run is real, so we test membership in the runtime set.
    witness_lines = [n for n in sorted(runtime_hits) if n not in import_time_lines]
    record = {{
        "nonce": nonce,
        "available": True,
        "file_executed": bool(lines),
        "line_executed": any(abs(n - target_line) <= {window} for n in witness_lines),
        "executed_lines": lines[:200],
        "import_only_lines": sorted(hits - runtime_hits)[:200],
        "import_time_lines_ignored": sorted(import_time_lines)[:200],
        "resolved_target": target_real if have_real else "",
        "error": err[-400:],
    }}
    os.write(record_fd, ("\\n" + prefix + json.dumps(record) + "\\n").encode("utf-8"))

_sentinel_witness()
'''


def build_harness(
    poc_code: str,
    target_file: str,
    target_line: int,
    *,
    nonce: str,
    mount: str = "/target",
    workdir: str = "/tmp",
    import_root: str = "",
) -> str:
    """Wrap PoC source in a tracing harness.

    The harness puts the target's import root -- the mount itself for a flat
    layout, `<mount>/src` for a src layout -- on `sys.path` so the PoC can import
    the module under test the way the project would, runs the PoC with a line
    tracer installed, and prints a JSON witness record carrying `nonce`. It never
    fails the run: a PoC that raises still produces a record, because "it crashed"
    is itself evidence.

    `nonce` is required: a record is only believed if it carries the value the
    caller generated for this run (see `parse_witness`).
    """
    if not nonce:
        raise ValueError("build_harness needs a nonce; use new_nonce()")
    basename = target_file.replace("\\", "/").split("/")[-1]
    return HARNESS_TEMPLATE.format(
        target_basename=basename,
        target_path=f"{mount.rstrip('/')}/{target_file.replace(chr(92), '/')}",
        target_line=int(target_line or 0),
        prefix=WITNESS_PREFIX,
        nonce=nonce,
        poc=poc_code,
        import_path=_join(mount, import_root),
        workdir=workdir,
        window=LINE_WINDOW,
    )


def _join(mount: str, rel: str) -> str:
    rel = rel.replace("\\", "/").strip("/")
    return f"{mount.rstrip('/')}/{rel}" if rel else mount


def parse_witness(
    output: str, target_file: str = "", target_line: int = 0, *, nonce: str
) -> WitnessResult:
    """Recover the harness's own witness record from sandbox output.

    Only a record carrying this run's nonce is believed, and exactly one must be
    present. Anything the PoC printed that merely looks like a record is ignored,
    and reported in `error` so the attempt is visible in the report.

    Absence of an authentic record is not a failure of the finding -- it means the
    trace is unavailable, and the caller must not treat that as disproof. It also
    must not be treated as proof: an unavailable witness grades CLASS_ONLY at best.
    """
    authentic: list[dict] = []
    ignored = 0
    malformed = ""
    for match in _WITNESS_RE.finditer(output or ""):
        try:
            data = json.loads(match.group(1))
        except (ValueError, TypeError) as exc:
            malformed = f"malformed witness record: {exc}"
            continue
        if isinstance(data, dict) and hmac.compare_digest(str(data.get("nonce", "")), nonce):
            authentic.append(data)
        else:
            ignored += 1

    notes = []
    if ignored:
        notes.append(f"ignored {ignored} record(s) without this run's nonce "
                     "(printed by the PoC, not the harness)")

    def unavailable(reason: str) -> WitnessResult:
        return WitnessResult(available=False, target_file=target_file,
                             target_line=target_line,
                             error="; ".join([reason, *notes]) if reason else "; ".join(notes))

    if len(authentic) > 1:
        return unavailable(f"{len(authentic)} records carried this run's nonce; "
                           "the trace cannot be trusted")
    if not authentic:
        return unavailable(malformed)

    data = authentic[0]
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
        error="; ".join([str(data.get("error", "")), *notes]).strip("; "),
    )


def strip_witness(output: str) -> str:
    """Remove witness records so report output shows only the exploit's own text."""
    return _WITNESS_RE.sub("", output or "").strip()


# --- PoC screen ---------------------------------------------------------------
#
# The PoC and the tracer share one interpreter, so a PoC can in principle reach
# the tracer's state. A model does not do that by accident; it does it when told
# to, and the instructions can arrive inside the target's own source, which is
# pasted into the prompt. These are the handles such a PoC would need. None of
# them has any use in exploiting an application bug, so a PoC that uses one is
# refused before it runs and the model is asked for another.

_TAMPER_ATTRS = {
    "settrace": "replaces the execution tracer",
    "setprofile": "installs a competing interpreter hook",
    "gettrace": "reads the execution tracer",
    "_getframe": "inspects interpreter frames",
    "currentframe": "inspects interpreter frames",
    "f_back": "walks interpreter frames",
    "f_locals": "reads another frame's variables",
    "f_globals": "reads another frame's globals",
    "get_referrers": "searches the heap for tracer state",
    "get_referents": "searches the heap for tracer state",
    "get_objects": "searches the heap for tracer state",
    "monitoring": "installs a competing interpreter hook",
    "_exit": "exits before the tracer can report",
    "dup2": "redirects the tracer's output descriptor",
    "addaudithook": "installs an interpreter hook",
}
_TAMPER_MODULES = {
    "__main__": "reaches into the harness module",
    "ctypes": "can rewrite interpreter memory",
    "inspect": "inspects interpreter frames",
}


def screen_poc(poc_code: str) -> list[str]:
    """Reasons this PoC may not run under the tracer. Empty means it may.

    A PoC that does not parse is let through: it fails on its own, and the
    failure output drives the self-correction loop like any other.
    """
    try:
        tree = ast.parse(poc_code)
    except (SyntaxError, ValueError):
        return []

    reasons: list[str] = []

    def flag(text: str) -> None:
        if text not in reasons:
            reasons.append(text)

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _TAMPER_ATTRS:
            flag(f"`.{node.attr}` {_TAMPER_ATTRS[node.attr]}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _TAMPER_MODULES:
                    flag(f"`import {alias.name}` {_TAMPER_MODULES[root]}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _TAMPER_MODULES:
                flag(f"`from {node.module} import ...` {_TAMPER_MODULES[root]}")
            for alias in node.names:
                if alias.name in _TAMPER_ATTRS:
                    flag(f"`{alias.name}` {_TAMPER_ATTRS[alias.name]}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if WITNESS_PREFIX.rstrip(":") in node.value:
                flag("prints text shaped like the tracer's own record")
            elif node.value in _TAMPER_MODULES or node.value in _TAMPER_ATTRS:
                flag(f"names `{node.value}` as a string, a way around this screen")
        elif isinstance(node, ast.Call) and _is_named_compile(node):
            # compile(src, "/work/app.py", ...) makes code the PoC wrote look like
            # it came from the target file, so its lines would be traced as hits.
            filename = node.args[1] if len(node.args) > 1 else next(
                (k.value for k in node.keywords if k.arg == "filename"), None)
            if filename is not None and not (
                isinstance(filename, ast.Constant)
                and isinstance(filename.value, str)
                and filename.value.startswith("<")
            ):
                flag("`compile()` with a real file name can pass the PoC's own code "
                     "off as the target's")
    return reasons


def _is_named_compile(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "compile") or (
        isinstance(func, ast.Attribute) and func.attr == "compile"
        and isinstance(func.value, ast.Name) and func.value.id == "builtins"
    )
