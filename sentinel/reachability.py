"""
sentinel/reachability.py
------------------------
Static pre-gate: can attacker-controlled data actually reach the line the hunter
flagged?

Why this exists
---------------
An LLM hunter reads code and pattern-matches. It will flag `cursor.execute(q)` as
SQL injection whether or not `q` can ever hold attacker input -- which is why the
benchmark's clean control target attracted false positives. Validating those costs
several model calls and container runs each, and the exploit that "proves" them is
usually a generic demo that never touches the code at all.

So before spending any of that, we ask a cheap, deterministic question: is there a
data-flow path from a taint SOURCE (request parameters, argv, env, stdin) to a
SINK (the dangerous call) at or near the reported line?

How it works
------------
1. Parse the file to an AST.
2. Seed taint: names bound from a source expression (`request.args.get("q")`,
   `input()`, `sys.argv[1]`, ...) become tainted.
3. Propagate to a fixpoint. Taint spreads through assignment, f-strings, `%`,
   `.format()`, `+`, `.join()`, containers, and one level of call-return.
4. Inter-procedural (one direction): if a tainted value is passed to a locally
   defined function, that function's matching parameter becomes tainted, and we
   iterate until nothing changes.
5. At each sink call, check whether any argument is tainted.

Design decisions worth defending
--------------------------------
* **Fail open.** If the file can't be parsed, the class is unknown, or no sink
  pattern matches, the verdict is NOT_ANALYZABLE and the candidate proceeds to
  validation. A static gate that blocks whenever it is unsure would trade a large
  amount of recall for a little precision. The gate may only ever *reject on
  positive evidence of no path* -- never on ignorance.
* **Literal-sourced classes are exempt.** A hardcoded secret has no taint source;
  the vulnerability *is* the literal. Those classes skip the taint question and
  check for a suspicious literal binding instead.
* **Line tolerance.** Models routinely report a line a little off (the call vs.
  the statement it sits in). Matching is done within a small window rather than on
  an exact line, so a one-line drift doesn't cause a false rejection.

This is deliberately an over-approximation: it is built to avoid false rejections,
not to be a complete taint engine. It has no path sensitivity, no alias analysis,
and does not cross module boundaries.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum

# How many lines either side of the reported line still count as "at" it.
LINE_TOLERANCE = 3

# Attribute/callable patterns whose *result* is attacker-controlled.
SOURCE_CALLS = {
    "input",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.get_json",
    "request.json",
    "os.environ.get",
    "os.getenv",
    "sys.stdin.read",
    "sys.stdin.readline",
    "flask.request.args.get",
}

# Attribute roots that are attacker-controlled when merely subscripted/read.
SOURCE_ROOTS = {
    "request.args",
    "request.form",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.json",
    "request.data",
    "sys.argv",
    "os.environ",
}

# Dangerous callables, grouped by the vulnerability class that names them.
# Keys are matched loosely against the hunter's free-text class string.
SINKS: dict[str, set[str]] = {
    "sql": {
        "execute",
        "executemany",
        "executescript",
        "cursor.execute",
        "raw",
    },
    "command": {
        "os.system",
        "os.popen",
        "os.execl", "os.execle", "os.execlp", "os.execlpe",
        "os.execv", "os.execve", "os.execvp", "os.execvpe",
        "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
        "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
        "os.posix_spawn", "os.posix_spawnp",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "commands.getoutput",
        "commands.getstatusoutput",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "pty.spawn",
        "eval",
        "exec",
    },
    "path": {
        "open",
        "io.open",
        "codecs.open",
        "os.open",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.rename",
        "os.replace",
        "os.listdir",
        "os.scandir",
        "os.mkdir",
        "os.makedirs",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "send_file",
        "pathlib.Path",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
    },
    "deserial": {
        "pickle.load",
        "pickle.loads",
        "pickle.Unpickler",
        "_pickle.loads",
        "cPickle.loads",
        "yaml.load",
        "yaml.load_all",
        "yaml.unsafe_load",
        "yaml.unsafe_load_all",
        "marshal.load",
        "marshal.loads",
        "dill.load",
        "dill.loads",
        "shelve.open",
        "jsonpickle.decode",
        "joblib.load",
        "torch.load",
        "pandas.read_pickle",
    },
    "ssrf": {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.request",
        "urllib.request.urlopen",
        "urlopen",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.request",
        "httpx.stream",
    },
    "template": {"render_template_string", "Template"},
}

# Classes where the bug is a literal in the source, not tainted data flow.
LITERAL_CLASSES = ("secret", "credential", "password", "api key", "token", "hardcoded")

# Substrings that make a literal assignment look like a credential.
SECRET_NAME_HINTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
)


class Verdict(str, Enum):
    REACHABLE = "reachable"
    SAFE_USAGE = "safe_usage"
    NO_TAINT_PATH = "no_taint_path"
    NO_SINK_AT_LINE = "no_sink_at_line"
    # A sink is there and receives data the gate can neither trace to a source nor
    # rule out: a function parameter, a variable, a call result. In a library the
    # parameter IS the attacker's input, so this must never reject.
    NO_KNOWN_SOURCE = "no_known_source"
    NOT_ANALYZABLE = "not_analyzable"

    @property
    def blocks(self) -> bool:
        """Only positive evidence of no path may reject a candidate."""
        return self in (
            Verdict.NO_TAINT_PATH,
            Verdict.NO_SINK_AT_LINE,
            Verdict.SAFE_USAGE,
        )


@dataclass
class Reachability:
    verdict: Verdict
    reason: str
    path: list[str] = field(default_factory=list)
    sink: str = ""

    @property
    def blocks(self) -> bool:
        return self.verdict.blocks

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "path": self.path,
            "sink": self.sink,
        }


def _dotted(node: ast.AST) -> str:
    """Render Name/Attribute chains as a dotted string: `os.path.join`."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map each locally bound import name to what it refers to.

    `from shlex import quote` binds `quote` to `shlex.quote`; so does
    `import shlex as s` for `s.quote`. Without this, `quote(x)` from
    `urllib.parse` and from `shlex` look identical, and only one of them keeps a
    shell safe.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _canonical(dotted: str, aliases: dict[str, str]) -> str:
    """Rewrite a call name's first segment through the file's imports."""
    if not dotted:
        return dotted
    head, _, rest = dotted.partition(".")
    if head in aliases:
        return aliases[head] + ("." + rest if rest else "")
    return dotted


def _call_name(func: ast.AST) -> str:
    """Name a call for sink matching, including calls on a chained expression.

    `_dotted` gives up when the chain is rooted in something other than a name, as
    in `conn.cursor().execute(q)`. The method name is still known, and a sink we
    cannot see is a sink the gate would wrongly report as absent.
    """
    dotted = _dotted(func)
    if dotted:
        return dotted
    if isinstance(func, ast.Attribute):
        return f"(...).{func.attr}"
    return ""


_LITERAL_NODES = (ast.Constant, ast.JoinedStr, ast.FormattedValue, ast.BinOp, ast.UnaryOp,
                  ast.Tuple, ast.List, ast.Set, ast.Dict, ast.operator, ast.unaryop,
                  ast.expr_context)


def _is_literal(node: ast.AST) -> bool:
    """True only if the expression is built from literals alone: no names, no calls.

    That is the positive evidence NO_TAINT_PATH needs. A variable that happens to
    hold a constant is not proven clean here; showing that takes def-use analysis
    the gate does not do, so it fails open instead.
    """
    return all(isinstance(n, _LITERAL_NODES) for n in ast.walk(node))


def _matches(dotted: str, patterns: set[str]) -> str:
    """Match a dotted call against patterns, allowing a suffix match.

    `db.cursor.execute` matches the pattern `execute`, because we cannot resolve
    what `db` is without type inference.
    """
    if not dotted:
        return ""
    if dotted in patterns:
        return dotted
    tail = dotted.rsplit(".", 1)[-1]
    for pat in patterns:
        if pat == tail or dotted.endswith("." + pat):
            return pat
    return ""


def _sink_group(vuln_class: str) -> set[str] | None:
    """Map the hunter's free-text class onto a sink group. None if unknown."""
    c = vuln_class.lower()
    if "sql" in c:
        return SINKS["sql"]
    if "command" in c or "os injection" in c or "rce" in c or "code injection" in c:
        return SINKS["command"]
    if "traversal" in c or "path" in c or "lfi" in c or "file inclusion" in c:
        return SINKS["path"]
    if "deserial" in c or "pickle" in c or "unmarshal" in c:
        return SINKS["deserial"]
    if "ssrf" in c or "request forgery" in c:
        return SINKS["ssrf"]
    if "template injection" in c or "ssti" in c:
        return SINKS["template"]
    return None


def _is_literal_class(vuln_class: str) -> bool:
    c = vuln_class.lower()
    return any(h in c for h in LITERAL_CLASSES)


class _TaintAnalysis:
    """Intra-file taint propagation to a fixpoint."""

    def __init__(
        self,
        tree: ast.Module,
        clean: frozenset[str] = frozenset(),
        aliases: dict[str, str] | None = None,
    ) -> None:
        self.tree = tree
        # Callables whose result is NOT tainted even when their input is. Empty
        # for the ordinary analysis; the sanitizer check reruns with a group's
        # sanitizers here, so a value counts as neutralized only if every path
        # to the sink passes through one.
        self.clean = clean
        self.aliases = aliases if aliases is not None else _import_aliases(tree)
        self.tainted: set[str] = set()
        self.origin: dict[str, str] = {}
        # Locally defined functions, so we can push taint into their parameters.
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node

    # -- source detection -------------------------------------------------

    def _is_source_expr(self, node: ast.AST) -> str:
        """Return a human-readable source description, or "" if not a source."""
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name and (name in SOURCE_CALLS or _matches(name, SOURCE_CALLS)):
                return f"{name}()"
            # request.args.get(...) where func is an Attribute chain
            for root in SOURCE_ROOTS:
                if name.startswith(root + ".") or name == root:
                    return f"{name}()"
        if isinstance(node, ast.Subscript):
            base = _dotted(node.value)
            if base in SOURCE_ROOTS or any(
                base.startswith(r) or base.endswith(r.split(".")[-1])
                for r in SOURCE_ROOTS
            ):
                return f"{base}[...]"
        if isinstance(node, ast.Attribute):
            name = _dotted(node)
            if name in SOURCE_ROOTS:
                return name
        return ""

    # -- taint propagation ------------------------------------------------

    def _expr_tainted(self, node: ast.AST) -> str:
        """Is this expression tainted? Returns a description or ""."""
        if node is None:
            return ""

        src = self._is_source_expr(node)
        if src:
            return src

        if isinstance(node, ast.Name):
            return self.origin.get(node.id, "") if node.id in self.tainted else ""

        # f"...{tainted}..."
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self._expr_tainted(v.value)
                    if t:
                        return t
            return ""

        # "..." % x   and   a + b
        if isinstance(node, ast.BinOp):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)

        # "...".format(x) / ",".join(xs) / str(x) / x.strip()
        if isinstance(node, ast.Call):
            if self.clean and _canonical(_dotted(node.func), self.aliases) in self.clean:
                return ""
            for a in list(node.args) + [k.value for k in node.keywords]:
                t = self._expr_tainted(a)
                if t:
                    return t
            # x.strip() where x is tainted
            if isinstance(node.func, ast.Attribute):
                t = self._expr_tainted(node.func.value)
                if t:
                    return t
            return ""

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                t = self._expr_tainted(e)
                if t:
                    return t
            return ""

        if isinstance(node, ast.Dict):
            for e in list(node.keys) + list(node.values):
                if e is not None:
                    t = self._expr_tainted(e)
                    if t:
                        return t
            return ""

        if isinstance(node, ast.Subscript):
            return self._expr_tainted(node.value)

        if isinstance(node, ast.Attribute):
            return self._expr_tainted(node.value)

        if isinstance(node, ast.IfExp):
            return self._expr_tainted(node.body) or self._expr_tainted(node.orelse)

        return ""

    def run(self, max_rounds: int = 6) -> None:
        """Propagate until nothing new becomes tainted."""
        for _ in range(max_rounds):
            before = len(self.tainted)
            self._round()
            if len(self.tainted) == before:
                return

    def _mark(self, name: str, why: str) -> None:
        if name and name not in self.tainted:
            self.tainted.add(name)
            self.origin[name] = why

    def _round(self) -> None:
        for node in ast.walk(self.tree):
            # x = <tainted>
            if isinstance(node, ast.Assign):
                why = self._expr_tainted(node.value)
                if why:
                    for tgt in node.targets:
                        for name in self._bound_names(tgt):
                            self._mark(name, why)

            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                why = self._expr_tainted(node.value)
                if why:
                    for name in self._bound_names(node.target):
                        self._mark(name, why)

            elif isinstance(node, ast.AugAssign):
                why = self._expr_tainted(node.value)
                if why:
                    for name in self._bound_names(node.target):
                        self._mark(name, why)

            # for x in <tainted>:
            elif isinstance(node, ast.For):
                why = self._expr_tainted(node.iter)
                if why:
                    for name in self._bound_names(node.target):
                        self._mark(name, why)

            # with open(tainted) as f  -- the handle carries taint
            elif isinstance(node, ast.withitem):
                why = self._expr_tainted(node.context_expr)
                if why and node.optional_vars is not None:
                    for name in self._bound_names(node.optional_vars):
                        self._mark(name, why)

            # f(tainted) where f is local -> its parameter becomes tainted
            elif isinstance(node, ast.Call):
                fname = _dotted(node.func)
                short = fname.rsplit(".", 1)[-1] if fname else ""
                fn = self.functions.get(fname) or self.functions.get(short)
                if fn is not None:
                    params = [a.arg for a in fn.args.args]
                    for i, arg in enumerate(node.args):
                        why = self._expr_tainted(arg)
                        if why and i < len(params):
                            self._mark(params[i], why)
                    for kw in node.keywords:
                        why = self._expr_tainted(kw.value)
                        if why and kw.arg in params:
                            self._mark(kw.arg, why)

    @staticmethod
    def _bound_names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            out: list[str] = []
            for e in target.elts:
                out.extend(_TaintAnalysis._bound_names(e))
            return out
        return []


def _flask_route_params(tree: ast.Module) -> set[str]:
    """Parameters of @app.route-decorated functions are URL-controlled."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            dotted = _dotted(dec.func if isinstance(dec, ast.Call) else dec)
            if dotted.endswith("route") or dotted.endswith("get") or dotted.endswith("post"):
                for a in node.args.args:
                    names.add(a.arg)
    return names


def _literal_secret_at(tree: ast.Module, line: int) -> Reachability | None:
    """For literal-based classes: is there a credential-shaped literal near `line`?"""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if abs(getattr(node, "lineno", -999) - line) > LINE_TOLERANCE:
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for tgt in targets:
            name = tgt.id if isinstance(tgt, ast.Name) else _dotted(tgt)
            if any(h in name.lower() for h in SECRET_NAME_HINTS):
                return Reachability(
                    Verdict.REACHABLE,
                    f"string literal bound to credential-shaped name `{name}`",
                    path=[f"{name} = <string literal> (line {node.lineno})"],
                    sink=name,
                )
    return None


# Callables that neutralize a tainted value for a given sink group, by fully
# qualified name after import resolution. Deliberately short. Absent on purpose:
#   * os.path.realpath / Path.resolve -- they canonicalize a path, they do not
#     confine it. `open(realpath(join(BASE, user)))` still reads /etc/passwd.
#   * urllib.parse.quote -- URL encoding, not shell quoting.
#   * subprocess.list2cmdline -- Windows argv quoting, not a POSIX shell's.
#   * SQL "escape" helpers -- charset-dependent; parameterization is the fix.
SANITIZERS: dict[str, frozenset[str]] = {
    "path": frozenset({
        "os.path.basename", "posixpath.basename", "ntpath.basename",
        "werkzeug.utils.secure_filename", "werkzeug.security.safe_join",
        "flask.safe_join", "flask.helpers.safe_join",
    }),
    "command": frozenset({"shlex.quote", "pipes.quote"}),
}

# argv[0] values that turn an argument vector back into a shell command line.
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox",
           "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}

_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


def _runs_a_shell(argv: ast.List | ast.Tuple) -> bool:
    if not argv.elts:
        return False
    first = argv.elts[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return True  # an attacker-chosen program is not "no shell"
    return first.value.replace("\\", "/").rsplit("/", 1)[-1].lower() in _SHELLS


def _safe_usage(call: ast.Call, group_key: str, name: str) -> str:
    """Recognize the idioms that make a dangerous-looking call actually safe.

    This is what separates a useful gate from a noisy one. On the benchmark's
    clean control, attacker data genuinely *does* reach `cursor.execute` and
    `subprocess.run` -- the code is safe because of *how* they are called, not
    because the data never arrives. A gate that only models taint would wave both
    through and catch nothing.

    Pattern-based, so it recognizes common correct usage rather than proving
    safety. It returns a reason only when the idiom is unambiguous.
    """
    # Parameterized SQL: execute(<constant sql>, <params>)
    if group_key == "sql" and len(call.args) >= 2:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            if "?" in first.value or "%s" in first.value or ":" in first.value:
                return (
                    "query string is a constant with bound parameters "
                    "(parameterized query)"
                )

    # subprocess with an argument vector and provably no shell. `shell=flag` is
    # not provably False, and ["sh", "-c", user] is a shell however it is passed.
    if (group_key == "command" and call.args and name.startswith("subprocess.")
            and isinstance(call.args[0], (ast.List, ast.Tuple))):
        shell_off = all(
            isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in call.keywords if kw.arg == "shell"
        )
        if shell_off and not _runs_a_shell(call.args[0]):
            return "argument vector passed without a shell (shell=False)"

    # yaml with a loader that only builds plain data, torch with weights_only.
    if group_key == "deserial":
        tail = name.rsplit(".", 1)[-1]
        if tail in ("load", "load_all") and "yaml" in name:
            loader = call.args[1] if len(call.args) > 1 else next(
                (k.value for k in call.keywords if k.arg == "Loader"), None)
            if loader is not None and _dotted(loader).rsplit(".", 1)[-1] in _SAFE_YAML_LOADERS:
                return "yaml loader restricted to plain data (SafeLoader)"
        if tail == "load" and "torch" in name and any(
            k.arg == "weights_only" and isinstance(k.value, ast.Constant)
            and k.value.value is True for k in call.keywords
        ):
            return "torch.load with weights_only=True"

    return ""


def _group_key(vuln_class: str) -> str:
    c = vuln_class.lower()
    if "sql" in c:
        return "sql"
    if "command" in c or "os injection" in c or "rce" in c or "code injection" in c:
        return "command"
    if "traversal" in c or "path" in c or "lfi" in c or "file inclusion" in c:
        return "path"
    if "deserial" in c or "pickle" in c or "unmarshal" in c:
        return "deserial"
    if "ssrf" in c or "request forgery" in c:
        return "ssrf"
    if "template injection" in c or "ssti" in c:
        return "template"
    return ""


def analyze(source: str, vuln_class: str, line: int) -> Reachability:
    """Decide whether the reported line is plausibly reachable by attacker input.

    Returns a Reachability whose `.blocks` is True only when there is positive
    evidence that no path exists. Anything uncertain fails open.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return Reachability(
            Verdict.NOT_ANALYZABLE, f"file did not parse ({exc.msg}); gate skipped"
        )

    # Literal-based classes (hardcoded secrets) have no taint source by nature.
    if _is_literal_class(vuln_class):
        found = _literal_secret_at(tree, line)
        if found is not None:
            return found
        return Reachability(
            Verdict.NOT_ANALYZABLE,
            "credential-style class with no matching literal found; gate skipped",
        )

    sinks = _sink_group(vuln_class)
    if sinks is None:
        return Reachability(
            Verdict.NOT_ANALYZABLE,
            f"no sink model for class '{vuln_class}'; gate skipped",
        )

    aliases = _import_aliases(tree)
    route_params = _flask_route_params(tree)

    def taint(clean: frozenset[str] = frozenset()) -> _TaintAnalysis:
        a = _TaintAnalysis(tree, clean=clean, aliases=aliases)
        # Seed: Flask view parameters are URL-controlled.
        for p in route_params:
            a._mark(p, "URL route parameter")
        a.run()
        return a

    analysis = taint()
    gkey = _group_key(vuln_class)
    # The same analysis with this class's sanitizers treated as clean. A call is
    # sanitized only if its arguments are tainted here in NEITHER sense -- that is,
    # every tainted path into it went through a sanitizer. Checking whether a
    # sanitizer merely appears somewhere in the arguments let
    # `f"ls {quote(a)} {b}"` pass as safe.
    sanitizers = SANITIZERS.get(gkey, frozenset())
    sanitized = taint(sanitizers) if sanitizers else None

    # Find sink calls at or near the reported line.
    near: list[tuple[ast.Call, str]] = []
    anywhere: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _canonical(_call_name(node.func), aliases)
        hit = _matches(dotted, sinks)
        if not hit:
            continue
        anywhere.append((node, dotted or hit))
        if abs(getattr(node, "lineno", -999) - line) <= LINE_TOLERANCE:
            near.append((node, dotted or hit))

    candidates = near or []
    if not candidates:
        # No sink we model is near the line. That is evidence only if nothing near
        # the line takes attacker data either: the catalogue is finite, and a call
        # it does not list is ignorance, not absence.
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and abs(getattr(node, "lineno", -999) - line) <= LINE_TOLERANCE):
                why = next((w for a in list(node.args) + [k.value for k in node.keywords]
                            if (w := analysis._expr_tainted(a))), "")
                name = _canonical(_call_name(node.func), aliases) or "a call"
                if why:
                    return Reachability(
                        Verdict.NOT_ANALYZABLE,
                        f"attacker-controlled data ({why}) reaches `{name}` at line "
                        f"{node.lineno}, which has no {vuln_class} sink model; "
                        "gate skipped",
                        sink=name,
                    )
        if not anywhere:
            return Reachability(
                Verdict.NO_SINK_AT_LINE,
                f"no {vuln_class} sink call anywhere in this file",
            )
        return Reachability(
            Verdict.NO_SINK_AT_LINE,
            f"no {vuln_class} sink call within {LINE_TOLERANCE} lines of line {line}",
        )

    safe_reasons: list[str] = []
    unresolved: list[str] = []

    for call, name in candidates:
        tainted_why = ""
        for arg in list(call.args) + [k.value for k in call.keywords]:
            tainted_why = analysis._expr_tainted(arg)
            if tainted_why:
                break
        if not tainted_why:
            args = list(call.args) + [k.value for k in call.keywords]
            if not all(_is_literal(a) for a in args):
                unresolved.append(f"`{name}` at line {call.lineno}")
            continue

        # Data arrives -- but is the call made safely?
        safe = _safe_usage(call, gkey, name)
        if not safe and sanitized is not None and not any(
            sanitized._expr_tainted(a) for a in list(call.args) + [k.value for k in call.keywords]
        ):
            safe = (f"every attacker-controlled value reaching `{name}` passes through "
                    f"a sanitizer ({', '.join(sorted(sanitizers))})")
        if safe:
            safe_reasons.append(f"`{name}` at line {call.lineno}: {safe}")
            continue

        return Reachability(
            Verdict.REACHABLE,
            f"attacker-controlled data reaches `{name}`",
            path=[f"source: {tainted_why}", f"sink: {name}() at line {call.lineno}"],
            sink=name,
        )

    # Checked before SAFE_USAGE on purpose: one safely-made call nearby is not
    # evidence about a different call the gate could not resolve.
    if unresolved:
        return Reachability(
            Verdict.NO_KNOWN_SOURCE,
            "; ".join(unresolved) + ": receives data the gate cannot trace to a "
            "source or rule out, so validation decides",
            sink=", ".join(sorted({n for _, n in candidates})),
        )

    if safe_reasons:
        return Reachability(
            Verdict.SAFE_USAGE,
            "; ".join(safe_reasons),
            path=safe_reasons,
            sink=", ".join(sorted({n for _, n in candidates})),
        )

    sink_names = ", ".join(sorted({n for _, n in candidates}))
    return Reachability(
        Verdict.NO_TAINT_PATH,
        f"`{sink_names}` at line {line} receives only literal values",
        sink=sink_names,
    )
