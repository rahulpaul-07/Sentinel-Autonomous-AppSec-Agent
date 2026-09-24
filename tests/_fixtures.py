"""Shared fixtures: build a realistic ScanReport WITHOUT calling an LLM or Docker.

The sample deliberately covers all five evidence tiers, because the report and the
serialization both branch on them -- a fixture with only "confirmed" and "rejected"
would let tier bugs through.

Every entry is something the real pipeline can produce. In particular the hardcoded
secret is CLASS_ONLY, not LINE_PROVEN: it sits on a module-level line, which only
ever runs because the module was imported, and import-time execution is never
counted as a witness. `python -m examples.render_sample_report` renders this fixture into
the sample report published on the project page.
"""

from __future__ import annotations

from sentinel.evidence import Evidence
from sentinel.hunter import Finding
from sentinel.patcher import Patch
from sentinel.reachability import Reachability, Verdict
from sentinel.scanner import ScanReport, ScannedFinding
from sentinel.validator import ValidationResult
from sentinel.witness import WitnessResult


def sample_report() -> ScanReport:
    sqli = Finding(
        vuln_class="SQL Injection", file="app.py", line=33, severity="critical",
        description="username from request flows unsanitized into an SQL string.",
        confidence=0.95,
    )
    secret = Finding(
        vuln_class="Hardcoded Secret", file="app.py", line=18, severity="high",
        description="an admin password is written directly in source.",
        confidence=0.9,
    )
    deser = Finding(
        vuln_class="Insecure Deserialization", file="app.py", line=61, severity="high",
        description="pickle.loads on attacker-supplied bytes.",
        confidence=0.7,
    )
    ping_fp = Finding(
        vuln_class="Command Injection", file="app.py", line=50, severity="high",
        description="host reaches subprocess.run with an argument list (no shell).",
        confidence=0.4,
    )
    poc = "import app\n# ... exploit ...\nprint('SENTINEL_PWNED')\n"
    generic_poc = "import sqlite3\n# reproduces the class in isolation\nprint('SENTINEL_PWNED')\n"
    diff = ("--- a/app.py\n+++ b/app.py\n@@ -33 +33 @@\n"
            '-    query = "SELECT * FROM users WHERE name = \'" + username + "\'"\n'
            '+    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))\n')

    hit_sqli = WitnessResult(available=True, file_executed=True, line_executed=True,
                             executed_lines=[30, 31, 33], target_file="app.py", target_line=33)
    # The PoC imported the module and printed the marker; line 18 ran, but only
    # because the import executed it.
    imported_secret = WitnessResult(available=True, file_executed=True, line_executed=False,
                                    executed_lines=[9, 10, 12, 14, 18],
                                    import_only_lines=[9, 10, 12, 14, 18],
                                    target_file="app.py", target_line=18)
    cmdi = Finding(
        vuln_class="Command Injection", file="app.py", line=45, severity="critical",
        description="host from the request is appended to a shell command passed to os.system.",
        confidence=1.0,
    )
    miss = WitnessResult(available=True, file_executed=False, line_executed=False,
                         executed_lines=[], target_file="app.py", target_line=61)

    return ScanReport(
        target="targets/vulnerable_app",
        model="groq/openai/gpt-oss-120b",
        elapsed_seconds=12.34,
        scanned=[
            # line-proven: exploit ran AND the reported line executed
            ScannedFinding(
                finding=sqli, confirmed=True, evidence=Evidence.LINE_PROVEN,
                validation=ValidationResult(sqli, True, Evidence.LINE_PROVEN, poc,
                                            "SENTINEL_PWNED", 1, hit_sqli),
            ),
            # class-only: marker printed, the line ran, but only at import time
            ScannedFinding(
                finding=secret, confirmed=True, evidence=Evidence.CLASS_ONLY,
                validation=ValidationResult(secret, True, Evidence.CLASS_ONLY,
                                            "import app\nprint('SENTINEL_PWNED')\n",
                                            "SENTINEL_PWNED", 1, imported_secret),
            ),
            # class-only: marker printed, but the target file never ran
            ScannedFinding(
                finding=deser, confirmed=True, evidence=Evidence.CLASS_ONLY,
                validation=ValidationResult(deser, True, Evidence.CLASS_ONLY, generic_poc,
                                            "SENTINEL_PWNED", 1, miss),
            ),
            # not testable: the sandbox image lacked a package the target imports
            ScannedFinding(
                finding=cmdi, confirmed=False, evidence=Evidence.ENV_INCOMPLETE,
                validation=ValidationResult(
                    cmdi, False, Evidence.ENV_INCOMPLETE, poc,
                    "ModuleNotFoundError: No module named 'flask'", 3, None,
                    missing_module="flask",
                ),
            ),
            # gated out by static analysis before any model call
            ScannedFinding(
                finding=ping_fp, confirmed=False, evidence=Evidence.UNREACHABLE,
                reachability=Reachability(
                    Verdict.SAFE_USAGE,
                    "`subprocess.run` at line 50: argument vector passed without a shell "
                    "(shell=False)",
                    sink="subprocess.run",
                ),
            ),
        ],
        patches=[Patch(sqli, diff, "fixed source")],
    )
