"""Shared fixtures: build a realistic ScanReport WITHOUT calling an LLM or Docker.

The sample deliberately covers all four evidence tiers, because the report and the
serialization both branch on them -- a fixture with only "confirmed" and "rejected"
would let tier bugs through.
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
    hit_secret = WitnessResult(available=True, file_executed=True, line_executed=True,
                               executed_lines=[16, 18], target_file="app.py", target_line=18)
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
            ScannedFinding(
                finding=secret, confirmed=True, evidence=Evidence.LINE_PROVEN,
                validation=ValidationResult(secret, True, Evidence.LINE_PROVEN, poc,
                                            "SENTINEL_PWNED", 2, hit_secret),
            ),
            # class-only: marker printed, but the target file never ran
            ScannedFinding(
                finding=deser, confirmed=True, evidence=Evidence.CLASS_ONLY,
                validation=ValidationResult(deser, True, Evidence.CLASS_ONLY, generic_poc,
                                            "SENTINEL_PWNED", 1, miss),
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
