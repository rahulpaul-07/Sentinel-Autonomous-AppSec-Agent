"""
sentinel/patcher.py
-------------------
The Patcher: for the line-proven findings in a file, propose one minimal fix.

It asks the model to rewrite the file with every proven vulnerability fixed, then
computes a real unified diff (with Python's difflib) between the original and the
fix -- so we show exactly what changed, accurately, without trusting the model to
format a diff.

A proposed file is checked before anyone is offered it. It must be non-empty,
must parse as Python, and must actually differ from the original. A reply that
fails any of these is kept on the report as an invalid patch -- never applied.
Whether the fix actually stops the exploit is a separate question, answered by
replaying the exploit against it (see Scanner._verify_patch).
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field

from sentinel.hunter import Finding
from sentinel.llm import LLMClient
from sentinel.prompting import UNTRUSTED_NOTICE, fence

SYSTEM_PROMPT = (
    "You are a senior secure-coding engineer. You fix security vulnerabilities with "
    "the smallest change that removes the risk while preserving behavior. You output "
    "ONLY the complete corrected file contents -- no prose, no markdown. "
    + UNTRUSTED_NOTICE
)

PATCH_PROMPT = """This file contains confirmed security vulnerabilities, each
demonstrated against the code:

{issues}

Rewrite the ENTIRE file with ALL of them fixed using secure, idiomatic approaches
(for example: parameterized SQL queries, argument lists instead of shell strings,
paths confined to their base directory, secrets read from environment variables,
safe serialization formats). Keep every function name and signature, and change
as little else as possible.

{code_block}

Output ONLY the full corrected file contents.
"""

# Outcomes of replaying the proven exploits against the patched file.
VERIFIED = "verified"                  # target code ran, exploit no longer succeeds
STILL_EXPLOITABLE = "still_exploitable"
INCONCLUSIVE = "inconclusive"          # the exploit could not reach the patched code
NOT_RUN = "not_run"


@dataclass
class Patch:
    finding: Finding                   # the first finding, kept for older callers
    diff: str
    fixed_code: str
    findings: list[Finding] = field(default_factory=list)
    valid: bool = True
    problem: str = ""                  # why an invalid patch is invalid
    verification: str = NOT_RUN
    verification_detail: str = ""

    @property
    def file(self) -> str:
        return self.finding.file

    @property
    def applicable(self) -> bool:
        """Safe to write without a human reading it first."""
        return self.valid and self.verification == VERIFIED

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "vuln_class": self.finding.vuln_class,
            "fixes": [{"vuln_class": f.vuln_class, "line": f.line} for f in self.findings],
            "diff": self.diff,
            "valid": self.valid,
            "problem": self.problem,
            "verification": self.verification,
            "verification_detail": self.verification_detail,
        }


class Patcher:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def propose(self, findings: Finding | list[Finding], original_code: str) -> Patch:
        """One fix for every given finding. All must be in the same file."""
        findings = [findings] if isinstance(findings, Finding) else list(findings)
        if not findings:
            raise ValueError("propose() needs at least one finding")
        if len({f.file for f in findings}) != 1:
            raise ValueError("propose() fixes one file at a time")

        issues = "\n".join(
            f"  - {f.vuln_class} at line {f.line}: {f.description}" for f in findings
        )
        reply = self.llm.complete(
            prompt=PATCH_PROMPT.format(
                issues=issues, code_block=fence(findings[0].file, original_code)
            ),
            system=SYSTEM_PROMPT,
        ).text
        fixed = _match_trailing_newline(self._clean(reply), original_code)
        patch = Patch(
            finding=findings[0],
            diff=self._make_diff(original_code, fixed, findings[0].file),
            fixed_code=fixed,
            findings=findings,
        )
        patch.problem = _invalid_because(fixed, original_code)
        patch.valid = not patch.problem
        return patch

    def _make_diff(self, original: str, fixed: str, filename: str) -> str:
        diff_lines = difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff_lines)

    def _clean(self, text: str) -> str:
        """Strip markdown code fences if the model added them despite instructions."""
        text = text.strip()
        fence_ = "`" * 3
        if text.startswith(fence_):
            lines = text.splitlines()
            lines = lines[1:]
            if lines and lines[-1].strip().startswith(fence_):
                lines = lines[:-1]
            text = "\n".join(lines)
        return text


def _match_trailing_newline(fixed: str, original: str) -> str:
    """Stripping the reply removed the file's final newline; put it back."""
    if original.endswith("\n") and fixed and not fixed.endswith("\n"):
        return fixed + "\n"
    return fixed


def _invalid_because(fixed: str, original: str) -> str:
    if not fixed.strip():
        return "the model returned an empty file"
    if fixed == original:
        return "the model returned the file unchanged"
    try:
        ast.parse(fixed)
    except SyntaxError as exc:
        return f"the proposed file does not parse: {exc.msg} (line {exc.lineno})"
    return ""


def write_fixed(path, text: str) -> None:
    """Write a fixed file keeping the original's line endings.

    Text-mode writes translate newlines to the platform's, so on Windows
    applying a fix used to turn an LF file into CRLF -- a diff on every line.
    """
    from pathlib import Path

    path = Path(path)
    try:
        crlf = b"\r\n" in path.read_bytes()
    except OSError:
        crlf = False
    path.write_text(text, encoding="utf-8", newline="\r\n" if crlf else "\n")
