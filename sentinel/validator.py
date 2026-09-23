"""
sentinel/validator.py
---------------------
The Validator: turns a Finding from a CLAIM into graded EVIDENCE -- or rejects it.

For each finding it:
  1. asks the LLM to write a proof-of-concept (PoC) that IMPORTS the module under
     test and drives the real vulnerable function, printing a unique marker
     (SENTINEL_PWNED) only if the vulnerability is real,
  2. wraps the PoC in a line-tracing harness and runs it in the locked-down
     sandbox with the target mounted read-only,
  3. if the marker is absent, feeds the failure BACK to the model and retries
     (self-correction) -- up to max_attempts times,
  4. grades the outcome on the evidence ladder:
        marker + reported line executed -> LINE_PROVEN   (this line is exploitable)
        marker + reported line not run  -> CLASS_ONLY    (only the class is shown)
        no marker                       -> UNPROVEN

The distinction in step 4 is the point of the whole system. A marker-only check
treats "I reproduced SQL injection somewhere" and "I exploited THIS line" as the
same result; they are not. The line witness keeps them separate without needing
any ground-truth label -- the finding's own reported location is the target.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.sandbox import Sandbox
from sentinel.hunter import Finding
from sentinel.evidence import Evidence
from sentinel.witness import build_harness, parse_witness, strip_witness, WitnessResult

MARKER = "SENTINEL_PWNED"

# `ModuleNotFoundError: No module named 'flask'` and friends.
_MISSING_MODULE_RE = re.compile(r"No module named ['\"]([\w.]+)['\"]")


def missing_dependency(output: str, target_module: str) -> str | None:
    """Name the third-party module the sandbox lacks, if that is why a PoC died.

    The distinction that matters here is WHICH module is missing:

      * the target's own module  -> the code under test was never mounted into the
        container. That is an infrastructure fault on our side, and it must stay
        UNPROVEN so it stays visible rather than being excused as an environment
        gap.
      * anything else            -> the target imports a third-party package that
        the sandbox image does not have. The exploit never got to run, so grading
        it UNPROVEN would claim we tested something we did not.
    """
    for match in _MISSING_MODULE_RE.finditer(output or ""):
        module = match.group(1).split(".")[0]
        if module and module != target_module:
            return module
    return None

# Where the sandbox mounts the target codebase (read-only). The harness adds this
# to sys.path so the PoC can import the real module under test.
MOUNT = "/work"

SYSTEM_PROMPT = (
    "You are an exploit developer writing a minimal proof-of-concept to demonstrate "
    "a specific vulnerability in a specific file. You output ONLY a runnable Python "
    "script -- no prose, no markdown."
)

POC_PROMPT = """A security scan reported this potential vulnerability:

  Class:       {vuln_class}
  File/line:   {file}:{line}
  Description: {description}

The file under test is importable as the module `{module}` (its directory is on
sys.path). Here is its source:
--- BEGIN {file} ---
{code}
--- END {file} ---

Write a SHORT Python 3 script that proves THIS SPECIFIC vulnerability by actually
exercising the reported code.

STRICT RULES:
  - IMPORT the real code: `import {module}` (or `from {module} import ...`) and
    call the vulnerable function/route directly. Do NOT re-implement the vulnerable
    pattern yourself -- the proof must run the code in {file}.
  - Set up anything the target needs first (create any files, data, or tables it
    reads; build a Flask test client with `.test_client()` for a route).
  - Feed it a malicious, attacker-controlled input that triggers the flaw at the
    reported location.
  - Print this EXACT marker, and ONLY if the exploit genuinely succeeds: {marker}
  - Use ONLY the Python standard library plus whatever {file} already imports. No
    network, no pip installs.

Output ONLY the Python code, nothing else.
"""

FIX_PROMPT = """Your previous proof-of-concept did NOT print the marker {marker}.
Here is the script and what happened when it ran.

Previous PoC:
--- BEGIN POC ---
{poc}
--- END POC ---

Output when it ran:
--- BEGIN OUTPUT ---
{output}
--- END OUTPUT ---

Fix the script so it correctly demonstrates the {vuln_class} vulnerability at
{file}:{line} and prints {marker} on success. Remember to IMPORT and drive the
real code in {file} rather than re-implementing it. Keep it standard-library only
and set up anything it needs. Output ONLY the corrected Python code.
"""


@dataclass
class ValidationResult:
    finding: Finding
    confirmed: bool               # marker printed (either proof tier)
    evidence: Evidence            # the graded tier
    poc_code: str
    output: str                   # exploit output, witness record stripped out
    attempts: int
    witness: WitnessResult | None = None
    missing_module: str = ""     # set when the sandbox lacked a dependency

    @property
    def line_proven(self) -> bool:
        return self.evidence.is_line_proven


class Validator:
    def __init__(
        self,
        llm: LLMClient,
        sandbox: Sandbox,
        target: str | Path | None = None,
        max_attempts: int = 3,
    ) -> None:
        self.llm = llm
        self.sandbox = sandbox
        # The target directory is mounted read-only at MOUNT inside the sandbox so
        # the PoC can import the module under test. Without it the container has no
        # copy of the code, `import <target>` fails, and every exploit dies with
        # ModuleNotFoundError before it can prove anything.
        self.target = Path(target) if target is not None else None
        self.max_attempts = max_attempts

    def validate(self, finding: Finding, code: str) -> ValidationResult:
        poc = self._initial_poc(finding, code)
        clean_output = ""
        witness: WitnessResult | None = None

        for attempt in range(1, self.max_attempts + 1):
            harness = build_harness(
                poc_code=poc,
                target_file=finding.file,
                target_line=finding.line,
                mount=MOUNT,
                workdir="/tmp",
            )
            result = self.sandbox.run(self._as_command(harness), workdir=self.target)
            raw = result.stdout + result.stderr
            witness = parse_witness(result.stdout, finding.file, finding.line)
            clean_output = strip_witness(raw)

            if MARKER in result.stdout:
                evidence = (
                    Evidence.LINE_PROVEN
                    if witness.available and witness.line_executed
                    else Evidence.CLASS_ONLY
                )
                return ValidationResult(
                    finding=finding,
                    confirmed=True,
                    evidence=evidence,
                    poc_code=poc,
                    output=clean_output,
                    attempts=attempt,
                    witness=witness,
                )

            # No marker: self-correct from the failure if attempts remain.
            if attempt < self.max_attempts:
                poc = self._fix_poc(finding, code, poc, clean_output)

        # Every attempt failed. Before calling the claim unproven, check whether we
        # ever actually got to test it: if the target could not even be imported
        # because the sandbox lacks one of its dependencies, nothing was tested and
        # saying "unproven" would overstate the run.
        missing = missing_dependency(clean_output, self._module_name(finding.file))
        return ValidationResult(
            finding=finding,
            confirmed=False,
            evidence=Evidence.ENV_INCOMPLETE if missing else Evidence.UNPROVEN,
            poc_code=poc,
            output=clean_output,
            attempts=self.max_attempts,
            witness=witness,
            missing_module=missing or "",
        )

    # -- prompting --------------------------------------------------------

    def _module_name(self, file: str) -> str:
        stem = file.replace("\\", "/").split("/")[-1]
        return stem[:-3] if stem.endswith(".py") else stem

    def _initial_poc(self, finding: Finding, code: str) -> str:
        prompt = POC_PROMPT.format(
            vuln_class=finding.vuln_class,
            file=finding.file,
            line=finding.line,
            description=finding.description,
            code=code,
            module=self._module_name(finding.file),
            marker=MARKER,
        )
        return self._clean(self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT).text)

    def _fix_poc(self, finding: Finding, code: str, poc: str, output: str) -> str:
        prompt = FIX_PROMPT.format(
            marker=MARKER,
            poc=poc,
            output=output,
            vuln_class=finding.vuln_class,
            file=finding.file,
            line=finding.line,
        )
        return self._clean(self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT).text)

    def _clean(self, text: str) -> str:
        """Strip markdown code fences if the model added them despite instructions."""
        text = text.strip()
        fence = "`" * 3
        if text.startswith(fence):
            lines = text.splitlines()
            lines = lines[1:]
            if lines and lines[-1].strip().startswith(fence):
                lines = lines[:-1]
            text = "\n".join(lines)
        return text

    def _as_command(self, poc_code: str) -> str:
        """Turn PoC source into a shell command that runs it inside the container."""
        encoded = base64.b64encode(poc_code.encode("utf-8")).decode("ascii")
        return f"echo {encoded} | base64 -d | python3"
