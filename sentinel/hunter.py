"""
sentinel/hunter.py
------------------
The Hunter agent: the "brain" that uses the tool layer (its hands) and the model
layer (its reasoning) to find candidate vulnerabilities in a codebase.

For each file in the target it:
  1. reads the source (with line numbers) via Tools,
  2. asks the LLM to analyze it and return structured findings as JSON,
  3. parses that JSON into typed Finding objects.

Everything the Hunter reports is a CLAIM. The Validator is what turns a claim into
proof (or discards it). The Hunter's job is recall -- surface every plausible bug --
and leave precision to the stage that can actually execute an exploit.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from sentinel.llm import LLMClient
from sentinel.tools import Tools


@dataclass
class Finding:
    """One vulnerability the Hunter believes it found."""
    vuln_class: str
    file: str
    line: int
    severity: str
    description: str
    confidence: float

    def to_dict(self) -> dict:
        return asdict(self)


SYSTEM_PROMPT = (
    "You are a meticulous application security analyst. You find real, exploitable "
    "vulnerabilities in source code, and you never invent issues that aren't there. "
    "You respond with JSON only - no prose, no markdown."
)

# {path} and {source} are filled in per file before sending to the model.
USER_PROMPT = """Analyze this Python file for security vulnerabilities.

Look especially for: SQL injection, command injection, hardcoded secrets,
path traversal, SSRF, and insecure deserialization.

For each vulnerability, report:
  - vuln_class: a short name, e.g. "SQL Injection"
  - line: the exact line number where it occurs
  - severity: one of "low", "medium", "high", "critical"
  - description: one sentence tracing the untrusted data from source to sink
  - confidence: a number from 0.0 to 1.0

File: {path}
--- BEGIN CODE ---
{source}
--- END CODE ---

Respond with ONLY this JSON shape and nothing else:
{{"findings": [{{"vuln_class": "", "line": 0, "severity": "", "description": "", "confidence": 0.0}}]}}
If you find nothing, respond with {{"findings": []}}.
"""


def _extract_json_object(raw: str) -> dict | None:
    """Pull the first complete JSON object out of a model reply, robustly.

    Why not just `re.search(r"\\{.*\\}", raw, DOTALL)`? That greedy match runs from
    the first '{' to the LAST '}' in the whole string. If the model emits a fenced
    block, or any prose containing braces, or two objects, the captured span is
    malformed and json.loads throws -- and the whole file's findings are silently
    dropped.

    Instead we scan for the first '{' and walk forward tracking brace depth (while
    respecting string literals and escapes) until the matching '}' closes it. That
    yields exactly one balanced object, which is what the model was asked for.
    """
    start = raw.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = raw[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    return None
    return None


class Hunter:
    def __init__(self, llm: LLMClient, tools: Tools) -> None:
        self.llm = llm
        self.tools = tools

    def hunt(self) -> list[Finding]:
        """Analyze every file in the target and return all candidate findings."""
        all_findings: list[Finding] = []
        for rel_path in self.tools.list_files():
            source = self.tools.read_file(rel_path)
            all_findings.extend(self._hunt_file(rel_path, source))
        return all_findings

    def _hunt_file(self, path: str, source: str) -> list[Finding]:
        prompt = USER_PROMPT.format(path=path, source=source)
        response = self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT)
        return self._parse(response.text, path)

    def _parse(self, raw: str, path: str) -> list[Finding]:
        """Turn the model's JSON reply into Finding objects, tolerantly."""
        data = _extract_json_object(raw)
        if data is None:
            return []

        findings: list[Finding] = []
        for item in data.get("findings", []):
            try:
                findings.append(
                    Finding(
                        vuln_class=str(item["vuln_class"]),
                        file=path,
                        line=int(item["line"]),
                        severity=str(item.get("severity", "unknown")),
                        description=str(item.get("description", "")),
                        confidence=float(item.get("confidence", 0.0)),
                    )
                )
            except (KeyError, ValueError, TypeError):
                # Skip a malformed entry rather than crashing the whole run.
                continue
        return findings
