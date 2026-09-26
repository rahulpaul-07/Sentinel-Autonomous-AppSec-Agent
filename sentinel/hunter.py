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
import math
from dataclasses import asdict, dataclass

from sentinel.llm import LLMClient
from sentinel.prompting import UNTRUSTED_NOTICE, fence
from sentinel.tools import Tools

# Model output is untrusted too: it reaches the terminal, JSON, SARIF and an HTML
# page. Every field is reduced to a known shape before anything downstream sees it.
SEVERITIES = ("critical", "high", "medium", "low")
_MAX_CLASS_CHARS = 80
_MAX_DESCRIPTION_CHARS = 500


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
    "You respond with JSON only - no prose, no markdown. " + UNTRUSTED_NOTICE
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
{source_block}

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
    return _parse_json_object(raw)[0]


REPLY_CAP = 4000   # chars of an unreadable reply kept as evidence


def _parse_json_object(raw: str) -> tuple[dict | None, str]:
    """Like `_extract_json_object`, but also say why nothing came out."""
    start = raw.find("{")
    if start == -1:
        return None, "no JSON object in reply"

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
                    return json.loads(candidate), ""
                except json.JSONDecodeError as exc:
                    return None, f"invalid JSON: {exc}"
    return None, "unbalanced braces: no complete JSON object"


def _read_findings(raw: str) -> tuple[list | None, str]:
    """The reply's findings list, or None and the reason there isn't one.

    Only an explicit `"findings": []` means the model looked and found nothing.
    """
    data, error = _parse_json_object(raw)
    if data is None:
        return None, error
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None, "JSON object has no 'findings' list"
    return items, ""


class Hunter:
    def __init__(self, llm: LLMClient, tools: Tools) -> None:
        self.llm = llm
        self.tools = tools
        # An empty result has to be explainable. These record the two ways a reply
        # can yield nothing other than "the model found nothing": a reply with no
        # usable findings list, and individual entries too malformed to keep.
        self.unreadable_files: list[str] = []
        self.unreadable_details: dict[str, dict] = {}
        # Files whose first reply was malformed and whose second one was used.
        self.retried_files: list[str] = []
        self.dropped_entries = 0
        # The same claim reported twice would be validated twice.
        self.duplicate_entries = 0

    def hunt(self) -> list[Finding]:
        """Analyze every file in the target and return all candidate findings."""
        self.unreadable_files = []
        self.unreadable_details = {}
        self.retried_files = []
        self.dropped_entries = 0
        self.duplicate_entries = 0
        all_findings: list[Finding] = []
        for rel_path in self.tools.list_files():
            source = self.tools.read_file(rel_path)
            all_findings.extend(self._hunt_file(rel_path, source))
        return all_findings

    def _hunt_file(self, path: str, source: str) -> list[Finding]:
        prompt = USER_PROMPT.format(path=path, source_block=fence(path, source))
        response = self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT)
        items, error = _read_findings(response.text)
        attempts = 1

        if items is None:
            # Malformed replies are random: the same prompt that produced `}]]}` once
            # parsed in 12 of 13 attempts. Asking again is model-agnostic and never
            # guesses at what a broken reply meant, which repairing it would.
            response = self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT)
            items, error = _read_findings(response.text)
            attempts = 2
            if items is not None:
                self.retried_files.append(path)

        if items is None:
            self.unreadable_files.append(path)
            # The whole reply, not a head excerpt: parse failures are usually at
            # the end. These replies are short; the cap only guards against a
            # runaway one.
            self.unreadable_details[path] = {
                "reply_chars": len(response.text),
                "finish_reason": getattr(response, "finish_reason", ""),
                "parse_error": error,
                "attempts": attempts,
                "reply": response.text[:REPLY_CAP],
            }
            return []
        return self._findings(items, path, line_count=source.count("\n") + 1)

    def _findings(self, items: list, path: str, line_count: int | None = None) -> list[Finding]:
        """Turn parsed finding entries into Finding objects, counting any dropped.

        An entry is dropped when it cannot name a real location: no class, or a
        line that is not in the file. Other fields are normalised rather than
        trusted: severity to a fixed vocabulary, confidence into [0, 1], free text
        to a bounded length.
        """
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for item in items:
            try:
                finding = _normalise(item, path, line_count)
            except (KeyError, ValueError, TypeError, AttributeError):
                # Skip a malformed entry rather than crashing the whole run, but
                # count it so the loss is visible.
                self.dropped_entries += 1
                continue
            key = (finding.file, finding.line, finding.vuln_class.lower())
            if key in seen:
                self.duplicate_entries += 1
                continue
            seen.add(key)
            findings.append(finding)
        return findings


def _normalise(item: dict, path: str, line_count: int | None) -> Finding:
    vuln_class = " ".join(str(item["vuln_class"]).split())[:_MAX_CLASS_CHARS]
    if not vuln_class:
        raise ValueError("empty vuln_class")
    line = item["line"]
    if isinstance(line, bool) or not isinstance(line, (int, float, str)):
        raise TypeError("line is not a number")
    line = int(line)
    if line < 1 or (line_count is not None and line > line_count):
        raise ValueError(f"line {line} is not in the file")
    severity = str(item.get("severity", "")).strip().lower()
    if severity not in SEVERITIES:
        severity = "unknown"
    try:
        confidence = float(item.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    if math.isnan(confidence):
        confidence = 0.0
    confidence = min(max(confidence, 0.0), 1.0)
    description = " ".join(str(item.get("description", "")).split())
    return Finding(
        vuln_class=vuln_class,
        file=path,
        line=line,
        severity=severity,
        description=description[:_MAX_DESCRIPTION_CHARS],
        confidence=confidence,
    )
