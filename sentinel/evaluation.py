"""
sentinel/evaluation.py
----------------------
The evaluation harness: measures how good Sentinel is against labeled ground truth.

The metric math itself lives in sentinel/metrics.py (pure, dependency-free). This
module is the part that actually runs a scan against a labeled target and turns the
confirmed findings into TP/FP/FN by matching them to the ground truth.

Matching a finding to a truth is deliberately fuzzy on the class name (models say
"Path Traversal" where the label says "Directory Traversal") but strict on location
(same file, within LINE_TOLERANCE lines), so a right-class/wrong-place guess doesn't
get counted as a hit.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.hunter import Finding
from sentinel.metrics import Metrics, TieredMetrics
from sentinel.scanner import Scanner

__all__ = ["Metrics", "TieredMetrics", "evaluate_target", "evaluate_target_tiered"]

LINE_TOLERANCE = 5

# Words that describe vulnerabilities in general rather than a class. Sharing one
# of these says nothing: "SQL Injection" and "Command Injection" share "injection".
_STOP_WORDS = {
    "the", "and", "for", "from", "into", "via", "with", "using", "of",
    "injection", "insecure", "unsafe", "untrusted", "improper", "arbitrary",
    "remote", "execution", "vulnerability", "data", "user", "input", "attacker",
    "controlled", "unsanitized", "possible", "potential",
}

# A class is identified by its family when its name mentions one. Two findings
# match only if they share a family, so qualifiers ("... via f-string") can never
# make two different classes look alike.
CLASS_FAMILIES = {
    "sql": {"sql", "sqli"},
    "command": {"command", "cmdi", "shell"},
    "code": {"code", "eval", "rce"},
    "path": {"path", "directory", "traversal", "lfi"},
    "deserialization": {"deserialization", "deserialisation", "pickle", "unpickling"},
    "secret": {"hardcoded", "secret", "secrets", "credential", "credentials", "password"},
    "xss": {"xss", "scripting"},
    "ssrf": {"ssrf", "serverside"},
    "xxe": {"xxe", "entity"},
    "template": {"ssti", "template"},
    "redirect": {"redirect"},
}


def _tokens(name: str) -> set[str]:
    # Hyphens are dropped rather than split on, so "hard-coded" is "hardcoded"
    # and "server-side" is "serverside".
    return set(re.findall(r"[a-z0-9]+", name.lower().replace("-", "")))


def _families(name: str) -> set[str]:
    tokens = _tokens(name)
    return {family for family, words in CLASS_FAMILIES.items() if tokens & words}


def _keywords(name: str) -> set[str]:
    return {w for w in _tokens(name) if len(w) > 2 and w not in _STOP_WORDS}


def _class_matches(a: str, b: str) -> bool:
    """Do two class names describe the same kind of vulnerability?

    Models phrase classes differently ("Path Traversal" vs "Directory Traversal"),
    so exact comparison is too strict. Families decide whenever both names mention
    one; shared distinctive keywords decide only when a name names no known family.
    """
    fa, fb = _families(a), _families(b)
    if fa and fb:
        return bool(fa & fb)
    return bool(_keywords(a) & _keywords(b))


def _matches(finding: Finding, truth: dict) -> bool:
    return (
        finding.file == truth["file"]
        and abs(finding.line - truth["line"]) <= LINE_TOLERANCE
        and _class_matches(finding.vuln_class, truth["vuln_class"])
    )


def _score(findings: list[Finding], truths: list[dict]) -> Metrics:
    """Match a set of findings against ground truth and count TP/FP/FN."""
    matched: set[int] = set()
    tp = 0
    for finding in findings:
        idx = next(
            (i for i, t in enumerate(truths) if i not in matched and _matches(finding, t)),
            None,
        )
        if idx is not None:
            tp += 1
            matched.add(idx)

    fp = len(findings) - tp
    fn = len(truths) - len(matched)
    return Metrics(tp=tp, fp=fp, fn=fn)


def evaluate_target_tiered(
    llm: LLMClient, target: str, build_env: bool = False
) -> TieredMetrics:
    """Score a target at both readings of "confirmed".

    The same scan is scored twice -- once counting every finding whose exploit
    printed the marker (what a marker-only tool reports), once counting only the
    findings whose reported line was observed to execute. The difference between
    the two is the measurable value of the execution witness.
    """
    truths = json.loads(
        (Path(target) / "ground_truth.json").read_text(encoding="utf-8")
    )["vulnerabilities"]

    scanner = Scanner(llm, target, build_env=build_env)
    report = scanner.scan(patch=False)

    tiers = Counter(s.evidence.value for s in report.scanned)
    return TieredMetrics(
        permissive=_score([s.finding for s in report.confirmed], truths),
        strict=_score([s.finding for s in report.line_proven], truths),
        tiers=dict(tiers),
        environment=report.environment.to_dict() if report.environment else None,
    )


def evaluate_target(llm: LLMClient, target: str, build_env: bool = False) -> Metrics:
    """Headline score: the strict reading (line-proven findings only)."""
    return evaluate_target_tiered(llm, target, build_env=build_env).strict
