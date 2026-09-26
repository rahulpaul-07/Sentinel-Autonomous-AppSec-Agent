"""
sentinel/sarif.py
-----------------
Export a ScanReport as SARIF 2.1.0, the format GitHub code scanning and most
security dashboards ingest.

What goes in, and at what level, follows the evidence ladder:

  LINE_PROVEN  -> level "error"    an exploit drove the reported line
  CLASS_ONLY   -> level "warning"  an exploit worked; this line was never shown to run

Nothing weaker is exported. An unproven candidate is a model's suspicion, and
putting suspicions into a code-scanning dashboard is how scanners earn the noise
reputation this project exists to avoid. The evidence tier, the witness and the
hunter's confidence travel in each result's property bag, so a consumer can
filter further.

Paths are written relative to the current directory when the target is inside
it -- GitHub resolves them against the repository root, which is where CI runs.
"""

from __future__ import annotations

import hashlib
import re
from importlib import metadata
from pathlib import Path

from sentinel.evidence import Evidence
from sentinel.scanner import ScanReport

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/rahulpaul-07/Sentinel-Autonomous-AppSec-Agent"

_LEVEL = {Evidence.LINE_PROVEN: "error", Evidence.CLASS_ONLY: "warning"}

# GitHub ranks alerts by `security-severity`, a CVSS-like score on the rule.
_SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0,
                      "unknown": 5.0}


def _version() -> str:
    try:
        return metadata.version("sentinel-appsec")
    except metadata.PackageNotFoundError:
        return "0.0.0"


def rule_id(vuln_class: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", vuln_class.lower()).strip("-") or "finding"
    return f"sentinel/{slug}"


def _uri(target: Path, file: str) -> str:
    path = (target / file).resolve()
    try:
        return path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return Path(file).as_posix()


def _fingerprint(target: Path, file: str, line: int, vuln_class: str) -> str:
    """Stable across unrelated edits: keyed on the line's text, not its number."""
    try:
        text = (target / file).read_text(encoding="utf-8", errors="replace").splitlines()
        content = text[line - 1].strip() if 0 < line <= len(text) else ""
    except OSError:
        content = ""
    raw = f"{file}\0{rule_id(vuln_class)}\0{content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def to_sarif(report: ScanReport) -> dict:
    target = Path(report.target)
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for s in report.scanned:
        level = _LEVEL.get(s.evidence)
        if level is None:
            continue
        f = s.finding
        rid = rule_id(f.vuln_class)
        severity = f.severity if f.severity in _SECURITY_SEVERITY else "unknown"
        rule = rules.setdefault(rid, {
            "id": rid,
            "name": f.vuln_class,
            "shortDescription": {"text": f.vuln_class},
            "helpUri": INFO_URI,
            "properties": {"tags": ["security"], "security-severity": "0.0"},
        })
        # A rule's severity is the worst any of its proven results reached.
        current = float(rule["properties"]["security-severity"])
        rule["properties"]["security-severity"] = str(
            max(current, _SECURITY_SEVERITY[severity]))

        witness = s.validation.witness.explain() if s.validation and s.validation.witness else ""
        message = f"{f.vuln_class}: {f.description}" if f.description else f.vuln_class
        if s.evidence is Evidence.CLASS_ONLY:
            message += " (Exploit succeeded, but this line was never shown to execute.)"
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(target, f.file)},
                    "region": {"startLine": f.line},
                },
            }],
            "partialFingerprints": {
                "sentinelFinding/v1": _fingerprint(target, f.file, f.line, f.vuln_class),
            },
            "properties": {
                "evidence": s.evidence.value,
                "severity": severity,
                "confidence": f.confidence,
                "witness": witness,
                "attempts": s.validation.attempts if s.validation else 0,
            },
        })

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sentinel",
                "informationUri": INFO_URI,
                "semanticVersion": _version(),
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {
                "model": report.model,
                "candidates": len(report.scanned),
                "evidence": report.evidence_counts(),
            },
        }],
    }
