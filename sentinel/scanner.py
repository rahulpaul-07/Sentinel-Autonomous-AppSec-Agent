"""
sentinel/scanner.py
-------------------
The Orchestrator: coordinates the whole pipeline and returns a structured
ScanReport.

Pipeline per candidate:
    hunt -> [reachability gate] -> validate (witness) -> grade evidence -> patch

Design choices worth defending:
  * scan() is PURE: it analyzes and returns data. It never prints, asks for input,
    or writes files -- so it's easy to test and reuse (CLI, HTML report, or CI can
    all call it). Human-in-the-loop and file-writing live in the CLI layer instead.
  * The reachability gate runs BEFORE any model call. It rejects candidates where
    static analysis finds positive evidence of no attacker path (or a safe-usage
    idiom), turning a class of hallucinated findings into a free, deterministic
    rejection -- each avoided validation is several model calls plus container runs.
    It fails open: anything it cannot analyze proceeds to validation.
  * We patch each FILE once, not each finding. Several findings often share a file,
    so we group confirmed findings by file and generate a single fix per file.
  * A budget (max_findings) caps how much work we do, so a huge repo can't run away
    with time and tokens.
  * A confidence gate (min_confidence) skips validating candidates the hunter itself
    barely believes. Skipped candidates are still recorded, never silently dropped.
  * "Confirmed" is graded, not binary. Only findings whose reported LINE was shown
    to execute are line-proven; class-only proofs are reported as a weaker tier so
    the headline number never overstates what was demonstrated.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.tools import Tools
from sentinel.hunter import Hunter, Finding
from sentinel.sandbox import Sandbox
from sentinel.validator import Validator, ValidationResult
from sentinel.patcher import Patcher, Patch
from sentinel.evidence import Evidence
from sentinel import reachability
from sentinel.reachability import Reachability


@dataclass
class ScannedFinding:
    finding: Finding
    confirmed: bool                          # marker printed (either proof tier)
    evidence: Evidence = Evidence.UNPROVEN
    validation: ValidationResult | None = None   # None if skipped or gated out
    reachability: Reachability | None = None      # static pre-gate result

    @property
    def line_proven(self) -> bool:
        return self.evidence.is_line_proven

    @property
    def gated_out(self) -> bool:
        return self.evidence is Evidence.UNREACHABLE

    def to_dict(self) -> dict:
        d = {
            "finding": self.finding.to_dict(),
            "confirmed": self.confirmed,
            "evidence": self.evidence.value,
            "evidence_label": self.evidence.label,
        }
        if self.reachability is not None:
            d["reachability"] = self.reachability.to_dict()
        if self.validation is not None:
            d["validation"] = {
                "attempts": self.validation.attempts,
                "poc_code": self.validation.poc_code,
                "output": self.validation.output,
            }
            if self.validation.witness is not None:
                d["validation"]["witness"] = self.validation.witness.to_dict()
        return d


@dataclass
class ScanReport:
    target: str
    scanned: list[ScannedFinding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    model: str = ""
    elapsed_seconds: float = 0.0

    # -- evidence-tier views ---------------------------------------------

    @property
    def line_proven(self) -> list[ScannedFinding]:
        """The headline set: findings whose reported line was shown to execute."""
        return [s for s in self.scanned if s.evidence is Evidence.LINE_PROVEN]

    @property
    def class_only(self) -> list[ScannedFinding]:
        """Exploit succeeded, but the reported line never ran -- a weaker claim."""
        return [s for s in self.scanned if s.evidence is Evidence.CLASS_ONLY]

    @property
    def confirmed(self) -> list[ScannedFinding]:
        """Either proof tier -- the permissive count a marker-only tool would report."""
        return [s for s in self.scanned if s.confirmed]

    @property
    def gated_out(self) -> list[ScannedFinding]:
        """Rejected by static analysis before any model call."""
        return [s for s in self.scanned if s.evidence is Evidence.UNREACHABLE]

    @property
    def rejected(self) -> list[ScannedFinding]:
        """Everything not confirmed by an exploit: unproven + gated out."""
        return [s for s in self.scanned if not s.confirmed]

    def severity_counts(self) -> dict[str, int]:
        """Severity breakdown over line-proven findings only."""
        counts: dict[str, int] = defaultdict(int)
        for s in self.line_proven:
            counts[s.finding.severity.lower() or "unknown"] += 1
        return dict(counts)

    def evidence_counts(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for s in self.scanned:
            counts[s.evidence.value] += 1
        return dict(counts)

    def summary(self) -> str:
        return (
            f"Target: {self.target}\n"
            f"  Candidate findings:   {len(self.scanned)}\n"
            f"  Gated out (no path):  {len(self.gated_out)}\n"
            f"  Line-proven:          {len(self.line_proven)}\n"
            f"  Class-only:           {len(self.class_only)}\n"
            f"  Files with fixes:     {len(self.patches)}"
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "model": self.model,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "counts": {
                "candidates": len(self.scanned),
                "line_proven": len(self.line_proven),
                "class_only": len(self.class_only),
                "confirmed": len(self.confirmed),
                "gated_out": len(self.gated_out),
                "rejected": len(self.rejected),
                "patched_files": len(self.patches),
                "by_severity": self.severity_counts(),
                "by_evidence": self.evidence_counts(),
            },
            "scanned": [s.to_dict() for s in self.scanned],
            "patches": [
                {
                    "file": p.finding.file,
                    "vuln_class": p.finding.vuln_class,
                    "diff": p.diff,
                }
                for p in self.patches
            ],
        }


class Scanner:
    def __init__(
        self,
        llm: LLMClient,
        target: str,
        max_findings: int = 20,
        min_confidence: float = 0.0,
        use_reachability_gate: bool = True,
    ) -> None:
        self.llm = llm
        self.target = target
        self.max_findings = max_findings
        self.min_confidence = min_confidence
        self.use_reachability_gate = use_reachability_gate
        self.tools = Tools(target)
        self.hunter = Hunter(llm, self.tools)
        self.validator = Validator(llm, Sandbox())
        self.patcher = Patcher(llm)

    def scan(self, validate: bool = True, patch: bool = True) -> ScanReport:
        started = time.perf_counter()
        report = ScanReport(target=self.target, model=self.llm.model)

        findings = self.hunter.hunt()[: self.max_findings]

        for finding in findings:
            # Confidence gate: don't spend validation on noise the hunter dismissed.
            if validate and finding.confidence < self.min_confidence:
                report.scanned.append(
                    ScannedFinding(finding=finding, confirmed=False)
                )
                continue

            if not validate:
                report.scanned.append(
                    ScannedFinding(finding=finding, confirmed=False)
                )
                continue

            numbered = self.tools.read_file(finding.file)

            # Static reachability gate -- before any model call.
            reach = None
            if self.use_reachability_gate:
                reach = self._gate(finding)
                if reach is not None and reach.blocks:
                    report.scanned.append(
                        ScannedFinding(
                            finding=finding,
                            confirmed=False,
                            evidence=Evidence.UNREACHABLE,
                            reachability=reach,
                        )
                    )
                    continue

            result = self.validator.validate(finding, numbered)
            report.scanned.append(
                ScannedFinding(
                    finding=finding,
                    confirmed=result.confirmed,
                    evidence=result.evidence,
                    validation=result,
                    reachability=reach,
                )
            )

        if patch:
            report.patches = self._patch_confirmed(report)

        report.elapsed_seconds = time.perf_counter() - started
        return report

    def _gate(self, finding: Finding) -> Reachability | None:
        """Run the static reachability gate on a finding. Returns None on error."""
        try:
            raw = (Path(self.target) / finding.file).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return None
        return reachability.analyze(raw, finding.vuln_class, finding.line)

    def _patch_confirmed(self, report: ScanReport) -> list[Patch]:
        """Patch files that have a line-proven finding.

        Class-only findings are deliberately NOT patched: if we could not show the
        reported line even runs, we should not rewrite it.
        """
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for s in report.line_proven:
            by_file[s.finding.file].append(s.finding)

        patches: list[Patch] = []
        for file, findings in by_file.items():
            raw = (Path(self.target) / file).read_text(encoding="utf-8", errors="replace")
            patches.append(self.patcher.propose(findings[0], raw))
        return patches
