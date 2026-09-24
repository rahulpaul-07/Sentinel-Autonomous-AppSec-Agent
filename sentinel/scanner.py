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
from sentinel.environment import Environment, prepare_environment
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
            if self.validation.missing_module:
                d["validation"]["missing_module"] = self.validation.missing_module
        return d


def describe_unreadable(detail: dict | None) -> str:
    """One phrase saying what an unreadable hunter reply looked like."""
    if not detail:
        return "no detail recorded"
    body = ("empty reply" if detail.get("reply_chars") == 0
            else f"{detail.get('reply_chars')} chars")
    if detail.get("parse_error"):
        body += f": {detail['parse_error']}"
    if detail.get("finish_reason"):
        body += f", finish_reason={detail['finish_reason']}"
    if detail.get("attempts"):
        body += f", {detail['attempts']} attempts"
    return body


@dataclass
class ScanReport:
    target: str
    scanned: list[ScannedFinding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    model: str = ""
    elapsed_seconds: float = 0.0
    # The image the exploits ran in. Recorded on every report so a result can be
    # reproduced, and so a reader can tell a dependency gap from a failed exploit.
    environment: Environment | None = None
    # Files whose hunter reply could not be read, and findings dropped as malformed.
    # Without these, an unreadable reply looks exactly like "nothing found".
    hunter_unreadable: list[str] = field(default_factory=list)
    hunter_unreadable_details: dict = field(default_factory=dict)
    hunter_retried: list[str] = field(default_factory=list)
    hunter_dropped: int = 0

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
    def not_testable(self) -> list[ScannedFinding]:
        """Claims we never got to test, because the sandbox lacked a dependency."""
        return [s for s in self.scanned if s.evidence is Evidence.ENV_INCOMPLETE]

    @property
    def gated_out(self) -> list[ScannedFinding]:
        """Rejected by static analysis before any model call."""
        return [s for s in self.scanned if s.evidence is Evidence.UNREACHABLE]

    @property
    def rejected(self) -> list[ScannedFinding]:
        """Everything not confirmed by an exploit, including the untestable ones."""
        return [s for s in self.scanned if not s.confirmed]

    @property
    def not_demonstrated(self) -> list[ScannedFinding]:
        """Claims we actually tested and could not demonstrate.

        Deliberately narrower than `rejected`: a claim the sandbox could not test at
        all is reported under its own tier, so counting it here would inflate the
        number of exploits that genuinely failed.
        """
        return [
            s for s in self.scanned
            if not s.confirmed and s.evidence is not Evidence.ENV_INCOMPLETE
        ]

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
        env = ""
        if self.environment is not None:
            env = f"  Sandbox image:        {self.environment.image} ({self.environment.status})\n"
            if self.environment.status == "build_failed":
                env += ("  WARNING: dependency image failed to build; exploits ran in the "
                        "bare image, so missing imports grade as not testable.\n")
        if self.hunter_unreadable:
            described = ", ".join(
                f"{f} ({describe_unreadable(self.hunter_unreadable_details.get(f))})"
                for f in self.hunter_unreadable
            )
            env += (f"  WARNING: hunter reply unreadable for {described}. Those files "
                    "were not analysed; no findings there does not mean none exist.\n")
        if self.hunter_dropped:
            env += f"  WARNING: {self.hunter_dropped} malformed finding(s) dropped.\n"
        return (
            f"Target: {self.target}\n"
            + env
            + f"  Candidate findings:   {len(self.scanned)}\n"
            f"  Gated out (no path):  {len(self.gated_out)}\n"
            f"  Line-proven:          {len(self.line_proven)}\n"
            f"  Class-only:           {len(self.class_only)}\n"
            f"  Not testable:         {len(self.not_testable)}\n"
            f"  Files with fixes:     {len(self.patches)}"
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "model": self.model,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "environment": self.environment.to_dict() if self.environment else None,
            "hunter": {"unreadable_files": self.hunter_unreadable,
                       "details": self.hunter_unreadable_details,
                       "retried_files": self.hunter_retried,
                       "dropped_entries": self.hunter_dropped},
            "counts": {
                "candidates": len(self.scanned),
                "line_proven": len(self.line_proven),
                "class_only": len(self.class_only),
                "confirmed": len(self.confirmed),
                "gated_out": len(self.gated_out),
            "not_testable": len(self.not_testable),
                "rejected": len(self.rejected),
            "not_demonstrated": len(self.not_demonstrated),
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
        build_env: bool = False,
        image: str | None = None,
        env_root: str | None = None,
    ) -> None:
        self.llm = llm
        self.target = target
        self.max_findings = max_findings
        self.min_confidence = min_confidence
        self.use_reachability_gate = use_reachability_gate
        # Opt-in: building runs `pip install` for the target's dependencies with
        # network. See sentinel/environment.py for why that is a trust decision.
        self.build_env = build_env
        # Where declared dependencies live. Usually the target itself, but a scan
        # scoped to part of a repository still needs the repository's own
        # requirements.txt or pyproject.toml.
        self.env_root = env_root if env_root is not None else target
        self.tools = Tools(target)
        self.hunter = Hunter(llm, self.tools)
        sandbox = Sandbox(image=image) if image else Sandbox()
        self.validator = Validator(llm, sandbox, target=target)
        self.patcher = Patcher(llm)

    def scan(self, validate: bool = True, patch: bool = True) -> ScanReport:
        started = time.perf_counter()
        report = ScanReport(target=self.target, model=self.llm.model)

        if validate:
            if self.build_env:
                report.environment = prepare_environment(
                    self.env_root, base=self.validator.sandbox.image
                )
                self.validator.sandbox.image = report.environment.image
            else:
                report.environment = Environment(image=self.validator.sandbox.image)

        findings = self.hunter.hunt()[: self.max_findings]
        report.hunter_unreadable = list(self.hunter.unreadable_files)
        report.hunter_unreadable_details = dict(self.hunter.unreadable_details)
        report.hunter_retried = list(self.hunter.retried_files)
        report.hunter_dropped = self.hunter.dropped_entries

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
