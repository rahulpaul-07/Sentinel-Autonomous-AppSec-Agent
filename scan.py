"""
scan.py
-------
Sentinel's command-line entry point: scan a target, show what was proven, write
HTML/JSON/SARIF reports, and apply fixes ONLY with your approval (human-in-the-loop
-- no file changes without your OK).

Examples:
  sentinel targets/vulnerable_app
  sentinel targets/vulnerable_app --report report.html --open
  sentinel targets/vulnerable_app --json results.json --no-patch
  sentinel src/ --sarif sentinel.sarif --fail-on high      # in CI
  sentinel targets/vulnerable_app --no-validate            # hunter only, unproven

Exit codes:
  0  scan completed (and nothing met --fail-on)
  1  a line-proven finding met the --fail-on threshold
  2  bad arguments or configuration
  3  Docker is not usable
  4  the model provider's usage limit stopped the scan
  5  the model provider refused the request (bad key, unknown model, outage)
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from sentinel.llm import LLMClient, ModelError, QuotaExhausted
from sentinel.patcher import write_fixed
from sentinel.sandbox import Sandbox, SandboxUnavailable
from sentinel.scanner import Scanner

EXIT_FINDINGS, EXIT_USAGE, EXIT_NO_DOCKER, EXIT_QUOTA, EXIT_MODEL = 1, 2, 3, 4, 5

# Severity ranks for --fail-on. A proven finding whose severity the model did not
# state counts as critical: a gate should fail closed on what it cannot rank.
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 4}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Find, prove, and fix security vulnerabilities in source code.",
    )
    p.add_argument("target", nargs="?", default="targets/vulnerable_app",
                   help="Path to the directory to scan.")
    out = p.add_argument_group("output")
    out.add_argument("--report", metavar="PATH",
                     help="Write a self-contained HTML report to PATH.")
    out.add_argument("--json", metavar="PATH", dest="json_path",
                     help="Write machine-readable JSON results to PATH.")
    out.add_argument("--sarif", metavar="PATH",
                     help="Write SARIF 2.1.0 (line-proven and class-only findings) "
                          "for GitHub code scanning.")
    out.add_argument("--open", action="store_true",
                     help="Open the HTML report in a browser when done (needs --report).")
    out.add_argument("--show-class-only", action="store_true",
                     help="Also list findings whose exploit never reached the reported line.")
    pipe = p.add_argument_group("pipeline")
    pipe.add_argument("--no-validate", action="store_true",
                      help="Skip the sandbox validation step (findings stay UNPROVEN).")
    pipe.add_argument("--no-patch", action="store_true",
                      help="Do not generate or offer secure-fix diffs.")
    pipe.add_argument("--no-verify-fix", action="store_true",
                      help="Do not replay the proving exploit against a proposed fix.")
    pipe.add_argument("--no-gate", action="store_true",
                      help="Disable the static reachability gate (validate every candidate).")
    pipe.add_argument("--min-confidence", type=float, default=0.0, metavar="F",
                      help="Skip validating candidates below this hunter confidence (0-1).")
    pipe.add_argument("--max-findings", type=int, default=20, metavar="N",
                      help="Grade at most N candidates, highest confidence first (default 20).")
    pipe.add_argument("--build-env", action="store_true",
                      help="Build a sandbox image with the target's declared dependencies "
                           "(runs pip install with network; use only on code you trust "
                           "enough to install).")
    gate = p.add_argument_group("automation")
    gate.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"],
                      default="none",
                      help="Exit 1 if a line-proven finding is at or above this severity.")
    gate.add_argument("--yes", action="store_true",
                      help="Apply fixes without prompting -- only fixes whose replayed "
                           "exploit no longer succeeds. Others are listed, never applied.")
    args = p.parse_args(argv)

    if not 0.0 <= args.min_confidence <= 1.0:
        p.error("--min-confidence must be between 0 and 1")
    if args.max_findings < 1:
        p.error("--max-findings must be at least 1")
    if args.open and not args.report:
        p.error("--open needs --report PATH")
    return args


def should_fail(report, threshold: str) -> list:
    """The line-proven findings at or above `threshold`."""
    if threshold == "none":
        return []
    floor = SEVERITY_RANK[threshold]
    return [s for s in report.line_proven
            if SEVERITY_RANK.get(s.finding.severity, SEVERITY_RANK["unknown"]) >= floor]


def _print_summary(report, validate: bool, show_class_only: bool) -> None:
    print(report.summary())
    print()
    for s in report.line_proven:
        f = s.finding
        print(f"  [LINE PROVEN] {f.vuln_class}  {f.file}:{f.line}  (severity: {f.severity})")
    if validate and not report.line_proven:
        print("  No finding was proven exploitable at its reported line.")

    if report.class_only:
        print(f"\n  {len(report.class_only)} candidate(s) had a working exploit that never "
              "reached the reported line.")
        print("  These prove the vulnerability class, not this code. Not counted, not patched.")
        if show_class_only:
            for s in report.class_only:
                print(f"    [CLASS ONLY] {s.finding.vuln_class}  {s.finding.file}:{s.finding.line}")

    if report.not_testable:
        mods = sorted({s.validation.missing_module for s in report.not_testable
                       if s.validation and s.validation.missing_module})
        print(f"\n  {len(report.not_testable)} candidate(s) could not be tested: the sandbox "
              f"image lacks {', '.join(mods) if mods else 'a dependency'} that the target imports.")
        print("  These are not failed exploits -- nothing was proven or disproven.")

    if report.gated_out:
        print(f"\n  {len(report.gated_out)} candidate(s) rejected by static analysis "
              "before any model call.")
    print()


def _write_outputs(report, args) -> None:
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON results written to {args.json_path}")
    if args.sarif:
        from sentinel.sarif import to_sarif
        Path(args.sarif).write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
        print(f"SARIF written to {args.sarif}")
    if args.report:
        from sentinel.report import write_html
        out = write_html(report, args.report)
        print(f"HTML report written to {out}")
        if args.open:
            webbrowser.open(Path(out).as_uri())


def _offer_patches(report, target: str, auto_yes: bool) -> None:
    for patch in report.patches:
        print("=" * 64)
        print(f"Proposed fix for: {patch.file}  "
              f"({', '.join(f'{f.vuln_class} line {f.line}' for f in patch.findings)})")
        print("=" * 64)
        if not patch.valid:
            print(f"  Not offered: {patch.problem}.\n")
            continue
        print(patch.diff)
        print(f"  Verification: {patch.verification}"
              + (f" -- {patch.verification_detail}" if patch.verification_detail else ""))
        if auto_yes:
            answer = "y" if patch.applicable else "n"
            if not patch.applicable:
                print("  --yes applies only verified fixes; review this one by hand.")
        else:
            answer = input(f"Apply this fix to {patch.file}? [y/N] ").strip().lower()
        if answer == "y":
            write_fixed(Path(target) / patch.file, patch.fixed_code)
            print(f"  Applied - {patch.file} updated.\n")
        else:
            print("  Skipped - no changes made.\n")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    target = args.target
    validate = not args.no_validate
    patch = not args.no_patch

    if not Path(target).is_dir():
        print(f"error: target not found or not a directory: {target}", file=sys.stderr)
        return EXIT_USAGE

    # Fail fast and clearly if validation is on but Docker isn't usable -- otherwise
    # every finding would be silently rejected for the wrong reason.
    if validate:
        try:
            Sandbox.preflight()
        except SandboxUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            print("       (or pass --no-validate to run the hunter without proof)",
                  file=sys.stderr)
            return EXIT_NO_DOCKER

    try:
        llm = LLMClient()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(f"Scanning {target} with {llm.model} ...\n")
    scanner = Scanner(
        llm,
        target,
        max_findings=args.max_findings,
        min_confidence=args.min_confidence,
        use_reachability_gate=not args.no_gate,
        build_env=args.build_env,
        verify_fixes=not args.no_verify_fix,
    )
    try:
        report = scanner.scan(validate=validate, patch=patch)
    except QuotaExhausted as exc:
        print(f"error: {exc.summary()}. No report was written.", file=sys.stderr)
        return EXIT_QUOTA
    except ModelError as exc:
        print(f"error: model call failed: {exc}. No report was written.", file=sys.stderr)
        return EXIT_MODEL

    _print_summary(report, validate, args.show_class_only)
    _write_outputs(report, args)
    if patch:
        _offer_patches(report, target, args.yes)

    failing = should_fail(report, args.fail_on)
    if failing:
        print(f"{len(failing)} line-proven finding(s) at or above '{args.fail_on}'.",
              file=sys.stderr)
        return EXIT_FINDINGS
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
