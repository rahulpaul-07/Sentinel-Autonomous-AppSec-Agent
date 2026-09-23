"""
scan.py
-------
Sentinel's command-line entry point: scan a target, show what was proven, write an
HTML/JSON report, and apply fixes ONLY with your approval (human-in-the-loop -- no
file changes without your OK).

Examples:
  python scan.py targets/vulnerable_app
  python scan.py targets/vulnerable_app --report report.html --open
  python scan.py targets/vulnerable_app --json results.json --no-patch
  python scan.py targets/vulnerable_app --no-validate      # hunter only, unproven
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.sandbox import Sandbox, SandboxUnavailable
from sentinel.scanner import Scanner


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Find, prove, and fix security vulnerabilities in source code.",
    )
    p.add_argument("target", nargs="?", default="targets/vulnerable_app",
                   help="Path to the directory to scan.")
    p.add_argument("--report", metavar="PATH",
                   help="Write a self-contained HTML report to PATH.")
    p.add_argument("--json", metavar="PATH", dest="json_path",
                   help="Write machine-readable JSON results to PATH.")
    p.add_argument("--open", action="store_true",
                   help="Open the HTML report in a browser when done.")
    p.add_argument("--no-validate", action="store_true",
                   help="Skip the sandbox validation step (findings stay UNPROVEN).")
    p.add_argument("--no-patch", action="store_true",
                   help="Do not generate or offer secure-fix diffs.")
    p.add_argument("--no-gate", action="store_true",
                   help="disable the static reachability gate (validate every candidate)")
    p.add_argument("--show-class-only", action="store_true",
                   help="also list findings whose exploit never reached the reported line")
    p.add_argument("--min-confidence", type=float, default=0.0, metavar="F",
                   help="Skip validating candidates below this hunter confidence (0-1).")
    p.add_argument("--yes", action="store_true",
                   help="Auto-apply every proposed fix without prompting (use with care).")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    target = args.target
    validate = not args.no_validate
    patch = not args.no_patch

    if not Path(target).is_dir():
        print(f"error: target not found or not a directory: {target}", file=sys.stderr)
        return 2

    # Fail fast and clearly if validation is on but Docker isn't usable -- otherwise
    # every finding would be silently rejected for the wrong reason.
    if validate:
        try:
            Sandbox.preflight()
        except SandboxUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            print("       (or pass --no-validate to run the hunter without proof)",
                  file=sys.stderr)
            return 3

    print(f"Scanning {target} ...\n")
    scanner = Scanner(
        LLMClient(),
        target,
        min_confidence=args.min_confidence,
        use_reachability_gate=not args.no_gate,
    )
    report = scanner.scan(validate=validate, patch=patch)

    print(report.summary())
    print()
    for s in report.line_proven:
        f = s.finding
        print(f"  [LINE PROVEN] {f.vuln_class}  {f.file}:{f.line}  (severity: {f.severity})")
    if validate and not report.line_proven:
        print("  No finding was proven exploitable at its reported line.")

    if report.class_only:
        print(
            f"\n  {len(report.class_only)} candidate(s) had a working exploit that never "
            "reached the reported line."
        )
        print("  These prove the vulnerability class, not this code. Not counted, not patched.")
        if args.show_class_only:
            for s in report.class_only:
                f = s.finding
                print(f"    [CLASS ONLY] {f.vuln_class}  {f.file}:{f.line}")

    if report.not_testable:
        mods = sorted({
            s.validation.missing_module
            for s in report.not_testable
            if s.validation and s.validation.missing_module
        })
        print(
            f"\n  {len(report.not_testable)} candidate(s) could not be tested: the sandbox "
            f"image lacks {', '.join(mods) if mods else 'a dependency'} that the target imports."
        )
        print("  These are not failed exploits -- nothing was proven or disproven.")

    if report.gated_out:
        print(
            f"\n  {len(report.gated_out)} candidate(s) rejected by static analysis "
            "before any model call."
        )
    print()

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        print(f"JSON results written to {args.json_path}")

    if args.report:
        from sentinel.report import write_html
        out = write_html(report, args.report)
        print(f"HTML report written to {out}")
        if args.open:
            webbrowser.open(Path(out).as_uri())

    if patch and report.patches:
        for patch_ in report.patches:
            print("=" * 64)
            print(f"Proposed fix for: {patch_.finding.file}")
            print("=" * 64)
            print(patch_.diff)
            if args.yes:
                answer = "y"
            else:
                answer = input(
                    f"Apply this fix to {patch_.finding.file}? [y/N] "
                ).strip().lower()
            if answer == "y":
                (Path(target) / patch_.finding.file).write_text(
                    patch_.fixed_code, encoding="utf-8"
                )
                print(f"  Applied - {patch_.finding.file} updated.\n")
            else:
                print("  Skipped - no changes made.\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
