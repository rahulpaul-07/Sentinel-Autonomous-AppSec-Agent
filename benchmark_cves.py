"""
benchmark_cves.py
-----------------
Run Sentinel against the real-world CVE benchmark.

    sentinel-cve                                  # every case, one run
    sentinel-cve --runs 5 --json cve-results.json # five runs, full record saved
    sentinel-cve --only CVE-2024-12345            # one case

Each case is scanned twice per run: at the vulnerable commit and at the fixed
commit. The rules that turn scans into numbers live in sentinel/cve_benchmark.py
and are described in benchmarks/cves/README.md. They are fixed before any run.

This needs Docker and network: repositories are fetched, and each target's
declared dependencies are installed into its sandbox image at build time.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel.cve_benchmark import ManifestError, load_manifest, run_benchmark

DEFAULT_MANIFEST = "benchmarks/cves/manifest.json"
DEFAULT_CACHE = ".cve-cache"


def _pct(value) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _range(spread: dict, key: str) -> str:
    r = spread.get(key)
    if not r:
        return "n/a"
    lo, hi = _pct(r["min"]), _pct(r["max"])
    return lo if lo == hi else f"{lo}-{hi}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark Sentinel on real-world CVEs.")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--cache", default=DEFAULT_CACHE, help="Where repositories are checked out.")
    ap.add_argument("--only", metavar="ID", action="append", help="Run only these case ids.")
    ap.add_argument("--json", metavar="PATH", dest="json_path",
                    help="Write the full record (every case, every run) to PATH.")
    args = ap.parse_args()

    manifest = Path(args.manifest)
    try:
        cases = load_manifest(manifest)
    except ManifestError as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.only:
        cases = [c for c in cases if c.id in set(args.only)]
    if not cases:
        print("No cases to run. Add entries to the manifest first; see "
              "benchmarks/cves/README.md.", file=sys.stderr)
        return 2

    from sentinel.llm import LLMClient
    from sentinel.sandbox import Sandbox, SandboxUnavailable
    try:
        Sandbox.preflight()
    except SandboxUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    from sentinel.llm import QuotaExhausted
    try:
        record = run_benchmark(cases, LLMClient(), args.runs, args.cache,
                               manifest_bytes=manifest.read_bytes())
    except QuotaExhausted as exc:
        print(f"Stopped: {exc.summary()}. Nothing was recorded; re-run once the "
              "limit clears.", file=sys.stderr)
        return 4

    print(f"{'case':<22}{'run':>4}  {'vulnerable':<15}{'fixed: line-proven':<20}note")
    for r in record["results"]:
        note = r["error"] or (f"{len(r['unlabelled_line_proven'])} other line-proven, review"
                              if r["unlabelled_line_proven"] else "")
        fixed = ", ".join(r["fixed_line_proven"]) or "-"
        print(f"{r['case_id']:<22}{r['run']:>4}  {r['outcome']:<15}{fixed:<20}{note}")

    first = record["per_run"][0]
    s = record["spread"]
    print(f"\nCases scored: {first['cases_scored']}   errored: {first['cases_errored']}"
          f"   runs: {record['runs']}   model: {record['model']}")
    print(f"Line-proven recall:                 {_range(s, 'line_proven_recall')}")
    print(f"Line-proven recall, testable only:  {_range(s, 'line_proven_recall_of_testable')}")
    print(f"Permissive (marker-only) recall:    {_range(s, 'permissive_recall')}")
    print(f"Class-only share of confirmed:      {_range(s, 'class_only_share_of_confirmed')}")
    print("\nRanges are min-max across runs. Quote the range, not the best run.")
    if any(r["cases_errored"] for r in record["per_run"]):
        print("Some cases errored and are excluded above. A run with errors is not "
              "publishable until they are fixed or the cases are removed with a reason.")
    if record["sentinel"].get("dirty"):
        print("Warning: the working tree has uncommitted changes, so this run cannot be "
              "tied to a commit.")

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"\nFull record written to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
