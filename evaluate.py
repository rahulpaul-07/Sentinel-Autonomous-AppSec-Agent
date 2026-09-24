"""
evaluate.py
-----------
Run Sentinel against every labeled target and report accuracy metrics.

    python evaluate.py                 # one run
    python evaluate.py --runs 5        # five runs, report mean +/- spread
    python evaluate.py --json m.json   # also dump raw per-run metrics

Why repeated runs? Hosted models are not bit-reproducible even at temperature 0, so
a single run is one noisy sample. Quoting one figure from one run overstates
certainty. With --runs N we report the mean and the min-max spread across runs,
which is the honest way to characterise a stochastic pipeline on a small benchmark.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from dataclasses import dataclass

from sentinel.llm import LLMClient
from sentinel.metrics import Metrics
from sentinel.evaluation import evaluate_target_tiered
from sentinel.provenance import stamp
from sentinel.sandbox import Sandbox, SandboxUnavailable

TARGETS = [
    "targets/vulnerable_app",
    "targets/safe_app",
    "targets/traversal_app",
    "targets/deserialize_app",
]

# Order the tiers print in, strongest evidence first.
TIER_ORDER = ["line_proven", "class_only", "unproven", "env_incomplete", "unreachable"]
TIER_LABELS = {"line_proven": "line-proven", "class_only": "class-only",
               "unproven": "unproven", "env_incomplete": "not testable",
               "unreachable": "gated out"}


@dataclass
class RunResult:
    strict: Metrics
    permissive: Metrics
    tiers: dict            # summed over targets
    targets: list          # per target: name, tiers, environment
    warnings: list


def _one_run(llm: LLMClient, build_env: bool) -> RunResult:
    strict, permissive = Metrics(), Metrics()
    tiers: Counter = Counter()
    per_target, warnings = [], []
    for target in TARGETS:
        m = evaluate_target_tiered(llm, target, build_env=build_env)
        strict, permissive = strict + m.strict, permissive + m.permissive
        tiers.update(m.tiers)
        env = m.environment or {}
        hunter = m.hunter or {}
        per_target.append({"target": target, "tiers": m.tiers, "environment": env,
                           "hunter": hunter})
        if hunter.get("unreadable_files"):
            warnings.append(f"{target}: hunter reply unreadable for "
                            f"{', '.join(hunter['unreadable_files'])}; not analysed")
        if hunter.get("dropped_entries"):
            warnings.append(f"{target}: {hunter['dropped_entries']} malformed finding(s) dropped")
        if env.get("status") == "build_failed":
            warnings.append(f"{target}: dependency image failed to build; exploits ran bare")
        if m.tiers.get("env_incomplete"):
            warnings.append(f"{target}: {m.tiers['env_incomplete']} finding(s) not testable")
    return RunResult(strict, permissive, dict(tiers), per_target, warnings)


def _pct(value) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _num(value) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _tier_line(tiers: dict, hunter: dict | None = None) -> str:
    parts = [f"{TIER_LABELS[t]} {tiers[t]}" for t in TIER_ORDER if tiers.get(t)]
    if parts:
        return ", ".join(parts)
    # Only claim "none reported" when every reply was read.
    if hunter and hunter.get("unreadable_files"):
        return "no candidates (hunter reply unreadable)"
    return "no candidates (model reported none)"


def _fmt_spread(values: list, pct: bool = True) -> str:
    """Mean and min-max over the runs where the ratio is defined. Says when it wasn't."""
    fmt = _pct if pct else _num
    defined = [v for v in values if v is not None]
    if not defined:
        return "n/a (undefined in every run: nothing to divide by)"
    lo, hi, mean = min(defined), max(defined), statistics.mean(defined)
    text = fmt(mean) if lo == hi else f"{fmt(mean)}  (range {fmt(lo)}-{fmt(hi)})"
    missing = len(values) - len(defined)
    if missing:
        text += f"  [undefined in {missing} of {len(values)} runs]"
    return text


def _score_line(m: Metrics) -> str:
    return (f"TP={m.tp} FP={m.fp} FN={m.fn}  "
            f"P={_pct(m.precision)} R={_pct(m.recall)} F1={_num(m.f1)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate Sentinel against labeled targets.")
    ap.add_argument("--runs", type=int, default=1, help="How many full passes to average.")
    ap.add_argument("--json", metavar="PATH", dest="json_path",
                    help="Write raw per-run metrics to PATH.")
    ap.add_argument("--no-build-env", action="store_true",
                    help="Run exploits in the bare image instead of building each "
                         "target's declared dependencies. Every benchmark target imports "
                         "Flask, so this grades them all not testable.")
    args = ap.parse_args()

    # Without Docker every exploit fails to start and is graded UNPROVEN, which
    # scores exactly like a model that found nothing. Refuse rather than print that.
    try:
        Sandbox.preflight()
    except SandboxUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Start Docker and re-run. No model calls were made.", file=sys.stderr)
        return 3

    llm = LLMClient()
    provenance = stamp(getattr(llm, "model", ""))
    rev = provenance["sentinel"]
    print(f"Model: {provenance['model']}   Sentinel: {rev['commit'][:7] or 'unknown'}"
          + ("  (UNCOMMITTED CHANGES)" if rev["dirty"] else ""))
    if rev["dirty"]:
        print("WARNING: tracked files differ from the commit, so these results cannot be "
              "tied to it. Commit first if you intend to publish them.")
    print()
    runs: list[RunResult] = []

    for i in range(1, args.runs + 1):
        print(f"=== Run {i}/{args.runs} ===")
        r = _one_run(llm, build_env=not args.no_build_env)
        runs.append(r)
        for t in r.targets:
            env = t["environment"]
            image = f"{env.get('image', '?')} ({env.get('status', '?')})" if env else "?"
            print(f"   {t['target']:<26} {image}")
            print(f"   {'':<26} {_tier_line(t['tiers'], t['hunter'])}")
        print(f"   strict (line-proven):     {_score_line(r.strict)}")
        print(f"   permissive (marker only): {_score_line(r.permissive)}")
        for w in r.warnings:
            print(f"   WARNING: {w}")
        print()

    print("==================  SUMMARY  ==================")
    print(f"Runs:      {args.runs}")
    print("Strict (line-proven only):")
    print(f"  Precision: {_fmt_spread([r.strict.precision for r in runs])}")
    print(f"  Recall:    {_fmt_spread([r.strict.recall for r in runs])}")
    print(f"  F1 score:  {_fmt_spread([r.strict.f1 for r in runs], pct=False)}")
    print("Permissive (marker printed, what a marker-only tool reports):")
    print(f"  Precision: {_fmt_spread([r.permissive.precision for r in runs])}")
    print(f"  Recall:    {_fmt_spread([r.permissive.recall for r in runs])}")
    if any(r.warnings for r in runs):
        print("\nSome runs had untestable findings or failed image builds (see WARNING")
        print("lines above). Those scores measure the environment, not the method.")
    print("\nA single run is one sample. Quote the range, not the best run.")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump({
                **provenance,
                "build_env": not args.no_build_env,
                "targets": TARGETS,
                "runs": [{
                    "strict": r.strict.to_dict(), "permissive": r.permissive.to_dict(),
                    "tiers": r.tiers, "targets": r.targets, "warnings": r.warnings,
                } for r in runs],
            }, fh, indent=2)
        print(f"\nRaw metrics written to {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
