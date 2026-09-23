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
from dataclasses import dataclass

from sentinel.llm import LLMClient
from sentinel.metrics import Metrics
from sentinel.evaluation import evaluate_target

TARGETS = [
    "targets/vulnerable_app",
    "targets/safe_app",
    "targets/traversal_app",
    "targets/deserialize_app",
]


@dataclass
class RunResult:
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int


def _one_run(llm: LLMClient) -> RunResult:
    total = Metrics()
    for target in TARGETS:
        total = total + evaluate_target(llm, target)
    return RunResult(total.precision, total.recall, total.f1, total.tp, total.fp, total.fn)


def _fmt_spread(values: list[float], pct: bool = True) -> str:
    lo, hi = min(values), max(values)
    mean = statistics.mean(values)
    if pct:
        if lo == hi:
            return f"{mean:.0%}"
        return f"{mean:.0%}  (range {lo:.0%}-{hi:.0%})"
    if lo == hi:
        return f"{mean:.2f}"
    return f"{mean:.2f}  (range {lo:.2f}-{hi:.2f})"


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate Sentinel against labeled targets.")
    ap.add_argument("--runs", type=int, default=1, help="How many full passes to average.")
    ap.add_argument("--json", metavar="PATH", dest="json_path",
                    help="Write raw per-run metrics to PATH.")
    args = ap.parse_args()

    llm = LLMClient()
    runs: list[RunResult] = []

    for i in range(1, args.runs + 1):
        print(f"=== Run {i}/{args.runs} ===")
        r = _one_run(llm)
        runs.append(r)
        print(f"   TP={r.tp} FP={r.fp} FN={r.fn}  "
              f"P={r.precision:.0%} R={r.recall:.0%} F1={r.f1:.2f}\n")

    print("==================  SUMMARY  ==================")
    if args.runs == 1:
        r = runs[0]
        print(f"Precision: {r.precision:.0%}")
        print(f"Recall:    {r.recall:.0%}")
        print(f"F1 score:  {r.f1:.2f}")
    else:
        print(f"Runs:      {args.runs}")
        print(f"Precision: {_fmt_spread([r.precision for r in runs])}")
        print(f"Recall:    {_fmt_spread([r.recall for r in runs])}")
        print(f"F1 score:  {_fmt_spread([r.f1 for r in runs], pct=False)}")
        print("\nA single run is one sample. The spread above is the honest picture;")
        print("do not quote the best run as the expected result.")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump([r.__dict__ for r in runs], fh, indent=2)
        print(f"\nRaw metrics written to {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
