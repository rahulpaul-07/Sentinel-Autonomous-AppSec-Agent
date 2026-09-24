"""
evaluate.py
-----------
Run Sentinel against every labeled target and report accuracy metrics.

    python evaluate.py                 # one run
    python evaluate.py --runs 5        # five runs, report mean +/- spread
    python evaluate.py --json m.json   # also dump raw per-run metrics
    python evaluate.py --runs 3 --json m.json --resume
                                       # finish a run a usage limit interrupted

Every finished run is written before the next one starts. If the provider's usage
limit stops the evaluation, the finished runs are kept, marked incomplete, and
--resume completes them later on the same code, model and settings.

Why repeated runs? Hosted models are not bit-reproducible even at temperature 0, so
a single run is one noisy sample. Quoting one figure from one run overstates
certainty. With --runs N we report the mean and the min-max spread across runs,
which is the honest way to characterise a stochastic pipeline on a small benchmark.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sentinel.llm import LLMClient, QuotaExhausted
from sentinel.metrics import Metrics
from sentinel.evaluation import evaluate_target_tiered
from sentinel.provenance import stamp
from sentinel.scanner import describe_unreadable
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
    started_at: str = ""
    tokens: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"started_at": self.started_at, "tokens": self.tokens,
                "strict": self.strict.to_dict(), "permissive": self.permissive.to_dict(),
                "tiers": self.tiers, "targets": self.targets, "warnings": self.warnings}

    @classmethod
    def from_dict(cls, d: dict) -> "RunResult":
        def metrics(m):
            return Metrics(m["tp"], m["fp"], m["fn"])
        return cls(metrics(d["strict"]), metrics(d["permissive"]), d.get("tiers", {}),
                   d.get("targets", []), d.get("warnings", []), d.get("started_at", ""),
                   d.get("tokens", {}))


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
            details = hunter.get("details") or {}
            described = ", ".join(f"{f} ({describe_unreadable(details.get(f))})"
                                  for f in hunter["unreadable_files"])
            warnings.append(f"{target}: hunter reply unreadable for {described}; "
                            "not analysed")
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


def _usage(llm) -> dict:
    usage = getattr(llm, "usage", None)
    return usage() if callable(usage) else {}


def _delta(after: dict, before: dict) -> dict:
    return {k: after.get(k, 0) - before.get(k, 0) for k in after}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _save(path: str, record: dict) -> None:
    """Write atomically: a crash mid-write must never leave half a results file."""
    tmp = Path(f"{path}.tmp")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _resume_mismatch(saved: dict, provenance: dict, build_env: bool) -> str:
    """Why the saved runs and new ones would not be one measurement, or ''."""
    rev, old = provenance["sentinel"], saved.get("sentinel", {})
    if rev.get("dirty") or old.get("dirty"):
        return ("uncommitted changes to tracked files, now or when the saved runs "
                "were made; the runs cannot be tied to one commit")
    if rev.get("commit") != old.get("commit"):
        return (f"the saved runs are from commit {str(old.get('commit'))[:7]}, "
                f"this checkout is {str(rev.get('commit'))[:7]}")
    if saved.get("model") != provenance["model"]:
        return f"the saved runs used model {saved.get('model')}, this run uses {provenance['model']}"
    if saved.get("build_env") != build_env:
        return "the saved runs used a different --no-build-env setting"
    if saved.get("targets") != TARGETS:
        return "the saved runs used a different set of targets"
    return ""


def _print_run(r: RunResult) -> None:
    for t in r.targets:
        env = t["environment"]
        image = f"{env.get('image', '?')} ({env.get('status', '?')})" if env else "?"
        print(f"   {t['target']:<26} {image}")
        print(f"   {'':<26} {_tier_line(t['tiers'], t['hunter'])}")
    print(f"   strict (line-proven):     {_score_line(r.strict)}")
    print(f"   permissive (marker only): {_score_line(r.permissive)}")
    if r.tokens:
        print(f"   tokens: {r.tokens.get('total_tokens', 0):,} over {r.tokens.get('calls', 0)} calls")
    for w in r.warnings:
        print(f"   WARNING: {w}")
    print()


def _print_summary(runs: list[RunResult], requested: int) -> None:
    print("==================  SUMMARY  ==================")
    print(f"Runs:      {len(runs)}" + (f" of {requested} requested" if len(runs) < requested else ""))
    print("Strict (line-proven only):")
    print(f"  Precision: {_fmt_spread([r.strict.precision for r in runs])}")
    print(f"  Recall:    {_fmt_spread([r.strict.recall for r in runs])}")
    print(f"  F1 score:  {_fmt_spread([r.strict.f1 for r in runs], pct=False)}")
    print("Permissive (marker printed, what a marker-only tool reports):")
    print(f"  Precision: {_fmt_spread([r.permissive.precision for r in runs])}")
    print(f"  Recall:    {_fmt_spread([r.permissive.recall for r in runs])}")
    costs = [r.tokens.get("total_tokens") for r in runs if r.tokens.get("total_tokens")]
    if costs:
        print(f"Tokens per run: {min(costs):,}" + (f"-{max(costs):,}" if max(costs) != min(costs) else ""))
    if any(r.warnings for r in runs):
        print("\nSome runs printed WARNING lines above. Read them before quoting these")
        print("scores: each marks something that was not measured.")
    print("\nA single run is one sample. Quote the range, not the best run.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate Sentinel against labeled targets.")
    ap.add_argument("--runs", type=int, default=1, help="How many full passes to average.")
    ap.add_argument("--json", metavar="PATH", dest="json_path",
                    help="Write raw per-run metrics to PATH, after every run.")
    ap.add_argument("--resume", action="store_true",
                    help="Continue the evaluation saved at --json PATH up to --runs runs. "
                         "Refused unless the code, model and settings match.")
    ap.add_argument("--no-build-env", action="store_true",
                    help="Run exploits in the bare image instead of building each "
                         "target's declared dependencies. Every benchmark target imports "
                         "Flask, so this grades them all not testable.")
    args = ap.parse_args()
    build_env = not args.no_build_env

    if args.resume and not args.json_path:
        print("error: --resume needs --json PATH, the evaluation to continue.", file=sys.stderr)
        return 2

    # Refuse to clobber a results file before touching Docker or the model: a
    # refusal should cost nothing.
    existing = bool(args.json_path) and Path(args.json_path).exists()
    if existing and not args.resume:
        print(f"error: {args.json_path} already exists. Results files are never "
              "overwritten: pass --resume to continue it, or choose another path.",
              file=sys.stderr)
        return 2

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

    saved: dict | None = None
    if existing:
        saved = json.loads(Path(args.json_path).read_text(encoding="utf-8"))
        mismatch = _resume_mismatch(saved, provenance, build_env)
        if mismatch:
            print(f"error: cannot resume {args.json_path}: {mismatch}. Start a new file "
                  "instead.", file=sys.stderr)
            return 2

    runs = [RunResult.from_dict(d) for d in (saved or {}).get("runs", [])]
    if saved is not None and len(runs) >= args.runs:
        print(f"{args.json_path} is already complete ({len(runs)} runs); nothing to do.")
        _print_summary(runs, args.runs)
        return 0

    print(f"Model: {provenance['model']}   Sentinel: {rev['commit'][:7] or 'unknown'}"
          + ("  (UNCOMMITTED CHANGES)" if rev["dirty"] else ""))
    if rev["dirty"]:
        print("WARNING: tracked files differ from the commit, so these results cannot be "
              "tied to it. Commit first if you intend to publish them.")
    if runs:
        print(f"Resuming {args.json_path}: {len(runs)} of {args.runs} runs already saved.")
    print()

    record = saved or {**provenance, "build_env": build_env, "targets": TARGETS}
    record["runs_requested"] = args.runs
    if saved is not None:
        record.setdefault("resumed_at", []).append(_now())

    def persist(stopped: str | None) -> None:
        if not args.json_path:
            return
        record["runs"] = [r.to_dict() for r in runs]
        record["complete"] = len(runs) >= args.runs
        record["stopped"] = stopped
        _save(args.json_path, record)

    for i in range(len(runs) + 1, args.runs + 1):
        print(f"=== Run {i}/{args.runs} ===")
        started, before = _now(), _usage(llm)
        try:
            r = _one_run(llm, build_env=build_env)
        except QuotaExhausted as exc:
            # The unfinished run is dropped: some targets were never scored, so it is
            # not a run. Everything finished is already on disk.
            persist(exc.summary())
            saved_note = (f"{len(runs)} of {args.runs} runs saved to {args.json_path}; "
                          "finish them with the same command plus --resume."
                          if args.json_path else "no --json path was given, so nothing was saved.")
            print(f"\nStopped: {exc.summary()}. Run {i} was not finished and is not counted; "
                  f"{saved_note}")
            return 4
        r.started_at, r.tokens = started, _delta(_usage(llm), before)
        runs.append(r)
        persist(None)
        _print_run(r)

    _print_summary(runs, args.runs)
    if args.json_path:
        print(f"\nRaw metrics written to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
