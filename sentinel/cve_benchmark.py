"""
sentinel/cve_benchmark.py
-------------------------
Measure Sentinel on real vulnerabilities in real projects.

Each case is a published vulnerability with the commit that has it and the
commit that fixed it. Sentinel scans both. That gives two measurements from one
label:

  * on the vulnerable commit: which evidence tier the known bug reached
  * on the fixed commit: whether anything was still "line-proven" in the file the
    fix touched, for the same class -- a false proof on realistic code, which the
    one hand-written clean control cannot give

The labels are for EVALUATION only. Nothing from the advisory or the fix reaches
the hunter: it scans the checkout like any unlabelled code. That keeps the claim
honest that the method needs no oracle -- the benchmark does, the method does not.

Every rule that decides a number is fixed in code here, before any run, and
described in benchmarks/cves/README.md. Changing one after seeing results is
exactly the tuning-to-the-test this file exists to prevent, so a rule change
should come with a re-run of every case, not just the ones it helps.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from sentinel.evaluation import LINE_TOLERANCE, _class_matches
from sentinel.evidence import Evidence

SCHEMA_VERSION = 1

# How a case's vulnerable-commit outcome is chosen when several findings match
# the labelled sink: the strongest evidence wins. UNPROVEN ranks above
# ENV_INCOMPLETE because "tested and failed" is a result, "not tested" is not.
OUTCOME_RANK = {
    Evidence.LINE_PROVEN.value: 5,
    Evidence.CLASS_ONLY.value: 4,
    Evidence.UNPROVEN.value: 3,
    Evidence.ENV_INCOMPLETE.value: 2,
    Evidence.UNREACHABLE.value: 1,
    "not_reported": 0,
}

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PYTHON = re.compile(r"^3\.\d+$")


# --- the manifest --------------------------------------------------------------

@dataclass(frozen=True)
class CveCase:
    id: str
    repo: str                  # clone URL
    vulnerable_commit: str     # full 40-character SHA
    fixed_commit: str
    vuln_class: str            # what a correct finding would call it
    cwe: str
    sink_file: str             # repo-relative, forward slashes
    sink_line: int             # on the vulnerable commit
    sink_rationale: str        # why THIS line is the sink, for a reader to check
    scan_path: str             # repo-relative directory the scan is scoped to
    python: str                # "3.12" -> python:3.12-slim
    published: str             # YYYY-MM-DD, to compare against model cutoffs

    @property
    def image(self) -> str:
        return f"python:{self.python}-slim"


class ManifestError(ValueError):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("invalid CVE manifest:\n  " + "\n  ".join(problems))


_REQUIRED = ("id", "repo", "vulnerable_commit", "fixed_commit", "vuln_class", "cwe",
             "sink", "sink_rationale", "scan_path", "python", "published")


def _posix(path: str) -> str:
    """Repo-relative, forward slashes, no leading `./`. Empty means the repo root."""
    if not path:
        return ""
    norm = str(PurePosixPath(path.replace("\\", "/")))
    return "" if norm == "." else norm


def parse_manifest(data: dict) -> list[CveCase]:
    """Validate every case and report every problem at once, not the first."""
    problems: list[str] = []
    if data.get("schema") != SCHEMA_VERSION:
        problems.append(f"schema must be {SCHEMA_VERSION}")
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list):
        raise ManifestError(problems + ["'cases' must be a list"])

    cases: list[CveCase] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_cases):
        where = f"case {i} ({raw.get('id', '?')})" if isinstance(raw, dict) else f"case {i}"
        if not isinstance(raw, dict):
            problems.append(f"{where}: must be an object")
            continue
        missing = [k for k in _REQUIRED if k not in raw]
        if missing:
            problems.append(f"{where}: missing {', '.join(missing)}")
            continue

        sink = raw["sink"] if isinstance(raw["sink"], dict) else {}
        sink_file = _posix(str(sink.get("file", "")))
        sink_line = sink.get("line")
        scan_path = _posix(str(raw["scan_path"]))
        local = []

        if raw["id"] in seen:
            local.append("duplicate id")
        for key in ("vulnerable_commit", "fixed_commit"):
            if not _SHA.match(str(raw[key])):
                local.append(f"{key} must be a full 40-character lowercase SHA")
        if raw["vulnerable_commit"] == raw["fixed_commit"]:
            local.append("vulnerable_commit and fixed_commit are the same")
        for label, value in (("sink.file", sink_file), ("scan_path", scan_path)):
            if value.startswith("/") or ".." in value.split("/"):
                local.append(f"{label} must be relative to the repo root, without '..'")
        if not sink_file.endswith(".py"):
            local.append("sink.file must be a .py path")
        if not isinstance(sink_line, int) or isinstance(sink_line, bool) or sink_line < 1:
            local.append("sink.line must be a positive integer")
        if scan_path and not (sink_file + "/").startswith(scan_path + "/"):
            local.append("sink.file is outside scan_path, so the scan could never find it")
        if len(str(raw["sink_rationale"]).strip()) < 20:
            local.append("sink_rationale must say why this line is the sink")
        if not _PYTHON.match(str(raw["python"])):
            local.append('python must look like "3.12"')
        if not _DATE.match(str(raw["published"])):
            local.append("published must be YYYY-MM-DD")

        seen.add(raw["id"])
        if local:
            problems.extend(f"{where}: {p}" for p in local)
            continue
        cases.append(CveCase(
            id=raw["id"], repo=raw["repo"], vulnerable_commit=raw["vulnerable_commit"],
            fixed_commit=raw["fixed_commit"], vuln_class=raw["vuln_class"], cwe=raw["cwe"],
            sink_file=sink_file, sink_line=sink_line, sink_rationale=raw["sink_rationale"],
            scan_path=scan_path, python=str(raw["python"]), published=raw["published"],
        ))

    if problems:
        raise ManifestError(problems)
    return cases


def load_manifest(path: str | Path) -> list[CveCase]:
    return parse_manifest(json.loads(Path(path).read_text(encoding="utf-8")))


# --- checkout ------------------------------------------------------------------

def checkout(repo: str, commit: str, dest: Path) -> Path:
    """Materialise exactly `commit` at `dest`, reusing it if already there.

    The resulting HEAD is checked against the requested SHA rather than trusted:
    scanning the wrong commit would silently mislabel every result for the case.
    """
    dest = Path(dest)
    if (dest / ".git").is_dir() and _head(dest) == commit:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    _git(dest, "init", "-q")
    _git(dest, "fetch", "-q", "--depth", "1", repo, commit)
    _git(dest, "checkout", "-q", "--force", "--detach", "FETCH_HEAD")
    head = _head(dest)
    if head != commit:
        raise RuntimeError(f"checkout of {commit} in {dest} produced {head}")
    return dest


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()[-500:]}")
    return proc.stdout.strip()


def _head(cwd: Path) -> str:
    try:
        return _git(cwd, "rev-parse", "HEAD")
    except RuntimeError:
        return ""


# --- scoring: the pre-registered rules -------------------------------------------

def _repo_path(case: CveCase, finding_file: str) -> str:
    """A finding's file is relative to the scan root; labels are relative to the repo."""
    rel = _posix(finding_file)
    return f"{case.scan_path}/{rel}" if case.scan_path else rel


def matches_sink(case: CveCase, finding) -> bool:
    """Same file, within LINE_TOLERANCE lines, and a class that shares a keyword."""
    return (
        _repo_path(case, finding.file) == case.sink_file
        and abs(finding.line - case.sink_line) <= LINE_TOLERANCE
        and _class_matches(finding.vuln_class, case.vuln_class)
    )


@dataclass
class CaseResult:
    case_id: str
    run: int
    outcome: str = "not_reported"          # vulnerable commit, strongest matching tier
    fixed_line_proven: list[str] = field(default_factory=list)
    fixed_class_only: int = 0
    unlabelled_line_proven: list[str] = field(default_factory=list)
    environment_vulnerable: dict | None = None
    environment_fixed: dict | None = None
    error: str = ""


def score_vulnerable(case: CveCase, report, result: CaseResult) -> None:
    best = "not_reported"
    for s in report.scanned:
        if matches_sink(case, s.finding):
            if OUTCOME_RANK[s.evidence.value] > OUTCOME_RANK[best]:
                best = s.evidence.value
        elif s.evidence is Evidence.LINE_PROVEN:
            # Proven, but not the labelled bug. It may be a real unknown bug or a
            # false proof; only a person reading it can say, so it is listed for
            # review and never counted either way.
            result.unlabelled_line_proven.append(
                f"{_repo_path(case, s.finding.file)}:{s.finding.line} {s.finding.vuln_class}"
            )
    result.outcome = best
    result.environment_vulnerable = _env(report)


def score_fixed(case: CveCase, report, result: CaseResult) -> None:
    """Anything line-proven in the patched file, same class, at any line.

    Any line, because the fix moves code around. This is an upper bound on false
    proofs: a different real bug of the same class in the same file would also
    land here, so every entry needs reading before it is called a false positive.
    """
    for s in report.scanned:
        same_file = _repo_path(case, s.finding.file) == case.sink_file
        if not (same_file and _class_matches(s.finding.vuln_class, case.vuln_class)):
            continue
        if s.evidence is Evidence.LINE_PROVEN:
            result.fixed_line_proven.append(f"{case.sink_file}:{s.finding.line}")
        elif s.evidence is Evidence.CLASS_ONLY:
            result.fixed_class_only += 1
    result.environment_fixed = _env(report)


def _env(report) -> dict | None:
    env = getattr(report, "environment", None)
    return env.to_dict() if env is not None else None


# --- aggregation -----------------------------------------------------------------

def aggregate(results: list[CaseResult]) -> dict:
    """Every metric states its denominator. Errored cases are excluded and counted."""
    scored = [r for r in results if not r.error]
    n = len(scored)
    counts = {k: sum(1 for r in scored if r.outcome == k) for k in OUTCOME_RANK}
    lp, co = counts["line_proven"], counts["class_only"]
    testable = n - counts["env_incomplete"]

    def ratio(num: int, den: int) -> float | None:
        return num / den if den else None

    return {
        "cases_scored": n,
        "cases_errored": len(results) - n,
        "outcomes": counts,
        # Strict: the headline. Untestable cases count as misses.
        "line_proven_recall": ratio(lp, n),
        # Same numerator, untestable cases removed. Report BOTH: quoting only this
        # one would let a broken build look like good recall.
        "line_proven_recall_of_testable": ratio(lp, testable),
        # What a marker-only scanner would report.
        "permissive_recall": ratio(lp + co, n),
        # Of the exploits that printed the marker, how many never ran the line.
        # This is the number the whole project's thesis rests on.
        "class_only_share_of_confirmed": ratio(co, lp + co),
        "fixed_versions_with_line_proof": sum(1 for r in scored if r.fixed_line_proven),
        "unlabelled_line_proven": sum(len(r.unlabelled_line_proven) for r in scored),
    }


def spread(per_run: list[dict]) -> dict:
    """Min and max of each ratio across runs. Never a single best run."""
    out = {}
    for key, value in per_run[0].items() if per_run else ():
        if isinstance(value, (int, float)) or value is None:
            values = [r[key] for r in per_run if r[key] is not None]
            out[key] = {"min": min(values), "max": max(values)} if values else None
    return out


# --- running -----------------------------------------------------------------------

def _sentinel_revision() -> dict:
    here = Path(__file__).resolve().parent.parent
    try:
        commit = _git(here, "rev-parse", "HEAD")
        dirty = bool(_git(here, "status", "--porcelain"))
    except (RuntimeError, OSError):
        return {"commit": "", "dirty": None}
    return {"commit": commit, "dirty": dirty}


def run_benchmark(cases: list[CveCase], llm, runs: int, cache_dir: str | Path,
                  scanner_factory=None, manifest_bytes: bytes = b"") -> dict:
    """Scan every case, vulnerable and fixed, `runs` times. Returns the full record."""
    if scanner_factory is None:
        from sentinel.scanner import Scanner
        scanner_factory = Scanner

    cache = Path(cache_dir)
    record = {
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": getattr(llm, "model", ""),
        "sentinel": _sentinel_revision(),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest() if manifest_bytes else "",
        "runs": runs,
        "rules": {"line_tolerance": LINE_TOLERANCE, "schema": SCHEMA_VERSION},
        "results": [],
        "per_run": [],
    }

    checkouts: dict[str, tuple[Path, Path] | str] = {}
    for case in cases:
        try:
            checkouts[case.id] = (
                checkout(case.repo, case.vulnerable_commit, cache / case.id / "vulnerable"),
                checkout(case.repo, case.fixed_commit, cache / case.id / "fixed"),
            )
        except RuntimeError as exc:
            checkouts[case.id] = f"checkout failed: {exc}"

    for run in range(1, runs + 1):
        run_results = []
        for case in cases:
            result = CaseResult(case_id=case.id, run=run)
            got = checkouts[case.id]
            if isinstance(got, str):
                result.error = got
            else:
                vulnerable, fixed = got
                try:
                    score_vulnerable(case, _scan(scanner_factory, llm, case, vulnerable), result)
                    score_fixed(case, _scan(scanner_factory, llm, case, fixed), result)
                except Exception as exc:  # one broken case must not end the run
                    result.error = f"{type(exc).__name__}: {exc}"
            run_results.append(result)
        record["results"].extend(asdict(r) for r in run_results)
        record["per_run"].append(aggregate(run_results))

    record["spread"] = spread(record["per_run"])
    return record


def _scan(scanner_factory, llm, case: CveCase, repo_root: Path):
    scan_root = repo_root / case.scan_path if case.scan_path else repo_root
    scanner = scanner_factory(
        llm, str(scan_root), build_env=True, image=case.image, env_root=str(repo_root)
    )
    return scanner.scan(patch=False)
