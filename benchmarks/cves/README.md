# Real-world CVE benchmark

Sentinel's own benchmark is five hand-written cases. This one uses published
vulnerabilities in real Python projects, scanned at the commit that has the bug and at
the commit that fixed it.

The manifest starts empty. Every case needs a sink line checked by a person, and a
number built on unchecked labels would be worse than no number.

## Rules, fixed before the first run

These decide every number the benchmark produces. They are implemented in
`sentinel/cve_benchmark.py` and `sentinel/evaluation.py`. Changing one after seeing
results is tuning to the test: if a rule changes, re-run every case, not only the ones
it helps, and say so where the numbers are reported.

### Selecting cases

Decide the selection rule and write it here **before** looking at how Sentinel does on
any candidate. Then take every advisory that passes it, not the ones that look promising.
Suggested rule:

1. Python advisories from the GitHub Advisory Database.
2. A CWE in a class Sentinel models: 89 (SQL), 78 (command), 22 (path), 502
   (deserialization), 94 (code), 918 (SSRF), 1336 (template).
3. A public fix commit in the project's own repository.
4. The vulnerable code can run in-process with no network: no database server, no
   external service. The sandbox has no network, so such a case could only ever be
   untestable.
5. Declared dependencies install on some `python:3.x-slim` image.
6. Published inside a stated date range.

Every advisory that passes 1-3 but is dropped goes in [`excluded.md`](excluded.md) with
the reason. A case is never dropped after its result is known.

### Labelling the sink

`sink` is the line, on the vulnerable commit, where attacker data does the damage: the
`execute`, the `system`, the `open`, the `loads`. It is often **not** a line the fix
touches, because fixes usually add validation upstream. Read the code; do not copy a
line number out of the diff. `sink_rationale` says why this line, in a sentence a
reader can check against the source.

### What counts as finding the bug

A finding matches the labelled sink when all three hold:

* it is in the same file (finding paths are relative to `scan_path`, labels to the repo)
* its line is within 5 lines of the sink
* its class is in the same family (`sql`, `command`, `path`, ...). When either name
  mentions no known family, they must share a distinctive keyword instead

If several findings match, the strongest evidence wins:
`line_proven` > `class_only` > `unproven` > `env_incomplete` > `unreachable` >
`not_reported`. Tested-and-failed ranks above not-tested because it is a result.

Line-proven findings that do not match the label are listed for review, never counted.
They may be real bugs nobody labelled, or false proofs; only reading them can tell.

### The fixed commit

Anything line-proven in the patched file, with the same class family, at any line, is
recorded. Any line, because the fix moves code. This is an **upper bound** on false
proofs: a different real bug of the same class in the same file would land here too,
so every entry is read before it is called a false positive.

### Metrics, and what each divides by

| Metric | Numerator | Denominator |
|---|---|---|
| Line-proven recall | cases graded `line_proven` | cases scored |
| Line-proven recall, testable only | same | cases scored minus `env_incomplete` |
| Permissive recall | `line_proven` + `class_only` | cases scored |
| Class-only share of confirmed | `class_only` | `line_proven` + `class_only` |
| Fixed versions with a line proof | cases with any entry above | (a count) |

Both recall readings are always reported together. Quoting only the testable one would
let a broken build look like good recall.

Cases that error (a failed checkout, a crash) are excluded from every denominator and
counted separately. A run with errors is not publishable until they are fixed or the
case is moved to `excluded.md` with the reason.

The class-only share is the number the project's central claim rests on. If it is near
zero on real code, the line witness rarely changes a grade. If it is substantial, it is
direct evidence that marker-only validation over-reports.

### Contamination

Models may have seen famous CVEs, and their fixes, in training. Record each case's
`published` date and compare it with the model's training cutoff where the provider
states one. Report results for cases published after the cutoff separately. A
line proof on the **fixed** commit of a well-known CVE is a signal of recall rather
than reasoning.

### Reporting

* Run with `--runs 3` or more and quote the min-max range, never the best run.
* Keep the `--json` record. It carries the model, the Sentinel commit, whether the
  tree was dirty, a hash of the manifest, and the sandbox image of every scan.
* Run from a clean tree, so the numbers tie to a commit.
* Report the per-case table, not only the aggregates. With 15 cases one case is
  roughly 7 points of recall.

## Running

```bash
sentinel-cve --runs 3 --json cve-results.json
sentinel-cve --only CVE-2024-12345
```

Needs Docker and network. Repositories are fetched into `.cve-cache/`, and each case's
declared dependencies (`requirements.txt`, else `pyproject.toml`, at the repo root) are
installed into its image at build time. The exploit still runs with no network.
Dependencies declared only in `setup.py` are not read; such a case will grade
`env_incomplete` and should be listed as a limitation or excluded with that reason.

## Manifest format

This example is illustrative and deliberately not a real advisory.

```json
{
  "schema": 1,
  "cases": [
    {
      "id": "CVE-2099-0001",
      "repo": "https://github.com/example/project.git",
      "vulnerable_commit": "<full 40-character SHA>",
      "fixed_commit": "<full 40-character SHA>",
      "vuln_class": "SQL Injection",
      "cwe": "CWE-89",
      "sink": {"file": "src/project/db.py", "line": 118},
      "sink_rationale": "search() concatenates the name argument into the query and executes it on this line",
      "scan_path": "src",
      "python": "3.11",
      "published": "2099-01-02"
    }
  ]
}
```

`scan_path` scopes the scan: the hunter reads only that directory, so scoping it to the
vulnerable file would leak the answer. Use the package root. SHAs must be full: the
checkout is verified against them, and a short SHA can become ambiguous.
