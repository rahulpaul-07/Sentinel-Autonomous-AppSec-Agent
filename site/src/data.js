// Every number on this page comes from a measured result committed to the repo
// (benchmarks/results/) or from a deterministic check in the test suite. The
// example evidence record and the report preview are rendered from the test
// fixture, and the page labels them as such where they appear.

export const REPO = "https://github.com/rahulpaul-07/Sentinel-Autonomous-AppSec-Agent";
export const RESULTS_FILE = `${REPO}/blob/master/benchmarks/results/2026-09-26-eval-gpt-oss-120b.json`;
export const PRE_AUDIT_FILE = `${REPO}/blob/master/benchmarks/results/2026-09-24-eval-gpt-oss-120b.json`;

// benchmarks/results/2026-09-26-eval-gpt-oss-120b.json -- commit a332400 (after the
// audit, answer-key comments removed), groq/openai/gpt-oss-120b, three runs,
// dependency images, network off.
export const CURRENT_RUNS = [
  { run: 1, strict: "80%", strictN: "4 of 5", precision: "80%", fp: 1,
    note: "false proof on the clean control" },
  { run: 2, strict: "60%", strictN: "3 of 5", precision: "75%", fp: 1,
    note: "false proof on the clean control; traversal file not analysed (malformed reply)" },
  { run: 3, strict: "60%", strictN: "3 of 5", precision: "100%", fp: 0,
    note: "the path-traversal exploit ran and failed" },
];

// August 2026, v1 validator: exploits did not import the target, so every
// success here reproduced a pattern in isolation -- class-only at best today.
export const V1_RUNS = [
  { run: 1, model: "gemini/gemini-3.5-flash", precision: "100%", recall: "80%", f1: "0.89",
    note: "missed insecure deserialization" },
  { run: 2, model: "groq/openai/gpt-oss-120b", precision: "100%", recall: "100%", f1: "1.00",
    note: "all five classes reproduced" },
  { run: 3, model: "groq/openai/gpt-oss-120b", precision: "71%", recall: "100%", f1: "0.83",
    note: "2 false positives on the clean control" },
];

const SRC = `${REPO}/blob/master`;

// One panel per stage, each showing a real artifact of that stage: the hunter's
// reply schema, the gate's actual verdicts (sentinel.reachability.analyze on the
// benchmark files), the sandbox's actual docker flags, a witness record from the
// recorded run in the demo, the two real lines the fix changes, and the verifier's
// own outcome strings.
export const STAGES = [
  { id: "hunt", n: "01", title: "Hunt", tag: "claims",
    what: "A model reads each file with line numbers and names candidates: class, file, line. Its reply is untrusted input, so it is parsed, cut to a fixed schema, severity checked against a fixed vocabulary, and deduplicated before anything else sees it.",
    label: "example reply, in the schema hunter.py requires",
    artifact: `{"findings": [
  {"vuln_class": "SQL Injection",
   "line": 33,
   "severity": "critical",
   "description": "request arg concatenated into SQL",
   "confidence": 0.95}
]}`,
    files: [["sentinel/hunter.py", `${SRC}/sentinel/hunter.py`]] },
  { id: "gate", n: "02", title: "Gate", tag: "static",
    what: "Deterministic AST taint analysis asks whether attacker data reaches the claimed line, and whether the call is already made safely. It rejects only on positive evidence. Anything it cannot model goes on to be tested.",
    label: "real output of reachability.analyze() on the benchmark",
    artifact: `analyze(vulnerable_app/app.py, "SQL Injection", 33)
  verdict  reachable
  reason   attacker-controlled data reaches \`cursor.execute\`
  path     source: request.args.get() -> sink: cursor.execute() at line 34

analyze(safe_app/app.py, "SQL Injection", 26)       rejected, no model call
  verdict  safe_usage
  reason   \`cursor.execute\` at line 26: query string is a constant
           with bound parameters (parameterized query)

analyze(safe_app/app.py, "SSRF", 34)                fails open, tested
  verdict  not_analyzable
  reason   attacker-controlled data (request.args.get()) reaches
           \`subprocess.run\` at line 34, which has no SSRF sink model;
           gate skipped`,
    files: [["sentinel/reachability.py", `${SRC}/sentinel/reachability.py`]] },
  { id: "prove", n: "03", title: "Prove", tag: "sandboxed",
    what: "The model writes an exploit that must import the target module and drive it. It runs inside the tracing harness in a disposable container. If it fails, its output goes back to the model, up to three attempts.",
    label: "the container flags, from sandbox.py",
    artifact: `docker run --rm --name sentinel-sbx-<id> \\
  --network none \\
  --memory=256m --memory-swap=256m --cpus=1.0 --pids-limit=128 \\
  --cap-drop ALL --security-opt no-new-privileges \\
  --user 65534:65534 -e PYTHONDONTWRITEBYTECODE=1 \\
  --read-only --tmpfs /tmp:size=64m \\
  -v <target>:/work:ro -w /work \\
  <image> sh -c '<harness; stdout and stderr capped at 1 MB>'
# killed after 20 s`,
    files: [["sentinel/validator.py", `${SRC}/sentinel/validator.py`],
            ["sentinel/sandbox.py", `${SRC}/sentinel/sandbox.py`]] },
  { id: "grade", n: "04", title: "Grade", tag: "tiered",
    what: "The harness writes one record, authenticated by a per-run nonce, listing which lines of the target executed and which ran only because it was imported. Import-time lines never count. Marker plus the accused line is LINE PROVEN; marker without it is CLASS ONLY.",
    label: "witness record from the 'drive the real code' run in the demo",
    artifact: `SENTINEL_WITNESS:{"nonce": "<per-run secret>",
  "available": true, "file_executed": true,
  "line_executed": true,
  "executed_lines": [1, 2, 4, 6, 7, 8, 9, 10, 12, 13, 14],
  ...}

marker printed  +  line 14 executed   ->  LINE_PROVEN`,
    files: [["sentinel/witness.py", `${SRC}/sentinel/witness.py`],
            ["sentinel/evidence.py", `${SRC}/sentinel/evidence.py`]] },
  { id: "fix", n: "05", title: "Fix", tag: "proven only",
    what: "One patch per file covers every line-proven finding in it. A reply that does not parse, or leaves the file unchanged, is never offered. Class-only findings are never patched.",
    label: "vulnerable_app/app.py:33-34 against the clean control's safe_app/app.py:26",
    diff: [
      ["-", `    query = "SELECT * FROM users WHERE name = '" + username + "'"`],
      ["-", "    cursor.execute(query)"],
      ["+", `    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))`],
    ],
    files: [["sentinel/patcher.py", `${SRC}/sentinel/patcher.py`]] },
  { id: "verify", n: "06", title: "Verify", tag: "replay",
    what: "The exploits that proved the findings are replayed, unchanged, against a patched copy of the tree. No model call. Only a verified fix can be applied with --yes.",
    label: "the three outcomes, as scanner.py reports them",
    artifact: `verified            patched code ran, exploit failed
still exploitable   the exploit still succeeds
inconclusive        the exploit never reached the patched code`,
    files: [["sentinel/scanner.py", `${SRC}/sentinel/scanner.py`]] },
];

// benchmarks/results/2026-09-26-eval-gpt-oss-120b.json, runs 1-3.
export const RUN_METRICS = [
  { key: "strict_recall", label: "Strict recall", note: "line proven", runs: [80, 60, 60] },
  { key: "strict_precision", label: "Strict precision", note: "line proven", runs: [80, 75, 100] },
  { key: "permissive_recall", label: "Permissive recall", note: "marker printed", runs: [100, 80, 80] },
];

export const FAQ = [
  { q: "Does Sentinel run my code?",
    a: "Yes. That is the point: an exploit imports the target and executes it. It does so in a Docker container with no network, a read-only root filesystem, every capability dropped, an unprivileged user, capped memory, CPU, processes and output, and a 20 second timeout. The target is mounted read-only. The one exception is --build-env, which runs pip install with network access to build the image, so it is opt-in." },
  { q: "How is this different from Semgrep or CodeQL?",
    a: "Those tools analyse code statically, by pattern and data flow, and never run an exploit. Sentinel's gate is static too, but it only filters. A finding counts only after an exploit has run against the code and the accused line executed. The cost of that is Docker, model calls, and Python only." },
  { q: "Which models work?",
    a: "Any provider litellm supports, chosen with one line: SENTINEL_MODEL in .env. It was developed on Ollama, Groq and Gemini. Model size matters: on the same benchmark, gpt-oss-120b line-proved 60 to 80% of the bugs, and the local qwen2.5-coder:7b 0 to 20%." },
  { q: "What does a run cost?",
    a: "Run 1 of the 26 September benchmark made 14 model calls and used 19,100 tokens across all four targets. Every results file records the tokens each run used." },
  { q: "Why are the results a range?",
    a: "Hosted models are not bit-reproducible, even at temperature 0, and the benchmark holds five bugs, so one case moves recall by 20 points. Three runs and their spread is the honest figure; the best run alone would not be." },
  { q: "Can it gate a CI pipeline?",
    a: "Yes. --sarif writes SARIF 2.1.0 for GitHub code scanning, --fail-on exits 1 on a line-proven finding at or above a severity, and the exit codes separate bad input, no Docker, an exhausted quota and a refused model request. Without a terminal, fixes are declined rather than prompting." },
  { q: "What is the false proof in the results?",
    a: "On the clean control, an exploit changed its sandbox environment so a safe route looked exploited, ran the accused line, and printed the success marker itself. The tracer confirmed the line ran, so it was graded LINE PROVEN. It is published with the results and listed first under the limits." },
];

// The repository, as the explorer shows it. Roles are the module docstrings.
export const REPO_TREE = [
  { name: "sentinel", children: [
    ["scanner.py", "Orchestrates the pipeline and builds the ScanReport."],
    ["hunter.py", "The LLM hunter. Parses the model's reply as untrusted input."],
    ["reachability.py", "Static taint gate with sanitizer recognition. Fails open."],
    ["validator.py", "Asks for exploits, runs them, self-corrects, grades them."],
    ["witness.py", "The tracing harness, its nonce-authenticated record, the pre-execution screen."],
    ["sandbox.py", "The Docker cage, with a preflight check."],
    ["environment.py", "Builds per-target sandbox images from declared dependencies."],
    ["patcher.py", "One fix per file; parse check; line endings preserved."],
    ["evidence.py", "The five-tier evidence ladder."],
    ["evaluation.py", "Scores scans against labelled ground truth, strict and permissive."],
    ["report.py", "Self-contained HTML report: escaped, no script, strict CSP."],
    ["sarif.py", "SARIF 2.1.0 export for GitHub code scanning."],
    ["llm.py", "Provider adapter: retries, backoff, quota handling, timeouts."],
    ["prompting.py", "Fences untrusted text with random delimiters."],
  ] },
  { name: "tests", children: [
    ["test_witness.py", "Runs the real tracing harness against a real file."],
    ["test_witness_integrity.py", "Each known forgery, run through the harness; none may prove a line."],
    ["test_reachability.py", "The gate's verdicts, including every audited bypass."],
    ["test_fix_loop.py", "Fix verification, --yes, line endings, closed stdin."],
    ["integration/", "15 tests against a real Docker daemon."],
  ] },
  { name: "targets", children: [
    ["vulnerable_app/", "SQL injection, command injection, a hardcoded secret."],
    ["traversal_app/", "Path traversal."],
    ["deserialize_app/", "Insecure deserialization."],
    ["safe_app/", "The clean control: should produce nothing."],
  ] },
  { name: "benchmarks", children: [
    ["results/", "Unedited results files; every published number comes from one."],
    ["cves/", "Real-world CVE harness with pre-registered scoring. No cases yet."],
  ] },
  { file: "scan.py", role: "The sentinel CLI." },
  { file: "evaluate.py", role: "sentinel-eval: runs the benchmark and reports the spread." },
];

export const TIERS = [
  { key: "line_proven", label: "Line proven", tone: "proof",
    rule: "marker printed and the reported line executed",
    counted: "Counted, patched, exported as error" },
  { key: "class_only", label: "Class only", tone: "warn",
    rule: "marker printed, reported line never ran",
    counted: "Reported, never counted or patched" },
  { key: "env_incomplete", label: "Not testable", tone: "muted",
    rule: "exploit stopped at a missing third-party import",
    counted: "Its own tier: nothing was tested" },
  { key: "unproven", label: "Unproven", tone: "muted",
    rule: "no marker after three self-correcting attempts",
    counted: "Reported as not demonstrated" },
  { key: "unreachable", label: "No path", tone: "muted",
    rule: "rejected by the static gate, before any exploit",
    counted: "Reported with the gate's reason" },
];

// Controls, each pinned by a test named in the repository.
export const CONTROLS = [
  { title: "The container",
    items: ["--network none", "--read-only root, 64 MB tmpfs", "--cap-drop ALL",
            "--user 65534, no-new-privileges", "memory, swap, CPU and PID caps",
            "1 MB output cap, enforced inside", "20 s hard timeout"] },
  { title: "The witness",
    items: ["per-run nonce authenticates the trace record",
            "tracer state unreachable from the exploit",
            "record written to a private file descriptor",
            "exploits that touch frames, trace hooks or os._exit refused before running",
            "import-time execution never counts"] },
  { title: "The prompts and reports",
    items: ["target source fenced with random delimiters",
            "model output normalised to a fixed schema",
            "HTML report: escaped, no script, CSP default-src 'none'",
            "symlinks never followed out of the target",
            "dependency images are opt-in: pip install runs with network"] },
];

// The September 2026 audit. Each row was reproduced against the prior code and is
// now pinned by a regression test that fails if the fix is reverted.
export const AUDIT = [
  { severity: "critical", area: "Witness",
    finding: "An exploit that never called the vulnerable function could be graded LINE PROVEN: print a record-shaped line and exit before the harness, or import __main__ and add the line to the tracer's hit set.",
    fix: "Nonce-authenticated record, tracer state in closures, private output descriptor, pre-execution screen." },
  { severity: "high", area: "Gate",
    finding: "Real bugs were rejected before testing: realpath() treated as containment, one quoted argument excusing an unquoted one, [\"sh\", \"-c\", x] treated as shell-free, unlisted sinks treated as absent.",
    fix: "Sanitizers resolved through imports and checked by a second taint pass; unmodelled tainted calls fail open." },
  { severity: "high", area: "Report",
    finding: "Model-supplied severity reached the HTML report unescaped.",
    fix: "Escaping, a fixed severity vocabulary at the parse boundary, and a CSP that forbids script." },
  { severity: "high", area: "Prompts",
    finding: "A target containing the fixed --- END CODE --- delimiter could close its own block and address the model.",
    fix: "Random per-block fences and an untrusted-data notice in every system prompt." },
  { severity: "medium", area: "Fixes",
    finding: "Only the first proven bug per file was patched; unparseable replies were offered and applied by --yes.",
    fix: "One fix covers every proven finding, must parse, and is verified by replaying the exploit; --yes applies only verified fixes." },
  { severity: "medium", area: "Benchmark",
    finding: "Target files carried comments naming each bug and its line, so the model saw the answers.",
    fix: "Comments removed with line numbers preserved; a test fails if hints return." },
  { severity: "medium", area: "Sandbox",
    finding: "Exploits ran as root in the container, and output was captured unbounded.",
    fix: "Unprivileged user, no-new-privileges, in-container output cap." },
];

export const LIMITS = [
  "The success marker is printed by the exploit. The tracer proves the accused line ran, not that the attack worked, so an exploit that rigs its sandbox environment can declare success. It happened on the clean control on 26 September, and closing it is the top roadmap item.",
  "The tracer records that a line executed, not that attacker data flowed through it. With the taint gate this is strong evidence; it is not a dataflow proof.",
  "The tracer runs in the exploit's own interpreter. The integrity checks stop accidental and naively injected forgery, not an exploit engineered to evade them; tracing from outside the process would.",
  "Prompt fencing lowers the odds of injection but cannot remove them. An injected finding still has to be proven; an injected \"report nothing\" is the residual risk.",
  "The benchmark is five labelled bugs and one clean control. Enough to catch regressions, not to quote a headline accuracy. The CVE harness exists; its manifest has no cases yet.",
  "A hardcoded secret lives on a module-level line, which runs only on import and never counts as a witness. It tops out at class-only: execution is the wrong kind of evidence for it.",
  "Python only. The gate is intra-file and pattern-based, and does not see through aliasing or across modules.",
];

// PoC-Gym, arXiv:2602.04165, section 5.1: 44% of runtime-valid candidates did not
// reach the real vulnerability sink under post-hoc validation.
export const POC_GYM = "https://arxiv.org/abs/2602.04165";

// Counts from `pytest --collect-only` (offline) and `pytest -m docker`, and the jobs
// in .github/workflows/ci.yml. Update these when either changes.
export const FACTS = [
  { value: "5", unit: "evidence tiers", note: "graded, never yes/no" },
  { value: "340 + 15", unit: "tests", note: "offline, plus real Docker" },
  { value: "6", unit: "CI jobs", note: "tests, sandbox, lint, audits, site" },
  { value: "SARIF", unit: "2.1.0", note: "for GitHub code scanning" },
];

export const QUICKSTART = `python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .

# pick a model: SENTINEL_MODEL plus that provider's key
cp .env.example .env

# scan, prove, and open the report (Docker must be running)
sentinel targets/vulnerable_app --build-env --report report.html --open

# measure against the labelled benchmark, spread included
sentinel-eval --runs 5`;

export const CI_JOBS = [
  { name: "Python tests", body: "The 340 offline tests. The model and the container are stubbed, and the tests assert on how both are called." },
  { name: "Sandbox", body: "The 15 Docker tests: real docker run, security flags, read-only mount, in-container tracer. The job fails if Docker is missing; it never skips." },
  { name: "Import isolation", body: "The analysis modules are imported with only pytest installed, which proves they do not pull in the LLM stack." },
  { name: "Lint", body: "ruff with pyflakes, bugbear, pyupgrade and the bandit security rules." },
  { name: "Dependency audit", body: "pip-audit on the pinned Python lockfile and npm audit on this page's toolchain." },
  { name: "Site drift", body: "Rebuilds this page and fails if the committed docs/ differs from its source." },
];

export const STACK = [
  ["Language", "Python 3.12, standard-library ast for the taint analysis"],
  ["Models", "litellm: Ollama, Groq, Gemini, Anthropic, OpenAI"],
  ["Isolation", "Docker, with sys.settrace for the line witness"],
  ["Output", "Self-contained HTML, JSON, SARIF 2.1.0"],
  ["Quality", "pytest, ruff (bandit rules), pip-audit, npm audit"],
  ["This page", "React, Vite, Tailwind, Motion; components adapted from Magic UI (MIT); self-hosted fonts, strict CSP, no third-party requests"],
];

export const CI_SNIPPET = `- name: Sentinel
  env:
    SENTINEL_MODEL: groq/openai/gpt-oss-120b
    GROQ_API_KEY: \${{ secrets.GROQ_API_KEY }}
  run: |
    pip install git+${REPO}
    sentinel src/ --no-patch --sarif sentinel.sarif --fail-on high

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sentinel.sarif`;
