// Every number on this page comes from a measured result committed to the repo
// (benchmarks/results/) or from a deterministic check in the test suite. The
// example evidence record and the report preview are rendered from the test
// fixture, and the page labels them as such where they appear.

export const REPO = "https://github.com/rahulpaul-07/Sentinel-Autonomous-AppSec-Agent";
export const RESULTS_FILE = `${REPO}/blob/master/benchmarks/results/2026-09-24-eval-gpt-oss-120b.json`;

// benchmarks/results/2026-09-24-eval-gpt-oss-120b.json -- commit 6a2b78d,
// groq/openai/gpt-oss-120b, three runs, dependency images, network off.
export const CURRENT_RUNS = [
  { run: 1, strict: "60%", strictN: "3 of 5", permissive: "80%", permissiveN: "4 of 5", fp: 0,
    note: "the path-traversal exploit ran and failed" },
  { run: 2, strict: "80%", strictN: "4 of 5", permissive: "100%", permissiveN: "5 of 5", fp: 0, note: "" },
  { run: 3, strict: "80%", strictN: "4 of 5", permissive: "100%", permissiveN: "5 of 5", fp: 0, note: "" },
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

// Deterministic verdicts of the static gate, pinned by tests/test_reachability.py.
export const GATE = [
  { claim: "SQL Injection", file: "vulnerable_app/app.py:33", verdict: "reachable",
    detail: "request.args.get() reaches cursor.execute", blocked: false },
  { claim: "Command Injection", file: "vulnerable_app/app.py:45", verdict: "reachable",
    detail: "request.args.get() reaches os.system", blocked: false },
  { claim: "Path Traversal", file: "traversal_app/app.py:22", verdict: "reachable",
    detail: "request.args.get() reaches open", blocked: false },
  { claim: "SQL Injection", file: "safe_app/app.py:26", verdict: "safe usage",
    detail: "constant query with bound parameters", blocked: true },
  { claim: "Command Injection", file: "safe_app/app.py:34", verdict: "safe usage",
    detail: "argument vector, no shell, program is not a shell", blocked: true },
  { claim: "Hardcoded Secret", file: "safe_app/app.py:17", verdict: "not analyzable",
    detail: "an env-var read is not a literal, so the gate declines to guess", blocked: false },
];

export const PIPELINE = [
  { n: "01", title: "Hunt",
    body: "A model reads each file and proposes candidates: class, file, line. They are claims, and some are invented. Its reply is parsed as untrusted input and normalised before anything else sees it." },
  { n: "02", title: "Gate",
    body: "Static taint analysis asks whether attacker data can reach that line, and whether the call is made safely. It rejects only on positive evidence; anything it cannot model goes on to be tested." },
  { n: "03", title: "Prove",
    body: "The model writes an exploit that imports the real module. It runs in a network-off, unprivileged container under a line tracer. The marker says an exploit worked; the trace says which line ran." },
  { n: "04", title: "Grade",
    body: "Marker plus the accused line executing is LINE PROVEN. Marker without it is CLASS ONLY. Only line-proven findings are counted, patched, or exported as errors." },
  { n: "05", title: "Fix",
    body: "One patch per file covering every proven finding. It must parse and must change something, or it is never offered." },
  { n: "06", title: "Verify the fix",
    body: "The exploits that proved the findings are replayed against a patched copy of the tree. No model call. A fix passes only if the patched code ran and no exploit succeeded." },
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
  "The tracer records that a line executed, not that attacker data flowed through it. With the taint gate this is strong evidence; it is not a dataflow proof.",
  "The tracer runs in the exploit's own interpreter. The integrity checks stop accidental and naively injected forgery, not an exploit engineered to evade them; tracing from outside the process would.",
  "Prompt fencing lowers the odds of injection but cannot remove them. An injected finding still has to be proven; an injected \"report nothing\" is the residual risk.",
  "The benchmark is five labelled bugs and one clean control. Enough to catch regressions, not to quote a headline accuracy. The CVE harness exists; its manifest has no cases yet.",
  "A hardcoded secret lives on a module-level line, which runs only on import and never counts as a witness. It tops out at class-only: execution is the wrong kind of evidence for it.",
  "Python only. The gate is intra-file and pattern-based, and does not see through aliasing or across modules.",
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
