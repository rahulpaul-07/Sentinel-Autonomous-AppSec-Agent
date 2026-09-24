// Every number on this site comes from the project's own measured results or from
// deterministic checks in its test suite. The report preview is the one rendered
// artifact that is not a scan result, and the page says so where it is shown.

export const REPO = "https://github.com/rahulpaul-07/Sentinel-Autonomous-AppSec-Agent";

// Measured August 2026 with the v1 validator, across four targets / five
// vulnerability classes. v1 asked for self-contained exploits that did not import the
// target, so these predate the witness and are not results for the current pipeline.
export const RUNS = [
  { run: 1, model: "gemini/gemini-3.5-flash", precision: "100%", recall: "80%", f1: "0.89",
    note: "missed insecure deserialization" },
  { run: 2, model: "groq/openai/gpt-oss-120b", precision: "100%", recall: "100%", f1: "1.00",
    note: "all five classes reproduced" },
  { run: 3, model: "groq/openai/gpt-oss-120b", precision: "71%", recall: "100%", f1: "0.83",
    note: "2 false positives on the clean control" },
];

// Deterministic results from the static gate, reproduced by tests/test_reachability.py.
export const GATE = [
  { claim: "SQL Injection", file: "vulnerable_app/app.py:33", verdict: "reachable",
    detail: "attacker-controlled data reaches cursor.execute", blocked: false },
  { claim: "Command Injection", file: "vulnerable_app/app.py:45", verdict: "reachable",
    detail: "attacker-controlled data reaches os.system", blocked: false },
  { claim: "Path Traversal", file: "traversal_app/app.py:22", verdict: "reachable",
    detail: "attacker-controlled data reaches open", blocked: false },
  { claim: "SQL Injection", file: "safe_app/app.py:26", verdict: "safe usage",
    detail: "query string is a constant with bound parameters", blocked: true },
  { claim: "Command Injection", file: "safe_app/app.py:34", verdict: "safe usage",
    detail: "argument vector passed without a shell (shell=False)", blocked: true },
  { claim: "Hardcoded Secret", file: "safe_app/app.py:17", verdict: "not analyzable",
    detail: "env-var read is not a literal — gate fails open, validation decides", blocked: false },
];

export const PIPELINE = [
  { id: "ingest", n: "01", title: "Map the code",
    body: "The target is parsed into an AST code map — the surface the agent reasons over, rather than raw text." },
  { id: "hunt", n: "02", title: "Find candidates",
    body: "A model proposes candidate findings: class, file, line. These are suspicions, and it will invent some of them." },
  { id: "gate", n: "03", title: "Gate on reachability",
    body: "Before any exploit is written, static taint analysis asks whether attacker data can reach that line, and whether the call is already made safely. Rejections here cost nothing.",
    accent: true },
  { id: "prove", n: "04", title: "Prove it, and witness it",
    body: "The exploit imports the real module and drives it inside a network-off sandbox, under a line tracer. The marker proves an exploit ran; the trace proves which line ran." },
  { id: "patch", n: "05", title: "Fix what was proven",
    body: "Only line-proven findings produce a fix diff, behind a human approval gate. A line we could not show executes is never rewritten." },
];

export const TIERS = [
  { key: "line_proven", label: "Line proven", tone: "proof",
    rule: "marker printed + reported line executed",
    meaning: "The specific claim was demonstrated against this code. This is the only tier counted as a finding." },
  { key: "class_only", label: "Class only", tone: "warn",
    rule: "marker printed + reported line never ran",
    meaning: "The exploit proved the vulnerability class in the abstract without touching the code under test. Reported, but never counted or patched." },
  { key: "env_incomplete", label: "Not testable", tone: "muted",
    rule: "exploit stopped at a missing third-party import",
    meaning: "The sandbox lacked a package the target imports, so nothing was tested. Reported on its own, never counted as a failed exploit." },
  { key: "unproven", label: "Unproven", tone: "muted",
    rule: "no marker after N self-correcting attempts",
    meaning: "The claim could not be demonstrated by a working exploit." },
  { key: "unreachable", label: "No path", tone: "violet",
    rule: "rejected by static analysis, before any model call",
    meaning: "No route from attacker input to that line, or the call is already made safely." },
];

export const LIMITS = [
  "The line tracer records that a line executed, not that tainted data flowed through it. Combined with the taint gate this is strong evidence; it is not a dataflow proof.",
  "The benchmark is five cases across four targets. That is enough to make changes measurable and to catch regressions — not enough to quote a headline accuracy number.",
  "The static gate is pattern-based and deliberately fails open: anything it cannot analyze proceeds to validation, so it never trades recall for a cleaner number.",
  "Lines that run only because the module was imported never count as a witness. A hardcoded secret lives on such a line, so it tops out at class-only: execution is the wrong kind of evidence for it.",
  "Imports follow __init__.py: src/pkg/db.py is imported as pkg.db. Namespace packages without __init__.py are imported from the file's own directory, which breaks relative imports inside them.",
  "sys.settrace does not see into C extensions and conflicts with debuggers or coverage tools sharing the hook.",
];
