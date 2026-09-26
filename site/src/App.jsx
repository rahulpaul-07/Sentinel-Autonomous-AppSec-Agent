import { useEffect, useState } from "react";
import { ArrowUpRight, Github, Moon, Sun } from "lucide-react";

import { ProofLab } from "@/components/proof-lab";
import { cn } from "@/lib";
import {
  AUDIT, CI_SNIPPET, CONTROLS, CURRENT_RUNS, GATE, LIMITS, PIPELINE, REPO,
  RESULTS_FILE, TIERS, V1_RUNS,
} from "./data";

/* ------------------------------------------------------------------ shell */

function useTheme() {
  const [theme, setTheme] = useState(null);   // null: follow the system
  useEffect(() => {
    try {
      const saved = localStorage.getItem("theme");
      if (saved === "light" || saved === "dark") setTheme(saved);
    } catch { /* storage blocked: follow the system */ }
  }, []);
  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme;
  }, [theme]);
  const toggle = () => {
    const current = theme ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    setTheme(next);
    try { localStorage.setItem("theme", next); } catch { /* not persisted */ }
  };
  return toggle;
}

const NAV = [["problem", "Problem"], ["method", "Method"], ["hardening", "Hardening"],
             ["results", "Results"], ["limits", "Limits"]];

function Nav() {
  const toggle = useTheme();
  return (
    <nav className="sticky top-0 z-40 border-b border-rule bg-paper/90 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-page items-center gap-6 px-4 sm:px-8">
        <a href="#top" className="font-mono text-[14px] font-semibold tracking-[.14em] text-ink">
          SENTINEL
        </a>
        <div className="ml-auto flex items-center gap-5 text-[14px]">
          {NAV.map(([id, label]) => (
            <a key={id} href={`#${id}`} className="hidden text-body hover:text-ink md:inline">{label}</a>
          ))}
          <button onClick={toggle} aria-label="Toggle colour theme" className="p-1 text-body hover:text-ink">
            <Sun className="hidden h-4 w-4 dark:block" aria-hidden />
            <Moon className="h-4 w-4 dark:hidden" aria-hidden />
          </button>
          <a href={REPO} target="_blank" rel="noopener noreferrer"
             className="inline-flex items-center gap-1.5 border border-ink px-3 py-1 text-ink hover:bg-ink hover:text-paper">
            <Github className="h-3.5 w-3.5" aria-hidden /> Source
          </a>
        </div>
      </div>
    </nav>
  );
}

function Section({ id, n, label, title, lede, children }) {
  return (
    <section id={id} className="border-t border-rule">
      <div className="mx-auto grid max-w-page gap-x-12 px-4 py-16 sm:px-8 sm:py-24 lg:grid-cols-[180px_minmax(0,1fr)]">
        <p className="mb-4 font-mono text-[12px] uppercase tracking-[.14em] text-muted lg:sticky lg:top-24 lg:self-start">
          <span className="text-ink">§{n}</span> {label}
        </p>
        <div className="min-w-0">
          {title && (
            <h2 className="max-w-[26ch] text-[28px] font-semibold leading-[1.15] tracking-[-0.015em] text-ink sm:text-[38px]">
              {title}
            </h2>
          )}
          {lede && <p className="mt-5 max-w-[64ch] text-[16px] leading-[1.65] text-body">{lede}</p>}
          {children}
        </div>
      </div>
    </section>
  );
}

function Table({ head, children, min = 560 }) {
  return (
    <div className="mt-8 overflow-x-auto border border-rule">
      <table className="w-full text-left text-[14px]" style={{ minWidth: min }}>
        <thead>
          <tr className="border-b border-rule bg-panel font-mono text-[11.5px] uppercase tracking-[.08em] text-muted">
            {head.map((h) => <th key={h} scope="col" className="px-4 py-2.5 font-medium">{h}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-rule">{children}</tbody>
      </table>
    </div>
  );
}

const toneText = { proof: "text-proof", warn: "text-warn", muted: "text-muted" };

/* ------------------------------------------------------------------- hero */

const RECORD = [
  ["claim", "SQL Injection · app.py:33 · critical", ""],
  ["gate", "request.args.get() → cursor.execute · reachable", ""],
  ["exploit", "import app; drive get_user() with ' OR '1'='1", ""],
  ["marker", "printed", "text-proof"],
  ["trace", "app.py:33 executed after import · nonce ok", "text-proof"],
  ["verdict", "LINE PROVEN", "font-semibold text-proof"],
  ["fix", "parameterized query · replay: exploit fails", ""],
];

function Hero() {
  return (
    <header id="top" className="mx-auto max-w-page px-4 pb-16 pt-14 sm:px-8 sm:pb-24 sm:pt-20">
      <p className="font-mono text-[12px] uppercase tracking-[.14em] text-muted">
        Autonomous AppSec agent · Python · MIT
      </p>
      <div className="mt-8 grid gap-12 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] lg:items-end">
        <div>
          <h1 className="text-[40px] font-semibold leading-[1.04] tracking-[-0.025em] text-ink sm:text-[60px]">
            A finding is a claim.
            <br />
            Sentinel makes it <span className="text-proof">prove itself</span>.
          </h1>
          <p className="mt-6 max-w-[54ch] text-[17px] leading-[1.6] text-body sm:text-[18px]">
            An LLM will invent a vulnerability, then write an exploit that &ldquo;proves&rdquo; it
            without ever running your code. Sentinel runs the exploit against the exact line it
            accused, under a tracer, and grades the finding by what actually executed. Then it
            replays the same exploit against its own fix.
          </p>
          <div className="mt-8 flex flex-wrap gap-3 text-[15px]">
            <a href={REPO} target="_blank" rel="noopener noreferrer"
               className="inline-flex items-center gap-2 bg-ink px-5 py-2.5 font-medium text-paper hover:opacity-85">
              <Github className="h-4 w-4" aria-hidden /> Read the source
            </a>
            <a href="./sample-report.html"
               className="inline-flex items-center gap-2 border border-ink px-5 py-2.5 font-medium text-ink hover:bg-panel">
              Sample report <ArrowUpRight className="h-4 w-4" aria-hidden />
            </a>
          </div>
        </div>

        <figure className="min-w-0 border border-rule bg-panel">
          <figcaption className="flex justify-between border-b border-rule px-4 py-2 font-mono text-[11.5px] text-muted">
            <span>evidence record</span><span>illustrative</span>
          </figcaption>
          <dl className="px-4 py-3 font-mono text-[12.5px] leading-[1.9]">
            {RECORD.map(([k, v, tone]) => (
              <div key={k} className="grid grid-cols-[72px_minmax(0,1fr)] gap-3">
                <dt className="text-muted">{k}</dt>
                <dd className={cn("min-w-0 break-words text-ink", tone)}>{v}</dd>
              </div>
            ))}
          </dl>
        </figure>
      </div>
    </header>
  );
}

/* ---------------------------------------------------------------- problem */

const GENERIC = `import sqlite3
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE t (a TEXT)")
q = "SELECT * FROM t WHERE a = '" + payload + "'"
if conn.execute(q).fetchall():
    print("SENTINEL_PWNED")`;

const TARGETED = `import app
conn = app.setup()
rows = app.login(conn, "' OR '1'='1")
if rows:
    print("SENTINEL_PWNED")`;

function Exhibit({ tag, head, code, trace, verdict, tone }) {
  return (
    <figure className="flex min-w-0 flex-col border border-rule">
      <figcaption className="flex items-baseline justify-between border-b border-rule px-4 py-2.5">
        <span className="text-[14.5px] font-medium text-ink">{head}</span>
        <span className="font-mono text-[11.5px] text-muted">{tag}</span>
      </figcaption>
      <pre className="flex-1 overflow-x-auto bg-panel p-4 font-mono text-[12.5px] leading-relaxed text-ink">{code}</pre>
      <dl className="grid grid-cols-3 border-t border-rule font-mono text-[12px]">
        <div className="border-r border-rule px-4 py-2.5"><dt className="text-muted">marker</dt><dd className="text-proof">printed</dd></div>
        <div className="border-r border-rule px-4 py-2.5"><dt className="text-muted">trace</dt><dd className={trace.ok ? "text-proof" : "text-sev"}>{trace.text}</dd></div>
        <div className="px-4 py-2.5"><dt className="text-muted">graded</dt><dd className={cn("font-semibold", tone)}>{verdict}</dd></div>
      </dl>
    </figure>
  );
}

function Problem() {
  return (
    <Section id="problem" n="01" label="Problem"
      title="Both exploits print the success marker. One of them never ran your code."
      lede="A scanner that checks for the marker alone reports these identically, and that is how a confident, well-formatted, fabricated finding reaches a developer.">
      <div className="mt-10 grid gap-4 md:grid-cols-2">
        <Exhibit tag="A" head="Reproduces the pattern in isolation" code={GENERIC}
                 trace={{ ok: false, text: "app.py never ran" }} verdict="CLASS ONLY" tone="text-warn" />
        <Exhibit tag="B" head="Drives the reported code" code={TARGETED}
                 trace={{ ok: true, text: "app.py:33 ran" }} verdict="LINE PROVEN" tone="text-proof" />
      </div>
      <p className="mt-8 max-w-[66ch] text-[15.5px] leading-[1.65] text-body">
        Published work on generated exploits found that re-running them with instrumentation
        invalidated roughly <strong className="font-semibold text-ink">44%</strong> of those that had passed a
        marker-only check. Those systems compare the trace with a location from a labelled benchmark,
        which measures a technique but cannot run on unlabelled code. Sentinel uses the finding&rsquo;s
        own reported line as the target, so the check needs no ground truth.
      </p>
      <ProofLab />
    </Section>
  );
}

/* ----------------------------------------------------------------- method */

function Method() {
  return (
    <Section id="method" n="02" label="Method"
      title="Grade every candidate by what was demonstrated."
      lede="A yes/no scanner throws away the most useful thing it knows: how much it actually showed. The cheap deterministic check runs before the expensive stochastic one, so invented candidates cost nothing to reject.">
      <Table head={["Tier", "Rule", "What happens"]}>
        {TIERS.map((t) => (
          <tr key={t.key}>
            <td className={cn("whitespace-nowrap px-4 py-3 font-mono text-[12.5px] font-semibold uppercase tracking-wide", toneText[t.tone])}>{t.label}</td>
            <td className="px-4 py-3 text-body">{t.rule}</td>
            <td className="px-4 py-3 text-muted">{t.counted}</td>
          </tr>
        ))}
      </Table>

      <ol className="mt-14 grid gap-px border border-rule bg-rule sm:grid-cols-2 lg:grid-cols-3">
        {PIPELINE.map((s) => (
          <li key={s.n} className="bg-paper p-5">
            <p className="font-mono text-[12px] text-muted">{s.n}</p>
            <h3 className="mt-1 text-[17px] font-semibold text-ink">{s.title}</h3>
            <p className="mt-2 text-[14.5px] leading-[1.6] text-body">{s.body}</p>
          </li>
        ))}
      </ol>

      <h3 className="mt-16 text-[20px] font-semibold text-ink">The static gate</h3>
      <p className="mt-3 max-w-[64ch] text-[15.5px] leading-[1.65] text-body">
        On the clean control, attacker data genuinely reaches <code className="font-mono text-[14px]">cursor.execute</code> and{" "}
        <code className="font-mono text-[14px]">subprocess.run</code>. The code is safe because of how those calls are
        made, so a gate that modelled taint alone would catch nothing. It may reject only on positive
        evidence; the last row is it declining to guess.
      </p>
      <Table head={["Claim", "Location", "Verdict", "Reason"]} min={680}>
        {GATE.map((g) => (
          <tr key={g.file + g.claim}>
            <td className="px-4 py-3 text-ink">{g.claim}</td>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-[12.5px] text-body">{g.file}</td>
            <td className={cn("whitespace-nowrap px-4 py-3 font-mono text-[12.5px]", g.blocked ? "text-ink" : "text-muted")}>
              {g.blocked ? "rejected · " : "proceeds · "}{g.verdict}
            </td>
            <td className="px-4 py-3 text-muted">{g.detail}</td>
          </tr>
        ))}
      </Table>
    </Section>
  );
}

/* -------------------------------------------------------------- hardening */

const SEV_TONE = { critical: "text-sev", high: "text-sev", medium: "text-warn" };

function Hardening() {
  return (
    <Section id="hardening" n="03" label="Hardening"
      title="The exploit is untrusted code. So is the code being scanned."
      lede="A scanner earns its keep on code nobody has vetted, and that code can carry instructions for the model reading it. Each control below is pinned by a test that fails if it is removed.">
      <div className="mt-10 grid gap-px border border-rule bg-rule md:grid-cols-3">
        {CONTROLS.map((c) => (
          <div key={c.title} className="bg-paper p-5">
            <h3 className="text-[16px] font-semibold text-ink">{c.title}</h3>
            <ul className="mt-3 space-y-1.5 text-[14px] leading-[1.5] text-body">
              {c.items.map((item) => (
                <li key={item} className="flex gap-2">
                  <span className="mt-[9px] h-px w-2.5 shrink-0 bg-muted" aria-hidden />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <h3 className="mt-16 text-[20px] font-semibold text-ink">Audit, September 2026</h3>
      <p className="mt-3 max-w-[64ch] text-[15.5px] leading-[1.65] text-body">
        A review of the pipeline against its own threat model. Every finding was reproduced
        against the prior code before it was fixed, and each fix ships with a regression test.
      </p>
      <Table head={["Severity", "Area", "Finding", "Fix"]} min={760}>
        {AUDIT.map((a) => (
          <tr key={a.area + a.finding.slice(0, 20)} className="align-top">
            <td className={cn("px-4 py-3 font-mono text-[12px] font-semibold uppercase", SEV_TONE[a.severity])}>{a.severity}</td>
            <td className="px-4 py-3 text-ink">{a.area}</td>
            <td className="px-4 py-3 text-body">{a.finding}</td>
            <td className="px-4 py-3 text-muted">{a.fix}</td>
          </tr>
        ))}
      </Table>
    </Section>
  );
}

/* ---------------------------------------------------------------- results */

function Results() {
  return (
    <Section id="results" n="04" label="Results"
      title="Measured, with the caveats that come with it."
      lede="Three runs of the current pipeline with gpt-oss-120b, on four targets holding five labelled bugs and a clean control, exploits running in each target's dependency image with the network off.">
      <div className="mt-8 border border-l-4 border-rule border-l-warn bg-panel p-5 text-[15px] leading-[1.6] text-body">
        <strong className="font-semibold text-ink">Re-measurement pending.</strong> These runs predate the
        September 2026 audit. The benchmark targets then carried comments naming each bug, which the model
        could read, and the gate and witness fixes change grading. Treat the figures as history until the
        next run lands in <code className="font-mono text-[13.5px]">benchmarks/results/</code>.
      </div>

      <Table head={["Run", "Strict recall · line proven", "Permissive recall · marker", "False positives", "Note"]} min={680}>
        {CURRENT_RUNS.map((r) => (
          <tr key={r.run}>
            <td className="px-4 py-3 font-mono text-muted">{r.run}</td>
            <td className="px-4 py-3"><span className="text-[17px] font-semibold text-ink">{r.strict}</span> <span className="text-muted">({r.strictN})</span></td>
            <td className="px-4 py-3"><span className="text-[17px] font-semibold text-ink">{r.permissive}</span> <span className="text-muted">({r.permissiveN})</span></td>
            <td className="px-4 py-3 font-mono text-ink">{r.fp}</td>
            <td className="px-4 py-3 text-muted">{r.note}</td>
          </tr>
        ))}
      </Table>

      <div className="mt-8 grid gap-6 text-[15px] leading-[1.65] text-body md:grid-cols-2">
        <p>
          <strong className="font-semibold text-ink">Strict recall cannot exceed 80% here.</strong> The
          hardcoded secret sits on a module-level line that runs only on import, and import-time
          execution is never counted. That one finding is the whole gap between the two readings in every run.
        </p>
        <p>
          <strong className="font-semibold text-ink">There is no precision figure.</strong> Three or four
          findings were line-proven per run, too few to divide by, and the clean control was only
          analysed in one run: in the other two the model&rsquo;s reply could not be parsed.{" "}
          <a href={RESULTS_FILE} className="text-ink underline" target="_blank" rel="noopener noreferrer">Unedited results file</a>.
        </p>
      </div>

      <details className="mt-10 border border-rule">
        <summary className="cursor-pointer px-4 py-3 text-[15px] font-medium text-ink hover:bg-panel">
          v1 runs, August 2026: a different validator
        </summary>
        <div className="border-t border-rule px-4 pb-5">
          <p className="mt-4 max-w-[66ch] text-[14.5px] leading-[1.6] text-body">
            The v1 validator asked for self-contained exploits that did not import the target, so every
            success below reproduced a pattern in isolation: class-only at best on today&rsquo;s ladder.
            Kept because it is what was measured.
          </p>
          <Table head={["Run", "Model", "Precision", "Recall", "F1", "Note"]} min={620}>
            {V1_RUNS.map((r) => (
              <tr key={r.run}>
                <td className="px-4 py-3 font-mono text-muted">{r.run}</td>
                <td className="px-4 py-3 font-mono text-[12.5px] text-body">{r.model}</td>
                <td className="px-4 py-3 text-ink">{r.precision}</td>
                <td className="px-4 py-3 text-ink">{r.recall}</td>
                <td className="px-4 py-3 text-ink">{r.f1}</td>
                <td className="px-4 py-3 text-muted">{r.note}</td>
              </tr>
            ))}
          </Table>
        </div>
      </details>
    </Section>
  );
}

/* ------------------------------------------------------------------ usage */

function Usage() {
  return (
    <Section id="usage" n="05" label="Output"
      title="A case file for people, SARIF for pipelines."
      lede="A scan writes a self-contained HTML report with no script and no external requests, JSON, and SARIF 2.1.0 for GitHub code scanning. Only line-proven findings are errors and only they can fail a build; class-only findings are warnings; suspicions stay out of the dashboard.">
      <div className="mt-10 grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <figure className="min-w-0 border border-rule">
          <img src="./report-preview.png" loading="lazy" className="block w-full"
               alt="Sentinel's HTML report rendered from the test fixture: one line-proven SQL injection, class-only, not-testable and gated-out candidates." />
          <figcaption className="border-t border-rule px-4 py-2.5 text-[13px] text-muted">
            The real renderer on the test fixture, so every tier appears. Not a scan result.{" "}
            <a className="text-ink underline" href="./sample-report.html">Open it</a>.
          </figcaption>
        </figure>
        <figure className="flex min-w-0 flex-col border border-rule">
          <figcaption className="border-b border-rule px-4 py-2.5 font-mono text-[11.5px] text-muted">
            .github/workflows/security.yml · excerpt
          </figcaption>
          <pre className="flex-1 overflow-x-auto bg-panel p-4 font-mono text-[12.5px] leading-relaxed text-ink">{CI_SNIPPET}</pre>
        </figure>
      </div>
    </Section>
  );
}

/* ----------------------------------------------------------------- limits */

function Limits() {
  return (
    <Section id="limits" n="06" label="Limits" title="What it does not do.">
      <ol className="mt-8 divide-y divide-rule border-y border-rule">
        {LIMITS.map((l, i) => (
          <li key={l} className="grid grid-cols-[32px_minmax(0,1fr)] gap-3 py-4 text-[15px] leading-[1.6] text-body">
            <span className="font-mono text-[12px] leading-[1.6rem] text-muted">{String(i + 1).padStart(2, "0")}</span>
            <span>{l}</span>
          </li>
        ))}
      </ol>
    </Section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-rule">
      <div className="mx-auto flex max-w-page flex-wrap items-baseline justify-between gap-4 px-4 py-10 text-[14px] sm:px-8">
        <p className="text-muted">
          <span className="font-mono font-semibold tracking-[.14em] text-ink">SENTINEL</span>{" "}
          · Rahul Paul · MIT licensed
        </p>
        <div className="flex gap-5">
          <a className="text-body hover:text-ink" href={REPO} target="_blank" rel="noopener noreferrer">Source</a>
          <a className="text-body hover:text-ink" href={`${REPO}#quickstart`} target="_blank" rel="noopener noreferrer">Quickstart</a>
          <a className="text-body hover:text-ink" href="https://github.com/rahulpaul-07" target="_blank" rel="noopener noreferrer">GitHub</a>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Problem />
        <Method />
        <Hardening />
        <Results />
        <Usage />
        <Limits />
      </main>
      <Footer />
    </>
  );
}
