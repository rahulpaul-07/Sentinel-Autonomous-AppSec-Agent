import { useEffect, useState } from "react";
import { LazyMotion, MotionConfig, domAnimation } from "motion/react";
import { ArrowUpRight, Github, Moon, Sun } from "lucide-react";

import { Faq } from "@/components/faq";
import { ProofLab } from "@/components/proof-lab";
import { RepoExplorer } from "@/components/repo-explorer";
import { ResultsStrip } from "@/components/results-strip";
import { StageExplorer } from "@/components/stage-explorer";
import { BlurFade } from "@/components/ui/blur-fade";
import { CopyBlock } from "@/components/ui/copy-block";
import { NumberTicker } from "@/components/ui/number-ticker";
import { ScrollProgress } from "@/components/ui/scroll-progress";
import { AnimatedSpan, Terminal, TypingAnimation } from "@/components/ui/terminal";
import { cn } from "@/lib";
import {
  AUDIT, CI_JOBS, CI_SNIPPET, CONTROLS, CURRENT_RUNS, FACTS, LIMITS, POC_GYM,
  PRE_AUDIT_FILE, QUICKSTART, REPO, RESULTS_FILE, STACK, TIERS, V1_RUNS,
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

const NAV = [["problem", "Demo"], ["method", "How it works"], ["results", "Results"],
             ["hardening", "Security"], ["quickstart", "Quickstart"], ["faq", "FAQ"]];

function Nav() {
  const toggle = useTheme();
  return (
    <nav className="sticky top-0 z-40 border-b border-rule bg-paper/90 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-page items-center gap-6 px-4 sm:px-8">
        <a href="#top" className="font-mono text-[14px] font-semibold tracking-[.14em] text-ink">SENTINEL</a>
        <div className="ml-auto flex items-center gap-5 text-[14px]">
          {NAV.map(([id, label]) => (
            <a key={id} href={`#${id}`} className="hidden text-body hover:text-ink lg:inline">{label}</a>
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

/** An accent phrase in the italic serif. Used once per headline at most. */
const Em = ({ children, className }) => (
  <em className={cn("font-serif text-[1.08em] font-normal italic tracking-normal", className)}>{children}</em>
);

function Section({ id, n, label, title, lede, children }) {
  return (
    <section id={id} className="border-t border-rule">
      <div className="mx-auto grid max-w-page gap-x-12 px-4 py-16 sm:px-8 sm:py-24 lg:grid-cols-[180px_minmax(0,1fr)]">
        <p className="mb-4 font-mono text-[12px] uppercase tracking-[.14em] text-muted lg:sticky lg:top-24 lg:self-start">
          <span className="text-ink">§{n}</span> {label}
        </p>
        <div className="min-w-0">
          <BlurFade>
            {title && (
              <h2 className="max-w-[24ch] text-[30px] font-semibold leading-[1.12] tracking-[-0.02em] text-ink sm:text-[42px]">
                {title}
              </h2>
            )}
            {lede && <p className="mt-5 max-w-[64ch] text-[16px] leading-[1.65] text-body">{lede}</p>}
          </BlurFade>
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

const NBSP = " ";

function HeroTerminal() {
  return (
    <div className="min-w-0">
      <Terminal title="~/sentinel" note="illustrative">
        <TypingAnimation className="text-ink">$ sentinel targets/vulnerable_app --build-env --no-patch --sarif sentinel.sarif</TypingAnimation>
        <AnimatedSpan className="text-muted">Scanning targets/vulnerable_app with groq/openai/gpt-oss-120b ...</AnimatedSpan>
        <AnimatedSpan>{NBSP}</AnimatedSpan>
        <AnimatedSpan>Target: targets/vulnerable_app</AnimatedSpan>
        <AnimatedSpan className="text-body">  Sandbox image:        sentinel-env:bb86bd8c197a (cached)</AnimatedSpan>
        <AnimatedSpan className="text-body">  Candidate findings:   3</AnimatedSpan>
        <AnimatedSpan className="text-body">  Gated out (no path):  0</AnimatedSpan>
        <AnimatedSpan className="text-body">  Line-proven:          <span className="font-semibold text-proof">2</span></AnimatedSpan>
        <AnimatedSpan className="text-body">  Class-only:           <span className="font-semibold text-warn">1</span></AnimatedSpan>
        <AnimatedSpan className="text-body">  Not testable:         0</AnimatedSpan>
        <AnimatedSpan>{NBSP}</AnimatedSpan>
        <AnimatedSpan className="text-proof">  [LINE PROVEN] SQL Injection  app.py:33</AnimatedSpan>
        <AnimatedSpan className="text-proof">  [LINE PROVEN] Command Injection  app.py:45</AnimatedSpan>
        <AnimatedSpan>{NBSP}</AnimatedSpan>
        <AnimatedSpan className="text-warn">  1 candidate(s) had a working exploit that never reached the reported line.</AnimatedSpan>
        <AnimatedSpan className="text-muted">  These prove the vulnerability class, not this code. Not counted, not patched.</AnimatedSpan>
        <AnimatedSpan className="text-body">SARIF written to sentinel.sarif</AnimatedSpan>
      </Terminal>
      <p className="mt-2 text-[12.5px] leading-relaxed text-muted">
        The CLI&rsquo;s output format with the grades of run 1 in the{" "}
        <a href={RESULTS_FILE} className="underline hover:text-ink" target="_blank" rel="noopener noreferrer">26 September record</a>;
        severities omitted.
      </p>
    </div>
  );
}

function Fact({ f }) {
  const parts = String(f.value).split(/(\d+)/).filter(Boolean);
  return (
    <div className="bg-paper px-5 py-4">
      <dt className="text-[13px] text-muted">{f.note}</dt>
      <dd className="mt-1 text-ink">
        <span className="text-[26px] font-semibold tracking-[-0.01em]">
          {parts.map((p, i) => (/^\d+$/.test(p) ? <NumberTicker key={i} value={Number(p)} /> : <span key={i}>{p}</span>))}
        </span>{" "}
        <span className="text-[15px]">{f.unit}</span>
      </dd>
    </div>
  );
}

function Hero() {
  return (
    <header id="top" className="mx-auto max-w-page px-4 pb-16 pt-14 sm:px-8 sm:pb-20 sm:pt-20">
      <p className="font-mono text-[12px] uppercase tracking-[.14em] text-muted">
        Autonomous AppSec agent · Python · MIT
      </p>
      <div className="mt-8 grid gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)] lg:items-center">
        <BlurFade>
          <h1 className="text-[44px] font-semibold leading-[1.02] tracking-[-0.03em] text-ink sm:text-[64px]">
            A finding is a claim.<br className="hidden sm:block" /> Sentinel makes it <Em className="text-proof">prove itself.</Em>
          </h1>
          <p className="mt-6 max-w-[52ch] text-[17px] leading-[1.6] text-body sm:text-[18px]">
            An LLM will invent a vulnerability, then write an exploit that &ldquo;proves&rdquo; it without
            running your code. Sentinel runs the exploit against the exact line it accused, under a tracer,
            and grades the finding by what actually executed. Then it replays the exploit against its own fix.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3 text-[15px]">
            <a href={REPO} target="_blank" rel="noopener noreferrer"
               className="inline-flex items-center gap-2 bg-ink px-5 py-2.5 font-medium text-paper hover:opacity-85">
              <Github className="h-4 w-4" aria-hidden /> Read the source
            </a>
            <a href="#problem"
               className="inline-flex items-center gap-2 border border-ink px-5 py-2.5 font-medium text-ink hover:bg-panel">
              Try the tracer
            </a>
            <a href="./sample-report.html"
               className="inline-flex items-center gap-1 px-2 py-2.5 font-medium text-ink underline decoration-rule underline-offset-4 hover:decoration-ink">
              Sample report <ArrowUpRight className="h-4 w-4" aria-hidden />
            </a>
          </div>
        </BlurFade>
        <HeroTerminal />
      </div>

      <dl className="mt-14 grid grid-cols-2 gap-px border border-rule bg-rule lg:grid-cols-4">
        {FACTS.map((f) => <Fact key={f.unit} f={f} />)}
      </dl>
    </header>
  );
}

/* ---------------------------------------------------------------- problem */

function Problem() {
  return (
    <Section id="problem" n="01" label="Demo"
      title={<>Both exploits print the success marker. One of them <Em>never ran</Em> your code.</>}
      lede="A scanner that checks for the marker alone reports these identically. That is how a confident, well-formatted, fabricated finding reaches a developer.">
      <p className="mt-6 max-w-[66ch] text-[15.5px] leading-[1.65] text-body">
        In PoC-Gym&rsquo;s study of LLM-written Java exploits,{" "}
        <strong className="font-semibold text-ink">44%</strong> of the ones its runtime check accepted never
        reached the real vulnerable location (
        <a href={POC_GYM} className="text-ink underline" target="_blank" rel="noopener noreferrer">arXiv:2602.04165</a>,
        §5.1). That re-check needs a labelled benchmark to say where the bug is. Sentinel uses the
        finding&rsquo;s own reported line as the target, so it needs no ground truth. Pick an exploit and
        replay its trace: each is a recorded run of the real harness.
      </p>
      <ProofLab />
    </Section>
  );
}

/* ----------------------------------------------------------------- method */

function Method() {
  return (
    <Section id="method" n="02" label="How it works"
      title={<>Six stages. The cheap, deterministic one runs <Em>first</Em>.</>}
      lede="Invented candidates should cost nothing to reject, so a static gate runs before any exploit is written. Step through the pipeline: each stage shows a real artifact from the code.">
      <StageExplorer />

      <h3 className="mt-16 text-[20px] font-semibold text-ink">The evidence ladder</h3>
      <p className="mt-3 max-w-[64ch] text-[15.5px] leading-[1.65] text-body">
        A yes/no scanner throws away the most useful thing it knows: how much it actually showed.
        Collapsing class-only into &ldquo;confirmed&rdquo; is the overstatement this project exists to avoid.
      </p>
      <Table head={["Tier", "Rule", "What happens"]}>
        {TIERS.map((t) => (
          <tr key={t.key}>
            <td className={cn("whitespace-nowrap px-4 py-3 font-mono text-[12.5px] font-semibold uppercase tracking-wide", toneText[t.tone])}>{t.label}</td>
            <td className="px-4 py-3 text-body">{t.rule}</td>
            <td className="px-4 py-3 text-muted">{t.counted}</td>
          </tr>
        ))}
      </Table>
    </Section>
  );
}

/* ---------------------------------------------------------------- results */

function Stat({ label, children, note }) {
  return (
    <div className="bg-paper px-5 py-5">
      <dt className="text-[13px] text-muted">{label}</dt>
      <dd className="mt-1 text-[34px] font-semibold tracking-[-0.02em] text-ink">{children}</dd>
      <dd className="text-[13px] text-muted">{note}</dd>
    </div>
  );
}

function Results() {
  return (
    <Section id="results" n="03" label="Results"
      title={<>Measured after the audit, <Em>including</Em> what went wrong.</>}
      lede="Three runs on 26 September 2026 with gpt-oss-120b: four targets holding five labelled bugs and a clean control, exploits running with the network off. A range is reported because one case moves recall by 20 points.">
      <dl className="mt-10 grid gap-px border border-rule bg-rule sm:grid-cols-3">
        <Stat label="Strict recall" note="line proven, 3 runs">
          <NumberTicker value={60} />&ndash;<NumberTicker value={80} />%
        </Stat>
        <Stat label="Strict precision" note="line proven, 3 runs">
          <NumberTicker value={75} />&ndash;<NumberTicker value={100} />%
        </Stat>
        <Stat label="False proofs" note="on the clean control">
          <span className="text-sev"><NumberTicker value={2} /></span> of 3 runs
        </Stat>
      </dl>

      <ResultsStrip />

      <div className="mt-8 border border-l-4 border-rule border-l-sev bg-panel p-5 text-[15px] leading-[1.6] text-body">
        <strong className="font-semibold text-ink">The false proof, disclosed.</strong> In two runs the model
        claimed SSRF on the control&rsquo;s <code className="font-mono text-[13.5px]">ping</code> route. The gate has
        no SSRF model for a subprocess call, so it failed open as designed. The exploit then changed the sandbox
        environment so the route looked exploited, ran the accused line, and printed the marker itself. The tracer
        confirmed the line ran, so it was graded line proven. The marker is the exploit&rsquo;s own word, and
        closing that gap is the top roadmap item.
      </div>

      <details className="mt-8 border border-rule">
        <summary className="cursor-pointer px-4 py-3 text-[15px] font-medium text-ink hover:bg-panel">
          Per-run table and records
        </summary>
        <div className="border-t border-rule px-4 pb-5">
          <Table head={["Run", "Strict recall", "Strict precision", "False proofs", "Note"]} min={640}>
            {CURRENT_RUNS.map((r) => (
              <tr key={r.run} className="align-top">
                <td className="px-4 py-3 font-mono text-muted">{r.run}</td>
                <td className="px-4 py-3 text-ink">{r.strict} <span className="text-muted">({r.strictN})</span></td>
                <td className="px-4 py-3 text-ink">{r.precision}</td>
                <td className={cn("px-4 py-3 font-mono", r.fp ? "text-sev" : "text-ink")}>{r.fp}</td>
                <td className="px-4 py-3 text-muted">{r.note}</td>
              </tr>
            ))}
          </Table>
          <p className="mt-4 text-[14px] leading-[1.6] text-body">
            <a href={RESULTS_FILE} className="text-ink underline" target="_blank" rel="noopener noreferrer">Unedited results file</a>.
            Before the audit, with answer-key comments still in the targets, the same model scored 60&ndash;80%
            (<a href={PRE_AUDIT_FILE} className="text-ink underline" target="_blank" rel="noopener noreferrer">record</a>).
            A local qwen2.5-coder:7b line-proved 0&ndash;20% with no false proofs.
          </p>
        </div>
      </details>

      <details className="mt-4 border border-rule">
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

/* -------------------------------------------------------------- hardening */

const SEV_TONE = { critical: "text-sev", high: "text-sev", medium: "text-warn" };

function Hardening() {
  return (
    <Section id="hardening" n="04" label="Security"
      title={<>The exploit is untrusted code. So is the code <Em>being scanned</Em>.</>}
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
        A review of the pipeline against its own threat model. Every finding was reproduced against the prior
        code before it was fixed, and each fix ships with a regression test.
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

/* ------------------------------------------------------------- quickstart */

function Quickstart() {
  return (
    <Section id="quickstart" n="05" label="Quickstart"
      title={<>Python 3.12, Docker, and <Em>any</Em> model you have.</>}
      lede="A free Groq or Gemini key works, as does a local Ollama model or an Anthropic or OpenAI key. The provider is one line in .env. Without Docker the scanner stops with a clear error instead of reporting that it found nothing.">
      <div className="mt-10">
        <CopyBlock caption="terminal" code={QUICKSTART} />
      </div>
      <p className="mt-6 max-w-[66ch] text-[15px] leading-[1.65] text-body">
        A scan writes a self-contained HTML report with no script and no external requests, JSON, and SARIF
        2.1.0. Only line-proven findings are errors, and only they can fail a build. Exit codes separate a failing
        finding (1) from bad input (2), no Docker (3), an exhausted quota (4) and a refused model request (5).{" "}
        <a className="text-ink underline" href={`${REPO}#command-line-options`} target="_blank" rel="noopener noreferrer">All options</a>.
      </p>
      <div className="mt-10 grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <figure className="min-w-0 border border-rule">
          <img src="./report-preview.png" loading="lazy" className="block w-full"
               alt="Sentinel's HTML report rendered from the test fixture: one line-proven SQL injection, class-only, not-testable and gated-out candidates." />
          <figcaption className="border-t border-rule px-4 py-2.5 text-[13px] text-muted">
            The real renderer on the test fixture, so every tier appears. Not a scan result.{" "}
            <a className="text-ink underline" href="./sample-report.html">Open it</a>.
          </figcaption>
        </figure>
        <CopyBlock caption=".github/workflows/security.yml · excerpt" code={CI_SNIPPET} />
      </div>
    </Section>
  );
}

/* ------------------------------------------------------------ engineering */

function Engineering() {
  return (
    <Section id="engineering" n="06" label="Engineering"
      title={<>Tested at the boundaries where it <Em>could lie</Em>.</>}
      lede="Most tests stub the model and the container, and assert on how each was called, not only on what came back. That rule exists because of a real bug: the validator once never mounted the target, every exploit died on import, and every stubbed test still passed.">
      <ol className="mt-10 grid gap-px border border-rule bg-rule sm:grid-cols-2 lg:grid-cols-3">
        {CI_JOBS.map((j, i) => (
          <li key={j.name} className="bg-paper p-5">
            <p className="font-mono text-[12px] text-muted">CI · {String(i + 1).padStart(2, "0")}</p>
            <h3 className="mt-1 text-[16px] font-semibold text-ink">{j.name}</h3>
            <p className="mt-2 text-[14px] leading-[1.6] text-body">{j.body}</p>
          </li>
        ))}
      </ol>

      <h3 className="mt-14 text-[20px] font-semibold text-ink">Explore the repository</h3>
      <p className="mt-3 max-w-[64ch] text-[15.5px] leading-[1.65] text-body">
        About 4,900 lines of Python in the package. Pick a file to see what it is responsible for.
      </p>
      <RepoExplorer />

      <h3 className="mt-14 text-[20px] font-semibold text-ink">Stack</h3>
      <dl className="mt-5 divide-y divide-rule border-y border-rule text-[15px]">
        {STACK.map(([k, v]) => (
          <div key={k} className="grid gap-1 py-3 sm:grid-cols-[160px_minmax(0,1fr)] sm:gap-4">
            <dt className="font-mono text-[12.5px] uppercase tracking-[.08em] text-muted sm:leading-[1.6rem]">{k}</dt>
            <dd className="text-body">{v}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

/* ---------------------------------------------------------- faq and limits */

function Questions() {
  return (
    <Section id="faq" n="07" label="FAQ" title={<>Questions, <Em>answered</Em>.</>}>
      <Faq />
    </Section>
  );
}

function Limits() {
  return (
    <Section id="limits" n="08" label="Limits" title={<>What it does <Em>not</Em> do.</>}>
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

function Closing() {
  return (
    <section className="border-t border-rule bg-panel">
      <div className="mx-auto flex max-w-page flex-col items-start gap-8 px-4 py-20 sm:px-8 lg:flex-row lg:items-end lg:justify-between">
        <BlurFade>
          <p className="max-w-[18ch] text-[38px] font-semibold leading-[1.05] tracking-[-0.02em] text-ink sm:text-[52px]">
            Read the code. <Em>Run the benchmark.</Em>
          </p>
        </BlurFade>
        <div className="flex flex-wrap gap-3 text-[15px]">
          <a href={REPO} target="_blank" rel="noopener noreferrer"
             className="inline-flex items-center gap-2 bg-ink px-5 py-2.5 font-medium text-paper hover:opacity-85">
            <Github className="h-4 w-4" aria-hidden /> Source on GitHub
          </a>
          <a href="#quickstart" className="inline-flex items-center gap-2 border border-ink px-5 py-2.5 font-medium text-ink hover:bg-paper">
            Quickstart
          </a>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-rule">
      <div className="mx-auto flex max-w-page flex-wrap items-baseline justify-between gap-4 px-4 py-10 text-[14px] sm:px-8">
        <p className="text-muted">
          <span className="font-mono font-semibold tracking-[.14em] text-ink">SENTINEL</span>{" "}
          · designed and built by{" "}
          <a className="text-ink underline" href="https://github.com/rahulpaul-07" target="_blank" rel="noopener noreferrer">Rahul Paul</a>
          {" "}· MIT licensed
        </p>
        <div className="flex gap-5">
          <a className="text-body hover:text-ink" href={REPO} target="_blank" rel="noopener noreferrer">Source</a>
          <a className="text-body hover:text-ink" href={`${REPO}/blob/master/CHANGELOG.md`} target="_blank" rel="noopener noreferrer">Changelog</a>
          <a className="text-body hover:text-ink" href={`${REPO}/blob/master/SECURITY.md`} target="_blank" rel="noopener noreferrer">Security policy</a>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  return (
    <LazyMotion features={domAnimation} strict>
    <MotionConfig reducedMotion="user">
      <ScrollProgress />
      <Nav />
      <main>
        <Hero />
        <Problem />
        <Method />
        <Results />
        <Hardening />
        <Quickstart />
        <Engineering />
        <Questions />
        <Limits />
        <Closing />
      </main>
      <Footer />
    </MotionConfig>
    </LazyMotion>
  );
}
