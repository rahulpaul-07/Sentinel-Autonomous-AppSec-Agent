import { useRef } from "react";
import { motion } from "motion/react";
import { ShieldCheck, Github, ArrowRight, Check, X, Minus } from "lucide-react";

import { Terminal, AnimatedSpan, TypingAnimation } from "@/components/ui/terminal";
import { BorderBeam } from "@/components/ui/border-beam";
import { NumberTicker } from "@/components/ui/number-ticker";
import { DotPattern } from "@/components/ui/dot-pattern";
import { AnimatedBeam } from "@/components/ui/animated-beam";
import { cn } from "@/lib";
import { REPO, RUNS, GATE, PIPELINE, TIERS, LIMITS } from "./data";

/* ------------------------------------------------------------------ shell */

function Nav() {
  return (
    <nav className="sticky top-0 z-50 border-b border-line bg-base/80 backdrop-blur-xl">
      <div className="mx-auto flex h-15 max-w-5xl items-center gap-6 px-5 py-3 sm:px-8">
        <a href="#top" className="flex items-center gap-2 font-display text-[17px] font-semibold">
          <ShieldCheck className="mr-1 h-5 w-5 text-violet" strokeWidth={2} />
          Sentinel
        </a>
        <div className="ml-auto flex items-center gap-6 text-sm">
          <a className="hidden text-muted transition-colors hover:text-ink sm:ml-5 sm:inline" href="#problem">Problem</a>
          <a className="hidden text-muted transition-colors hover:text-ink sm:ml-5 sm:inline" href="#how">How</a>
          <a className="hidden text-muted transition-colors hover:text-ink sm:ml-5 sm:inline" href="#results">Results</a>
          <a
            href={REPO} target="_blank" rel="noopener"
            className="relative overflow-hidden rounded-lg border border-line bg-surface px-3.5 py-1.5 transition-colors hover:border-violet"
          >
            GitHub
          </a>
        </div>
      </div>
    </nav>
  );
}

function Section({ id, label, title, lede, children, className }) {
  return (
    <section id={id} className={cn("border-t border-line py-16 sm:py-24", className)}>
      <div className="mx-auto max-w-5xl px-5 sm:px-8">
        {label && <p className="mb-3 font-mono text-[13px] text-violets">{label}</p>}
        {title && (
          <h2 className="max-w-[24ch] font-display text-[28px] font-semibold leading-[1.12] tracking-tight sm:text-[40px]">
            {title}
          </h2>
        )}
        {lede && <p className="mt-4 max-w-[62ch] text-[15px] leading-relaxed text-muted sm:text-base">{lede}</p>}
        {children}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------- hero */

function Hero() {
  return (
    <header className="relative overflow-hidden pb-14 pt-16 sm:pb-20 sm:pt-24">
      <DotPattern className="[mask-image:radial-gradient(420px_circle_at_center,white,transparent)] opacity-60" cr={0.7} />
      <div className="relative mx-auto max-w-5xl px-5 sm:px-8">
        <motion.span
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
          className="mb-6 inline-flex items-center gap-2.5 font-mono text-[13px] text-violets"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-proof shadow-[0_0_0_4px_rgba(47,212,122,.14)]" />
          Autonomous AppSec agent
        </motion.span>

        <motion.h1
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.05 }}
          className="max-w-[15ch] font-display text-[40px] font-semibold leading-[1.02] tracking-[-0.025em] sm:text-[66px]"
        >
          Any scanner can flag it.
          <br />
          This one <span className="text-proof">proves</span> it.
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.12 }}
          className="mt-6 max-w-[60ch] text-[16px] leading-relaxed text-muted sm:text-[19px]"
        >
          An LLM will happily invent a vulnerability, then write an exploit that
          &ldquo;proves&rdquo; it without ever running your code. Sentinel executes the
          exploit against the <span className="text-ink">exact line it accused</span> and
          traces whether that line actually ran.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.18 }}
          className="mt-8 flex flex-wrap gap-3"
        >
          <a
            href={REPO} target="_blank" rel="noopener"
            className="inline-flex items-center gap-2 rounded-lg bg-violet px-5 py-3 text-[15px] font-semibold text-base transition-colors hover:bg-violets"
          >
            <Github className="h-4 w-4" /> View the source
          </a>
          <a
            href="#problem"
            className="inline-flex items-center gap-2 rounded-lg border border-line px-5 py-3 text-[15px] font-medium transition-colors hover:border-faint"
          >
            See the problem <ArrowRight className="h-4 w-4" />
          </a>
        </motion.div>

        <div className="relative mt-12 rounded-xl">
          <Terminal title="sentinel — grading one candidate">
            <TypingAnimation delay={300} className="text-violets">
              $ sentinel targets/vulnerable_app --report report.html
            </TypingAnimation>
            <AnimatedSpan delay={1600} className="text-muted">
              <span><span className="text-faint">ingest</span>{"    "}AST code map · 3 modules</span>
            </AnimatedSpan>
            <AnimatedSpan delay={2000} className="text-warn">
              <span>hunter{"    "}candidate → SQL injection · app.py:33</span>
            </AnimatedSpan>
            <AnimatedSpan delay={2400} className="text-violets">
              <span>gate{"      "}taint path: request.args.get() → cursor.execute · proceed</span>
            </AnimatedSpan>
            <AnimatedSpan delay={2800} className="text-muted">
              <span>sandbox{"   "}docker · network-off · caps-dropped · ephemeral</span>
            </AnimatedSpan>
            <AnimatedSpan delay={3200} className="text-proof">
              <span className="font-bold">sandbox{"   "}SENTINEL_PWNED</span>
            </AnimatedSpan>
            <AnimatedSpan delay={3600} className="text-proof">
              <span className="font-bold">witness{"   "}app.py:33 executed during the exploit</span>
            </AnimatedSpan>
            <AnimatedSpan delay={4100} className="text-proof">
              <span className="font-bold">
                ✓ LINE PROVEN{"  "}
                <span className="font-normal text-ink">SQL injection · critical · fix diff written</span>
              </span>
            </AnimatedSpan>
          </Terminal>
          <BorderBeam size={120} duration={10} />
        </div>
      </div>
    </header>
  );
}

/* ---------------------------------------------------------------- problem */

function ProofRow({ tone, icon: Icon, head, poc, marker, trace, verdict, vtone }) {
  return (
    <div className={cn("rounded-xl border bg-surface p-5", tone)}>
      <div className="mb-3 flex items-center gap-2 font-display text-[15px] font-semibold">
        <Icon className="h-4 w-4" /> {head}
      </div>
      <pre className="mb-4 overflow-x-auto rounded-lg border border-line bg-base p-3 font-mono text-[12px] leading-relaxed text-muted">
{poc}
      </pre>
      <dl className="space-y-2 text-[13px]">
        <div className="flex justify-between gap-3">
          <dt className="text-faint">Success marker</dt>
          <dd className="font-mono text-proof">{marker}</dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-faint">Line trace</dt>
          <dd className={cn("font-mono", trace.ok ? "text-proof" : "text-sev")}>{trace.text}</dd>
        </div>
        <div className="flex justify-between gap-3 border-t border-line pt-2">
          <dt className="text-faint">Graded</dt>
          <dd className={cn("font-mono font-bold", vtone)}>{verdict}</dd>
        </div>
      </dl>
    </div>
  );
}

function Problem() {
  return (
    <Section
      id="problem"
      label="The problem"
      title="Both of these exploits print the success marker."
      lede="Only one of them touched the code it accused. A scanner that checks for the marker alone reports them identically — and that is how a confident, well-formatted, entirely fabricated finding reaches a developer."
    >
      <div className="mt-10 grid gap-4 md:grid-cols-2">
        <ProofRow
          tone="border-sev/40"
          icon={X}
          head="Reproduces the pattern in isolation"
          poc={`import sqlite3
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE t (a TEXT)")
q = "SELECT * FROM t WHERE a = '" + payload + "'"
if conn.execute(q).fetchall():
    print("SENTINEL_PWNED")`}
          marker="printed"
          trace={{ ok: false, text: "app.py never executed" }}
          verdict="CLASS ONLY"
          vtone="text-warn"
        />
        <ProofRow
          tone="border-proof/40"
          icon={Check}
          head="Drives the real reported code"
          poc={`import app
conn = app.setup()
rows = app.login(conn, "' OR '1'='1")
if rows:
    print("SENTINEL_PWNED")`}
          marker="printed"
          trace={{ ok: true, text: "app.py:33 executed" }}
          verdict="LINE PROVEN"
          vtone="text-proof"
        />
      </div>
      <p className="mt-6 max-w-[68ch] text-[15px] leading-relaxed text-muted">
        Published work on generated exploits found that re-running them with
        instrumentation invalidated roughly <span className="text-ink">44%</span> of
        the ones that had passed a marker-only check. Those systems compare the trace
        against a vulnerable location supplied by a labeled benchmark — which works for
        measuring a technique, but not on code where nobody knows the answer yet.
      </p>
    </Section>
  );
}

/* ------------------------------------------------------------ contribution */

function Contribution() {
  return (
    <Section
      id="idea"
      label="The idea"
      title="Make the claim check itself."
      lede="The hunter asserts a class, a file, and a line. That assertion is its own witness target — so the trace can be checked without any ground truth, on code that has never been labeled."
    >
      <div className="relative mt-10 overflow-hidden rounded-xl border border-line bg-surface p-6 sm:p-8">
        <div
          aria-hidden
          className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-violet to-transparent"
        />
        <div className="relative grid gap-6 font-mono text-[13px] sm:grid-cols-3">
          <div>
            <p className="mb-2 text-faint">The claim</p>
            <p className="text-ink">SQL Injection</p>
            <p className="text-violets">app.py:33</p>
          </div>
          <div>
            <p className="mb-2 text-faint">Becomes the target</p>
            <p className="text-muted">trace app.py</p>
            <p className="text-muted">did line 33 run?</p>
          </div>
          <div>
            <p className="mb-2 text-faint">Grades itself</p>
            <p className="text-proof">yes → line proven</p>
            <p className="text-warn">no → class only</p>
          </div>
        </div>
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        {TIERS.map((t) => (
          <div key={t.key} className="rounded-xl border border-line bg-surface p-5">
            <div className="mb-2 flex items-center gap-2.5">
              <span
                className={cn(
                  "rounded-md px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-wide",
                  t.tone === "proof" && "bg-proof/15 text-proof",
                  t.tone === "warn" && "bg-warn/15 text-warn",
                  t.tone === "violet" && "bg-violet/15 text-violets",
                  t.tone === "muted" && "bg-line text-muted"
                )}
              >
                {t.label}
              </span>
              <code className="text-[12px] text-faint">{t.rule}</code>
            </div>
            <p className="text-[14px] leading-relaxed text-muted">{t.meaning}</p>
          </div>
        ))}
      </div>
    </Section>
  );
}

/* --------------------------------------------------------------- pipeline */

function Pipeline() {
  const container = useRef(null);
  const refs = PIPELINE.map(() => useRef(null));

  return (
    <Section
      id="how"
      label="The loop"
      title="Five stages, one rule: nothing ships unproven."
      lede="The cheap deterministic check runs before the expensive stochastic one, so hallucinated candidates are rejected for free rather than after several model calls and container runs."
    >
      <div ref={container} className="relative mt-10">
        {refs.slice(0, -1).map((r, i) => (
          <AnimatedBeam
            key={i}
            containerRef={container}
            fromRef={r}
            toRef={refs[i + 1]}
            duration={5}
            delay={i * 0.6}
            pathWidth={1.5}
          />
        ))}
        <div className="relative grid gap-3">
          {PIPELINE.map((s, i) => (
            <div
              key={s.id}
              ref={refs[i]}
              className={cn(
                "relative overflow-hidden rounded-xl border bg-surface p-5 transition-colors",
                s.accent ? "border-violet/40" : "border-line hover:border-faint"
              )}
            >
              {s.accent && <BorderBeam size={70} duration={9} />}
              <div className="flex items-baseline gap-3">
                <span className="mr-3 font-mono text-[12px] text-faint">{s.n}</span>
                <h3 className="font-display text-[17px] font-semibold tracking-tight">{s.title}</h3>
              </div>
              <p className="mt-2 max-w-[70ch] text-[14px] leading-relaxed text-muted">{s.body}</p>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}

/* ----------------------------------------------------------------- gate */

function Gate() {
  return (
    <Section
      id="gate"
      label="The static gate"
      title="Attacker data reaching a dangerous call is not the same as a bug."
      lede="On the clean control, tainted input genuinely does flow into cursor.execute and subprocess.run. The code is safe because of how those calls are made. A gate that modeled taint alone would wave both through — recognizing the safe idiom is what makes it useful."
    >
      <div className="mt-10 overflow-x-auto rounded-xl border border-line">
        <table className="w-full min-w-[640px] text-left text-[13.5px]">
          <thead>
            <tr className="bg-base/60 font-mono text-[12px] text-faint">
              <th className="px-4 py-3 font-medium">Claim</th>
              <th className="px-4 py-3 font-medium">Location</th>
              <th className="px-4 py-3 font-medium">Verdict</th>
              <th className="px-4 py-3 font-medium">Why</th>
            </tr>
          </thead>
          <tbody>
            {GATE.map((g, i) => (
              <tr key={i} className="border-t border-line">
                <td className="px-4 py-3">{g.claim}</td>
                <td className="px-4 py-3 font-mono text-[12.5px] text-violets">{g.file}</td>
                <td className="px-4 py-3">
                  <span
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[11.5px] font-semibold",
                      g.blocked ? "bg-violet/15 text-violets" : "bg-proof/10 text-proof"
                    )}
                  >
                    {g.blocked ? <X className="h-3 w-3" /> : <Check className="h-3 w-3" />}
                    {g.verdict}
                  </span>
                </td>
                <td className="px-4 py-3 text-muted">{g.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-5 flex items-start gap-2 text-[14px] leading-relaxed text-muted">
        <Minus className="mt-1.5 h-3 w-3 shrink-0 text-faint" />
        <span>
          The last row is the gate declining to guess. An environment-variable read is not
          a string literal, so it cannot be called safe — it fails open and validation
          decides. The gate may only reject on positive evidence, never on ignorance.
        </span>
      </p>
    </Section>
  );
}

/* --------------------------------------------------------------- results */

function Stat({ value, suffix, label, decimals = 0, tone }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-5">
      <div className={cn("font-display text-[30px] font-semibold tracking-tight sm:text-[34px]", tone)}>
        <NumberTicker value={value} decimalPlaces={decimals} suffix={suffix} />
      </div>
      <div className="mt-2 text-[13px] leading-snug text-muted">{label}</div>
    </div>
  );
}

function Results() {
  return (
    <Section
      id="results"
      label="Results · measured August 2026"
      title="Every figure here is a measured range."
      lede="Scored by a reproducible harness against labeled ground truth: four targets, five vulnerability classes, plus a clean control. Hosted providers are not bit-reproducible even at temperature 0, so the same model varies between runs."
    >
      <div className="mt-10 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat value={5} label="Vulnerability classes in the benchmark, plus a clean control" />
        <Stat value={1.0} decimals={2} label="Best observed F1 — all five proven" tone="text-proof" />
        <Stat value={100} suffix="%" label="Recall on the two hardest classes after the self-correction loop, up from 60%" tone="text-proof" />
        <Stat value={60} label="Tests, all running offline — no Docker, no API key" />
      </div>

      <div className="mt-6 overflow-x-auto rounded-xl border border-line">
        <table className="w-full min-w-[620px] text-left text-[13.5px]">
          <thead>
            <tr className="bg-base/60 font-mono text-[12px] text-faint">
              <th className="px-4 py-3 font-medium">Run</th>
              <th className="px-4 py-3 font-medium">Model</th>
              <th className="px-4 py-3 font-medium">Precision</th>
              <th className="px-4 py-3 font-medium">Recall</th>
              <th className="px-4 py-3 font-medium">F1</th>
              <th className="px-4 py-3 font-medium">Note</th>
            </tr>
          </thead>
          <tbody>
            {RUNS.map((r) => (
              <tr key={r.run} className={cn("border-t border-line", r.best && "bg-proof/[.05]")}>
                <td className="px-4 py-3">{r.run}</td>
                <td className="px-4 py-3 font-mono text-[12.5px] text-violets">{r.model}</td>
                <td className={cn("px-4 py-3", r.best && "font-semibold text-proof")}>{r.precision}</td>
                <td className={cn("px-4 py-3", r.best && "font-semibold text-proof")}>{r.recall}</td>
                <td className={cn("px-4 py-3", r.best && "font-semibold text-proof")}>{r.f1}</td>
                <td className="px-4 py-3 text-faint">{r.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-6 rounded-xl border border-line border-l-2 border-l-violet bg-surface p-6">
        <p className="text-[14.5px] leading-relaxed text-muted">
          <span className="font-medium text-ink">Why a range, not a headline number.</span>{" "}
          Five cases is far too few to quote a single figure from with confidence. The
          honest summary is the spread: <span className="text-ink">precision 71–100%, recall 80–100%</span>.
          The result worth defending is not a score but a methodology where every change
          is measurable — the harness caught the recall regression in run 1 and the
          precision drop in run 3 before either slipped past, and{" "}
          <span className="font-medium text-proof">recall on the two hardest classes rose from 60% to 100%</span>{" "}
          after the self-correction loop was added, with precision holding.
        </p>
        <p className="mt-4 text-[14.5px] leading-relaxed text-muted">
          The evaluator now scores the same scan twice — once counting any exploit that
          printed the marker, once counting only line-proven findings. The gap between
          those two numbers is exactly the amount a marker-only scanner overstates.
        </p>
      </div>
    </Section>
  );
}

/* ---------------------------------------------------------------- report */

function Report() {
  return (
    <Section
      id="report"
      label="The artifact"
      title="The output is a case file, not a warning list."
      lede="A scan writes a self-contained HTML report — no external requests, no JavaScript. Each finding carries its evidence tier, the exploit, the line trace that graded it, and the fix diff. Rejected and class-only candidates are shown too, so nothing is silently dropped."
    >
      <div className="relative mt-10 overflow-hidden rounded-xl border border-line bg-surface">
        <img
          src="./report-preview.png"
          alt="Sentinel HTML scan report showing summary tiles, severity breakdown, and a confirmed SQL injection finding with its embedded proof-of-concept exploit and fix diff."
          className="block w-full"
          loading="lazy"
        />
        <div className="border-t border-line px-5 py-4 text-[13.5px] text-muted">
          Generated by <code className="font-mono text-violets">sentinel targets/vulnerable_app --report report.html</code>.
          Sample output from a labeled test target.
        </div>
      </div>
    </Section>
  );
}

/* ---------------------------------------------------------------- limits */

function Limits() {
  return (
    <Section id="limits" label="Honest limits" title="What it does not do.">
      <ul className="mt-8 divide-y divide-line overflow-hidden rounded-xl border border-line bg-surface">
        {LIMITS.map((l, i) => (
          <li key={i} className="px-5 py-4 text-[14.5px] leading-relaxed text-muted">
            {l}
          </li>
        ))}
      </ul>
    </Section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-line py-12">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-5 px-5 sm:px-8">
        <p className="text-[13.5px] leading-relaxed text-faint">
          Sentinel — autonomous AppSec agent.
          <br />
          Inspired by the cyber-reasoning systems of DARPA&rsquo;s AI Cyber Challenge, scoped as a
          single-developer build. MIT licensed.
        </p>
        <div className="flex flex-wrap gap-5 text-[14px]">
          <a className="text-muted transition-colors hover:text-ink" href={REPO} target="_blank" rel="noopener">Source</a>
          <a className="text-muted transition-colors hover:text-ink" href={`${REPO}#quickstart`} target="_blank" rel="noopener">Quickstart</a>
          <a className="text-muted transition-colors hover:text-ink" href="https://github.com/rahulpaul-07" target="_blank" rel="noopener">More work</a>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  return (
    <>
      <Nav />
      <div id="top" />
      <Hero />
      <Problem />
      <Contribution />
      <Pipeline />
      <Gate />
      <Results />
      <Report />
      <Limits />
      <Footer />
    </>
  );
}
