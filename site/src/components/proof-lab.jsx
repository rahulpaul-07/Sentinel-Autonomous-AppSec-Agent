import { useEffect, useRef, useState } from "react";
import { Check, Play, RotateCcw, X } from "lucide-react";

import { cn } from "@/lib";
import { LAB_RUNS, LAB_SINK_LINE, LAB_TARGET } from "@/lab-data";

const TIER = {
  line_proven: { label: "LINE PROVEN", tone: "text-proof", edge: "border-l-proof" },
  class_only: { label: "CLASS ONLY", tone: "text-warn", edge: "border-l-warn" },
  unproven: { label: "UNPROVEN", tone: "text-muted", edge: "border-l-rule" },
};

const STEP_MS = 80;

/** The target source, with executed lines marked as the recorded trace replays. */
function SourceView({ lit, running }) {
  const lines = LAB_TARGET.replace(/\n$/, "").split("\n");
  return (
    <figure className="min-w-0 self-start border border-rule bg-panel">
      <figcaption className="flex items-center justify-between border-b border-rule px-3 py-2 font-mono text-[11.5px] text-muted">
        <span>app.py</span>
        <span aria-live="polite">{running ? "tracing" : `${lit.length} lines executed`}</span>
      </figcaption>
      <pre className="overflow-x-auto py-2 font-mono text-[12.5px] leading-[1.7]">
        {lines.map((text, i) => {
          const n = i + 1;
          const hit = lit.includes(n);
          const sink = n === LAB_SINK_LINE;
          return (
            <div
              key={n}
              className={cn(
                "flex border-l-2 border-transparent px-3",
                hit && "border-l-ink/40 bg-ink/[.05]",
                hit && sink && "border-l-proof bg-proof/[.12]"
              )}
            >
              <span className={cn("mr-4 w-5 shrink-0 select-none text-right",
                                  sink ? "font-semibold text-sev" : "text-muted/70")}>
                {n}
              </span>
              <code className={hit ? "text-ink" : "text-muted"}>{text || " "}</code>
            </div>
          );
        })}
      </pre>
    </figure>
  );
}

function Check_({ label, ok, value }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-rule py-2 last:border-b-0">
      <dt className="text-[13px] text-muted">{label}</dt>
      <dd className={cn("flex items-center gap-1.5 font-mono text-[12.5px]", ok ? "text-proof" : "text-sev")}>
        {ok ? <Check className="h-3.5 w-3.5" aria-hidden /> : <X className="h-3.5 w-3.5" aria-hidden />}
        {value}
      </dd>
    </div>
  );
}

function Verdict({ run }) {
  const t = TIER[run.evidence];
  return (
    <div className={cn("border border-rule border-l-4 bg-paper p-4", t.edge)}>
      <dl>
        <Check_ label="Success marker" ok={run.marker} value={run.marker ? "printed" : "absent"} />
        <Check_ label="Target file executed" ok={run.fileExecuted} value={run.fileExecuted ? "yes" : "no"} />
        <Check_ label={`Accused line ${LAB_SINK_LINE} executed`} ok={run.lineExecuted}
                value={run.lineExecuted ? "yes" : "no"} />
      </dl>
      <p className="mt-3 flex items-baseline justify-between gap-3">
        <span className="text-[13px] text-muted">Graded</span>
        <span className={cn("font-mono text-[13px] font-semibold tracking-wide", t.tone)}>{t.label}</span>
      </p>
      <p className="mt-2 text-[13.5px] leading-relaxed text-body">{run.explain}</p>
    </div>
  );
}

export function ProofLab() {
  const [active, setActive] = useState(0);
  const [lit, setLit] = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const timers = useRef([]);
  const run = LAB_RUNS[active];

  const clear = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };
  useEffect(() => clear, []);

  const reset = () => {
    clear();
    setLit([]);
    setRunning(false);
    setDone(false);
  };

  const execute = () => {
    reset();
    const lines = run.executedLines;
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduced || lines.length === 0) {
      setLit(lines);
      setDone(true);
      return;
    }
    setRunning(true);
    lines.forEach((n, i) => {
      timers.current.push(setTimeout(() => setLit((prev) => [...prev, n]), STEP_MS * (i + 1)));
    });
    timers.current.push(setTimeout(() => {
      setRunning(false);
      setDone(true);
    }, STEP_MS * (lines.length + 1) + 100));
  };

  return (
    <div className="mt-10 border border-rule">
      <div role="tablist" aria-label="Exploit" className="grid grid-cols-2 border-b border-rule md:grid-cols-4">
        {LAB_RUNS.map((r, i) => (
          <button
            key={r.id}
            role="tab"
            aria-selected={i === active}
            onClick={() => { reset(); setActive(i); }}
            className={cn(
              "border-rule px-4 py-3 text-left text-[13.5px] transition-colors",
              "border-b md:border-b-0 [&:not(:last-child)]:border-r",
              i === active ? "bg-ink text-paper" : "text-body hover:bg-panel"
            )}
          >
            <span className="block font-mono text-[11px] opacity-70">0{i + 1}</span>
            {r.name}
          </button>
        ))}
      </div>

      <div className="grid gap-6 p-4 sm:p-6 lg:grid-cols-2">
        <div className="min-w-0">
          <p className="max-w-[60ch] text-[14.5px] leading-relaxed text-body">{run.blurb}</p>
          <p className="mb-2 mt-5 font-mono text-[11px] uppercase tracking-[.12em] text-muted">Exploit</p>
          <pre className="h-[170px] overflow-auto border border-rule bg-panel p-3 font-mono text-[12.5px] leading-relaxed text-ink">
            {run.poc}
          </pre>
          <div className="mt-3 flex gap-2">
            <button
              onClick={execute}
              disabled={running}
              className="inline-flex items-center gap-2 bg-ink px-4 py-2 text-[14px] font-medium text-paper transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Play className="h-4 w-4" aria-hidden /> {running ? "Tracing" : "Replay the trace"}
            </button>
            {(done || running) && (
              <button
                onClick={reset}
                className="inline-flex items-center gap-2 border border-rule px-3 py-2 text-[14px] text-body transition-colors hover:bg-panel"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden /> Reset
              </button>
            )}
          </div>
          <div className="mt-4 lg:min-h-[180px]" aria-live="polite">
            {done ? (
              <Verdict run={run} />
            ) : (
              <p className="text-[13.5px] leading-relaxed text-muted">
                Replay it and watch which lines of <code className="font-mono">app.py</code> the
                tracer recorded. Line {LAB_SINK_LINE} is the one the hunter accused.
              </p>
            )}
          </div>
        </div>
        <SourceView lit={lit} running={running} />
      </div>

      <p className="border-t border-rule px-5 py-3 text-[12.5px] leading-relaxed text-muted sm:px-6">
        Captured from real runs of the tracing harness in <code className="font-mono">sentinel/witness.py</code> and
        replayed here. The first two both print the success marker; a marker-only scanner reports them as proven.
      </p>
    </div>
  );
}
