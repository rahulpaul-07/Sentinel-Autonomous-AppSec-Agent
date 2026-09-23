import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Play, RotateCcw, Check, X, CircleDot } from "lucide-react";

import { cn } from "@/lib";
import { BorderBeam } from "@/components/ui/border-beam";
import { LAB_TARGET, LAB_SINK_LINE, LAB_RUNS } from "@/lab-data";

const TIER_STYLE = {
  line_proven: {
    label: "LINE PROVEN",
    ring: "border-proof/50",
    text: "text-proof",
    chip: "bg-proof/15 text-proof",
  },
  class_only: {
    label: "CLASS ONLY",
    ring: "border-warn/50",
    text: "text-warn",
    chip: "bg-warn/15 text-warn",
  },
  unproven: {
    label: "UNPROVEN",
    ring: "border-line",
    text: "text-muted",
    chip: "bg-line text-muted",
  },
};

/** The target source, with executed lines lit up as the trace replays. */
function SourceView({ litLines, sink, running }) {
  const lines = LAB_TARGET.replace(/\n$/, "").split("\n");
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-base">
      <div className="flex items-center justify-between border-b border-line px-3 py-2">
        <span className="font-mono text-[11.5px] text-faint">app.py</span>
        <span className="font-mono text-[11px] text-faint">
          {running ? "tracing…" : `${litLines.length} lines executed`}
        </span>
      </div>
      <pre className="overflow-x-auto py-2 font-mono text-[12px] leading-[1.75]">
        {lines.map((text, i) => {
          const n = i + 1;
          const lit = litLines.includes(n);
          const isSink = n === sink || n === sink - 1;
          return (
            <div
              key={n}
              className={cn(
                "flex px-3 transition-colors duration-200",
                lit && "bg-violet/[.13]",
                lit && isSink && "bg-proof/20"
              )}
            >
              <span
                className={cn(
                  "mr-3 w-6 shrink-0 select-none text-right",
                  lit ? "text-violets" : "text-faint/50",
                  isSink && "font-bold text-sev"
                )}
              >
                {n}
              </span>
              <code className={cn(lit ? "text-ink" : "text-faint/60")}>{text || " "}</code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function Verdict({ run }) {
  const t = TIER_STYLE[run.evidence];
  const Row = ({ label, ok, value }) => (
    <div className="flex items-center justify-between gap-3 border-b border-line py-2 last:border-b-0">
      <span className="text-[12.5px] text-faint">{label}</span>
      <span
        className={cn(
          "flex items-center gap-1.5 font-mono text-[12.5px]",
          ok ? "text-proof" : "text-sev"
        )}
      >
        {ok ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
        {value}
      </span>
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn("rounded-lg border bg-base p-4", t.ring)}
    >
      <Row label="Success marker" ok={run.marker} value={run.marker ? "printed" : "absent"} />
      <Row
        label="Target file executed"
        ok={run.fileExecuted}
        value={run.fileExecuted ? "yes" : "no"}
      />
      <Row
        label={`Reported line ${LAB_SINK_LINE} executed`}
        ok={run.lineExecuted}
        value={run.lineExecuted ? "yes" : "no"}
      />
      <div className="mt-3 flex items-center justify-between gap-3">
        <span className="text-[12.5px] text-faint">Graded</span>
        <span className={cn("rounded-md px-2 py-1 font-mono text-[12px] font-bold", t.chip)}>
          {t.label}
        </span>
      </div>
      <p className="mt-3 text-[13px] leading-relaxed text-muted">{run.explain}</p>
    </motion.div>
  );
}

export function ProofLab() {
  const [active, setActive] = useState(0);
  const [litLines, setLitLines] = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const timers = useRef([]);

  const run = LAB_RUNS[active];

  const clearTimers = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };

  useEffect(() => () => clearTimers(), []);

  const reset = () => {
    clearTimers();
    setLitLines([]);
    setRunning(false);
    setDone(false);
  };

  const execute = () => {
    clearTimers();
    setLitLines([]);
    setDone(false);
    setRunning(true);

    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const lines = run.executedLines;

    if (reduced || lines.length === 0) {
      setLitLines(lines);
      setRunning(false);
      setDone(true);
      return;
    }

    lines.forEach((n, i) => {
      timers.current.push(
        setTimeout(() => setLitLines((prev) => [...prev, n]), 90 * (i + 1))
      );
    });
    timers.current.push(
      setTimeout(() => {
        setRunning(false);
        setDone(true);
      }, 90 * (lines.length + 1) + 120)
    );
  };

  const select = (i) => {
    reset();
    setActive(i);
  };

  return (
    <div className="relative mt-10 overflow-hidden rounded-xl border border-line bg-surface p-5 sm:p-6">
      <BorderBeam size={110} duration={12} />

      {/* exploit picker */}
      <div className="relative flex flex-wrap gap-2">
        {LAB_RUNS.map((r, i) => (
          <button
            key={r.id}
            onClick={() => select(i)}
            aria-pressed={i === active}
            className={cn(
              "rounded-lg border px-3 py-2 text-left text-[13px] transition-colors",
              i === active
                ? "border-violet bg-violet/10 text-ink"
                : "border-line bg-base text-muted hover:border-faint hover:text-ink"
            )}
          >
            {r.name}
          </button>
        ))}
      </div>

      <p className="relative mt-3 max-w-[70ch] text-[13.5px] leading-relaxed text-muted">
        {run.blurb}
      </p>

      <div className="relative mt-5 grid gap-4 lg:grid-cols-2">
        {/* left: the exploit + controls */}
        <div>
          <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-faint">
            Proof-of-concept
          </div>
          <pre className="h-[186px] overflow-auto rounded-lg border border-line bg-base p-3 font-mono text-[12px] leading-relaxed text-muted">
            {run.poc}
          </pre>

          <div className="mt-3 flex gap-2">
            <button
              onClick={execute}
              disabled={running}
              className={cn(
                "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-[13.5px] font-semibold transition-colors",
                running
                  ? "cursor-not-allowed bg-line text-faint"
                  : "bg-violet text-base hover:bg-violets"
              )}
            >
              {running ? (
                <>
                  <CircleDot className="h-4 w-4 animate-pulse" /> Tracing…
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" /> Run in sandbox
                </>
              )}
            </button>
            {(done || running) && (
              <button
                onClick={reset}
                className="inline-flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-[13.5px] text-muted transition-colors hover:border-faint hover:text-ink"
              >
                <RotateCcw className="h-3.5 w-3.5" /> Reset
              </button>
            )}
          </div>

          <div className="mt-3 min-h-[92px]">
            <AnimatePresence mode="wait">
              {done ? (
                <Verdict key={run.id} run={run} />
              ) : (
                <motion.p
                  key="idle"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="pt-2 text-[13px] leading-relaxed text-faint"
                >
                  Run it and watch which lines of{" "}
                  <span className="font-mono text-muted">app.py</span> the tracer records.
                  Line {LAB_SINK_LINE} is the one the hunter accused.
                </motion.p>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* right: the target, lighting up */}
        <div>
          <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-faint">
            Target under trace
          </div>
          <SourceView litLines={litLines} sink={LAB_SINK_LINE} running={running} />
          {done && run.stdout && (
            <pre className="mt-3 overflow-x-auto rounded-lg border border-line bg-base p-3 font-mono text-[12px] text-proof">
              {run.stdout}
            </pre>
          )}
        </div>
      </div>

      <p className="relative mt-5 border-t border-line pt-4 text-[12.5px] leading-relaxed text-faint">
        These are outputs captured from real runs of the tracing harness in{" "}
        <span className="font-mono text-muted">sentinel/witness.py</span>, replayed here.
        The first two exploits both print the success marker — a scanner that checks only
        for the marker reports them as proven findings.
      </p>
    </div>
  );
}
