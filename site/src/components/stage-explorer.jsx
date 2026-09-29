import { createRef, useMemo, useRef, useState } from "react";
import { ArrowUpRight } from "lucide-react";

import { AnimatedBeam } from "@/components/ui/animated-beam";
import { cn } from "@/lib";
import { STAGES } from "@/data";

function Artifact({ stage }) {
  if (stage.diff) {
    return (
      <pre className="overflow-x-auto bg-panel py-3 font-mono text-[12.5px] leading-[1.7]">
        {stage.diff.map(([sign, line]) => (
          <div key={line} className={cn("px-4", sign === "-" ? "bg-sev/[.08] text-sev" : "bg-proof/[.10] text-proof")}>
            <span className="mr-3 select-none" aria-hidden>{sign}</span>
            <span className="sr-only">{sign === "-" ? "removed: " : "added: "}</span>
            {line}
          </div>
        ))}
      </pre>
    );
  }
  return (
    <pre className="overflow-x-auto bg-panel p-4 font-mono text-[12.5px] leading-[1.7] text-ink">{stage.artifact}</pre>
  );
}

/**
 * The pipeline as a set of tabs. Beams light up the edges a candidate has
 * travelled to reach the selected stage, so the diagram answers "where am I".
 */
export function StageExplorer() {
  const [active, setActive] = useState(0);
  const container = useRef(null);
  const nodes = useMemo(() => STAGES.map(() => createRef()), []);
  const stage = STAGES[active];

  const onKey = (e) => {
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!step && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const next = e.key === "Home" ? 0 : e.key === "End" ? STAGES.length - 1
      : (active + step + STAGES.length) % STAGES.length;
    setActive(next);
    nodes[next].current?.focus();
  };

  return (
    <div className="mt-10 border border-rule">
      <div className="overflow-x-auto border-b border-rule bg-panel">
        <div ref={container} role="tablist" aria-label="Pipeline stage" onKeyDown={onKey}
             className="relative grid min-w-[760px] grid-cols-6 gap-7 px-5 py-6">
          {STAGES.slice(1).map((s, i) => (
            <AnimatedBeam key={s.id} containerRef={container} fromRef={nodes[i]} toRef={nodes[i + 1]}
                          active={i < active} />
          ))}
          {STAGES.map((s, i) => (
            <button
              key={s.id}
              ref={nodes[i]}
              type="button"
              role="tab"
              id={`stage-tab-${s.id}`}
              aria-selected={i === active}
              aria-controls="stage-panel"
              tabIndex={i === active ? 0 : -1}
              onClick={() => setActive(i)}
              className={cn(
                "relative z-10 flex flex-col items-start justify-start border px-3 py-3 text-left transition-colors",
                i === active ? "border-ink bg-ink text-paper"
                  : i < active ? "border-proof/50 bg-paper text-ink hover:border-ink"
                  : "border-rule bg-paper text-body hover:border-ink hover:text-ink"
              )}
            >
              <span className="block font-mono text-[11px] opacity-70">{s.n}</span>
              <span className="block text-[16px] font-semibold">{s.title}</span>
              <span className="mt-1 block font-mono text-[10.5px] uppercase tracking-[.08em] opacity-70">{s.tag}</span>
            </button>
          ))}
        </div>
      </div>

      <div id="stage-panel" role="tabpanel" aria-labelledby={`stage-tab-${stage.id}`}
           className="grid gap-6 p-5 sm:p-6 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <div className="min-w-0">
          <p className="font-mono text-[12px] uppercase tracking-[.12em] text-muted">Stage {stage.n}</p>
          <h3 className="mt-1 text-[24px] font-semibold tracking-[-0.01em] text-ink">{stage.title}</h3>
          <p className="mt-3 max-w-[56ch] text-[15px] leading-[1.65] text-body">{stage.what}</p>
          <ul className="mt-5 space-y-1.5">
            {stage.files.map(([name, href]) => (
              <li key={name}>
                <a href={href} target="_blank" rel="noopener noreferrer"
                   className="inline-flex items-center gap-1 font-mono text-[13px] text-ink underline decoration-rule underline-offset-4 hover:decoration-ink">
                  {name} <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
                </a>
              </li>
            ))}
          </ul>
          <div className="mt-6 flex gap-2">
            <button type="button" onClick={() => setActive(Math.max(0, active - 1))} disabled={active === 0}
                    className="border border-rule px-3 py-1.5 text-[13.5px] text-body hover:border-ink hover:text-ink disabled:opacity-40">
              Previous
            </button>
            <button type="button" onClick={() => setActive(Math.min(STAGES.length - 1, active + 1))}
                    disabled={active === STAGES.length - 1}
                    className="bg-ink px-3 py-1.5 text-[13.5px] font-medium text-paper hover:opacity-85 disabled:opacity-40">
              Next stage
            </button>
          </div>
        </div>
        <figure className="min-w-0 self-start border border-rule">
          <figcaption className="border-b border-rule px-4 py-2 font-mono text-[11.5px] text-muted">{stage.label}</figcaption>
          <Artifact stage={stage} />
        </figure>
      </div>
    </div>
  );
}
