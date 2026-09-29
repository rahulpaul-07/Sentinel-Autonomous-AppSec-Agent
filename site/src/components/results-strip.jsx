// Spread of each metric over the three runs: one track per metric, 0-100%, a bar
// from the lowest run to the highest, and a marker per distinct value. One ink
// colour throughout; the table below it carries the same numbers as text.

import { useState } from "react";

import { RUN_METRICS } from "@/data";

function groups(runs) {
  const byValue = new Map();
  runs.forEach((v, i) => byValue.set(v, [...(byValue.get(v) ?? []), i + 1]));
  return [...byValue.entries()].map(([value, ids]) => ({ value, ids }));
}

const runsText = (ids) => (ids.length === 1 ? `Run ${ids[0]}` : `Runs ${ids.join(" and ")}`);

export function ResultsStrip() {
  const [tip, setTip] = useState(null);   // "metric:value"

  return (
    <figure className="mt-10 border border-rule">
      <figcaption className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule px-4 py-2.5">
        <span className="text-[14.5px] font-medium text-ink">Each metric across the three runs</span>
        <span className="font-mono text-[11.5px] text-muted">gpt-oss-120b · 26 Sep 2026 · 5 labelled bugs + clean control</span>
      </figcaption>
      <div className="space-y-7 px-4 py-6 sm:px-6">
        {RUN_METRICS.map((m) => {
          const lo = Math.min(...m.runs);
          const hi = Math.max(...m.runs);
          return (
            <div key={m.key} className="grid items-center gap-x-6 gap-y-2 sm:grid-cols-[170px_minmax(0,1fr)_72px]">
              <div>
                <p className="text-[14.5px] font-medium text-ink">{m.label}</p>
                <p className="font-mono text-[11.5px] text-muted">{m.note}</p>
              </div>
              <div className="relative h-8" role="group" aria-label={`${m.label}: ${lo} to ${hi} percent`}>
                {[0, 50, 100].map((g) => (
                  <span key={g} className="absolute top-0 h-full w-px bg-rule" style={{ left: `${g}%` }} aria-hidden />
                ))}
                <span className="absolute top-1/2 h-1 -translate-y-1/2 rounded-full bg-ink/25"
                      style={{ left: `${lo}%`, width: `${Math.max(hi - lo, 0.5)}%` }} aria-hidden />
                {groups(m.runs).map(({ value, ids }) => {
                  const key = `${m.key}:${value}`;
                  return (
                    <button
                      key={key}
                      type="button"
                      aria-label={`${runsText(ids)}: ${value}%`}
                      onMouseEnter={() => setTip(key)} onMouseLeave={() => setTip(null)}
                      onFocus={() => setTip(key)} onBlur={() => setTip(null)}
                      className="group absolute top-1/2 -translate-x-1/2 -translate-y-1/2 p-2"
                      style={{ left: `${value}%` }}
                    >
                      <span className="block h-3 w-3 rounded-full bg-ink ring-2 ring-paper" aria-hidden />
                      {ids.length > 1 && (
                        <span className="absolute -top-3 left-1/2 -translate-x-1/2 font-mono text-[10px] text-muted" aria-hidden>
                          ×{ids.length}
                        </span>
                      )}
                      {tip === key && (
                        <span role="tooltip"
                              className={`absolute bottom-full z-10 mb-1 whitespace-nowrap border border-rule bg-paper px-2 py-1 font-mono text-[11.5px] text-ink shadow-sm ${value >= 85 ? "right-0" : value <= 15 ? "left-0" : "left-1/2 -translate-x-1/2"}`}>
                          {runsText(ids)} · {value}%
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
              <p className="font-mono text-[13px] text-ink sm:text-right">{lo === hi ? `${lo}%` : `${lo}–${hi}%`}</p>
            </div>
          );
        })}
        <div className="grid gap-x-6 sm:grid-cols-[170px_minmax(0,1fr)_72px]" aria-hidden>
          <span />
          <div className="relative h-4 font-mono text-[11px] text-muted">
            <span className="absolute left-0">0%</span>
            <span className="absolute left-1/2 -translate-x-1/2">50%</span>
            <span className="absolute right-0">100%</span>
          </div>
        </div>
      </div>
      <p className="border-t border-rule px-4 py-2.5 text-[13px] leading-relaxed text-muted sm:px-6">
        The gap between the strict and permissive recall is how much a scanner that checks only the
        marker would overstate. Here it is the hardcoded secret, which execution cannot prove.
      </p>
    </figure>
  );
}
