// The pipeline as the code runs it: sentinel/scanner.py calls these stages in this
// order. Colours come from the theme tokens, so the diagram follows light and dark.

const STAGES = [
  { n: "01", title: "Hunt", lines: ["LLM reads each file,", "claims class · file · line"] },
  { n: "02", title: "Gate", lines: ["AST taint + sanitizers,", "rejects on evidence only"] },
  { n: "03", title: "Prove", lines: ["exploit imports the target,", "Docker · no network · tracer"] },
  { n: "04", title: "Grade", lines: ["marker + accused line", "→ evidence tier"] },
  { n: "05", title: "Fix", lines: ["one patch per file,", "must parse and change"] },
  { n: "06", title: "Verify", lines: ["replay the exploit", "on a patched copy"] },
];

const W = 140;      // stage width
const STEP = 176;   // stage pitch
const TOP = 28;
const H = 96;
const MID = TOP + H / 2;
const x = (i) => 2 + i * STEP;
const cx = (i) => x(i) + W / 2;

export function PipelineDiagram() {
  return (
    <figure className="mt-10 border border-rule">
      <div className="overflow-x-auto bg-panel">
        <svg viewBox="0 0 1024 300" className="block w-full min-w-[760px]" role="img"
             aria-labelledby="pipeline-title pipeline-desc">
          <title id="pipeline-title">Sentinel's pipeline</title>
          <desc id="pipeline-desc">
            Six stages left to right: hunt, gate, prove, grade, fix, verify. The gate can
            reject a candidate with no model call. Proving retries up to three times with
            the failure output. Grading assigns line proven, class only, unproven or not
            testable. Only line-proven findings are patched, and each fix is verified by
            replaying the exploit.
          </desc>
          <defs>
            <marker id="pipeline-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" className="text-muted" fill="currentColor" />
            </marker>
          </defs>

          {STAGES.slice(1).map((_, i) => (
            <line key={i} x1={x(i) + W + 2} y1={MID} x2={x(i + 1) - 4} y2={MID}
                  className="stroke-muted" strokeWidth="1.5" markerEnd="url(#pipeline-arrow)" />
          ))}

          {STAGES.map((s, i) => (
            <g key={s.n}>
              <rect x={x(i)} y={TOP} width={W} height={H}
                    className={i === 3 ? "fill-paper stroke-ink" : "fill-paper stroke-rule"}
                    strokeWidth={i === 3 ? 1.5 : 1} />
              <text x={x(i) + 12} y={TOP + 22} className="fill-muted font-mono" fontSize="12">{s.n}</text>
              <text x={x(i) + 12} y={TOP + 46} className="fill-ink" fontSize="17" fontWeight="600">{s.title}</text>
              {s.lines.map((l, j) => (
                <text key={j} x={x(i) + 12} y={TOP + 66 + j * 16} className="fill-body" fontSize="11.5">{l}</text>
              ))}
            </g>
          ))}

          {/* Gate: rejection without a model call. */}
          <line x1={cx(1)} y1={TOP + H} x2={cx(1)} y2={196} className="stroke-muted"
                strokeWidth="1.5" strokeDasharray="4 4" markerEnd="url(#pipeline-arrow)" />
          <text x={cx(1)} y={218} textAnchor="middle" className="fill-ink font-mono" fontSize="12" fontWeight="600">NO PATH</text>
          <text x={cx(1)} y={236} textAnchor="middle" className="fill-muted" fontSize="11.5">zero model calls</text>

          {/* Prove: self-correction loop. */}
          <path d={`M ${cx(2) + 30} ${TOP + H} v 44 h -60 v -40`} fill="none" className="stroke-muted"
                strokeWidth="1.5" markerEnd="url(#pipeline-arrow)" />
          <text x={cx(2)} y={196} textAnchor="middle" className="fill-muted" fontSize="11.5">retry with the failure</text>
          <text x={cx(2)} y={212} textAnchor="middle" className="fill-muted" fontSize="11.5">output, up to 3 attempts</text>

          {/* Grade: the ladder. */}
          <line x1={cx(3)} y1={TOP + H} x2={cx(3)} y2={160} className="stroke-muted" strokeWidth="1.5" />
          {[["LINE PROVEN", "fill-proof"], ["CLASS ONLY", "fill-warn"], ["UNPROVEN", "fill-muted"],
            ["NOT TESTABLE", "fill-muted"]].map(([label, tone], j) => (
            <text key={label} x={cx(3)} y={180 + j * 20} textAnchor="middle"
                  className={`${tone} font-mono`} fontSize="12" fontWeight="600">{label}</text>
          ))}

          {/* Fix and verify outcomes. */}
          <text x={cx(4)} y={178} textAnchor="middle" className="fill-muted" fontSize="11.5">only line-proven</text>
          <text x={cx(4)} y={194} textAnchor="middle" className="fill-muted" fontSize="11.5">findings are patched</text>
          {[["verified", "fill-proof"], ["still exploitable", "fill-sev"], ["inconclusive", "fill-muted"]]
            .map(([label, tone], j) => (
              <text key={label} x={cx(5)} y={178 + j * 18} textAnchor="middle"
                    className={`${tone} font-mono`} fontSize="12">{label}</text>
            ))}

          <text x={1022} y={284} textAnchor="end" className="fill-muted font-mono" fontSize="11.5">
            report → HTML · JSON · SARIF 2.1.0
          </text>
        </svg>
      </div>
      <figcaption className="border-t border-rule px-4 py-2.5 text-[13px] text-muted">
        The order <code className="font-mono text-[12px]">sentinel/scanner.py</code> runs them in. The cheap,
        deterministic gate runs before the expensive, stochastic proof. Scroll sideways on a narrow screen.
      </figcaption>
    </figure>
  );
}
