// Adapted from Magic UI's Terminal (https://magicui.design, MIT licence).
// Changes: JSX instead of TSX, the site's colour tokens, a caption bar instead of
// window dots, a replay control, and reduced motion shows the whole session at once.

import {
  Children, createContext, useContext, useEffect, useMemo, useRef, useState,
} from "react";
import { m, useInView, useReducedMotion } from "motion/react";
import { RotateCcw } from "lucide-react";

import { cn } from "@/lib";

const SequenceContext = createContext(null);
const ItemIndexContext = createContext(null);

export function AnimatedSpan({ children, className }) {
  const sequence = useContext(SequenceContext);
  const itemIndex = useContext(ItemIndexContext);
  const [started, setStarted] = useState(false);

  useEffect(() => {
    if (sequence?.sequenceStarted && !started && sequence.activeIndex === itemIndex) {
      setStarted(true);
    }
  }, [sequence, started, itemIndex]);

  const show = sequence ? started : true;
  return (
    <m.div
      initial={{ opacity: 0, y: -4 }}
      animate={show ? { opacity: 1, y: 0 } : { opacity: 0, y: -4 }}
      transition={{ duration: 0.25 }}
      className={cn("whitespace-pre-wrap", className)}
      onAnimationComplete={() => {
        if (sequence && itemIndex !== null && show) sequence.completeItem(itemIndex);
      }}
    >
      {children}
    </m.div>
  );
}

export function TypingAnimation({ children, className, duration = 38 }) {
  const sequence = useContext(SequenceContext);
  const itemIndex = useContext(ItemIndexContext);
  const reduced = useReducedMotion();
  const [text, setText] = useState(reduced ? children : "");
  const [started, setStarted] = useState(false);
  const complete = useRef(null);
  complete.current = () => sequence?.completeItem(itemIndex);

  useEffect(() => {
    if (!sequence) { setStarted(true); return; }
    if (sequence.sequenceStarted && !started && sequence.activeIndex === itemIndex) setStarted(true);
  }, [sequence, started, itemIndex]);

  useEffect(() => {
    if (!started) return undefined;
    if (reduced) {
      setText(children);
      complete.current?.();
      return undefined;
    }
    let i = 0;
    const timer = setInterval(() => {
      i += 1;
      setText(children.slice(0, i));
      if (i >= children.length) {
        clearInterval(timer);
        complete.current?.();
      }
    }, duration);
    return () => clearInterval(timer);
  }, [children, duration, started, reduced]);

  return <span className={cn("whitespace-pre-wrap", className)}>{text}</span>;
}

/** Plays its children one after another once scrolled into view. */
export function Terminal({ children, title, note, className }) {
  const ref = useRef(null);
  const inView = useInView(ref, { amount: 0.3, once: true });
  const reduced = useReducedMotion();
  const [run, setRun] = useState(0);
  const [active, setActive] = useState(0);
  const count = Children.count(children);

  const context = useMemo(() => (reduced ? null : {
    completeItem: (i) => setActive((current) => (i === current ? current + 1 : current)),
    activeIndex: active,
    sequenceStarted: inView,
  }), [reduced, active, inView]);

  const items = Children.toArray(children).map((child, i) => (
    <ItemIndexContext.Provider key={`${run}-${i}`} value={i}>{child}</ItemIndexContext.Provider>
  ));

  const replay = () => { setActive(0); setRun((r) => r + 1); };
  const finished = reduced || active >= count;

  return (
    <figure ref={ref} className={cn("flex min-w-0 flex-col border border-rule bg-panel", className)}>
      <figcaption className="flex items-center justify-between gap-3 border-b border-rule px-4 py-2 font-mono text-[11.5px] text-muted">
        <span>{title}</span>
        <span className="flex items-center gap-3">
          {note && <span>{note}</span>}
          <button
            type="button"
            onClick={replay}
            disabled={!finished}
            aria-label="Replay the session"
            className="inline-flex items-center gap-1 text-body hover:text-ink disabled:opacity-40"
          >
            <RotateCcw className="h-3 w-3" aria-hidden /> replay
          </button>
        </span>
      </figcaption>
      <pre className="min-h-[380px] overflow-x-auto p-4 font-mono text-[12.5px] leading-[1.65] text-ink">
        <code className="grid gap-y-0.5">
          <SequenceContext.Provider value={context}>{items}</SequenceContext.Provider>
        </code>
      </pre>
    </figure>
  );
}
