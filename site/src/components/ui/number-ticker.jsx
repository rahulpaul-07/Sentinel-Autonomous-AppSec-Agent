// Adapted from Magic UI's Number Ticker (https://magicui.design, MIT licence).
// Changes: JSX and the site's tokens. The real value is in the markup from the
// start, so a page captured without scrolling (a link preview, print, a crawler)
// never shows 0. The count-up is a fixed-length tween rather than the original
// spring: a spring's long tail sat at 59% or 98% for a moment, a figure that was
// never measured. Skipped under reduced motion.

import { useEffect, useRef } from "react";
import { animate, useInView, useReducedMotion } from "motion/react";

import { cn } from "@/lib";

export function NumberTicker({ value, delay = 0, duration = 1.1, className }) {
  const ref = useRef(null);
  const reduced = useReducedMotion();
  const inView = useInView(ref, { once: true, margin: "0px" });

  useEffect(() => {
    if (!inView || reduced) return undefined;
    const controls = animate(0, value, {
      delay, duration, ease: "easeOut",
      onUpdate: (latest) => { if (ref.current) ref.current.textContent = String(Math.round(latest)); },
      onComplete: () => { if (ref.current) ref.current.textContent = String(value); },
    });
    return () => {
      controls.stop();
      if (ref.current) ref.current.textContent = String(value);
    };
  }, [inView, reduced, value, delay, duration]);

  return <span ref={ref} className={cn("inline-block tabular-nums", className)}>{value}</span>;
}
