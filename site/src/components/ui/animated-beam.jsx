// Adapted from Magic UI's Animated Beam (https://magicui.design, MIT licence).
// Changes: JSX, colours from the site's tokens set through style (CSS variables do
// not resolve inside SVG presentation attributes), an `active` switch so only the
// edges a candidate has travelled light up, and a static path under reduced motion.

import { useEffect, useId, useState } from "react";
import { m, useReducedMotion } from "motion/react";

import { cn } from "@/lib";

export function AnimatedBeam({
  containerRef,
  fromRef,
  toRef,
  active = true,
  curvature = 0,
  duration = 2.4,
  delay = 0,
  repeatDelay = 1.2,
  className,
}) {
  const id = useId();
  const reduced = useReducedMotion();
  const [d, setD] = useState("");
  const [size, setSize] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const update = () => {
      const c = containerRef.current;
      const a = fromRef.current;
      const b = toRef.current;
      if (!c || !a || !b) return;
      const box = c.getBoundingClientRect();
      const ra = a.getBoundingClientRect();
      const rb = b.getBoundingClientRect();
      setSize({ width: box.width, height: box.height });
      // Edge to edge, not centre to centre, so the beam never runs under a node.
      const sx = ra.right - box.left;
      const sy = ra.top - box.top + ra.height / 2;
      const ex = rb.left - box.left;
      const ey = rb.top - box.top + rb.height / 2;
      setD(`M ${sx},${sy} Q ${(sx + ex) / 2},${sy - curvature} ${ex},${ey}`);
    };
    const observer = new ResizeObserver(update);
    if (containerRef.current) observer.observe(containerRef.current);
    update();
    return () => observer.disconnect();
  }, [containerRef, fromRef, toRef, curvature]);

  return (
    <svg
      fill="none"
      width={size.width}
      height={size.height}
      viewBox={`0 0 ${size.width} ${size.height}`}
      aria-hidden
      className={cn("pointer-events-none absolute left-0 top-0", className)}
    >
      <path d={d} strokeWidth={2} strokeLinecap="round"
            style={{ stroke: active ? "rgb(var(--proof) / .35)" : "rgb(var(--rule))" }} />
      {active && !reduced && (
        <>
          <path d={d} strokeWidth={2} strokeLinecap="round" stroke={`url(#${id})`} />
          <defs>
            <m.linearGradient
              id={id}
              gradientUnits="userSpaceOnUse"
              initial={{ x1: "0%", x2: "0%", y1: "0%", y2: "0%" }}
              animate={{ x1: ["10%", "110%"], x2: ["0%", "100%"], y1: ["0%", "0%"], y2: ["0%", "0%"] }}
              transition={{ delay, duration, ease: [0.16, 1, 0.3, 1], repeat: Infinity, repeatDelay }}
            >
              <stop style={{ stopColor: "rgb(var(--proof))", stopOpacity: 0 }} />
              <stop style={{ stopColor: "rgb(var(--proof))" }} />
              <stop offset="32.5%" style={{ stopColor: "rgb(var(--proof))" }} />
              <stop offset="100%" style={{ stopColor: "rgb(var(--proof))", stopOpacity: 0 }} />
            </m.linearGradient>
          </defs>
        </>
      )}
    </svg>
  );
}
