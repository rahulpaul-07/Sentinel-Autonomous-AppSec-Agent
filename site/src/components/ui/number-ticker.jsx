// Magic UI - Number Ticker (MIT).
import { useEffect, useRef, useState } from "react";
import { useInView, useMotionValue, useSpring } from "motion/react";
import { cn } from "@/lib";

export function NumberTicker({
  value, direction = "up", delay = 0, className, decimalPlaces = 0, suffix = "",
}) {
  const ref = useRef(null);
  const motionValue = useMotionValue(direction === "down" ? value : 0);
  const springValue = useSpring(motionValue, { damping: 60, stiffness: 100 });
  const isInView = useInView(ref, { once: true, margin: "0px" });
  const [display, setDisplay] = useState("0");

  // Users who ask for reduced motion get the final number immediately, and it is
  // also the safe fallback: a stat that renders "0" because an animation never
  // ran is worse than no animation at all.
  const reduced =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => {
    if (reduced) {
      setDisplay(
        Intl.NumberFormat("en-US", {
          minimumFractionDigits: decimalPlaces,
          maximumFractionDigits: decimalPlaces,
        }).format(value)
      );
      return;
    }
    if (!isInView) return;
    const t = setTimeout(() => motionValue.set(direction === "down" ? 0 : value), delay * 1000);
    return () => clearTimeout(t);
  }, [motionValue, isInView, delay, value, direction, reduced, decimalPlaces]);

  useEffect(
    () =>
      springValue.on("change", (latest) => {
        setDisplay(
          Intl.NumberFormat("en-US", {
            minimumFractionDigits: decimalPlaces,
            maximumFractionDigits: decimalPlaces,
          }).format(Number(latest.toFixed(decimalPlaces)))
        );
      }),
    [springValue, decimalPlaces]
  );

  return (
    <span ref={ref} className={cn("inline-block tabular-nums tracking-tight", className)}>
      {display}
      {suffix}
    </span>
  );
}
