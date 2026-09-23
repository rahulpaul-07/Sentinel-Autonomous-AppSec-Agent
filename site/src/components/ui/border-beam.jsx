// Magic UI - Border Beam (MIT). Vendored per the registry's copy-in model.
import { motion } from "motion/react";
import { cn } from "@/lib";

export function BorderBeam({
  className, size = 60, duration = 8, delay = 0,
  colorFrom = "#7c5cff", colorTo = "#2fd47a", style, ...props
}) {
  return (
    <div className="pointer-events-none absolute inset-0 rounded-[inherit] border border-transparent [mask-clip:padding-box,border-box] [mask-composite:intersect] [mask-image:linear-gradient(transparent,transparent),linear-gradient(#000,#000)]">
      <motion.div
        className={cn(
          "absolute aspect-square bg-gradient-to-l from-[var(--color-from)] via-[var(--color-to)] to-transparent",
          className
        )}
        style={{
          width: size,
          offsetPath: `rect(0 auto auto 0 round ${size}px)`,
          "--color-from": colorFrom,
          "--color-to": colorTo,
          ...style,
        }}
        initial={{ offsetDistance: "0%" }}
        animate={{ offsetDistance: "100%" }}
        transition={{ repeat: Infinity, ease: "linear", duration, delay: -delay }}
        {...props}
      />
    </div>
  );
}
