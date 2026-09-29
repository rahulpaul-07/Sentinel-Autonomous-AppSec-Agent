// Adapted from Magic UI's Blur Fade (https://magicui.design, MIT licence).
// Changes: JSX, in-view by default, a smaller offset and blur. Under reduced motion
// MotionConfig (in App) drops the movement and the content only fades.

import { useRef } from "react";
import { m, useInView } from "motion/react";

export function BlurFade({ children, className, delay = 0, duration = 0.45, offset = 8, as = "div" }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });
  const Component = m[as];
  return (
    <Component
      ref={ref}
      className={className}
      initial={{ opacity: 0, y: offset, filter: "blur(4px)" }}
      animate={inView ? { opacity: 1, y: 0, filter: "blur(0px)" } : undefined}
      transition={{ delay, duration, ease: "easeOut" }}
    >
      {children}
    </Component>
  );
}
