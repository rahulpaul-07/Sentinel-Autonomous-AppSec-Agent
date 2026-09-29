// Adapted from Magic UI's Scroll Progress (https://magicui.design, MIT licence).
// Changes: JSX, and a single ink hairline instead of a gradient.

import { m, useScroll } from "motion/react";

export function ScrollProgress() {
  const { scrollYProgress } = useScroll();
  return (
    <m.div
      aria-hidden
      className="fixed inset-x-0 top-0 z-50 h-[2px] origin-left bg-ink"
      style={{ scaleX: scrollYProgress }}
    />
  );
}
