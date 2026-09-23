// Magic UI - Terminal (MIT). Sequenced reveal of real CLI output.
import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { cn } from "@/lib";

export function AnimatedSpan({ children, delay = 0, className, ...props }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -4 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-40px" }}
      transition={{ duration: 0.25, delay: delay / 1000 }}
      className={cn("grid text-sm font-normal tracking-tight", className)}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function TypingAnimation({ children, className, duration = 45, delay = 0, ...props }) {
  const [started, setStarted] = useState(false);
  const [text, setText] = useState("");

  useEffect(() => {
    const t = setTimeout(() => setStarted(true), delay);
    return () => clearTimeout(t);
  }, [delay]);

  useEffect(() => {
    if (!started) return;
    let i = 0;
    const id = setInterval(() => {
      if (i < children.length) {
        setText(children.substring(0, i + 1));
        i++;
      } else {
        clearInterval(id);
      }
    }, duration);
    return () => clearInterval(id);
  }, [children, duration, started]);

  return (
    <motion.div className={cn("text-sm font-normal tracking-tight", className)} {...props}>
      {text}
    </motion.div>
  );
}

export function Terminal({ children, className, title = "sentinel" }) {
  return (
    <div
      className={cn(
        "z-0 h-full max-h-[520px] w-full rounded-xl border border-line bg-surface",
        className
      )}
    >
      <div className="flex flex-col gap-y-2 border-b border-line p-4">
        <div className="flex flex-row items-center gap-x-2">
          <div className="h-2.5 w-2.5 rounded-full bg-[#2b3242]" />
          <div className="h-2.5 w-2.5 rounded-full bg-[#2b3242]" />
          <div className="h-2.5 w-2.5 rounded-full bg-[#2b3242]" />
          <span className="ml-2 font-mono text-xs text-faint">{title}</span>
        </div>
      </div>
      <pre className="overflow-auto p-4">
        <code className="grid gap-y-1 font-mono text-[13px] leading-relaxed">{children}</code>
      </pre>
    </div>
  );
}
