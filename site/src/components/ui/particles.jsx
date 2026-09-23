// Magic UI - Particles (MIT). Canvas particle field with subtle pointer parallax.
import { useEffect, useRef, useState, useCallback } from "react";
import { cn } from "@/lib";

function hexToRgb(hex) {
  hex = hex.replace(/^#/, "");
  if (hex.length === 3) hex = hex.split("").map((c) => c + c).join("");
  const n = parseInt(hex, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export function Particles({
  className, quantity = 60, staticity = 50, ease = 50, size = 0.4,
  refresh = false, color = "#7c5cff", vx = 0, vy = 0,
}) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const context = useRef(null);
  const circles = useRef([]);
  const mouse = useRef({ x: 0, y: 0 });
  const canvasSize = useRef({ w: 0, h: 0 });
  const rafID = useRef(null);
  const [dpr, setDpr] = useState(1);
  const rgb = hexToRgb(color);

  const circleParams = useCallback(() => {
    const { w, h } = canvasSize.current;
    return {
      x: Math.floor(Math.random() * w),
      y: Math.floor(Math.random() * h),
      translateX: 0, translateY: 0,
      size: Math.floor(Math.random() * 2) + size,
      alpha: 0,
      targetAlpha: parseFloat((Math.random() * 0.5 + 0.1).toFixed(1)),
      dx: (Math.random() - 0.5) * 0.1,
      dy: (Math.random() - 0.5) * 0.1,
      magnetism: 0.1 + Math.random() * 4,
    };
  }, [size]);

  const resize = useCallback(() => {
    if (!containerRef.current || !canvasRef.current || !context.current) return;
    const { offsetWidth: w, offsetHeight: h } = containerRef.current;
    canvasSize.current = { w, h };
    canvasRef.current.width = w * dpr;
    canvasRef.current.height = h * dpr;
    canvasRef.current.style.width = `${w}px`;
    canvasRef.current.style.height = `${h}px`;
    context.current.scale(dpr, dpr);
    circles.current = Array.from({ length: quantity }, circleParams);
  }, [dpr, quantity, circleParams]);

  useEffect(() => {
    setDpr(window.devicePixelRatio || 1);
    if (canvasRef.current) context.current = canvasRef.current.getContext("2d");
  }, []);

  useEffect(() => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    resize();
    if (reduced) return; // honour reduced motion: draw nothing rather than animate

    const onMove = (e) => {
      if (!canvasRef.current) return;
      const rect = canvasRef.current.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      if (Math.abs(x) < rect.width / 2 && Math.abs(y) < rect.height / 2) {
        mouse.current = { x, y };
      }
    };

    const draw = () => {
      const ctx = context.current;
      const { w, h } = canvasSize.current;
      if (!ctx) return;
      ctx.clearRect(0, 0, w, h);
      circles.current.forEach((c, i) => {
        const edges = [
          c.x + c.translateX - c.size,
          w - c.x - c.translateX - c.size,
          c.y + c.translateY - c.size,
          h - c.y - c.translateY - c.size,
        ];
        const closest = Math.min(...edges);
        const remap = parseFloat(
          (((closest - 0) * (1 - 0)) / (20 - 0) + 0).toFixed(2)
        );
        c.alpha = remap > 1 ? c.targetAlpha : c.targetAlpha * remap;
        c.x += c.dx + vx;
        c.y += c.dy + vy;
        c.translateX += (mouse.current.x / (staticity / c.magnetism) - c.translateX) / ease;
        c.translateY += (mouse.current.y / (staticity / c.magnetism) - c.translateY) / ease;

        ctx.translate(c.translateX, c.translateY);
        ctx.beginPath();
        ctx.arc(c.x, c.y, c.size, 0, 2 * Math.PI);
        ctx.fillStyle = `rgba(${rgb.join(", ")}, ${c.alpha})`;
        ctx.fill();
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        if (closest < 0) circles.current[i] = circleParams();
      });
      rafID.current = window.requestAnimationFrame(draw);
    };

    draw();
    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", onMove);
    return () => {
      if (rafID.current != null) window.cancelAnimationFrame(rafID.current);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
    };
  }, [resize, circleParams, dpr, ease, staticity, vx, vy, refresh, rgb.join()]);

  return (
    <div ref={containerRef} className={cn("pointer-events-none", className)} aria-hidden>
      <canvas ref={canvasRef} className="size-full" />
    </div>
  );
}
