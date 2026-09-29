// Numbered question list after 21st.dev's FAQ layout. Native <details>, so it
// works without script and with the keyboard.

import { Plus } from "lucide-react";

import { FAQ } from "@/data";

export function Faq() {
  return (
    <div className="mt-8 border-t border-rule">
      {FAQ.map((item, i) => (
        <details key={item.q} className="group border-b border-rule">
          <summary className="flex cursor-pointer list-none items-baseline gap-4 py-4 text-ink hover:text-ink [&::-webkit-details-marker]:hidden">
            <span className="w-7 shrink-0 font-mono text-[12px] text-muted">{String(i + 1).padStart(2, "0")}</span>
            <span className="flex-1 text-[16px] font-medium">{item.q}</span>
            <Plus className="h-4 w-4 shrink-0 translate-y-0.5 text-muted transition-transform group-open:rotate-45" aria-hidden />
          </summary>
          <p className="max-w-[70ch] pb-5 pl-11 pr-8 text-[15px] leading-[1.65] text-body">{item.a}</p>
        </details>
      ))}
    </div>
  );
}
