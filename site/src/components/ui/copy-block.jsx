import { useState } from "react";
import { Check, Copy } from "lucide-react";

/** A captioned code block with a copy button. Copies `copy` if given, else `code`. */
export function CopyBlock({ caption, code, copy }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(copy ?? code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);   // clipboard blocked: the text is still selectable
    }
  };
  return (
    <figure className="flex min-w-0 flex-col border border-rule">
      <figcaption className="flex items-center justify-between border-b border-rule px-4 py-2 font-mono text-[11.5px] text-muted">
        <span>{caption}</span>
        <button type="button" onClick={onCopy} aria-label={`Copy ${caption}`}
                className="inline-flex items-center gap-1.5 text-body hover:text-ink">
          {copied ? <Check className="h-3.5 w-3.5 text-proof" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
          <span aria-live="polite">{copied ? "copied" : "copy"}</span>
        </button>
      </figcaption>
      <pre className="flex-1 overflow-x-auto bg-panel p-4 font-mono text-[12.5px] leading-relaxed text-ink">{code}</pre>
    </figure>
  );
}
