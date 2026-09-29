// A file tree in the spirit of Magic UI's File Tree, without its Radix and
// shadcn dependencies: folders are disclosure buttons, files select a detail.

import { useState } from "react";
import { ArrowUpRight, ChevronRight, FileCode2, Folder, FolderOpen } from "lucide-react";

import { cn } from "@/lib";
import { REPO, REPO_TREE } from "@/data";

const pathOf = (folder, name) => (folder ? `${folder}/${name}` : name).replace(/\/$/, "");

export function RepoExplorer() {
  const [open, setOpen] = useState({ sentinel: true });
  const [selected, setSelected] = useState({ path: "sentinel/witness.py",
    role: "The tracing harness, its nonce-authenticated record, the pre-execution screen." });

  const renderFile = (folder, name, role) => {
    const path = pathOf(folder, name);
    const isSel = selected.path === path;
    return (
      <li key={path}>
        <button type="button" onClick={() => setSelected({ path, role })} aria-pressed={isSel}
                className={cn("flex w-full items-center gap-2 px-2 py-1 text-left font-mono text-[13px]",
                              isSel ? "bg-ink text-paper" : "text-body hover:bg-panel hover:text-ink")}>
          <FileCode2 className="h-3.5 w-3.5 shrink-0 opacity-70" aria-hidden />
          <span className="truncate">{name}</span>
        </button>
      </li>
    );
  };

  const isDir = selected.path && !/\.\w+$/.test(selected.path);
  const href = `${REPO}/${isDir ? "tree" : "blob"}/master/${selected.path}`;

  return (
    <div className="mt-8 grid border border-rule md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <ul className="max-h-[420px] overflow-y-auto border-b border-rule p-2 md:border-b-0 md:border-r" aria-label="Repository files">
        {REPO_TREE.map((node) => node.file ? (
          renderFile("", node.file, node.role)
        ) : (
          <li key={node.name}>
            <button type="button" aria-expanded={!!open[node.name]}
                    onClick={() => setOpen((o) => ({ ...o, [node.name]: !o[node.name] }))}
                    className="flex w-full items-center gap-2 px-2 py-1 text-left font-mono text-[13px] text-ink hover:bg-panel">
              <ChevronRight className={cn("h-3.5 w-3.5 shrink-0 transition-transform", open[node.name] && "rotate-90")} aria-hidden />
              {open[node.name] ? <FolderOpen className="h-3.5 w-3.5 shrink-0" aria-hidden />
                               : <Folder className="h-3.5 w-3.5 shrink-0" aria-hidden />}
              {node.name}/
            </button>
            {open[node.name] && (
              <ul className="ml-4 border-l border-rule pl-2">
                {node.children.map(([name, role]) => (
                  renderFile(node.name, name, role)
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      <div className="p-5" aria-live="polite">
        <p className="font-mono text-[12px] uppercase tracking-[.12em] text-muted">Selected</p>
        <p className="mt-1 break-all font-mono text-[15px] text-ink">{selected.path}</p>
        <p className="mt-3 text-[15px] leading-[1.6] text-body">{selected.role}</p>
        <a href={href} target="_blank" rel="noopener noreferrer"
           className="mt-5 inline-flex items-center gap-1 text-[14px] text-ink underline decoration-rule underline-offset-4 hover:decoration-ink">
          Open on GitHub <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
        </a>
      </div>
    </div>
  );
}
