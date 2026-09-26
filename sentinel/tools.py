"""
sentinel/tools.py
-----------------
The "tool layer": the small, safe functions the AI agent calls to investigate a
codebase. Think of these as the agent's hands — the ONLY ways it can touch the
target. Every tool here is:

  * SCOPED to the target directory. The agent can never read outside it. This
    blocks path-traversal (a confused/manipulated agent trying to read /etc/passwd
    or your SSH keys).
  * READ-ONLY. Investigation never modifies the target.
  * SMALL and PREDICTABLE. One clear job each, returning text/data the model can
    use. Good tool design is the #1 driver of agent reliability.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

# Directories that hold someone else's code or generated files. Scanning them costs
# a model call per file and reports bugs in dependencies as bugs in the target.
IGNORE_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules",
    ".venv", "venv", "site-packages", "dist-packages",
    ".tox", ".nox", ".eggs", "build", "dist",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
})

# A hunter prompt carries the whole file. Past this size a file is generated code
# or data, and would blow the model's context; it is skipped and reported.
MAX_FILE_BYTES = 256 * 1024


def _ignored_dir(path: Path) -> bool:
    return (path.name in IGNORE_DIRS
            or path.name.endswith(".egg-info")
            or (path / "pyvenv.cfg").is_file())   # a virtualenv under any name


def discover(root: str | Path) -> tuple[list[str], dict[str, str]]:
    """Python files to analyse under `root`, and the ones skipped with the reason.

    Paths are relative to `root`, in forward-slash form, sorted. Ignore rules apply
    to directories *inside* the target only, never to the directories above it.
    Symlinks are never followed out of the target: a link to ~/.ssh/id_rsa named
    app.py would otherwise have its contents sent to a third-party model.
    """
    base = Path(root).resolve()
    files: list[str] = []
    skipped: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not _ignored_dir(here / d))
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = here / name
            rel = path.relative_to(base).as_posix()
            try:
                real = path.resolve(strict=True)
            except (OSError, RuntimeError):
                skipped[rel] = "unresolvable (broken or looping symlink)"
                continue
            if not real.is_relative_to(base):
                skipped[rel] = "symlink leading outside the target"
                continue
            if real.stat().st_size > MAX_FILE_BYTES:
                skipped[rel] = f"larger than {MAX_FILE_BYTES // 1024} KiB"
                continue
            files.append(rel)
    return sorted(files), skipped


@dataclass
class GrepMatch:
    path: str          # path relative to the target root
    line_number: int
    line: str          # the matching line, stripped of surrounding whitespace


class Tools:
    """Read-only investigation tools, locked to a single target directory."""

    def __init__(self, root: str | Path) -> None:
        # Resolve to one absolute path. Every tool is confined to here.
        self.root = Path(root).resolve()
        self.skipped: dict[str, str] = {}

    def _safe_path(self, relative_path: str) -> Path:
        """Resolve a path and REFUSE anything that escapes the target root.

        This is the security boundary for the whole tool layer. A path like
        '../../etc/passwd' resolves outside self.root, so we reject it.
        """
        candidate = (self.root / relative_path).resolve()
        if not candidate.is_relative_to(self.root):
            raise ValueError(
                f"Refused: path escapes the target directory: {relative_path}"
            )
        return candidate

    def list_files(self) -> list[str]:
        """List the Python files in the target to analyse, relative to the root.

        Files left out for a reason other than being ignored dependencies are
        recorded in `self.skipped`, so a report can say what was never read.
        """
        files, self.skipped = discover(self.root)
        return files

    def read_file(
        self,
        relative_path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> str:
        """Read a file (or a slice) from inside the target directory.

        Line numbers are 1-based and inclusive — matching how humans and error
        messages talk about code.
        """
        path = self._safe_path(relative_path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

        start = (start_line - 1) if start_line else 0
        end = end_line if end_line else len(lines)
        selected = lines[start:end]

        # Prefix each line with its real line number — the agent needs these to
        # report exactly WHERE a vulnerability is.
        numbered = [f"{n}: {text}" for n, text in enumerate(selected, start=start + 1)]
        return "\n".join(numbered)

    def grep(self, pattern: str) -> list[GrepMatch]:
        """Search every Python file in the target for a regex pattern."""
        regex = re.compile(pattern)
        matches: list[GrepMatch] = []
        for rel in self.list_files():
            path = self.root / rel
            text = path.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(GrepMatch(path=rel, line_number=i, line=line.strip()))
        return matches