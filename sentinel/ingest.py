"""
sentinel/ingest.py
------------------
Code ingestion: turn a target codebase (a folder of .py files) into a structured
"code map" the rest of Sentinel can reason about.

We use Python's built-in `ast` (Abstract Syntax Tree) module. An AST is source code
parsed into a tree of typed nodes: a function becomes a FunctionDef node, an import
becomes an Import node, etc. Walking that tree is far more reliable than searching
raw text with regexes, because it understands the code's structure.

(For multi-language support later we'd swap in tree-sitter. For our Python-first
MVP, `ast` is built in and perfect.)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.tools import IGNORE_DIRS, discover  # noqa: F401  (re-exported)


@dataclass
class FunctionInfo:
    """One function found in a file."""
    name: str
    start_line: int
    end_line: int


@dataclass
class FileInfo:
    """One source file and what we extracted from it."""
    path: Path
    source: str
    functions: list[FunctionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


@dataclass
class CodeMap:
    """The whole target codebase, ingested."""
    root: Path
    files: list[FileInfo] = field(default_factory=list)

    def summary(self) -> str:
        """A short human-readable overview of what we ingested."""
        total_functions = sum(len(f.functions) for f in self.files)
        return (
            f"Code map for: {self.root}\n"
            f"  Files:     {len(self.files)}\n"
            f"  Functions: {total_functions}"
        )


def _extract_from_file(path: Path) -> FileInfo:
    """Parse a single .py file into a FileInfo (functions + imports)."""
    source = path.read_text(encoding="utf-8", errors="replace")

    # Parse source text into an AST. If a file has a syntax error, don't crash the
    # whole run — record it as a FileInfo with no functions/imports.
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return FileInfo(path=path, source=source)

    functions: list[FunctionInfo] = []
    imports: list[str] = []

    # ast.walk visits every node in the tree. We keep the node types we care about.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(
                FunctionInfo(
                    name=node.name,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                )
            )
        elif isinstance(node, ast.Import):
            # e.g.  import os, sqlite3  ->  "os", "sqlite3"
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            # e.g.  from flask import Flask, request  ->  "flask"
            if node.module:
                imports.append(node.module)

    return FileInfo(path=path, source=source, functions=functions, imports=imports)


def ingest(root: str | Path) -> CodeMap:
    """Walk a directory and build a CodeMap of every Python file inside it."""
    root_path = Path(root).resolve()
    code_map = CodeMap(root=root_path)

    # The same discovery the hunter uses, so the map and the scan agree on what
    # the target is. It used to test ignore names against the absolute path, so a
    # project living under a directory called `build` was mapped as empty.
    files, _ = discover(root_path)
    for rel in files:
        code_map.files.append(_extract_from_file(root_path / rel))

    return code_map