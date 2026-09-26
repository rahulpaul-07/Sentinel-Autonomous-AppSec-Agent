"""
The benchmark must not hand the model its answers.

The hunter reads each target file verbatim. The targets used to carry comments
such as "VULN 2 (SQL injection): the username is glued directly into the SQL
text" on the lines above each labelled bug, and the clean control said "Argument
list, no shell -> no command injection". Every published number up to September
2026 was measured with those hints in the prompt.

Labels belong in ground_truth.json only. This test fails if a comment or
docstring in a target names a vulnerability class or says where one is.
"""

import ast
import io
import json
import re
import tokenize
from pathlib import Path

import pytest

TARGETS = sorted(p for p in Path("targets").iterdir() if (p / "ground_truth.json").is_file())

HINTS = re.compile(
    r"vuln|inject|travers|deserial|pickle payload|hardcoded|attacker|exploit|"
    r"secure|unsafe|sanitiz|parameteri|no shell|ground truth|false.positive",
    re.IGNORECASE,
)


def _prose(source: str) -> list[tuple[int, str]]:
    """Every comment and docstring in the file, with its line number."""
    out = [(tok.start[0], tok.string) for tok in
           tokenize.generate_tokens(io.StringIO(source).readline)
           if tok.type == tokenize.COMMENT]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                out.append((getattr(node, "lineno", 1), doc))
    return out


@pytest.mark.parametrize("target", TARGETS, ids=lambda p: p.name)
def test_target_prose_gives_no_hints(target):
    for path in target.rglob("*.py"):
        for line, text in _prose(path.read_text(encoding="utf-8")):
            match = HINTS.search(text)
            assert not match, f"{path}:{line} hints at the answer: {match.group(0)!r}"


@pytest.mark.parametrize("target", TARGETS, ids=lambda p: p.name)
def test_every_label_points_at_code(target):
    truth = json.loads((target / "ground_truth.json").read_text(encoding="utf-8"))
    for label in truth["vulnerabilities"]:
        lines = (target / label["file"]).read_text(encoding="utf-8").splitlines()
        assert 1 <= label["line"] <= len(lines)
        code = lines[label["line"] - 1].strip()
        assert code and not code.startswith("#"), f"{target.name}: label on {code!r}"
