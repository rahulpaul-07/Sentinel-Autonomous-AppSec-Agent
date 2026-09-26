"""
sentinel/provenance.py
----------------------
Record what produced a measurement, so a published number can be traced back.

A score is only reproducible if you know the code, the model and the moment it
came from. Both benchmark harnesses stamp their output with this.

"Dirty" means a TRACKED file differs from the commit. Untracked files are ignored
on purpose: a results file written by the previous run would otherwise mark every
later run dirty. The cost is that a new, uncommitted module would not be flagged,
so commit code before measuring with it.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, UTC
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def sentinel_revision(root: Path = REPO_ROOT) -> dict:
    """{"commit": sha or "", "dirty": bool or None} for the checkout Sentinel runs from."""
    try:
        commit = _git(root, "rev-parse", "HEAD")
        dirty = bool(_git(root, "status", "--porcelain", "--untracked-files=no"))
    except (RuntimeError, OSError):
        return {"commit": "", "dirty": None}
    return {"commit": commit, "dirty": dirty}


def stamp(model: str) -> dict:
    return {
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "model": model,
        "sentinel": sentinel_revision(),
    }


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip())
    return proc.stdout.strip()
