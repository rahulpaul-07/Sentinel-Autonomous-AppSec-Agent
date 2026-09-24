"""Provenance runs real git: a wrong dirty flag would mislabel every published run."""

import subprocess

from sentinel.provenance import sentinel_revision


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   cwd=cwd, check=True, capture_output=True)


def test_clean_commit_then_untracked_file_then_tracked_edit(tmp_path):
    (tmp_path / "code.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")

    rev = sentinel_revision(tmp_path)
    assert len(rev["commit"]) == 40 and rev["dirty"] is False

    # A results file from an earlier run must not mark the code dirty.
    (tmp_path / "eval-results.json").write_text("{}", encoding="utf-8")
    assert sentinel_revision(tmp_path)["dirty"] is False

    (tmp_path / "code.py").write_text("x = 2\n", encoding="utf-8")
    assert sentinel_revision(tmp_path)["dirty"] is True


def test_outside_a_repository_the_commit_is_unknown(tmp_path):
    assert sentinel_revision(tmp_path) == {"commit": "", "dirty": None}
