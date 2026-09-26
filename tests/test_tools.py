"""Unit tests for the read-only tool layer."""

import pytest

from sentinel.tools import Tools

TARGET = "targets/vulnerable_app"


def test_path_safety_blocks_escape():
    # The agent must never read outside the target directory.
    tools = Tools(TARGET)
    with pytest.raises(ValueError):
        tools.read_file("../../etc/passwd")


def test_list_files_finds_app():
    assert "app.py" in Tools(TARGET).list_files()


def test_grep_finds_execute():
    matches = Tools(TARGET).grep(r"\.execute\(")
    assert any(m.path == "app.py" for m in matches)

# --- discovery ------------------------------------------------------------------

from sentinel.ingest import ingest  # noqa: E402
from sentinel.tools import MAX_FILE_BYTES, discover  # noqa: E402


def _symlink(link, target):
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")


def test_virtualenvs_are_not_scanned_under_any_name(tmp_path):
    """Every file is a model call; a venv would scan thousands of dependency files."""
    (tmp_path / "app.py").write_text("x = 1\n")
    for venv in ("venv", "my-env"):
        (tmp_path / venv / "lib").mkdir(parents=True)
        (tmp_path / venv / "lib" / "dep.py").write_text("y = 2\n")
    (tmp_path / "my-env" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    assert Tools(tmp_path).list_files() == ["app.py"]


def test_symlink_out_of_the_target_is_never_read(tmp_path):
    """A malicious repo could link app.py to the user's private files."""
    secret = tmp_path / "outside" / "id_rsa"
    secret.parent.mkdir()
    secret.write_text("PRIVATE KEY\n")
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    _symlink(target / "evil.py", secret)

    tools = Tools(target)
    assert tools.list_files() == ["app.py"]
    assert "outside the target" in tools.skipped["evil.py"]


def test_one_bad_symlink_does_not_abort_the_scan(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    _symlink(tmp_path / "dangling.py", tmp_path / "missing.py")
    assert Tools(tmp_path).list_files() == ["app.py"]


def test_oversized_files_are_skipped_and_reported(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "generated.py").write_text("#" * (MAX_FILE_BYTES + 1))
    files, skipped = discover(tmp_path)
    assert files == ["app.py"] and "generated.py" in skipped


def test_ignore_rules_apply_only_inside_the_target(tmp_path):
    """Regression: a project stored under a directory named `build` was mapped empty."""
    project = tmp_path / "build" / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("def f():\n    pass\n")
    assert [f.path.name for f in ingest(project).files] == ["app.py"]
    assert Tools(project).list_files() == ["app.py"]
