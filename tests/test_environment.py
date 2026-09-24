"""
Tests for per-target sandbox images.

The failure modes worth pinning are all about CALLS, not return values:
  * the build recipe installing the target itself (a real exploit would then be
    traced through site-packages and graded CLASS_ONLY),
  * a built image never reaching `docker run`, so exploits still run bare,
  * building the image quietly dropping `--network none` on the run,
  * a flag that the CLI or evaluator accepts and never passes on.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinel import environment
from sentinel.environment import (
    Environment,
    dockerfile,
    find_dependencies,
    image_tag,
    prepare_environment,
)
from sentinel.llm import LLMResponse
from sentinel.sandbox import DEFAULT_IMAGE
from sentinel.scanner import Scanner


# --- dependency discovery ----------------------------------------------------

def test_requirements_are_read_and_local_installs_skipped(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# pinned\n"
        "flask==3.1.3\n"
        "requests>=2  # http\n"
        "\n"
        "-e .\n"
        ".\n"
        "./plugins/extra\n"
        "-r dev.txt\n",
        encoding="utf-8",
    )
    spec = find_dependencies(tmp_path)

    assert spec.source == "requirements.txt"
    assert spec.requirements == ["flask==3.1.3", "requests>=2"]
    assert spec.skipped == ["-e .", ".", "./plugins/extra", "-r dev.txt"]


def test_pyproject_dependencies_are_read(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["flask>=3", "pyyaml==6.0.3"]\n',
        encoding="utf-8",
    )
    spec = find_dependencies(tmp_path)

    assert spec.source == "pyproject.toml"
    assert spec.requirements == ["flask>=3", "pyyaml==6.0.3"]


def test_requirements_file_wins_over_pyproject(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.1.3\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["flask>=3"]\n', encoding="utf-8"
    )
    assert find_dependencies(tmp_path).requirements == ["flask==3.1.3"]


def test_unparseable_pyproject_is_recorded_not_raised(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    spec = find_dependencies(tmp_path)
    assert spec.requirements == [] and spec.skipped == ["unparseable"]


def test_no_declared_dependencies(tmp_path):
    spec = find_dependencies(tmp_path)
    assert spec.source == "" and spec.requirements == []


def test_benchmark_targets_declare_flask():
    """Every benchmark target imports Flask, so each must declare it."""
    for target in ("vulnerable_app", "safe_app", "traversal_app", "deserialize_app"):
        reqs = find_dependencies(Path("targets") / target).requirements
        assert any(r.lower().startswith("flask==") for r in reqs), target


# --- the image ---------------------------------------------------------------

def test_image_tag_is_content_addressed():
    assert image_tag(["flask==3.1.3"]) == image_tag(["flask==3.1.3"])
    assert image_tag(["flask==3.1.3"]) != image_tag(["flask==3.1.2"])
    assert image_tag(["flask==3.1.3"]) != image_tag(["flask==3.1.3"], base="python:3.11-slim")


def test_dockerfile_never_installs_the_target():
    """Installing the project would shadow the /work copy the tracer watches."""
    recipe = dockerfile()
    copies = [line for line in recipe.splitlines() if line.startswith("COPY")]

    assert copies == ["COPY requirements.txt /tmp/sentinel-requirements.txt"]
    assert "pip install ." not in recipe and " -e " not in recipe
    assert recipe.startswith(f"FROM {DEFAULT_IMAGE}\n")


# --- building: assert on the docker calls ------------------------------------

class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _record(calls, inspect_rc=1, build=None):
    """Fake subprocess.run for the environment module, recording every call."""
    def run(cmd, **kwargs):
        entry = {"cmd": list(cmd)}
        if cmd[:2] == ["docker", "build"]:
            ctx = Path(cmd[-1])
            entry["dockerfile"] = (ctx / "Dockerfile").read_text(encoding="utf-8")
            entry["requirements"] = (ctx / "requirements.txt").read_text(encoding="utf-8")
            calls.append(entry)
            if isinstance(build, BaseException):
                raise build
            return build or _Proc(0)
        calls.append(entry)
        return _Proc(inspect_rc)
    return run


def _target_with(tmp_path, reqs):
    (tmp_path / "requirements.txt").write_text(reqs, encoding="utf-8")
    return tmp_path


def test_no_dependencies_means_no_docker_calls(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(environment.subprocess, "run", _record(calls))

    env = prepare_environment(tmp_path)

    assert calls == []
    assert env.image == DEFAULT_IMAGE and env.status == "default"


def test_builds_a_tagged_image_from_the_declared_dependencies(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(environment.subprocess, "run", _record(calls))

    env = prepare_environment(_target_with(tmp_path, "flask==3.1.3\n-e .\n"))
    tag = image_tag(["flask==3.1.3"])

    assert calls[0]["cmd"] == ["docker", "image", "inspect", tag]
    build = calls[1]
    assert build["cmd"][:4] == ["docker", "build", "-t", tag]
    assert build["requirements"] == "flask==3.1.3\n"     # the skipped `-e .` is gone
    assert build["dockerfile"] == dockerfile()
    assert env.image == tag and env.status == "built"


def test_existing_image_is_reused_without_building(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(environment.subprocess, "run", _record(calls, inspect_rc=0))

    env = prepare_environment(_target_with(tmp_path, "flask==3.1.3\n"))

    assert [c["cmd"][1] for c in calls] == ["image"]
    assert env.status == "cached" and env.image == image_tag(["flask==3.1.3"])


def test_build_failure_falls_back_to_the_bare_image_and_says_why(monkeypatch, tmp_path):
    calls = []
    failed = _Proc(1, stderr="ERROR: No matching distribution found for nope==9")
    monkeypatch.setattr(environment.subprocess, "run", _record(calls, build=failed))

    env = prepare_environment(_target_with(tmp_path, "nope==9\n"))

    assert env.image == DEFAULT_IMAGE
    assert env.status == "build_failed"
    assert "No matching distribution" in env.error


def test_build_timeout_is_a_recorded_failure(monkeypatch, tmp_path):
    calls = []
    timeout = subprocess.TimeoutExpired(cmd="docker build", timeout=1)
    monkeypatch.setattr(environment.subprocess, "run", _record(calls, build=timeout))

    env = prepare_environment(_target_with(tmp_path, "flask==3.1.3\n"))

    assert env.status == "build_failed" and env.image == DEFAULT_IMAGE


# --- the scanner hands the image to `docker run` ------------------------------

class StubLLM:
    model = "stub/model"

    def complete(self, prompt, system=None):
        if "Analyze this Python file" in prompt:
            text = ('{"findings": [{"vuln_class": "SQL Injection", "line": 33,'
                    ' "severity": "critical", "description": "sqli", "confidence": 0.9}]}')
        else:
            text = "import app\nprint('SENTINEL_PWNED')"
        return LLMResponse(text=text, prompt_tokens=1, completion_tokens=1, cost_usd=0.0)


def _capture_docker_run(monkeypatch):
    commands = []

    def run(cmd, **kwargs):
        commands.append(list(cmd))
        return _Proc(0, stdout="SENTINEL_PWNED\n")

    monkeypatch.setattr("sentinel.sandbox.subprocess.run", run)
    return commands


def test_built_image_is_what_docker_run_uses(monkeypatch):
    built = Environment(image="sentinel-env:abc123", status="built")
    seen_targets = []

    def fake_prepare(target, base=DEFAULT_IMAGE):
        seen_targets.append((target, base))
        return built

    monkeypatch.setattr("sentinel.scanner.prepare_environment", fake_prepare)
    commands = _capture_docker_run(monkeypatch)

    report = Scanner(StubLLM(), "targets/vulnerable_app", build_env=True).scan(patch=False)

    assert seen_targets == [("targets/vulnerable_app", DEFAULT_IMAGE)]
    run = next(c for c in commands if c[:2] == ["docker", "run"])
    assert "sentinel-env:abc123" in run
    # The richer image must not loosen the cage.
    i = run.index("--network")
    assert run[i + 1] == "none"
    assert "--read-only" in run
    assert report.environment is built
    assert report.to_dict()["environment"]["image"] == "sentinel-env:abc123"


def test_without_build_env_nothing_is_built_and_the_image_is_recorded(monkeypatch):
    def must_not_build(*a, **k):
        raise AssertionError("prepare_environment called without --build-env")

    monkeypatch.setattr("sentinel.scanner.prepare_environment", must_not_build)
    commands = _capture_docker_run(monkeypatch)

    report = Scanner(StubLLM(), "targets/vulnerable_app").scan(patch=False)

    run = next(c for c in commands if c[:2] == ["docker", "run"])
    assert DEFAULT_IMAGE in run
    assert report.to_dict()["environment"] == {
        "image": DEFAULT_IMAGE, "source": "", "requirements": [], "skipped": [],
        "status": "default", "error": "",
    }


def test_failed_build_is_announced_in_the_summary(monkeypatch):
    monkeypatch.setattr(
        "sentinel.scanner.prepare_environment",
        lambda target, base=DEFAULT_IMAGE: Environment(
            image=DEFAULT_IMAGE, status="build_failed", error="boom"),
    )
    _capture_docker_run(monkeypatch)

    report = Scanner(StubLLM(), "targets/vulnerable_app", build_env=True).scan(patch=False)

    assert "build_failed" in report.summary()
    assert "WARNING" in report.summary()


def test_evaluator_passes_build_env_to_the_scanner(monkeypatch):
    """A flag the evaluator accepts but drops would silently grade every target bare."""
    from sentinel import evaluation

    seen = []

    class RecordingScanner:
        def __init__(self, llm, target, build_env=False, **kwargs):
            seen.append(build_env)

        def scan(self, patch=True):
            from sentinel.scanner import ScanReport
            return ScanReport(target="t")

    monkeypatch.setattr(evaluation, "Scanner", RecordingScanner)
    evaluation.evaluate_target(StubLLM(), "targets/vulnerable_app", build_env=True)
    evaluation.evaluate_target(StubLLM(), "targets/vulnerable_app")

    assert seen == [True, False]


def test_cli_passes_build_env_to_the_scanner(monkeypatch):
    import scan

    seen = {}

    class RecordingScanner:
        def __init__(self, llm, target, **kwargs):
            seen.update(kwargs)

        def scan(self, validate=True, patch=True):
            from sentinel.scanner import ScanReport
            return ScanReport(target=target_dir)

    target_dir = "targets/vulnerable_app"
    monkeypatch.setattr(scan, "Scanner", RecordingScanner)
    monkeypatch.setattr(scan, "LLMClient", lambda: StubLLM())
    monkeypatch.setattr("sys.argv", ["sentinel", target_dir, "--build-env",
                                     "--no-validate", "--no-patch"])
    scan.main()

    assert seen.get("build_env") is True


def test_dependencies_come_from_env_root_and_the_base_image_is_honoured(monkeypatch):
    """A scan scoped to a subdirectory must still build from the repo's own deps."""
    seen = []

    def fake_prepare(target, base=DEFAULT_IMAGE):
        seen.append((target, base))
        return Environment(image="sentinel-env:sub", status="built")

    monkeypatch.setattr("sentinel.scanner.prepare_environment", fake_prepare)
    commands = _capture_docker_run(monkeypatch)

    Scanner(StubLLM(), "targets/vulnerable_app", build_env=True,
            image="python:3.10-slim", env_root="targets").scan(patch=False)

    assert seen == [("targets", "python:3.10-slim")]
    run = next(c for c in commands if c[:2] == ["docker", "run"])
    assert "sentinel-env:sub" in run
