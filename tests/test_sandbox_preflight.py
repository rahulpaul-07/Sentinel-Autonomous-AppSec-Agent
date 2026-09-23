"""Preflight must raise a clear error when Docker is missing -- not fail silently."""

import subprocess
import pytest

from sentinel.sandbox import Sandbox, SandboxUnavailable


def test_missing_docker_cli(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.shutil.which", lambda _: None)
    with pytest.raises(SandboxUnavailable, match="not found on PATH"):
        Sandbox.preflight()


def test_daemon_down(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.shutil.which", lambda _: "/usr/bin/docker")

    def fake_run(*a, **k):
        return subprocess.CompletedProcess(a, returncode=1, stdout="", stderr="daemon down")

    monkeypatch.setattr("sentinel.sandbox.subprocess.run", fake_run)
    with pytest.raises(SandboxUnavailable, match="daemon isn't responding"):
        Sandbox.preflight()


def test_healthy_docker_passes(monkeypatch):
    monkeypatch.setattr("sentinel.sandbox.shutil.which", lambda _: "/usr/bin/docker")

    def fake_run(*a, **k):
        return subprocess.CompletedProcess(a, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("sentinel.sandbox.subprocess.run", fake_run)
    Sandbox.preflight()  # must not raise
