"""
Gate for tests that need a real Docker daemon.

Locally, a missing daemon skips these tests so the offline suite stays usable.
In CI, SENTINEL_REQUIRE_DOCKER=1 turns that skip into a failure: a job that
exists to exercise the real sandbox must not go green by skipping everything.
"""

import os

import pytest

from sentinel.sandbox import Sandbox, SandboxUnavailable


@pytest.fixture(scope="session", autouse=True)
def _docker_available():
    try:
        Sandbox.preflight()
    except SandboxUnavailable as exc:
        if os.environ.get("SENTINEL_REQUIRE_DOCKER") == "1":
            pytest.fail(f"SENTINEL_REQUIRE_DOCKER=1 but Docker is unusable: {exc}")
        pytest.skip(f"Docker unavailable: {exc}")
