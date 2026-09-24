"""
Per-target images, built and used for real.

The benchmark targets all import Flask. In the bare image every claim about them
grades ENV_INCOMPLETE. These tests build the image from the target's declared
dependencies and check that the same exploit then reaches LINE_PROVEN, which is
the whole point of building it. They need network for `pip install` at build
time; the exploit itself still runs with `--network none`.

Run with:  pytest -m docker
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.environment import prepare_environment
from sentinel.evidence import Evidence
from sentinel.hunter import Finding
from sentinel.sandbox import DEFAULT_IMAGE, Sandbox
from sentinel.validator import Validator
from tests.integration._support import FixedPocLLM

pytestmark = pytest.mark.docker

VULNERABLE_APP = Path("targets/vulnerable_app")

FLASK_SQLI_POC = """\
import sqlite3
import app
db = sqlite3.connect("app.db")
db.execute("CREATE TABLE IF NOT EXISTS users (name TEXT)")
db.execute("INSERT INTO users VALUES ('admin')")
db.commit()
resp = app.app.test_client().get("/user", query_string={"username": "' OR '1'='1"})
if "admin" in resp.get_data(as_text=True):
    print("SENTINEL_PWNED")
"""


def _validate(image: str):
    finding = Finding("SQL Injection", "app.py", 33, "critical", "sqli", 1.0)
    validator = Validator(FixedPocLLM(FLASK_SQLI_POC), Sandbox(image=image),
                          target=VULNERABLE_APP, max_attempts=1)
    return validator.validate(finding, (VULNERABLE_APP / "app.py").read_text("utf-8"))


def test_bare_image_cannot_test_a_flask_target():
    """The baseline this module exists to fix."""
    result = _validate(DEFAULT_IMAGE)

    assert result.evidence is Evidence.ENV_INCOMPLETE
    assert result.missing_module == "flask"


def test_built_image_lets_the_same_exploit_prove_the_line():
    env = prepare_environment(VULNERABLE_APP)
    assert env.status in ("built", "cached"), env.error

    result = _validate(env.image)

    assert result.evidence is Evidence.LINE_PROVEN, result.output
    assert 33 in result.witness.driven_lines


def test_target_is_not_installed_into_the_image():
    """The tracer must see /work/app.py, never a site-packages copy."""
    env = prepare_environment(VULNERABLE_APP)
    probe = "python3 -c \"import importlib.util as u; print(u.find_spec('app'))\""

    result = Sandbox(image=env.image).run(probe)

    assert "None" in result.stdout, result.stdout + result.stderr


def test_unresolvable_dependency_is_a_recorded_build_failure(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "sentinel-no-such-package-for-tests==0.0.1\n", encoding="utf-8"
    )
    env = prepare_environment(tmp_path)

    assert env.status == "build_failed"
    assert env.image == DEFAULT_IMAGE
    assert env.error
