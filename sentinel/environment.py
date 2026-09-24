"""
sentinel/environment.py
-----------------------
Give the sandbox the third-party packages the target imports.

The problem
-----------
The default sandbox image is a bare Python install. A target that imports Flask
dies at its own `import flask` before any exploit runs, so every claim about it is
graded ENV_INCOMPLETE. That grade is honest, but it means nothing was tested.

The approach
------------
Read the dependencies the target declares, and bake them into an image derived
from the default one. Install happens at BUILD time, with network, because the
sandbox itself runs with `--network none` and a read-only root filesystem: nothing
can be installed once an exploit is running. The exploit still runs in the same
cage; only the starting image differs.

Rules this module keeps
-----------------------
* Dependencies only, never the target itself. If the project were installed into
  site-packages, `import pkg` could load that copy instead of the one mounted at
  /work. The tracer would then see a path under site-packages, and a real exploit
  would be graded CLASS_ONLY. So editable and local-path installs (`-e .`, `.`,
  `./sub`, `file:`) are dropped and recorded as skipped.
* A build failure is not an error the scan should hide. It falls back to the
  default image, where the missing imports grade as ENV_INCOMPLETE, and the
  failure is recorded on the report so a reader can see why.
* Images are cached by a hash of the base image and the dependency list, so a
  second scan of the same target does not rebuild.

Trust boundary
--------------
`pip install` runs code from the packages it installs, with network. That is fine
for targets you chose, such as a benchmark. For arbitrary code it is a real risk
the sandbox does not cover, which is why building is opt-in (`--build-env`).
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.sandbox import DEFAULT_IMAGE

IMAGE_REPO = "sentinel-env"
BUILD_TIMEOUT_SECONDS = 900

# Requirement lines that would install the target itself, or pull in files we
# do not copy into the build context.
_LOCAL_PREFIXES = ("-e", "--editable", ".", "/", "file:", "-r", "--requirement",
                   "-c", "--constraint")


@dataclass
class DependencySpec:
    source: str = ""                                # which file they came from
    requirements: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


@dataclass
class Environment:
    """The image a scan's exploits ran in, and how it came to be."""

    image: str
    source: str = ""
    requirements: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    status: str = "default"      # default | built | cached | build_failed
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "source": self.source,
            "requirements": self.requirements,
            "skipped": self.skipped,
            "status": self.status,
            "error": self.error,
        }


def find_dependencies(target: str | Path) -> DependencySpec:
    """Read declared dependencies from requirements.txt, else pyproject.toml.

    requirements.txt wins when both exist because it is usually the pinned one,
    and the version that shipped is the version that has the bug.
    """
    root = Path(target)

    req = root / "requirements.txt"
    if req.is_file():
        spec = DependencySpec(source="requirements.txt")
        for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(_LOCAL_PREFIXES):
                spec.skipped.append(line)
            else:
                spec.requirements.append(line)
        return spec

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            return DependencySpec(source="pyproject.toml", skipped=["unparseable"])
        deps = data.get("project", {}).get("dependencies", [])
        return DependencySpec(source="pyproject.toml",
                              requirements=[str(d).strip() for d in deps if str(d).strip()])

    return DependencySpec()


def image_tag(requirements: list[str], base: str = DEFAULT_IMAGE) -> str:
    """Name the image by what is in it, so identical inputs reuse one image."""
    digest = hashlib.sha256(
        (base + "\n" + "\n".join(requirements)).encode("utf-8")
    ).hexdigest()
    return f"{IMAGE_REPO}:{digest[:12]}"


def dockerfile(base: str = DEFAULT_IMAGE) -> str:
    """The build recipe. Note what it does NOT do: copy or install the target."""
    return (
        f"FROM {base}\n"
        "COPY requirements.txt /tmp/sentinel-requirements.txt\n"
        "RUN pip install --no-cache-dir -r /tmp/sentinel-requirements.txt "
        "&& rm /tmp/sentinel-requirements.txt\n"
    )


def prepare_environment(target: str | Path, base: str = DEFAULT_IMAGE) -> Environment:
    """Return an image with the target's dependencies, building it if needed."""
    spec = find_dependencies(target)
    env = Environment(image=base, source=spec.source,
                      requirements=spec.requirements, skipped=spec.skipped)
    if not spec.requirements:
        return env

    tag = image_tag(spec.requirements, base)
    inspect = subprocess.run(["docker", "image", "inspect", tag],
                             capture_output=True, text=True)
    if inspect.returncode == 0:
        env.image, env.status = tag, "cached"
        return env

    with tempfile.TemporaryDirectory(prefix="sentinel-env-") as ctx:
        Path(ctx, "requirements.txt").write_text(
            "\n".join(spec.requirements) + "\n", encoding="utf-8"
        )
        Path(ctx, "Dockerfile").write_text(dockerfile(base), encoding="utf-8")
        try:
            build = subprocess.run(["docker", "build", "-t", tag, ctx],
                                   capture_output=True, text=True,
                                   timeout=BUILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            env.status, env.error = "build_failed", "docker build timed out"
            return env

    if build.returncode != 0:
        env.status = "build_failed"
        env.error = (build.stderr or build.stdout)[-1500:]
        return env

    env.image, env.status = tag, "built"
    return env
