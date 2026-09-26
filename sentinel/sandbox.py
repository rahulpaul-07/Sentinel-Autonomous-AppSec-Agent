"""
sentinel/sandbox.py
-------------------
Run untrusted code inside a locked-down, disposable Docker container.

The Validator uses this to execute proof-of-concept exploit code. That code is
UNTRUSTED, so the container is deliberately caged:

  --network none      no external network access at all
  --memory / --cpus   capped resources (can't exhaust the host); swap capped too
  --pids-limit        cap process count (blocks fork bombs)
  --read-only         root filesystem is immutable; scratch space is a capped tmpfs
  --cap-drop ALL      drop every Linux capability
  --user 65534        run as `nobody`, not as root inside the container
  no-new-privileges   setuid binaries cannot raise privileges again
  --rm                the container is deleted the moment it exits
  a hard timeout      we kill anything that runs too long
  an output cap       stdout and stderr are truncated INSIDE the container, so an
                      exploit printing in a loop cannot exhaust the host's memory

We shell out to the `docker` CLI with subprocess so every security flag is visible
in the code -- you should be able to point at each one and say why it's there.

Preflight
---------
Docker being installed is not the same as Docker running. If the daemon is down or
the CLI is missing, every validation would silently fail and every finding would be
rejected for the wrong reason -- the tool would look like it "found nothing" when it
actually never got to try. `preflight()` turns that into one clear, early error.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path


class SandboxUnavailable(RuntimeError):
    """Raised when Docker isn't usable, so the caller can fail fast and clearly."""


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


DEFAULT_IMAGE = "python:3.12-slim"

# Bytes kept from each of stdout and stderr. An exploit's useful output is a few
# kilobytes; the witness record is under 10. Anything past this is noise, and
# capturing it unbounded let a `while True: print(...)` fill host memory within
# the timeout.
OUTPUT_CAP_BYTES = 1_000_000

# The unprivileged user the container runs as (`nobody` in Debian images).
SANDBOX_USER = "65534:65534"


def capped(command: str, limit: int = OUTPUT_CAP_BYTES) -> str:
    """Wrap a shell command so each of its output streams stops at `limit` bytes.

    fd 3 carries the command's stdout past the pipe that caps its stderr; both caps
    run inside the container. A writer that overruns its cap gets SIGPIPE.
    """
    return (f"{{ {{ {command}; }} 2>&1 1>&3 | head -c {limit} 1>&2; }} 3>&1 "
            f"| head -c {limit}")


class Sandbox:
    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        memory: str = "256m",
        cpus: str = "1.0",
        pids_limit: int = 128,
        timeout_seconds: int = 20,
    ) -> None:
        self.image = image
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def preflight() -> None:
        """Check that the Docker CLI exists and the daemon answers. Raise if not.

        `docker info` is a cheap round-trip to the daemon: it succeeds only when the
        daemon is actually up, which `docker --version` (CLI only) does not tell us.
        """
        if shutil.which("docker") is None:
            raise SandboxUnavailable(
                "Docker CLI not found on PATH. Install Docker Desktop and ensure "
                "`docker` is available in your shell."
            )
        try:
            proc = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise SandboxUnavailable(f"Could not reach the Docker daemon: {exc}") from exc
        if proc.returncode != 0:
            raise SandboxUnavailable(
                "Docker is installed but the daemon isn't responding. Start Docker "
                "Desktop and wait until it reports 'running', then try again.\n"
                f"docker info said: {proc.stderr.strip() or proc.stdout.strip()}"
            )

    def run(self, command: str, workdir: Path | None = None) -> SandboxResult:
        """Run a shell command inside a caged container and capture its output.

        If `workdir` is given, that host folder is mounted READ-ONLY at /work inside
        the container, so code can be run but never modified.
        """
        # A unique name lets us force-kill this exact container if it hangs.
        name = f"sentinel-sbx-{uuid.uuid4().hex[:8]}"

        docker_cmd = [
            "docker", "run",
            "--rm",                        # delete the container when it exits
            "--name", name,
            "--network", "none",           # NO network access
            f"--memory={self.memory}",     # cap RAM
            f"--memory-swap={self.memory}",  # ...and swap: equal values mean none
            f"--cpus={self.cpus}",         # cap CPU
            f"--pids-limit={self.pids_limit}",  # cap process count (anti fork-bomb)
            "--cap-drop", "ALL",           # drop all Linux capabilities
            "--security-opt", "no-new-privileges",  # setuid cannot regain them
            "--user", SANDBOX_USER,        # not root, even inside the container
            "-e", "PYTHONDONTWRITEBYTECODE=1",  # never try to write into the mount
            "--read-only",                 # immutable root filesystem
            "--tmpfs", "/tmp:size=64m",    # capped scratch space the PoC can write to
        ]

        if workdir is not None:
            host = Path(workdir).resolve()
            docker_cmd += ["-v", f"{host}:/work:ro", "-w", "/work"]
        else:
            # No mount: run in the writable tmpfs so a PoC that creates files
            # (a throwaway sqlite db, a decoy file to read back) still works even
            # though the container's root filesystem is read-only.
            docker_cmd += ["-w", "/tmp"]

        # The image, then run the command through a shell inside the container.
        docker_cmd += [self.image, "sh", "-c", capped(command)]

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as e:
            # The CLI was killed by the timeout; make sure the container is gone too.
            subprocess.run(["docker", "kill", name], capture_output=True, text=True)
            return SandboxResult(
                exit_code=-1,
                stdout=e.stdout or "",
                stderr=(e.stderr or "") + "\n[sandbox] timed out",
                timed_out=True,
            )
