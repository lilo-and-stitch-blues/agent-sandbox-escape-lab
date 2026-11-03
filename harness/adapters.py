"""Sandbox-under-test adapters.

A `SandboxUnderTest` is anything that can execute a block of Python and hand
back stdout/stderr/returncode. Implement `run_code` to point the harness at the
execution environment you are *authorized* to assess:

  - NaiveLocalSandbox : runs code with the host interpreter, essentially
    un-contained. It is the BASELINE: every probe should report ESCAPED here,
    which proves the probes actually detect the capabilities they test.
  - DockerSandbox     : runs code in a locked-down container. It is the
    reference for what a hardened interpreter sandbox *should* block.

To assess a real authorized target later (e.g. an LLM code interpreter you have
written permission to test), write a new adapter whose `run_code` submits the
code through that target's normal interface and returns what came back. Do not
point this at a production system you are not cleared to test.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

from .result import ExecResult


class SandboxUnderTest:
    name = "base"

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        raise NotImplementedError

    def available(self) -> tuple[bool, str]:
        """Return (usable, reason). Override when the adapter has prerequisites."""
        return True, ""


class NaiveLocalSandbox(SandboxUnderTest):
    """Intentionally weak baseline: host interpreter, isolated temp workdir only."""
    name = "naive-local"

    def __init__(self, python: str | None = None):
        self.python = python or sys.executable

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        workdir = tempfile.mkdtemp(prefix="sbx_")
        script = os.path.join(workdir, "probe.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(code)
        try:
            proc = subprocess.run(
                [self.python, "-I", script],
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ExecResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(-1, exc.stdout or "", "TIMEOUT", timed_out=True)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class DockerSandbox(SandboxUnderTest):
    """Hardened reference sandbox. Requires Docker on PATH.

    Defaults model a reasonably-locked-down interpreter: no network, read-only
    root, a small writable tmpfs, dropped capabilities, non-root user.
    """
    name = "docker"

    def __init__(
        self,
        image: str = "python:3.12-slim",
        network: str = "none",
        read_only: bool = True,
        user: str = "65534:65534",   # nobody:nogroup
        mount_host: str | None = None,   # host dir to bind-mount at /mnt/host:ro
        pass_env: list[str] | None = None,  # host env var names to forward (-e)
        extra_args: list[str] | None = None,
    ):
        self.image = image
        self.network = network
        self.read_only = read_only
        self.user = user
        self.mount_host = mount_host
        self.pass_env = pass_env or []
        self.extra_args = extra_args or []

    def available(self) -> tuple[bool, str]:
        if shutil.which("docker") is None:
            return False, "docker not found on PATH"
        return True, ""

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        args = [
            "docker", "run", "--rm", "-i",
            "--network", self.network,
            "--user", self.user,
            "--cap-drop", "ALL",
            "--pids-limit", "64",
            "--memory", "256m",
            "--tmpfs", "/tmp:rw,size=16m",
        ]
        if self.read_only:
            args.append("--read-only")
        if self.mount_host:
            args += ["-v", f"{self.mount_host}:/mnt/host:ro"]
        for name in self.pass_env:
            args += ["-e", name]   # forwards the value from the current env
        args += self.extra_args
        args += [self.image, "python", "-I", "-"]
        try:
            proc = subprocess.run(
                args,
                input=code,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ExecResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(-1, exc.stdout or "", "TIMEOUT", timed_out=True)


ADAPTERS = {
    "naive-local": NaiveLocalSandbox,
    "docker": DockerSandbox,
}
