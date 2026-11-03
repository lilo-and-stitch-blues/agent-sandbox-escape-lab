"""Result and verdict types shared across the harness."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    ESCAPED = "ESCAPED"        # the sandbox allowed the forbidden capability
    CONTAINED = "CONTAINED"    # the sandbox blocked it
    ERROR = "ERROR"            # probe could not run / inconclusive
    SKIPPED = "SKIPPED"        # intentionally not executed (e.g. dangerous, gated off)


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Sentinels a probe prints on stdout to classify itself.
ESCAPE_MARKER = "__ESCAPE__"
CONTAINED_MARKER = "__CONTAINED__"


@dataclass
class ExecResult:
    """Raw result of running code inside a sandbox-under-test."""
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class ProbeResult:
    probe_id: str
    category: str
    severity: str
    verdict: str
    detail: str = ""
    taxonomy: list = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
