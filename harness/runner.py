"""Run probes against a sandbox-under-test and produce a report."""
from __future__ import annotations

import datetime as _dt
import json
import os

from .adapters import SandboxUnderTest
from .probes import PROBES, Probe
from .result import (CONTAINED_MARKER, ESCAPE_MARKER, ProbeResult, Verdict)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _classify(probe: Probe, stdout: str, stderr: str, timed_out: bool) -> tuple[str, str]:
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith(ESCAPE_MARKER):
            return Verdict.ESCAPED.value, line[len(ESCAPE_MARKER):].strip()
        if line.startswith(CONTAINED_MARKER):
            return Verdict.CONTAINED.value, line[len(CONTAINED_MARKER):].strip()
    if timed_out:
        return Verdict.ERROR.value, "probe timed out"
    return Verdict.ERROR.value, (stderr.strip().splitlines()[-1] if stderr.strip() else "no verdict emitted")


def run(sandbox: SandboxUnderTest, probes: list[Probe] | None = None,
        include_dangerous: bool = False, timeout: int = 30) -> list[ProbeResult]:
    probes = probes or PROBES
    results: list[ProbeResult] = []
    for probe in probes:
        if probe.dangerous and not include_dangerous:
            results.append(ProbeResult(
                probe.id, probe.category, probe.severity, Verdict.SKIPPED.value,
                "dangerous probe skipped (pass include_dangerous to run)", probe.taxonomy))
            continue
        exec_res = sandbox.run_code(probe.code, timeout=timeout)
        verdict, detail = _classify(probe, exec_res.stdout, exec_res.stderr, exec_res.timed_out)
        results.append(ProbeResult(
            probe.id, probe.category, probe.severity, verdict, detail,
            probe.taxonomy, exec_res.stdout.strip(), exec_res.stderr.strip()))
    return results


def summarize(results: list[ProbeResult]) -> dict:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    escaped = [r for r in results if r.verdict == Verdict.ESCAPED.value]
    worst = min((_SEV_ORDER.get(r.severity, 9) for r in escaped), default=9)
    worst_label = next((k for k, v in _SEV_ORDER.items() if v == worst), "NONE")
    return {"counts": counts, "escaped": len(escaped), "worst_escaped_severity": worst_label}


def write_reports(sandbox_name: str, results: list[ProbeResult], out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    stamp = _dt.datetime.now().isoformat(timespec="seconds")
    summary = summarize(results)

    base = f"{ts}_{sandbox_name}"
    json_path = os.path.join(out_dir, base + ".json")
    md_path = os.path.join(out_dir, base + ".md")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"sandbox": sandbox_name, "generated": stamp,
                   "summary": summary,
                   "results": [r.to_dict() for r in results]}, fh, indent=2)

    ordered = sorted(results, key=lambda r: (_SEV_ORDER.get(r.severity, 9), r.probe_id))
    lines = [
        f"# Interpreter-jailbreak sandbox assessment",
        "",
        f"- Sandbox under test: `{sandbox_name}`",
        f"- Generated: {stamp}",
        f"- Probes escaped: **{summary['escaped']}** / {len(results)}  "
        f"(worst escaped severity: **{summary['worst_escaped_severity']}**)",
        "",
        "| Probe | Category | Severity | Verdict | Detail |",
        "|---|---|---|---|---|",
    ]
    for r in ordered:
        detail = (r.detail or "").replace("|", "\\|")
        lines.append(f"| `{r.probe_id}` | {r.category} | {r.severity} | "
                     f"**{r.verdict}** | {detail} |")
    lines += ["", "## Taxonomy mapping", ""]
    for r in ordered:
        lines.append(f"- `{r.probe_id}`: {', '.join(r.taxonomy)}")
    lines += ["", "> Scope note: run only against sandboxes you own or are "
              "authorized to assess. This report records capability, not an "
              "attack on any third party."]
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    return {"json": json_path, "md": md_path, "summary": summary}
