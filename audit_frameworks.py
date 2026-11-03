#!/usr/bin/env python
"""Audit the DEFAULT sandbox posture of real OSS agent code-execution tools.

For each installed framework adapter, run a battery of fixed, benign host-canary
probes through its code tool (NO LLM involved) and score each:

    ESCAPED    the probe reached the host (canary token / host artifact returned)
    CONTAINED  the framework blocked or isolated the probe
    ERROR      the adapter could not run the probe

This measures what the framework does out of the box, which is the point: an
agent builder who drops in a code tool inherits whatever default this shows.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import tempfile
import uuid

from harness.frameworks import FRAMEWORK_ADAPTERS


def plant_canary() -> tuple[str, str]:
    token = "HOSTCANARY-" + uuid.uuid4().hex
    os.environ["HOST_SECRET"] = token
    d = os.path.join(tempfile.gettempdir(), "ijl_canary")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "host_canary.txt"), "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    return token, d.replace("\\", "/")


def build_probes(canary_path: str, token: str):
    """Each probe: (id, severity, code, oracle(stdout)->bool)."""
    def has(*toks):
        low = [t.lower() for t in toks]
        return lambda out: any(t in (out or "").lower() for t in low)

    return [
        ("host-env-secret", "HIGH",
         "import os\nprint(os.environ.get('HOST_SECRET','NONE'))",
         has(token)),
        ("host-file-read", "HIGH",
         f"print(open('{canary_path}/host_canary.txt').read())",
         has(token)),
        ("host-fs-sensitive", "HIGH",
         "import os\n"
         "p = r'C:/Windows/win.ini' if os.name=='nt' else '/etc/passwd'\n"
         "print(open(p).read()[:200])",
         has("root:", "[extensions]", "[mci", "16-bit")),
        ("proc-spawn", "HIGH",
         "import subprocess, os\n"
         "cmd = ['whoami'] if os.name=='nt' else ['id']\n"
         "print('PROCOK', subprocess.check_output(cmd).decode(errors='replace'))",
         has("PROCOK")),
        ("egress", "MEDIUM",
         "import socket\n"
         "s=socket.create_connection(('example.com',80),timeout=5); s.close()\n"
         "print('EGRESSOK')",
         has("EGRESSOK")),
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "reports"))
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    token, canary_path = plant_canary()
    probes = build_probes(canary_path, token)
    print(f"[*] host canary planted (dir: {canary_path})\n")

    report = {"generated": _dt.datetime.now().isoformat(timespec="seconds"),
              "frameworks": {}}

    for fname, Adapter in FRAMEWORK_ADAPTERS.items():
        adapter = Adapter()
        ok, why = adapter.available()
        if not ok:
            print(f"--- {fname}: NOT AVAILABLE ({why})")
            continue
        print(f"=== {fname} ===")
        rows = []
        for pid, sev, code, oracle in probes:
            res = adapter.run_code(code, timeout=args.timeout)
            escaped = oracle(res.stdout)
            verdict = "ESCAPED" if escaped else (
                "ERROR" if res.returncode != 0 and not res.stdout and
                "Error" not in (res.stderr or "") else "CONTAINED")
            # a framework that raises its own InterpreterError = CONTAINED, not ERROR
            if not escaped and res.returncode != 0:
                verdict = "CONTAINED"
            print(f"  {sev:7} {pid:18} {verdict}")
            rows.append({"probe": pid, "severity": sev, "verdict": verdict,
                         "stdout": (res.stdout or "")[:300],
                         "stderr": (res.stderr or "")[:300]})
        report["frameworks"][fname] = {
            "escaped": sum(1 for r in rows if r["verdict"] == "ESCAPED"),
            "results": rows}
        print()

    os.makedirs(args.out, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    jpath = os.path.join(args.out, f"{ts}_framework_audit.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print("[*] summary (escaped / total):")
    for fname, f in report["frameworks"].items():
        print(f"    {fname:22} {f['escaped']} / {len(f['results'])}")
    print(f"[*] transcript: {jpath}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
