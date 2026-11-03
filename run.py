#!/usr/bin/env python
"""CLI entry point for the interpreter-jailbreak sandbox assessment harness.

Examples
--------
    # baseline: the weak local sandbox (everything should ESCAPE)
    python run.py --sandbox naive-local

    # hardened reference: Docker (most should be CONTAINED)
    python run.py --sandbox docker

    # point the egress probe at your own canary
    CANARY_HOST=my.canary.example CANARY_PORT=443 python run.py --sandbox docker
"""
from __future__ import annotations

import argparse
import os
import sys

from harness.adapters import ADAPTERS
from harness.runner import run, write_reports


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sandbox", choices=sorted(ADAPTERS), default="naive-local",
                    help="which sandbox-under-test adapter to run (default: naive-local)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "reports"),
                    help="directory for JSON/Markdown reports")
    ap.add_argument("--timeout", type=int, default=30, help="per-probe timeout (s)")
    ap.add_argument("--dangerous", action="store_true",
                    help="also run probes marked dangerous (resource exhaustion)")
    ap.add_argument("--docker-image", default="python:3.12-slim",
                    help="image for the docker adapter")
    args = ap.parse_args()

    if args.sandbox == "docker":
        sandbox = ADAPTERS["docker"](image=args.docker_image)
    else:
        sandbox = ADAPTERS[args.sandbox]()

    ok, reason = sandbox.available()
    if not ok:
        print(f"[!] sandbox '{args.sandbox}' unavailable: {reason}", file=sys.stderr)
        return 2

    print(f"[*] assessing sandbox: {sandbox.name}")
    results = run(sandbox, include_dangerous=args.dangerous, timeout=args.timeout)

    for r in results:
        print(f"  {r.severity:8} {r.probe_id:20} {r.verdict:10} {r.detail}")

    paths = write_reports(sandbox.name, results, args.out)
    s = paths["summary"]
    print(f"\n[*] {s['escaped']} escaped (worst: {s['worst_escaped_severity']})")
    print(f"[*] report: {paths['md']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
