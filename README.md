# Your AI Agent's Python Tool Is a Shell

A small, auditable toolkit for measuring whether an **LLM agent's code-execution
tool** actually contains the code it runs — and for **automatically synthesizing
the payloads that escape it** when it doesn't.

Give an agent a "run Python" tool and you have handed model-written (and often
attacker-influenced) code a path toward your host. Many frameworks wrap that tool
in a language-level sandbox — an AST filter, an import allowlist, a dunder block —
and present it as a safety boundary. This toolkit tests that claim empirically
against the *real* executors, and ships the tooling behind a conference talk of
the same name.

> **Headline result:** against `smolagents` `LocalPythonExecutor` (v1.26.0), a one
> line `str.format` gadget reads host environment secrets and **survives the
> project's in-review hardening patch**; and authorizing a single ordinary import
> (`numpy`, `torch`, `joblib`, `pickle`, `yaml`, `subprocess`) yields full command
> execution. An AST allowlist is not a security boundary.

---

## Scope & ethics (read first)

- Run this **only** against a sandbox you own or are explicitly authorized to
  assess. Every shipped adapter is **local** — your machine, your Docker, a
  framework installed in your own venv. There is no adapter that targets a third
  party's hosted or production system, by design.
- The payloads prove **capability, not damage**: they read a sentinel you plant
  (an env var / a file), or execute a benign `echo <token>` into a temp file to
  demonstrate code execution. Nothing here attacks a third party or destroys data.
- The underlying bug classes are **public** (CVE-2025-5120, CVE-2025-9959,
  `str.format` dunder escapes, pickle deserialization). `smolagents` itself
  documents `LocalPythonExecutor` as *"not a security boundary."* This repo is a
  **defender's auditing tool and a systematization**, not a 0-day drop. Treat the
  findings as "why you need OS-level isolation," not as an exploit to point at
  someone's deployment.

---

## What's in here

| Tool | What it does |
|---|---|
| `audit_frameworks.py` | Runs fixed, benign host-canary probes through real framework code executors (LangChain `PythonREPLTool` / `PythonAstREPLTool`, `smolagents` `LocalPythonExecutor`, hardened `RestrictedPython`) and scores each **ESCAPED / CONTAINED**. No LLM in the loop — it measures the framework's *default posture*. |
| `gadget_synth.py` | **Automated `str.format` escape-gadget synthesizer.** Given a sandbox's guard policy (e.g. the dunder-block of the in-review patch), it breadth-first searches the live object graph and **emits + self-validates** working exfiltration payloads. Discovers a *family* of dunder-free routes, not one hand-written trick. |
| `rce_via_imports.py` | Proves **RCE-on-authorize**: authorize one common import and confirm command execution against the real sandbox (benign marker-file proof). |
| `demo_rce.py` | A clean, ASCII-safe **3-act live demo** (contained → host-secret read → RCE). `DEMO_PAUSE=1.2` adds stage pacing. |
| `run.py` / `run_agent.py` | Standalone probe battery against `naive-local` vs a hardened/`misconfigured` Docker sandbox, incl. an optional local-LLM-driven agent loop. |
| `harness/` | The adapters, probes, host-canary scoring, and report writers everything is built on. |

---

## Key findings

**Framework default posture** (`audit_frameworks.py`):

| Target | Default posture | Standard probes | `str.format` gadget |
|---|---|---|---|
| LangChain `PythonREPLTool` | in-process `exec()` | 5/5 escaped | n/a (already host) |
| LangChain `PythonAstREPLTool` | AST parse, then `exec()` | 5/5 escaped | n/a (already host) |
| smolagents `LocalPythonExecutor` | AST import/builtin allowlist | 0/5 blocked | **ESCAPED** — host env read |
| RestrictedPython (hardened) | AST rewrite + `safe_builtins` | 0/5 blocked | CONTAINED — bans `str.format` |

**Synthesized read gadgets** vs the in-review dunder-block patch (`gadget_synth.py --policy nodunder`) — all validated against the real sandbox:

```
{0.gi_frame.f_globals[inspect].os.environ[KEY]}
{0.gi_frame.f_globals[logging].os.environ[KEY]}
{0.gi_frame.f_globals[ast].sys.modules[os].environ[KEY]}
{0.gi_frame.f_globals[re].enum.sys.modules[os].environ[KEY]}
```

The `sys.modules` routes re-expose *every* loaded module, so a field-name denylist
cannot close the class.

**RCE by authorizing one ordinary import** (`rce_via_imports.py`): `subprocess`,
`pickle`, `numpy`, `torch`, `joblib`, `yaml` — 6/6. The guard never inspects class
objects and denylists only nine functions, so deserialization loaders
(`torch.load` / `numpy.load` / `joblib.load`) and exec-capable classes
(`subprocess.Popen`) pass straight through. **Loading a model is RCE.**

---

## Install

```bash
python -m pip install -r requirements.txt   # or install the extras you want to test:
python -m pip install smolagents langchain-experimental RestrictedPython
python -m pip install numpy torch joblib pyyaml      # for the deserialization RCE demos
```

Python 3.11+. Docker is optional (only for the `docker` sandbox profile).

## Quickstart

```bash
# audit whatever frameworks you have installed
python audit_frameworks.py

# synthesize + validate str.format read gadgets against the patched policy
python gadget_synth.py --policy nodunder

# prove RCE-on-authorize (writes only a benign marker file)
python rce_via_imports.py

# the 3-act stage demo
DEMO_PAUSE=1.2 python demo_rce.py
```

Example demo output:

```
ACT 1 - the default sandbox looks safe        => CONTAINED (import os / subprocess / __subclasses__)
ACT 2 - one str.format line                   => HOST SECRET LEAKED (defeats PR #2271)
ACT 3 - authorize numpy, load a dataset.npy   => ARBITRARY CODE EXECUTION on the host
```

---

## Why the AST sandbox leaks (smolagents 1.26.0)

- `str.format` resolves `{0.a.b[c]}` in CPython's C-level machinery, **below** every
  Python-level guard — so it is an arbitrary *read* primitive (no calls). A denylist
  of dunder field names can't help, because `sys.modules` and pre-imported stdlib
  modules reach `os.environ` with non-dunder names only.
- The result checker (`check_safer_result`) inspects **modules** and a nine-entry
  function denylist, but **never inspects class objects** — so `subprocess.Popen`
  and deserialization loaders pass.
- The *default* config does resist RCE (modules walled, dunder-call guard, clean base
  modules) — but real deployments widen `authorized_imports`, and that is the break.

The sound fixes are not more denylists: ban `str.format`/`format_map` on
attacker-influenced strings (as RestrictedPython does), don't seed importable modules
into the exec globals, and run untrusted code in a real OS-level sandbox (container,
microVM, or a hosted backend like E2B/Docker/Modal).

## License

MIT — see [LICENSE](LICENSE). Provided for authorized security research and
education. You are responsible for how you use it.
