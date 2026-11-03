"""Adapters for REAL open-source tool-using-agent code executors.

Each adapter implements `SandboxUnderTest.run_code` by submitting code to that
framework's actual code-execution tool, exactly as the framework runs it for an
agent. We then characterise containment with fixed, benign host-canary probes
(no LLM in the loop) so the result reflects the framework's DEFAULT security
posture, not model behaviour.

Only frameworks installed in the current environment report available().
"""
from __future__ import annotations

import io
import contextlib

from .adapters import SandboxUnderTest
from .result import ExecResult


class LangChainREPLAdapter(SandboxUnderTest):
    """LangChain PythonREPLTool — executes code with exec() in-process.

    Default posture: no sandbox; code runs in the host Python process.
    """
    name = "langchain-python-repl"

    def available(self):
        try:
            self._tool()
            return True, ""
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"

    def _tool(self):
        try:
            from langchain_experimental.tools.python.tool import PythonREPLTool
        except Exception:
            from langchain_experimental.tools import PythonREPLTool  # older layout
        return PythonREPLTool()

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        try:
            out = self._tool().run(code)
            return ExecResult(0, out if isinstance(out, str) else str(out), "")
        except Exception as e:  # noqa: BLE001
            return ExecResult(1, "", f"{type(e).__name__}: {e}")


class LangChainAstREPLAdapter(SandboxUnderTest):
    """LangChain PythonAstREPLTool — parses code to an AST, then exec()s it.

    Despite "Ast" in the name, this is NOT a sandbox: the AST is only used to
    return the last expression's value. Code runs in the host Python process
    with full access, same as PythonREPLTool.
    """
    name = "langchain-ast-repl"

    def available(self):
        try:
            self._tool()
            return True, ""
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"

    def _tool(self):
        try:
            from langchain_experimental.tools.python.tool import PythonAstREPLTool
        except Exception:
            from langchain_experimental.tools import PythonAstREPLTool  # older layout
        return PythonAstREPLTool()

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        try:
            out = self._tool().run(code)
            return ExecResult(0, out if isinstance(out, str) else str(out), "")
        except Exception as e:  # noqa: BLE001
            return ExecResult(1, "", f"{type(e).__name__}: {e}")


class RestrictedPythonAdapter(SandboxUnderTest):
    """RestrictedPython — AST-rewriting sandbox used by Zope/Plone and some
    agent stacks. Configured here the hardened, documented way: safe_builtins,
    safer_getattr (blocks underscore attributes), guarded unpack/iter, and a
    PrintCollector. compile_restricted rejects disallowed syntax at compile
    time; blocked operations raise, which we score as CONTAINED.
    """
    name = "restrictedpython"

    def available(self):
        try:
            import RestrictedPython  # noqa: F401
            return True, ""
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"

    def _globals(self):
        from RestrictedPython import safe_globals
        from RestrictedPython.Guards import (
            safe_builtins, safer_getattr,
            guarded_iter_unpack_sequence, guarded_unpack_sequence,
        )
        from RestrictedPython.PrintCollector import PrintCollector
        g = dict(safe_globals)
        g["__builtins__"] = dict(safe_builtins)
        g["_print_"] = PrintCollector
        g["_getattr_"] = safer_getattr
        g["_getiter_"] = iter
        g["_getitem_"] = lambda o, k: o[k]
        g["_iter_unpack_sequence_"] = guarded_iter_unpack_sequence
        g["_unpack_sequence_"] = guarded_unpack_sequence
        g["_write_"] = lambda x: x
        return g

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        from RestrictedPython import compile_restricted
        try:
            byt = compile_restricted(code, "<audit>", "exec")
        except Exception as e:  # noqa: BLE001 — compile-time rejection = contained
            return ExecResult(1, "", f"{type(e).__name__}: {e}")
        g = self._globals()
        loc: dict = {}
        try:
            exec(byt, g, loc)
            printer = loc.get("_print") or g.get("_print")
            printed = printer() if callable(printer) else ""
            return ExecResult(0, (printed or "").strip(), "")
        except Exception as e:  # noqa: BLE001 — runtime guard trip = contained
            return ExecResult(1, "", f"{type(e).__name__}: {e}")


class SmolagentsLocalAdapter(SandboxUnderTest):
    """smolagents LocalPythonExecutor — AST-filtered in-process interpreter.

    Default posture: imports/builtins restricted to an allowlist; dangerous
    modules raise InterpreterError unless explicitly authorized.
    """
    name = "smolagents-local"

    def __init__(self, authorized_imports: list[str] | None = None):
        # default [] = the framework's restrictive default posture
        self.authorized_imports = authorized_imports or []

    def available(self):
        try:
            self._executor()
            return True, ""
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"

    def _executor(self):
        from smolagents.local_python_executor import LocalPythonExecutor
        ex = LocalPythonExecutor(additional_authorized_imports=self.authorized_imports)
        # newer versions need tools registered before use
        for setter in ("send_tools", "send_variables"):
            fn = getattr(ex, setter, None)
            if fn:
                try:
                    fn({})
                except Exception:
                    pass
        return ex

    def run_code(self, code: str, timeout: int = 30) -> ExecResult:
        try:
            ex = self._executor()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = ex(code)
            printed = buf.getvalue()
            # executor also returns structured output in various shapes
            tail = ""
            try:
                logs = getattr(result, "logs", None)
                out = getattr(result, "output", None)
                tail = "\n".join(str(x) for x in (logs, out) if x)
            except Exception:  # noqa: BLE001
                tail = ""
            return ExecResult(0, (printed + "\n" + tail).strip(), "")
        except Exception as e:  # noqa: BLE001
            # InterpreterError here means the framework blocked the operation
            return ExecResult(1, "", f"{type(e).__name__}: {e}")


FRAMEWORK_ADAPTERS = {
    "langchain-python-repl": LangChainREPLAdapter,
    "langchain-ast-repl": LangChainAstREPLAdapter,
    "smolagents-local": SmolagentsLocalAdapter,
    "restrictedpython": RestrictedPythonAdapter,
}
