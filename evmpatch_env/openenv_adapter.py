"""
openenv_adapter.py — expose the evmpatch task as an OpenEnv (meta-pytorch/OpenEnv)
Gymnasium-style environment: reset() / step(action) / state, with pydantic Action /
Observation / State models and an execution-verified reward.

Two ways to get an OpenEnv from this repo:

  1. Automatic wrap (recommended, zero code):
        openenv import . --name evmpatch_env --output-dir build/openenv
     OpenEnv's importer understands the `verifiers` `load_environment(...)` convention
     (see OpenEnv README: `openenv import <source> ... Verifiers`), so the verifiers env
     in evmpatch_env/__init__.py becomes an OpenEnv server + client with no extra code.

  2. Native adapter (this file): a hand-written `EvmPatchEnvironment(Environment)` for
     when you want the OpenEnv contract directly (custom Action/Observation types, an
     HTTP/WebSocket server via `create_fastapi_app`, the web debugger, etc.). Its step()
     semantics mirror the verifiers tools exactly and it calls the SAME
     `evmpatch_env.sandbox` reward, so the two backends agree.

This module imports OpenEnv lazily so the package still works without `openenv` installed;
`build_openenv_app()` / the classes raise a clear error only if actually used without it.
Built against OpenEnv core at `openenv.core.env_server` (Environment, Action, Observation,
State, create_fastapi_app) and `openenv.core.client_types.StepResult`.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Optional

from . import sandbox
from . import (  # tool bodies + working-tree helpers, reused verbatim
    list_files as _list_files,
    read_file as _read_file,
    apply_patch as _apply_patch,
    run_tests as _run_tests,
    _diff_from_shipped,
)

try:  # OpenEnv is an optional dependency
    from openenv.core.env_server import (
        Action,
        Environment,
        Observation,
        State,
        create_fastapi_app,
    )
    _OPENENV = True
except Exception:  # pragma: no cover - openenv not installed
    _OPENENV = False
    Action = Observation = State = object          # type: ignore
    Environment = object                            # type: ignore
    create_fastapi_app = None                       # type: ignore


def _require_openenv() -> None:
    if not _OPENENV:
        raise ImportError(
            "openenv is not installed. `pip install openenv` (meta-pytorch/OpenEnv) to use "
            "the native adapter, or use `openenv import .` to auto-wrap the verifiers env."
        )


if _OPENENV:

    class EvmPatchAction(Action):
        """One tool call: tool in {list_files, read_file, apply_patch, run_tests, submit}."""
        tool: str
        path: Optional[str] = None
        find: Optional[str] = None
        replace: Optional[str] = None

    class EvmPatchObservation(Observation):
        """Tool output returned to the policy. `reward`/`done` come from the base class."""
        output: str = ""
        turn: int = 0
        max_turns: int = 30

    class EvmPatchState(State):
        task_id: str = ""
        turn: int = 0
        changed_files: list[str] = []

    class EvmPatchEnvironment(Environment):
        """OpenEnv server env: reset() serves the task prompt; step() runs one tool.

        The episode ends when the policy sends {tool: "submit"} or the turn budget is
        exhausted; the terminal observation carries the execution-verified scalar reward
        from `evmpatch_env.sandbox` (identical to the verifiers rubric).
        """

        SUPPORTS_CONCURRENT_SESSIONS = False  # one working tree per instance

        def __init__(self, task_dir: str, backend: str = "local", max_turns: int = 30):
            super().__init__()
            self._task_dir = Path(task_dir)
            self._backend = backend
            self._max_turns = max_turns
            self._st: dict[str, Any] = {}
            self._episode_id = ""
            self._turn = 0

        # -- helpers ---------------------------------------------------------------
        def _load_working_tree(self) -> None:
            import json, fnmatch
            meta = json.loads((self._task_dir / "task.json").read_text())
            shipped: dict[str, str] = {}
            for g in meta["patchable_globs"]:
                for p in sorted((self._task_dir / "project").glob(g)):
                    if p.is_file():
                        shipped[str(p.relative_to(self._task_dir / "project"))] = p.read_text()
            self._st = {
                "task_dir": str(self._task_dir), "backend": self._backend,
                "shipped": shipped, "work": dict(shipped), "dirty": False,
            }
            self._meta = meta

        def _prompt(self) -> str:
            src = self._st["work"].get("src/contracts/Token.sol", "")
            return (f"Incident: {self._meta['incident']} ({self._meta['chain']} @ block "
                    f"{self._meta['fork_block']}). Patch src/ so the exploit is blocked while "
                    f"functionality tests pass. Tools: list_files, read_file, apply_patch, "
                    f"run_tests, submit.\n\nsrc/contracts/Token.sol:\n{src}")

        # -- OpenEnv contract ------------------------------------------------------
        def reset(self, seed: Optional[int] = None, episode_id: Optional[str] = None,
                  **kwargs: Any) -> "EvmPatchObservation":
            self._episode_id = episode_id or str(uuid.uuid4())
            self._turn = 0
            self._load_working_tree()
            return EvmPatchObservation(output=self._prompt(), done=False, reward=None,
                                       turn=0, max_turns=self._max_turns)

        def step(self, action: "EvmPatchAction", timeout_s: Optional[float] = None,
                 **kwargs: Any) -> "EvmPatchObservation":
            self._turn += 1
            tool = action.tool
            if tool == "list_files":
                out = _list_files(state=self._st)
            elif tool == "read_file":
                out = _read_file(action.path or "", state=self._st)
            elif tool == "apply_patch":
                out = _apply_patch(action.path or "", action.find or "",
                                     action.replace or "", state=self._st)
            elif tool == "run_tests":
                out = _run_tests(state=self._st)
            elif tool == "submit":
                out = "submitted"
            else:
                out = f"ERROR: unknown tool {tool!r}"

            done = tool == "submit" or self._turn >= self._max_turns
            reward = None
            if done:
                patched = _diff_from_shipped(self._st)
                res = sandbox.compute_reward(self._task_dir, patched, backend=self._backend)
                reward = res.score
                out = (out + f"\n[terminal] score={res.score} detail={res.detail}")
            return EvmPatchObservation(output=out, done=done, reward=reward,
                                       turn=self._turn, max_turns=self._max_turns)

        @property
        def state(self) -> "EvmPatchState":
            changed = list((_diff_from_shipped(self._st) or {}).keys())
            return EvmPatchState(episode_id=self._episode_id, step_count=self._turn,
                                 task_id=getattr(self, "_meta", {}).get("task_id", ""),
                                 turn=self._turn, changed_files=changed)


def build_openenv_app(task_dir: str, backend: str = "local", max_turns: int = 30):
    """Return a FastAPI app serving the OpenEnv HTTP/WebSocket contract for one task.

    Run with e.g. `uvicorn` behind the Dockerfile; clients connect with an OpenEnv
    EnvClient. Raises if openenv is not installed.
    """
    _require_openenv()
    env = EvmPatchEnvironment(task_dir=task_dir, backend=backend, max_turns=max_turns)
    return create_fastapi_app(env, EvmPatchAction, EvmPatchObservation)


if __name__ == "__main__":
    import sys
    if not _OPENENV:
        print("openenv not installed; this adapter is a reference. "
              "Use `openenv import .` to auto-wrap the verifiers env.")
        sys.exit(0)
    td = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent.parent / "tasks" / "ngp_2025_09")
    env = EvmPatchEnvironment(td, backend="local", max_turns=5)
    obs = env.reset()
    print("reset output bytes:", len(obs.output))
    print("step(list_files):", env.step(EvmPatchAction(tool="list_files")).output[:120])
    print("state:", env.state)
