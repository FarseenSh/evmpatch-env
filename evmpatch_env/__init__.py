"""
evmpatch_env — an execution-verified RL environment for smart-contract vulnerability
PATCHING, in the Prime Intellect `verifiers` convention.

`load_environment(...)` returns a multi-turn tool environment (a verifiers
`StatefulToolEnv`; requires verifiers>=0.3.1). The policy is given the verified on-chain source of a contract that
was really exploited, plus a description of the incident, and must edit the source so
that a held-out proof-of-concept exploit no longer succeeds while functionality
invariants still hold. Reward is computed by actually compiling and running the exploit
and the hidden tests against frozen chain state inside a no-network sandbox
(`evmpatch_env.sandbox`) — it is binary and conjunctive (see sandbox.py).

Tools exposed to the policy: list_files, read_file, apply_patch, run_tests. Each episode
gets an isolated in-memory working copy of the patchable source; `run_tests` gives the
policy execution feedback (compile + which tests pass) without revealing the scalar
reward, and the terminal reward re-runs the same sandbox on the final source.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# `verifiers` and `datasets` are heavy, and neither the grader (sandbox.py) nor the task
# builder needs them. Import them softly so `python -m evmpatch_env.sandbox`, the pytest
# suite and CI all work on a box that only has Foundry — load_environment() is the only
# entry point that actually requires them, and it says so.
try:
    import verifiers as vf
    from datasets import Dataset
    _HAS_VERIFIERS = True
except Exception:                                    # pragma: no cover - optional dep
    vf = None
    Dataset = None
    _HAS_VERIFIERS = False

# NOTE: sandbox is imported lazily inside the two functions that need it. Importing it
# here would make `python -m evmpatch_env.sandbox` emit a RuntimeWarning (the module would
# already be in sys.modules when runpy executes it as __main__).

__version__ = "0.2.0"

SYSTEM_PROMPT = """You are a smart-contract security engineer. You are given the Solidity \
source of a contract that was exploited on-chain, and a description of the incident. Your \
job is to PATCH the source so the exploit no longer works, without breaking the contract.

Rules:
- You may only edit files under src/ (the contract source). You may NOT edit tests, \
foundry.toml, or anything else — those are the graded harness.
- Your patch must (a) make the proof-of-concept exploit fail, (b) keep all functionality \
tests passing, (c) still compile, and (d) preserve the public ABI (do not delete or \
re-type public/external functions).
- Use list_files and read_file to inspect the code, apply_patch to make minimal edits, \
and run_tests to check your work. Call run_tests before you finish.
- Prefer the smallest change that fixes the root cause. Do not disable the contract.

When you are confident the exploit is blocked and everything else still passes, stop."""

TOOL_INSTRUCTIONS = """
Available tools:
- list_files(): list the source files you are allowed to edit.
- read_file(path): return the current contents of a source file (path relative to project root, e.g. "src/contracts/Token.sol").
- apply_patch(path, find, replace): replace the FIRST exact occurrence of `find` with `replace` in the given source file. `find` must match exactly (including whitespace). Returns a confirmation or an error.
- run_tests(): compile the project and run the exploit PoC + hidden functionality tests against the frozen chain state. Returns compile status and per-test pass/fail so you can iterate. Does not reveal your score.
"""


# --------------------------------------------------------------------------- tools
# Each tool takes a hidden `state` arg (skipped in the tool-call JSON schema, injected per call
# by EvmPatchEnv.update_tool_args) so tool bodies can read/write the episode's working
# source tree at state["work"].
def list_files(state: str = "") -> str:
    """List the source files that may be edited in this task."""
    work = state["work"]
    return "\n".join(sorted(work.keys())) or "(no source files)"


def read_file(path: str, state: str = "") -> str:
    """Read the current contents of a patchable source file. `path` is relative to the project root."""
    work = state["work"]
    if path not in work:
        return f"ERROR: {path} is not an editable source file. Use list_files()."
    return work[path]


def apply_patch(path: str, find: str, replace: str, state: str = "") -> str:
    """Replace the first exact occurrence of `find` with `replace` in a source file.

    Args:
        path: source file path relative to the project root (e.g. src/contracts/Token.sol).
        find: exact substring to locate (must be unique enough to match intentionally).
        replace: text to substitute in.
    """
    work = state["work"]
    if path not in work:
        return f"ERROR: {path} is not editable. Use list_files()."
    cur = work[path]
    if find not in cur:
        return "ERROR: `find` text not found verbatim; re-read the file and copy exact whitespace."
    work[path] = cur.replace(find, replace, 1)
    state["dirty"] = True
    return f"OK: applied patch to {path} ({len(work[path])} bytes)."


def run_tests(state: str = "") -> str:
    """Compile and run the exploit PoC + hidden functionality tests against frozen state."""
    from . import sandbox
    patched = _diff_from_shipped(state)
    res = sandbox.compute_reward(state["task_dir"], patched, backend=state["backend"])
    state["last_result"] = res
    lines = [f"compiled: {res.compiled}"]
    if res.outcome == "inconclusive":
        # Never let the policy mistake a broken harness for a blocked exploit.
        lines.append(f"RUN INCONCLUSIVE ({res.reason}): {res.reason_detail}")
    if res.poc:
        lines.append(f"exploit PoC blocked (good): {res.poc_blocked}")
        for tid, t in sorted(res.poc.tests.items()):
            lines.append(f"  - {t.name}: {t.status}" + (f"  [{t.reason}]" if t.reason else ""))
    if res.hidden:
        lines.append(f"hidden functionality tests: {res.hidden.passed} pass / {res.hidden.failed} fail")
        for tid, t in sorted(res.hidden.tests.items()):
            lines.append(f"  - {t.name}: {t.status}" + (f"  [{t.reason}]" if t.reason else ""))
    if res.canaries:
        lines.append(f"WARNING (invalid patch): {', '.join(res.canaries)}")
    if not res.poc or not res.poc.compiled:
        tail = (res.poc.stdout_tail + res.poc.stderr_tail) if res.poc else ""
        lines.append("compile output tail:\n" + tail[-600:])
    return "\n".join(lines)


def _diff_from_shipped(state: dict) -> dict[str, str] | None:
    """Return {rel: content} for files that differ from the shipped source, else None."""
    shipped = state["shipped"]
    out = {rel: c for rel, c in state["work"].items() if shipped.get(rel) != c}
    return out or None


# --------------------------------------------------------------------- reward funcs
def patch_solved_reward(state: dict, **kwargs) -> float:
    """Terminal, execution-verified reward: 1.0 iff the sandbox says the patch is solved."""
    from . import sandbox
    patched = _diff_from_shipped(state)
    res = sandbox.compute_reward(state["task_dir"], patched, backend=state["backend"])
    state["final_result"] = res
    return res.score


# ------------------------------------------------------------------------- the env
class EvmPatchEnv(vf.StatefulToolEnv if _HAS_VERIFIERS else object):
    """StatefulToolEnv that gives each episode an isolated working copy of the source
    and injects it into every tool call via update_tool_args."""

    def __init__(self, task_index: dict[str, dict], backend: str, **kwargs):
        # register tools WITHOUT the hidden `state` arg in the model-facing schema
        super().__init__(tools=[], **kwargs)
        self._task_index = task_index
        self._backend = backend
        for tool in (list_files, read_file, apply_patch, run_tests):
            self.add_tool(tool, args_to_skip=["state"])

    async def setup_state(self, state: vf.State, **kwargs) -> vf.State:
        # `answer` carries the task_id; load that task's shipped source into a working copy
        task_id = state["answer"]
        meta = self._task_index[task_id]
        task_dir = Path(meta["task_dir"])
        shipped: dict[str, str] = {}
        import fnmatch
        for g in meta["patchable_globs"]:
            for p in sorted((task_dir / "project").glob(g)):
                if p.is_file():
                    rel = str(p.relative_to(task_dir / "project"))
                    shipped[rel] = p.read_text()
        state["task_dir"] = str(task_dir)
        state["backend"] = self._backend
        state["shipped"] = shipped
        state["work"] = dict(shipped)       # the agent's mutable copy
        state["dirty"] = False
        return state

    def update_tool_args(self, tool_name: str, tool_args: dict, messages, state: vf.State, **kwargs) -> dict:
        # inject the per-episode working tree into every tool call
        tool_args["state"] = state
        return tool_args


# ----------------------------------------------------------------------- entrypoint
def default_tasks_dir() -> Path:
    """The bundled task corpus: ``evmpatch_env/tasks`` inside an installed wheel, or the
    repository's top-level ``tasks/`` in a source checkout."""
    here = Path(__file__).resolve().parent
    bundled = here / "tasks"
    return bundled if bundled.is_dir() else here.parent / "tasks"


def _load_task_index(tasks_dir: Path, split: str, task_ids: list[str] | None) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for tj in sorted(tasks_dir.glob("*/task.json")):
        meta = json.loads(tj.read_text())
        meta["task_dir"] = str(tj.parent)
        if task_ids is not None:
            if meta["task_id"] not in task_ids:
                continue
        elif split != "all" and meta.get("split") != split:
            continue
        index[meta["task_id"]] = meta
    return index


def load_environment(
    tasks_dir: str | None = None,
    split: str = "train",
    backend: str = "local",
    max_turns: int = 30,
    task_ids: list[str] | None = None,
    **kwargs,
) -> vf.Environment:
    """Build the evmpatch environment.

    Args:
        tasks_dir: directory of task folders (default: the package's bundled ``tasks/``).
        split: 'train' (PoCs <= 2025-12), 'test' (2026-03..2026-08 held-out), or 'all'.
               The temporal split is a HARD rule enforced here and in build_task.py: test
               incidents never enter the training taskset.
        backend: 'local' (replay proxy on localhost, no egress) or 'docker'
                 (`docker run --network none`, production containment).
        max_turns: per-episode tool-call budget.
        task_ids: explicit allow-list of task ids (overrides `split`).
    """
    if not _HAS_VERIFIERS:
        raise ImportError(
            "load_environment() needs `verifiers>=0.3.1` and `datasets`; install them with "
            "`pip install -e .`. The grader (evmpatch_env.sandbox) and the task builder do "
            "not require them."
        )
    if tasks_dir is None:
        tasks_dir = default_tasks_dir()
    tasks_dir = Path(tasks_dir)

    index = _load_task_index(tasks_dir, split, task_ids)
    if not index:
        raise ValueError(f"no tasks for split={split!r} task_ids={task_ids!r} under {tasks_dir}")

    rows = []
    for task_id, meta in index.items():
        vuln_src = Path(meta["task_dir"]) / "project" / "src" / "contracts" / "Token.sol"
        src_text = vuln_src.read_text() if vuln_src.exists() else ""
        question = (
            f"# Incident: {meta['incident']}\n"
            f"Chain: {meta['chain']} (chain id {meta['chain_id']}), forked at block "
            f"{meta['fork_block']}. Vulnerability class: {meta['vulnerability_class']}.\n\n"
            f"{meta.get('notes','')}\n\n{TOOL_INSTRUCTIONS}\n\n"
            f"The main patchable contract is `src/contracts/Token.sol`. Its current "
            f"(vulnerable) source is:\n\n```solidity\n{src_text}\n```\n\n"
            f"Patch the source so the exploit is blocked. Call run_tests() to check, then stop."
        )
        rows.append({
            "question": question,
            "answer": task_id,                       # tool state loads the task by id
            "task": meta["vulnerability_class"],
            "info": {"task_id": task_id, "victim": meta["victim_address"],
                     "split": meta["split"], "source": meta["source"]},
        })

    dataset = Dataset.from_list(rows)
    rubric = vf.Rubric(funcs=[patch_solved_reward], weights=[1.0])

    return EvmPatchEnv(
        task_index=index,
        backend=backend,
        dataset=dataset,
        rubric=rubric,
        system_prompt=SYSTEM_PROMPT,
        max_turns=max_turns,
        **kwargs,
    )
