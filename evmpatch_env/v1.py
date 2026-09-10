"""evmpatch-env as a verifiers v1 taskset.

Each task is one exploited contract. `setup` gives the agent a Foundry project at
`/work/project` (the verified source, its libraries, the proof-of-concept exploit test and
a script that runs it offline against the frozen chain state), so the agent gets execution
feedback while it edits. The hidden functionality and security suites and the expected-test
manifest stay on the host until scoring: the reward re-stages the hash-locked harness
around the source read back from the container and grades it with the same three-valued
scorer as every other backend (`evmpatch_env.grade_runtime`).

`validate` implements the gold-patch and no-op bar: the task's reference repair must grade
`solved` and the shipped vulnerable source must grade `not_solved`; an `inconclusive`
outcome fails either check.

    uv run validate evmpatch-env --runtime.type docker --taskset.image evmpatch-env:latest
"""
from __future__ import annotations

import hashlib
import io
import logging
import tarfile
import time
from collections.abc import Iterable
from pathlib import Path

import verifiers.v1 as vf
from pydantic import Field
from verifiers.v1.errors import TaskError

from . import sandbox
from .build_task import apply_unified_diff
from .grade_runtime import GRADE_ROOT, _tar_filter, grade_in_runtime

logger = logging.getLogger(__name__)

WORKDIR = "/work"
PROJECT = f"{WORKDIR}/project"
DEFAULT_IMAGE = "evmpatch-env:latest"

SYSTEM_PROMPT = (
    "You are a smart-contract security engineer. You are given a Foundry project holding the "
    "Solidity source of a contract that was exploited on-chain, together with a description "
    "of the incident. Repair the source so the exploit no longer works without breaking the "
    "contract.\n\n"
    "Rules:\n"
    "- Edit only the contract source files named in the task. Never modify test/, "
    "foundry.toml, remappings.txt or lib/: they are the graded harness and any change to "
    "them scores 0.\n"
    "- The repair must block the proof-of-concept exploit, keep the project compiling, keep "
    "every public and external function callable, and keep legitimate use working. Hidden "
    "functionality and security tests run at scoring.\n"
    "- Prefer the smallest change that fixes the root cause. Do not disable the contract."
)

RUN_POC = """#!/bin/sh
# Compile the project and run the proof-of-concept exploit against the frozen chain state,
# offline, through the task's fail-closed replay proxy. The exploit test passes while the
# contract is vulnerable and fails once the exploit is blocked. The hidden functionality and
# security suites are not available here; they run at scoring.
set -u
WORK=/work
cd "$WORK/project" || exit 2
rm -f "$WORK/.proxy.port"
python3 "$WORK/rpc_replay.py" replay "$WORK/state/rpc_log.json" 0 \\
    --port-file "$WORK/.proxy.port" --miss-file "$WORK/.rpc_misses.json" \\
    >/dev/null 2>"$WORK/.replay.log" &
PROXY=$!
i=0
while [ ! -s "$WORK/.proxy.port" ] && [ "$i" -lt 200 ]; do sleep 0.1; i=$((i + 1)); done
PORT=$(cat "$WORK/.proxy.port" 2>/dev/null || echo 0)
if [ "$PORT" = "0" ]; then echo "replay proxy did not start (see $WORK/.replay.log)"; kill $PROXY 2>/dev/null; exit 2; fi
sleep 0.2
TASK_FORK_URL="http://127.0.0.1:$PORT" FOUNDRY_OFFLINE=true FOUNDRY_NO_STORAGE_CACHING=true NO_COLOR=1 \\
    forge test --match-path test/poc.t.sol -vv
RC=$?
kill $PROXY 2>/dev/null
rm -f "$WORK/.proxy.port"
exit $RC
"""


def _prompt(meta: dict, patch_rel: str) -> str:
    globs = ", ".join(f"`{g}`" for g in meta["patchable_globs"])
    return (
        f"# Incident: {meta['incident']}\n"
        f"Chain: {meta['chain']} (chain id {meta['chain_id']}), forked at block "
        f"{meta['fork_block']}. Vulnerability class: {meta['vulnerability_class']}.\n\n"
        f"{meta.get('notes', '')}\n\n"
        f"The Foundry project is at {PROJECT}. The vulnerable contract's source is "
        f"{PROJECT}/{patch_rel}; only files matching {globs} under {PROJECT} may be edited. "
        f"Do not modify test/, foundry.toml, remappings.txt or lib/.\n\n"
        f"Run `sh {WORKDIR}/run_poc.sh` to compile the project and execute the "
        f"proof-of-concept exploit against the frozen chain state (offline). The exploit test "
        f"passes while the contract is vulnerable and fails once the exploit is blocked. "
        f"Patch the source so the exploit is blocked while legitimate use keeps working, "
        f"check with the script, then stop."
    )


class EvmPatchData(vf.TaskData):
    task_id: str
    incident: str
    chain: str
    chain_id: int
    fork_block: int
    vulnerability_class: str
    victim_address: str
    date_month: str
    split: str
    patchable_globs: list[str]
    patch_rel: str
    """Project-relative path of the main patchable contract."""
    shipped_sha256: str
    """SHA-256 of the shipped (vulnerable) patchable source."""
    reference_diff: str
    """The reference repair as a unified diff against the shipped source; used by
    `validate` only and never shown to the agent."""
    tasks_dir: str
    """Host directory holding the task corpus; `<tasks_dir>/<task_id>` is the task."""
    grade_timeout: float = 900.0
    """Wall clock, in seconds, for one grading run inside the runtime."""


class EvmPatchState(vf.State):
    patched_src: dict[str, str] = Field(default_factory=dict)
    """Project-relative path -> content of every source file read back at finalize."""


class EvmPatchConfig(vf.TasksetConfig):
    split: str = "train"
    """`train` (incidents dated 2025-12 or earlier), `test` (2026-03 to 2026-08) or `all`."""
    task_ids: list[str] | None = None
    """Explicit allow-list of task ids (overrides `split`)."""
    tasks_dir: Path | None = None
    """Task corpus directory (default: the package's bundled tasks)."""
    image: str | None = DEFAULT_IMAGE
    """Container image with Foundry 1.7.1 and the warmed solc builds (the repository's
    Dockerfile). On Prime, the reference printed by `prime images push`."""
    restrict_egress: bool = False
    """Request no execution-time network for the agent. Grading is offline either way."""
    setup_timeout: float = 600.0
    grade_timeout: float = 900.0


class EvmPatchTask(vf.Task[EvmPatchData, EvmPatchState]):
    NEEDS_CONTAINER = True

    @property
    def key(self) -> str:
        return f"evmpatch/{self.data.task_id}"

    @property
    def task_dir(self) -> Path:
        return Path(self.data.tasks_dir) / self.data.task_id

    def _setup_bundle(self) -> bytes:
        """project/ (source, libraries, config) + the visible proof of concept + frozen
        state + replay proxy + the feedback script. Hidden suites and the manifest are
        deliberately absent."""
        td = self.task_dir
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(str(td / "project"), arcname="project", filter=_tar_filter)
            tar.add(str(td / "tests" / "poc.t.sol"), arcname="project/test/poc.t.sol", filter=_tar_filter)
            tar.add(str(td / "state" / "rpc_log.json"), arcname="state/rpc_log.json", filter=_tar_filter)
            tar.add(str(sandbox.RPC_REPLAY), arcname="rpc_replay.py", filter=_tar_filter)
            script = RUN_POC.encode()
            info = tarfile.TarInfo("run_poc.sh")
            info.size = len(script)
            info.mode = 0o755
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(script))
        return buf.getvalue()

    async def setup(self, trace: vf.Trace, runtime: vf.Runtime) -> None:
        bundle = self._setup_bundle()
        await runtime.write(f"{WORKDIR}/.setup.tgz", bundle)
        result = await runtime.run(
            ["sh", "-c", f"cd {WORKDIR} && tar --no-same-owner -xzf .setup.tgz && rm -f .setup.tgz"], {})
        if result.exit_code:
            raise TaskError(
                f"task setup failed (exit {result.exit_code}): "
                f"{(result.stderr or result.stdout).strip()[-500:]}")

    async def finalize(self, trace: vf.Trace, runtime: vf.Runtime) -> None:
        """Read back every file under the project's source tree. Scope is enforced at
        scoring: an edit outside `patchable_globs` is an out-of-scope canary."""
        listing = await runtime.run(["sh", "-c", f"cd {PROJECT} && find src -type f | sort"], {})
        if listing.exit_code:
            logger.warning("finalize: no project source tree to read back: %s",
                           (listing.stderr or listing.stdout).strip()[-200:])
            return
        for rel in listing.stdout.split():
            data = await runtime.read(f"{PROJECT}/{rel}", max_bytes=4_000_000)
            trace.state.patched_src[rel] = data.decode("utf-8", errors="replace")

    async def _grade(self, patched_src, runtime: vf.Runtime) -> sandbox.RewardResult:
        return await grade_in_runtime(self.task_dir, patched_src, runtime,
                                      root=GRADE_ROOT, timeout_s=self.data.grade_timeout)

    @vf.reward(weight=1.0)
    async def solved(self, trace: vf.Trace, runtime: vf.Runtime) -> float:
        patched = dict(trace.state.patched_src) or None
        res = await self._grade(patched, runtime)
        trace.record_metrics({
            "compiled": float(res.compiled),
            "poc_blocked": float(res.poc_blocked),
            "hidden_all_pass": float(res.hidden_all_pass),
            "diff_in_scope": float(res.diff_in_scope),
            "inconclusive": float(res.outcome == "inconclusive"),
        })
        trace.info["evmpatch"] = {
            "outcome": res.outcome,
            "reason": res.reason,
            "reason_detail": res.reason_detail[:500],
            "canaries": list(res.canaries),
            "changed_files": list(res.changed_files),
            "abi_invariants": dict(res.abi_invariants),
            "core_sha256": res.canonical_sha256(core_only=True),
        }
        return 1.0 if res.outcome == "solved" else 0.0

    async def validate(self, runtime: vf.Runtime) -> bool:
        """Gold patch and no-op checks through the runtime: the reference repair must
        grade `solved`, the shipped source must grade `not_solved`."""
        shipped_path = self.task_dir / "project" / self.data.patch_rel
        shipped = shipped_path.read_text()
        if hashlib.sha256(shipped_path.read_bytes()).hexdigest() != self.data.shipped_sha256:
            logger.error("validate %s: shipped source does not match the task data", self.data.task_id)
            return False
        reference = {self.data.patch_rel: apply_unified_diff(shipped, self.data.reference_diff)}
        gold = await self._grade(reference, runtime)
        noop = await self._grade(None, runtime)
        ok_gold = gold.outcome == "solved"
        ok_noop = noop.outcome == "not_solved"
        logger.info(
            "validate %s: reference repair -> %s%s; shipped source -> %s%s",
            self.data.task_id,
            gold.outcome, f" ({gold.reason})" if gold.reason else "",
            noop.outcome, f" ({noop.reason})" if noop.reason else "",
        )
        return ok_gold and ok_noop


class EvmPatchTaskset(vf.Taskset[EvmPatchTask, EvmPatchConfig]):
    def load(self) -> Iterable[EvmPatchTask]:
        from . import _load_task_index, default_tasks_dir

        tasks_dir = (Path(self.config.tasks_dir).resolve() if self.config.tasks_dir
                     else default_tasks_dir())
        index = _load_task_index(tasks_dir, self.config.split, self.config.task_ids)
        if not index:
            raise ValueError(
                f"no tasks for split={self.config.split!r} task_ids={self.config.task_ids!r} "
                f"under {tasks_dir}")
        for idx, (task_id, meta) in enumerate(index.items()):
            td = Path(meta["task_dir"])
            patch_rel = meta.get("patch_contract_ref", "src/contracts/Token.sol:Token").split(":")[0]
            shipped = (td / "project" / patch_rel).read_bytes()
            data = EvmPatchData(
                idx=idx,
                name=task_id,
                description=meta["incident"],
                prompt=_prompt(meta, patch_rel),
                system_prompt=SYSTEM_PROMPT,
                image=self.config.image,
                workdir=WORKDIR,
                network_allow=[] if self.config.restrict_egress else ["*"],
                timeout=vf.TaskTimeout(setup=self.config.setup_timeout,
                                       scoring=3 * self.config.grade_timeout),
                task_id=task_id,
                incident=meta["incident"],
                chain=meta["chain"],
                chain_id=meta["chain_id"],
                fork_block=meta["fork_block"],
                vulnerability_class=meta["vulnerability_class"],
                victim_address=meta["victim_address"],
                date_month=meta["date_month"],
                split=meta["split"],
                patchable_globs=list(meta["patchable_globs"]),
                patch_rel=patch_rel,
                shipped_sha256=hashlib.sha256(shipped).hexdigest(),
                reference_diff=(td / "reference_patch.sol.diff").read_text(),
                tasks_dir=str(tasks_dir),
                grade_timeout=self.config.grade_timeout,
            )
            yield EvmPatchTask(data, self.config.task)


__all__ = ["EvmPatchConfig", "EvmPatchData", "EvmPatchState", "EvmPatchTask", "EvmPatchTaskset"]
