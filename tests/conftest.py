"""Shared fixtures for the evmpatch grader tests.

Two suites live here:

  test_scorer_probes.py  — the ten synthetic scorer probes: reward-hack and fault shapes
                           fed through the real parser and scorer. Pure functions only:
                           no Foundry, no Docker, no RPC, no EVM.
  test_ngp_flip.py       — the real thing: the ngp_2025_09 task graded end to end
                           through the local backend, offline.

Anything that needs `forge` is skipped (not failed) when Foundry is absent, so the pure
scorer suite still runs on a bare box.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from evmpatch_env import build_task, sandbox  # noqa: E402

NGP = REPO / "tasks" / "ngp_2025_09"
TOKEN_REL = "src/contracts/Token.sol"

requires_forge = pytest.mark.skipif(
    shutil.which("forge") is None, reason="Foundry (forge) is not on PATH"
)


# The unified-diff applier lives in the shipped package (build_task uses it to observe
# the reference patch's block reason at build time); the tests reuse that one copy.
apply_unified_diff = build_task.apply_unified_diff


# ---------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="session")
def ngp_task() -> Path:
    return NGP


@pytest.fixture(scope="session")
def vulnerable_source() -> str:
    return (NGP / "project" / TOKEN_REL).read_text()


@pytest.fixture(scope="session")
def reference_patch(vulnerable_source: str) -> str:
    """The known-good fix, applied to the shipped vulnerable source."""
    diff = (NGP / "reference_patch.sol.diff").read_text()
    patched = apply_unified_diff(vulnerable_source, diff)
    assert patched != vulnerable_source
    assert "IUniswapV2Pair(mainPair).sync();" not in patched
    return patched


@pytest.fixture()
def broken_state_task(tmp_path: Path) -> Path:
    """A copy of the ngp task whose frozen chain state has been removed — the grader must
    call this INCONCLUSIVE, never 1.0."""
    dst = tmp_path / "ngp_no_state"
    shutil.copytree(NGP, dst)
    (dst / "state" / "rpc_log.json").unlink()
    return dst


def grade(task_dir: Path, source: str | None = None) -> sandbox.RewardResult:
    patched = {TOKEN_REL: source} if source is not None else None
    return sandbox.compute_reward(task_dir, patched, backend="local")
