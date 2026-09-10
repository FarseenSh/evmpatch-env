"""Every shipped task must flip, offline, on its own reference patch.

This is the corpus-level acceptance check: for each `tasks/<id>/`,

    vulnerable source   -> not_solved, and the PoC exploit oracle PASSES
    reference patch     -> solved, reward 1.0, every hidden test passes
    frozen state gone   -> inconclusive, never 1.0

plus the structural invariants a task must satisfy to be gradeable at all (hash locks
intact, manifest consistent, temporal split labelled).

Slow: each parameter runs the full Foundry pipeline twice. `-k <task_id>` narrows it.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from evmpatch_env import build_task, sandbox

from conftest import REPO, requires_forge

pytestmark = requires_forge

TASKS = sorted(p.parent for p in (REPO / "tasks").glob("*/task.json"))
TASK_IDS = [p.name for p in TASKS]


def _patch_rel(meta: dict) -> str:
    return meta.get("patch_contract_ref", "src/contracts/Token.sol:Token").split(":")[0]


def _reference_source(task: Path) -> str:
    meta = json.loads((task / "task.json").read_text())
    rel = _patch_rel(meta)
    src = (task / "project" / rel).read_text()
    return build_task.apply_unified_diff(src, (task / "reference_patch.sol.diff").read_text())


def _grade(task: Path, source: str | None):
    meta = json.loads((task / "task.json").read_text())
    patched = {_patch_rel(meta): source} if source is not None else None
    return sandbox.compute_reward(task, patched, backend="local")


# ------------------------------------------------------------------ structural checks
@pytest.mark.parametrize("task", TASKS, ids=TASK_IDS)
def test_task_is_well_formed(task: Path):
    meta = json.loads((task / "task.json").read_text())
    assert meta["split"] == build_task.split_for_month(meta["date_month"])
    assert meta["date_month"] <= "2025-12", "a test-split task must not be in the train corpus"
    assert (task / "reference_patch.sol.diff").exists(), "no reference patch to self-test with"
    assert (task / "state" / "rpc_log.json").exists(), "no frozen chain state"

    manifest = sandbox.load_manifest(task)
    assert manifest is not None
    assert manifest["poc"]["count"] >= 1 and manifest["hidden"]["count"] >= 3
    assert manifest["poc"]["exploit_oracle"] in manifest["poc"]["tests"]
    assert manifest["poc"]["recognised_block_reasons"], \
        "task declares no recognised 'exploit blocked' reason, so every block is unrecognised"

    # the harness must be hash-locked, and the locks must currently hold
    locked = set(meta["hash_locks"])
    assert "tests/poc.t.sol" in locked and "tests/manifest.json" in locked
    _, canaries = sandbox.check_scope_and_canaries(task, None)
    assert canaries == ["empty_patch"], f"shipped harness does not match its locks: {canaries}"


# --------------------------------------------------------------------- the flip check
@pytest.mark.parametrize("task", TASKS, ids=TASK_IDS)
def test_vulnerable_source_reproduces_the_exploit(task: Path):
    res = _grade(task, None)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED, (res.reason, res.reason_detail)
    assert res.score == 0.0
    manifest = sandbox.load_manifest(task)
    oracle = res.poc.tests[manifest["poc"]["exploit_oracle"]]
    assert oracle.status == "Success", "the shipped PoC no longer reproduces the exploit"
    assert res.functional_all_pass, \
        "a legitimate-use hidden test fails on the UNPATCHED contract"

    # A task may declare `hidden.security_tests`: hidden tests that assert the security
    # property rather than legitimate use. Those must FAIL here — a security obligation that
    # already holds on the vulnerable contract is vacuous and would credit an incomplete
    # repair.
    security = manifest["hidden"].get("security_tests") or []
    for tid in security:
        assert res.hidden.tests[tid].status == "Failure", (
            f"declared security obligation {tid} PASSES on the vulnerable contract; "
            "it cannot distinguish a repair from a non-repair")
    if security:
        assert not res.hidden_all_pass


@pytest.mark.parametrize("task", TASKS, ids=TASK_IDS)
def test_reference_patch_is_solved(task: Path):
    res = _grade(task, _reference_source(task))
    assert res.outcome == sandbox.OUTCOME_SOLVED, (res.reason, res.reason_detail)
    assert res.score == 1.0
    assert res.poc_blocked and res.hidden_all_pass and res.functional_all_pass
    assert res.tests_match_manifest
    assert res.canaries == []
    assert res.abi_invariants["dispatch_control"] == "Success", \
        "the dispatch control failed: this contract has a catch-all fallback and the " \
        "behavioural ABI check proves nothing for it"


@pytest.mark.parametrize("task", TASKS, ids=TASK_IDS)
def test_missing_frozen_state_is_inconclusive(task: Path, tmp_path: Path):
    broken = tmp_path / (task.name + "_no_state")
    shutil.copytree(task, broken)
    (broken / "state" / "rpc_log.json").unlink()
    res = _grade(broken, _reference_source(task))
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.score == 0.0
    assert res.reason in (sandbox.R_UNRECORDED_RPC, sandbox.R_SETUP_FAILED,
                          sandbox.R_PROXY_START)
