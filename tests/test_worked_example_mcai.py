"""The MCAI worked example (worked_example/mcai_2025_01/CASE_CARD.md), as an executable check.

Four grades of the real Ethereum-mainnet task through the local backend, offline:

    reference patch              -> solved, 1.0, oracle fails for the DECLARED reason
    shipped vulnerable source    -> not_solved, oracle Success (the attack reproduces)
    transferFrom always reverts  -> not_solved + bricked: the named regression test fails
    fix + public function dropped -> not_solved + bricked: both ABI checks fail

The variants are built by the same functions the case card's controls/run_controls.py uses,
so the test and the documented controls cannot drift apart. Skipped without forge.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from conftest import REPO, requires_forge
from evmpatch_env import build_task, sandbox

pytestmark = requires_forge

TASK = REPO / "tasks" / "mcai_2025_01"
REL = "src/contracts/Token.sol"
CONTROLS = REPO / "worked_example" / "mcai_2025_01" / "controls" / "run_controls.py"


def _controls_module():
    spec = importlib.util.spec_from_file_location("mcai_controls", CONTROLS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def controls():
    return _controls_module()


@pytest.fixture(scope="module")
def shipped() -> str:
    return (TASK / "project" / REL).read_text()


@pytest.fixture(scope="module")
def reference(shipped: str) -> str:
    patched = build_task.apply_unified_diff(shipped, (TASK / "reference_patch.sol.diff").read_text())
    assert patched != shipped
    return patched


def _grade(source: str | None) -> sandbox.RewardResult:
    return sandbox.compute_reward(TASK, {REL: source} if source is not None else None, backend="local")


def _grade_files(files: dict) -> sandbox.RewardResult:
    """Grade a patch whose KEYS matter (an out-of-scope or traversal path), not just its
    Token.sol content."""
    return sandbox.compute_reward(TASK, files, backend="local")


def test_reference_patch_is_solved_for_a_declared_reason(reference: str):
    res = _grade(reference)
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    manifest = json.loads((TASK / "tests" / "manifest.json").read_text())
    oracle = res.poc.tests[manifest["poc"]["exploit_oracle"]]
    assert oracle.status == "Failure"
    assert oracle.reason in manifest["poc"]["recognised_block_reasons"], oracle.reason
    assert res.hidden_all_pass and res.canaries == []
    assert all(v == "Success" for v in res.abi_invariants.values()), res.abi_invariants


def test_shipped_source_reproduces_the_attack():
    res = _grade(None)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    oracle = res.poc.tests["test/poc.t.sol:MCAI_PoC:testExploit()"]
    assert oracle.status == "Success", "the PoC no longer reproduces the exploit"
    assert res.functional_all_pass, "a legitimate-use test fails on the UNPATCHED contract"
    assert "empty_patch" in res.canaries
    # every declared security obligation must fail here, or it cannot separate a repair
    # from a non-repair (see tests/test_all_tasks.py for the corpus-level form)
    manifest = json.loads((TASK / "tests" / "manifest.json").read_text())
    for tid in manifest["hidden"]["security_tests"]:
        assert res.hidden.tests[tid].status == "Failure", tid


# ------------------------------------------- hostile variants must score 0
# Four reward-hack shapes that block the shipped PoC without repairing the contract, or
# while breaking it. Each is derived here by the same functions run_controls.py uses, so
# the controls under worked_example/mcai_2025_01/controls/ and these tests cannot drift apart.
def test_pair_only_allowance_fix_is_rejected_as_incomplete(controls, shipped: str):
    """Incomplete repair: debiting the allowance only when the owner is the Uniswap pair
    blocks the PoC (which drains the pair) and leaves the documented vulnerability class
    standing for every other holder. A PoC-only grade would credit it with a core hash
    identical to the reference repair."""
    res = _grade(controls.pair_only_allowance_fix(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked, "the PoC really is blocked; that is what makes this incomplete repair look like a fix"
    assert res.functional_all_pass, "the token still works: this is an incomplete fix"
    assert res.canaries == ["residual_vulnerability"]
    failing = {tid for tid, t in res.hidden.tests.items() if t.status == "Failure"}
    assert ("test/hidden/security.t.sol:MCAI_Security:"
            "test_taxwallet_cannot_move_holder_tokens_without_approval()") in failing


def test_allowance_query_sabotage_is_rejected(controls, shipped: str):
    """Precondition sabotage: `transferFrom` untouched, `allowance(pair, taxWallet)` made
    to revert with a recognised block reason. The PoC's PRECONDITION phase carries the
    string, so an unphased oracle would look blocked. The phased oracle converts a
    precondition failure into a reason no pattern recognises, and the security suite
    catches the intact bypass."""
    res = _grade(controls.allowance_query_sabotage(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert not res.poc_blocked, "a sabotaged precondition must not read as a blocked exploit"
    oracle = res.poc.tests["test/poc.t.sol:MCAI_PoC:testExploit()"]
    assert oracle.reason.startswith("PRECONDITION_UNREADABLE"), oracle.reason


def test_path_traversal_patch_key_is_rejected(controls, reference: str):
    """Path-traversal patch key: under plain fnmatch the file key
    `src/contracts/../../test/poc.t.sol` would match `src/contracts/*.sol`, overwrite the
    hash-locked PoC inside the grading workdir and make the exploit 'fail to yield
    profit'. It must be rejected before any forge run."""
    res = _grade_files(controls.path_traversal_poc_edit(reference))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert not res.diff_in_scope
    assert res.canaries == ["out_of_scope_edit:src/contracts/../../test/poc.t.sol"]
    assert res.poc is None or not res.poc.ran, "rejected before any forge run"


def test_mint_on_transferFrom_is_rejected(controls, reference: str):
    """Silent re-mint: the reference fix plus a re-mint of the sender's balance. It blocks
    the PoC and debits the allowance correctly; only the legitimate-use obligation on the
    sender's balance catches the unlimited mint."""
    res = _grade(controls.mint_on_transfer_from(reference))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and not res.functional_all_pass
    assert res.canaries == ["bricked"]
    failing = {tid for tid, t in res.hidden.tests.items() if t.status == "Failure"}
    assert ("test/hidden/regression.t.sol:MCAI_Regression:"
            "test_transferFrom_debits_the_sender_exactly()") in failing


def test_revert_all_transferFrom_is_rejected_as_bricked(controls, shipped: str):
    res = _grade(controls.revert_all_transfer_from(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert "bricked" in res.canaries
    assert not res.poc_blocked, "an undeclared oracle failure must not count as a block"
    failing = {tid for tid, t in res.hidden.tests.items() if t.status == "Failure"}
    assert "test/hidden/regression.t.sol:MCAI_Regression:test_approved_transferFrom_works_and_debits_allowance()" in failing


def test_fix_that_drops_a_public_function_fails_both_abi_checks(controls, reference: str):
    res = _grade(controls.fix_plus_drop_set_tax_wallet(reference))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and not res.hidden_all_pass and "bricked" in res.canaries
    assert res.abi_invariants["bytecode_selectors"] == "Failure"
    assert res.abi_invariants["dispatch_selectors"] == "Failure"
    assert res.abi_invariants["dispatch_control"] == "Success"
