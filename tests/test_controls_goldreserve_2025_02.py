"""The goldreserve_2025_02 controls (worked_example/goldreserve_2025_02/controls/), as an
executable check.

Nine grades of the real BSC task through the local backend, offline:

    reference patch                      -> solved 1.0, oracle fails for the DECLARED reason
    two ALTERNATIVE complete repairs     -> solved 1.0 (a correct repair need not be the reference)
    shipped vulnerable source            -> not_solved, oracle Success, every security obligation fails
    debt settled on transfers only       -> not_solved + residual_vulnerability   (incomplete repair)
    debt settled on mints only           -> not_solved + residual_vulnerability
    settlement on burns only             -> not_solved, oracle Success (the PoC itself catches it)
    claimProfit() always reverts         -> not_solved + bricked
    reference fix + a dropped public fn  -> not_solved + bricked, both ABI checks failing

The gap the security obligations pin: `incomplete_fix__debt_on_transfer_only` — settling
the claim debt on transfers but not on mints — blocks the shipped PoC, and the nine
legitimate-use obligations all hold on it, so a grade without security obligations would
credit it with a core hash IDENTICAL to the reference repair.

The variants are built by the same functions the case's controls/run_controls.py uses, so the
test and the documented controls cannot drift apart. Skipped without forge.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from conftest import REPO, requires_forge
from evmpatch_env import build_task, sandbox

pytestmark = requires_forge

TASK = REPO / "tasks" / "goldreserve_2025_02"
REL = "src/contracts/Token.sol"
CONTROLS = REPO / "worked_example" / "goldreserve_2025_02" / "controls" / "run_controls.py"
ORACLE = "test/poc.t.sol:GoldReserve_PoC:testExploit()"
SEC = "test/hidden/security.t.sol:GoldReserve_Security:"


@pytest.fixture(scope="module")
def controls():
    spec = importlib.util.spec_from_file_location("gold_controls", CONTROLS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads((TASK / "tests" / "manifest.json").read_text())


@pytest.fixture(scope="module")
def shipped() -> str:
    return (TASK / "project" / REL).read_text()


@pytest.fixture(scope="module")
def reference(shipped: str) -> str:
    patched = build_task.apply_unified_diff(shipped, (TASK / "reference_patch.sol.diff").read_text())
    assert patched != shipped
    return patched


def _grade(source: str | None) -> sandbox.RewardResult:
    return sandbox.compute_reward(TASK, {REL: source} if source is not None else None,
                                  backend="local")


def _failing(res: sandbox.RewardResult) -> set[str]:
    return {tid for tid, t in res.hidden.tests.items() if t.status != "Success"}


# --------------------------------------------------------------------- the flip, restated
def test_reference_patch_is_solved_for_a_declared_reason(reference: str, manifest: dict):
    res = _grade(reference)
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    oracle = res.poc.tests[ORACLE]
    assert oracle.status == "Failure"
    assert oracle.reason in manifest["poc"]["recognised_block_reasons"], oracle.reason
    assert res.hidden_all_pass and res.functional_all_pass and res.canaries == []


def test_shipped_source_reproduces_the_attack(shipped: str, manifest: dict):
    res = _grade(None)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc.tests[ORACLE].status == "Success", "the PoC no longer reproduces the exploit"
    assert res.functional_all_pass, "a legitimate-use test fails on the UNPATCHED contract"
    assert "empty_patch" in res.canaries
    # Every declared security obligation must FAIL here, or it cannot separate a repair from
    # a non-repair. tests/test_all_tasks.py asserts the same thing corpus-wide.
    for tid in manifest["hidden"]["security_tests"]:
        assert res.hidden.tests[tid].status == "Failure", tid


# ------------------------------------------------- complete repairs must still be credited
def test_alternative_repair_settling_before_super_is_solved(controls, shipped: str):
    """The same ledger written the other way round: settle the debt, then call
    super._update(). A repair is not required to be byte-identical to the reference."""
    res = _grade(controls.alt_settle_before_super(shipped))
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    assert res.canaries == []


def test_alternative_repair_with_a_separate_debt_mapping_is_solved(controls, shipped: str):
    """A genuinely different implementation: the debt lives in a new internal mapping and
    claimProfit() subtracts it, instead of being folded into claimedProfitPerAddress. The
    security obligations must not be over-fitted to the reference's data layout."""
    res = _grade(controls.alt_separate_debt_mapping(shipped))
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    assert res.canaries == []


# --------------------------------------------------- incomplete repairs must be rejected
def test_debt_on_transfer_only_is_rejected_as_incomplete(controls, reference: str):
    """Incomplete repair: settling on transfers but not on mints blocks the shipped PoC —
    which mints its eight NFTs after depositing the flash-loaned BNB — and leaves the
    mint-inheritance half of the vulnerability standing. A PoC-only grade would credit it
    with a core hash identical to the reference repair."""
    res = _grade(controls.debt_on_transfer_only(reference))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked, "the PoC really is blocked; that is what makes this incomplete repair look like a fix"
    assert res.functional_all_pass, "the contract still works: this is an incomplete fix"
    assert res.canaries == ["residual_vulnerability"]
    assert SEC + "test_nft_minted_after_a_deposit_inherits_no_profit()" in _failing(res)


def test_debt_on_mint_only_is_rejected_as_incomplete(controls, reference: str):
    """The mirror image: settling on mints but not on transfers blocks the PoC at its very
    first claim, so the exploit oracle alone would credit it, while the address-hopping half
    the incident repeated 22 times is untouched."""
    res = _grade(controls.debt_on_mint_only(reference))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and res.functional_all_pass
    assert res.canaries == ["residual_vulnerability"]
    assert SEC + "test_moving_the_nfts_to_a_fresh_address_cannot_reclaim_the_same_profit()" in _failing(res)


def test_settlement_on_burns_only_is_caught_by_the_poc(controls, shipped: str):
    """A patch shaped like the fix that settles nothing real. The exploit oracle still
    passes, so this one never needed the hidden suite."""
    res = _grade(controls.settle_on_burn_only(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert not res.poc_blocked
    assert res.poc.tests[ORACLE].status == "Success"


def test_claim_always_reverting_is_rejected_as_bricked(controls, shipped: str):
    """RECOGNISED REASON IN THE WRONG PLACE: claimProfit() always reverts with the declared
    'exploit blocked' string. Paying holders is what this contract is for, so the
    legitimate-use regression — not the security suite — is what rejects it."""
    res = _grade(controls.claim_always_reverts(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and not res.functional_all_pass
    assert res.canaries == ["bricked"]
    assert ("test/hidden/regression.t.sol:GoldReserve_Regression:"
            "test_mint_then_deposit_then_claim_pays_the_holder()") in _failing(res)


def test_fix_that_drops_a_public_function_fails_both_abi_checks(controls, reference: str):
    res = _grade(controls.fix_plus_abi_drop_set_mint_price(reference))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and not res.hidden_all_pass and "bricked" in res.canaries
    assert res.abi_invariants["bytecode_selectors"] == "Failure"
    assert res.abi_invariants["dispatch_selectors"] == "Failure"
    assert res.abi_invariants["dispatch_control"] == "Success"
