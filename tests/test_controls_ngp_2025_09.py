"""The ngp_2025_09 control set (worked_example/ngp_2025_09/controls/), as an executable check.

Real BSC task, graded end to end through the local backend, offline. The variants are built by
the same functions `worked_example/ngp_2025_09/controls/run_controls.py` uses, so the test and
the documented controls cannot drift apart. Skipped without forge.

What this pins, in one line each:

    reference                          -> solved 1.0, oracle fails for a DECLARED reason
    alt_fix__fees_charged_to_seller    -> solved 1.0: a DIFFERENT complete repair is credited
    shipped vulnerable source          -> not_solved, oracle Success, EVERY security
                                          obligation fails (else they are vacuous)
    incomplete_fix__sync_only_removed  -> not_solved + residual_vulnerability  (the incomplete
                                          repair the security obligations exist for: a PoC-only
                                          grade would credit it with the reference's core hash)
    incomplete_fix__drain_capped       -> not_solved + residual_vulnerability
    non_repair__cosmetic_rename        -> not_solved, caught by the PoC itself
    recognised_reason__approve_reverts -> not_solved + bricked (a declared block string at a
                                          statement that is not the exploit)
    fix_plus_sell_path_disabled        -> not_solved + bricked
    compile_failed                     -> inconclusive/compile_failed, never 1.0
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from conftest import REPO, requires_forge
from evmpatch_env import sandbox

pytestmark = requires_forge

TASK = REPO / "tasks" / "ngp_2025_09"
REL = "src/contracts/Token.sol"
CONTROLS = REPO / "worked_example" / "ngp_2025_09" / "controls" / "run_controls.py"
ORACLE = "test/poc.t.sol:NGP_PoC:testExploit()"
AMM_ROUND_TRIP = ("test/hidden/amm_regression.t.sol:NGP_AmmRegression:"
                  "test_amm_buy_then_sell_round_trip()")


@pytest.fixture(scope="module")
def controls():
    spec = importlib.util.spec_from_file_location("ngp_controls", CONTROLS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads((TASK / "tests" / "manifest.json").read_text())


def _grade(source: str | None) -> sandbox.RewardResult:
    return sandbox.compute_reward(TASK, {REL: source} if source is not None else None,
                                  backend="local")


def _failing(res: sandbox.RewardResult) -> set[str]:
    return {tid for tid, t in res.hidden.tests.items() if t.status != "Success"}


# --------------------------------------------------------------- the two baselines
def test_reference_patch_is_solved_for_a_declared_reason(controls, manifest):
    res = _grade(controls.REFERENCE)
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    oracle = res.poc.tests[ORACLE]
    assert oracle.status == "Failure"
    assert oracle.reason in manifest["poc"]["recognised_block_reasons"], oracle.reason
    assert res.hidden_all_pass and res.functional_all_pass and res.canaries == []
    assert all(v == "Success" for v in res.abi_invariants.values()), res.abi_invariants


def test_shipped_source_reproduces_the_attack_and_fails_every_security_obligation(manifest):
    res = _grade(None)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc.tests[ORACLE].status == "Success", "the PoC no longer reproduces the exploit"
    assert res.functional_all_pass, "a legitimate-use test fails on the UNPATCHED contract"
    assert "empty_patch" in res.canaries
    # Every declared security obligation must FAIL here, or it cannot separate a repair from a
    # non-repair — the failure mode that would silently undo this whole closure.
    security = manifest["hidden"]["security_tests"]
    assert security, "the task declares no security obligations"
    for tid in security:
        assert res.hidden.tests[tid].status == "Failure", tid


# ------------------------------------------------- complete repairs must be credited
def test_an_alternative_complete_repair_is_also_solved(controls, manifest):
    """The security obligations must state the CLASS, not fingerprint the reference's
    implementation. This repair keeps the treasury and reward fees and charges them to the
    SELLER instead of pulling them out of the pair — a different fix for the same bug — and
    must score 1.0 exactly like the reference."""
    res = _grade(controls.VARIANT_SOURCES["alt_fix__fees_charged_to_seller"])
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    assert res.poc_blocked and res.hidden_all_pass and res.canaries == []
    assert res.poc.tests[ORACLE].reason in manifest["poc"]["recognised_block_reasons"]


# ------------------------------------------------ incomplete repairs must be rejected
def test_sync_only_removed_is_rejected_as_incomplete(controls, manifest):
    """Incomplete repair: deleting only the mid-transfer `pair.sync()` blocks the PoC (which
    needs the re-price) and leaves a seller still emptying the pair inside their own
    transfer. A PoC-only grade would credit it with a core hash identical to the reference
    repair."""
    res = _grade(controls.VARIANT_SOURCES["incomplete_fix__sync_only_removed"])
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked, "the PoC really is blocked; that is what makes this incomplete repair look like a fix"
    assert res.functional_all_pass, "the token still works: this is an incomplete fix"
    assert res.canaries == ["residual_vulnerability"]
    assert _failing(res) == set(manifest["hidden"]["security_tests"])


def test_drain_capped_is_rejected_as_incomplete(controls, manifest):
    """A second incomplete repair of the same class: the drain is bounded to 1% of the pool and
    the sync is removed. The cap never binds on an ordinary trade."""
    res = _grade(controls.VARIANT_SOURCES["incomplete_fix__drain_capped"])
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and res.functional_all_pass
    assert res.canaries == ["residual_vulnerability"]
    assert _failing(res) <= set(manifest["hidden"]["security_tests"])
    assert _failing(res), "an incomplete repair that fails nothing proves nothing"


# ------------------------------------------------------- non-repairs and destruction
def test_cosmetic_rename_is_caught_by_the_poc_itself(controls):
    res = _grade(controls.VARIANT_SOURCES["non_repair__cosmetic_rename"])
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc.tests[ORACLE].status == "Success"
    assert not res.poc_blocked


def test_recognised_reason_at_approve_is_rejected_as_bricked(controls):
    """A declared block string produced by a statement that is not the exploit. After the PoC
    phase restructure the callback's approvals report a PRECONDITION_ reason that matches no
    recognised pattern, so this cannot read as a blocked exploit; the AMM round trip fails too,
    so the grade is a bricked contract."""
    res = _grade(controls.VARIANT_SOURCES["recognised_reason__approve_reverts"])
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert "bricked" in res.canaries
    assert not res.poc_blocked, "an undeclared oracle failure must not count as a block"
    assert res.poc.tests[ORACLE].reason.startswith("PRECONDITION_UNREADABLE"), \
        res.poc.tests[ORACLE].reason
    assert AMM_ROUND_TRIP in _failing(res)


def test_disabling_the_sell_path_is_rejected_as_bricked(controls):
    res = _grade(controls.VARIANT_SOURCES["fix_plus_sell_path_disabled"])
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert "bricked" in res.canaries and not res.functional_all_pass
    assert AMM_ROUND_TRIP in _failing(res)


def test_compile_error_is_inconclusive_and_never_credited(controls):
    res = _grade(controls.VARIANT_SOURCES["compile_failed"])
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_COMPILE_FAILED and res.score == 0.0
