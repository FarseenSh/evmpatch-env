"""The bitallx_2025_05 control set (worked_example/bitallx_2025_05/), as an executable check.

Ten grades of the real BSC task through the local backend, offline:

    shipped vulnerable source     -> not_solved, oracle Success, every security obligation FAILS
    reference repair              -> solved, 1.0, oracle fails for the DECLARED reason
    sum bounded by funded total   -> solved, 1.0   (an alternative complete repair)
    payout capped at funded total -> solved, 1.0   (a complete repair that pays nothing
                                                    instead of reverting)
    only amount[0] bounded        -> not_solved + residual_vulnerability  (incomplete repair)
    every element bounded         -> not_solved + residual_vulnerability
    bound only when funded > 0    -> not_solved, oracle Success (the PoC itself catches it)
    payout always reverts         -> not_solved + bricked
    fix + inserted state variable -> not_solved + bricked (live storage misread)
    syntax error                  -> inconclusive / compile_failed, never 1.0

The variants are built by the same functions the case's controls/run_controls.py uses, so
the test and the documented controls cannot drift apart. Skipped without forge.

Why the security obligations exist: `incomplete_fix__first_element_only` — bounding only
`amount[0]` by `totalSendAmount` — blocks the shipped one-element PoC while leaving every
multi-element payout exploitable, so a PoC-only grade would credit it with a core hash
IDENTICAL to the reference repair. `tests/hidden/security.t.sol` states the declared class
instead of the one shape the PoC uses, and `tests/manifest.json` lists it under
`hidden.security_tests`; the two incomplete-repair tests below pin that.
"""
from __future__ import annotations

import fnmatch
import importlib.util
import json
from pathlib import Path

import pytest

from conftest import REPO, requires_forge
from evmpatch_env import sandbox

pytestmark = requires_forge

TASK = REPO / "tasks" / "bitallx_2025_05"
REL = "src/contracts/Token.sol"
CONTROLS = REPO / "worked_example" / "bitallx_2025_05" / "controls" / "run_controls.py"

ORACLE = "test/poc.t.sol:Bitallx_PoC:testExploit()"
SEC = "test/hidden/security.t.sol:Bitallx_Security:"
S1 = SEC + "test_multi_element_over_request_pays_nothing()"
S2 = SEC + "test_single_element_over_request_from_fresh_payer_pays_nothing()"
S3 = SEC + "test_sum_over_funded_total_rejected_even_when_each_element_fits()"


def _controls_module():
    spec = importlib.util.spec_from_file_location("bitallx_controls", CONTROLS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def controls():
    return _controls_module()


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads((TASK / "tests" / "manifest.json").read_text())


@pytest.fixture(scope="module")
def shipped() -> str:
    return (TASK / "project" / REL).read_text()


def _grade(source: str | None) -> sandbox.RewardResult:
    return sandbox.compute_reward(TASK, {REL: source} if source is not None else None,
                                  backend="local")


def _failing(res: sandbox.RewardResult) -> set[str]:
    return {tid for tid, t in res.hidden.tests.items() if t.status != "Success"}


# ------------------------------------------------------------------------------ manifest
def test_manifest_declares_the_three_security_obligations(manifest: dict):
    """The closure's contract, asserted directly: the manifest is v2 and the three security
    obligations are listed as a subset of hidden.tests."""
    assert manifest["version"] == 2
    assert manifest["hidden"]["security_tests"] == [S1, S2, S3]
    assert set(manifest["hidden"]["security_tests"]) <= set(manifest["hidden"]["tests"])
    assert manifest["hidden"]["count"] == len(manifest["hidden"]["tests"]) == 13


# ------------------------------------------------------------------------------ baselines
def test_shipped_source_reproduces_the_attack(manifest: dict):
    res = _grade(None)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc.tests[ORACLE].status == "Success", "the PoC no longer reproduces the exploit"
    assert res.functional_all_pass, "a legitimate-use test fails on the UNPATCHED contract"
    assert "empty_patch" in res.canaries
    # every declared security obligation must fail here, or it cannot separate a repair
    # from a non-repair (see tests/test_all_tasks.py for the corpus-level form)
    for tid in manifest["hidden"]["security_tests"]:
        assert res.hidden.tests[tid].status == "Failure", tid


def test_reference_patch_is_solved_for_a_declared_reason(controls, manifest: dict):
    res = _grade(controls.REFERENCE)
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    oracle = res.poc.tests[ORACLE]
    assert oracle.status == "Failure"
    assert any(fnmatch.fnmatchcase(oracle.reason, p)
               for p in manifest["poc"]["recognised_block_reasons"]), oracle.reason
    assert res.hidden_all_pass and res.canaries == []
    assert all(v == "Success" for v in res.abi_invariants.values()), res.abi_invariants


# --------------------------------------------------- complete repairs must still score 1.0
def test_alternative_complete_repair_bounding_the_sum_is_solved(controls, shipped: str):
    """A different implementation of the same property — the sum must be <= the funded total
    rather than equal to it. A security obligation that only accepted the reference's exact
    code would show up here as a false negative."""
    res = _grade(controls.alt_complete_fix_sum_bounded(shipped))
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    assert res.hidden_all_pass and res.canaries == []


def test_alternative_complete_repair_capping_the_payout_is_solved(controls, shipped: str):
    """A different REMEDY: pay at most what was funded instead of reverting. The obligations
    are phrased 'revert OR pay nothing beyond the funded total' and assert balance deltas
    through try/catch, so a capping repair must be credited — and the oracle recognises it
    through `*exploit did not yield profit*` rather than through a revert string."""
    res = _grade(controls.alt_complete_fix_capped_payout(shipped))
    assert res.outcome == sandbox.OUTCOME_SOLVED and res.score == 1.0, (res.reason, res.reason_detail)
    assert res.hidden_all_pass and res.canaries == []
    assert res.poc_blocked
    assert "exploit did not yield profit" in res.poc.tests[ORACLE].reason


# ------------------------------------------------ incomplete repairs must score 0.0 + canary
def test_first_element_only_is_rejected_as_incomplete(controls, shipped: str):
    """Incomplete repair: bounding only amount[0] blocks the shipped one-element PoC, but a
    two-element array [0, treasury] with totalSendAmount = 0 still drains the contract. A
    PoC-only grade would credit it with a core hash identical to the reference repair."""
    res = _grade(controls.incomplete_fix_first_element_only(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked, "the PoC really is blocked; that is what makes this incomplete repair look like a fix"
    assert res.functional_all_pass, "the contract still works: this is an incomplete fix"
    assert res.canaries == ["residual_vulnerability"]
    assert S1 in _failing(res)


def test_each_element_bounded_is_rejected_as_incomplete(controls, shipped: str):
    """The same gap one step further out: every element is bounded by the funded total,
    the SUM never is, so [total, total] funded once is paid twice."""
    res = _grade(controls.incomplete_fix_each_element_bounded(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc_blocked and res.functional_all_pass
    assert res.canaries == ["residual_vulnerability"]
    assert S3 in _failing(res)


# ------------------------------------------------------ non-repair the PoC itself catches
def test_bound_only_when_funded_is_caught_by_the_poc(controls):
    """The reference bound applied only when totalSendAmount > 0. The whole incident is
    totalSendAmount = 0, so the exploit still runs and the oracle passes."""
    res = _grade(controls.non_repair_bound_only_when_funded(controls.REFERENCE))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.poc.tests[ORACLE].status == "Success"
    assert not res.poc_blocked


# ----------------------------------------------------------------- destructive controls
def test_payout_always_reverts_is_rejected_as_bricked(controls, shipped: str):
    """A recognised block reason in the wrong place: BitallxPayOut always reverts with the
    declared string, so the oracle looks blocked while nobody can be paid at all."""
    res = _grade(controls.recognised_reason_payout_always_reverts(shipped))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert "bricked" in res.canaries and not res.functional_all_pass
    assert ("test/hidden/regression.t.sol:Bitallx_Regression:"
            "test_funded_batch_payout_distributes_correctly()") in _failing(res)


def test_inserted_state_variable_is_rejected_as_bricked(controls):
    """The reference repair plus one inserted state variable. The grader etches the patched
    code onto the live address and keeps the live storage, so every variable below the
    insertion reads the wrong slot — the constraint task.json names explicitly."""
    res = _grade(controls.fix_plus_storage_slot_shift(controls.REFERENCE))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert "bricked" in res.canaries and not res.functional_all_pass
    assert ("test/hidden/regression.t.sol:Bitallx_Regression:"
            "test_live_storage_still_readable()") in _failing(res)


# ------------------------------------------------------------- infrastructure control
def test_compile_failure_is_inconclusive_never_credited(controls):
    res = _grade(controls.compile_error(controls.REFERENCE))
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE and res.score == 0.0
    assert not res.compiled
