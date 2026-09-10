"""End-to-end grading of the real ngp_2025_09 task, offline.

Every test here runs the actual pipeline: fail-closed replay proxy on a free port, a
uuid-named episode workdir, `forge test --json` for the PoC and the hidden suite, and the
scorer. No network is used or reachable — the proxy answers only what the task's
`state/rpc_log.json` recorded and returns a JSON-RPC error for anything else.

The three acceptance checks are `test_vulnerable_source_is_not_solved`,
`test_reference_patch_is_solved`, and `test_missing_frozen_state_is_inconclusive`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from evmpatch_env import sandbox

from conftest import TOKEN_REL, grade, requires_forge

pytestmark = requires_forge

AMM_TEST = "test/hidden/amm_regression.t.sol:NGP_AmmRegression:test_amm_buy_then_sell_round_trip()"
ABI_TEST = "test/hidden/invariants_auto.t.sol:AutoInvariants:test_abi_selectors_preserved()"
VACUITY_TEST = "test/hidden/invariants_auto.t.sol:AutoInvariants:test_selector_check_is_not_vacuous()"
DISPATCH_TEST = "test/hidden/invariants_auto.t.sol:AutoInvariants:test_abi_selectors_dispatch()"
CONTROL_TEST = "test/hidden/invariants_auto.t.sol:AutoInvariants:test_unknown_selector_is_rejected()"
ORACLE = "test/poc.t.sol:NGP_PoC:testExploit()"


# ------------------------------------------------------------------ acceptance checks
def test_vulnerable_source_is_not_solved(ngp_task):
    """Agent start state: the exploit still works, so reward is 0 — and the run is
    CONCLUSIVE (not_solved), because the evidence is valid."""
    res = grade(ngp_task, None)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert res.score == 0.0
    assert res.poc.tests[ORACLE].status == "Success", "the PoC must reproduce the exploit"
    assert not res.poc_blocked
    # Legitimate-use obligations hold on the UNPATCHED contract; the SECURITY obligations
    # (`hidden.security_tests`) fail there by
    # construction -- a security obligation that already held would be vacuous.
    assert res.functional_all_pass, "a legitimate-use hidden test fails on the UNPATCHED contract"
    security = (sandbox.load_manifest(ngp_task) or {})["hidden"].get("security_tests") or []
    assert security, "ngp_2025_09 declares no security obligations"
    for tid in security:
        assert res.hidden.tests[tid].status == "Failure", f"security obligation {tid} is vacuous"
    assert not res.hidden_all_pass
    assert res.canaries == ["empty_patch"]


def test_reference_patch_is_solved(ngp_task, reference_patch):
    res = grade(ngp_task, reference_patch)
    assert res.outcome == sandbox.OUTCOME_SOLVED
    assert res.score == 1.0
    assert res.poc_blocked and res.hidden_all_pass and res.compiled
    assert res.tests_match_manifest and res.diff_in_scope
    assert res.canaries == []
    assert res.changed_files == [TOKEN_REL]
    # The exploit is blocked because the flash loan can no longer be repaid: a revert on
    # the exploit path, not an infrastructure fault.
    assert res.poc_failure_kind == "revert"
    assert res.poc.tests[ORACLE].reason == "BEP20: transfer amount exceeds balance"


def test_missing_frozen_state_is_inconclusive(broken_state_task, reference_patch):
    """An infra-broken run must be INCONCLUSIVE and must never be 1.0: a broken harness
    must never pay out full reward."""
    res = grade(broken_state_task, reference_patch)
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.score == 0.0
    assert res.reason in (sandbox.R_UNRECORDED_RPC, sandbox.R_SETUP_FAILED,
                          sandbox.R_PROXY_START)
    assert not res.solved


# ------------------------------------------ the new hidden coverage actually bites (C)
def test_bricked_sell_path_is_caught_by_the_amm_regression(ngp_task, vulnerable_source):
    """A patch that 'fixes' the bug by disabling the sell path blocks the exploit and
    passes every legitimate-use hidden test that never enters `to == mainPair`. The AMM
    round trip catches it (the security obligations do too)."""
    bricked = vulnerable_source.replace(
        'require(sellState, "Sell not allowed");',
        'revert("sell path disabled by patch");', 1)
    assert bricked != vulnerable_source
    res = grade(ngp_task, bricked)

    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert res.score == 0.0
    # The PoC does fail (the exploit's own sell leg reverts), but for a reason this task
    # never declared as "exploit blocked". Because a hidden test ALSO fails, the run is not
    # ambiguous — it is a bricked contract, scored 0 with the canary rather than deferred
    # to a human as `unrecognised_failure`.
    assert not res.poc_blocked
    assert "bricked" in res.canaries
    failing = {tid for tid, t in res.hidden.tests.items() if t.status != "Success"}
    assert AMM_TEST in failing
    # and the AMM round trip is the only plain regression that catches it: the baseline
    # legitimate-use tests never enter the sell path. The security obligations
    # (tests/hidden/security.t.sol) also sell through the pair, so they fail on a disabled
    # sell path too and are excluded from the baseline set here.
    baseline_hidden = {tid for tid in res.hidden.tests
                       if "amm_regression" not in tid and "security.t.sol" not in tid}
    assert not (failing & baseline_hidden), (
        "a baseline hidden test also failed; the demonstration is weaker than claimed: "
        f"{failing & baseline_hidden}")


# ------------------------------------ the selector check is a real check, not a tautology (B)
def test_deleting_a_public_function_fails_the_abi_invariant(ngp_task, vulnerable_source):
    """A selector check that only asserted `code.length > 0` would pass for ANY non-empty
    contract. The PUSH4 walk must actually notice a removed external function."""
    start = vulnerable_source.index("    function getBuyInfo(")
    end = vulnerable_source.index("    function resetBuyRecord(", start)
    stripped = vulnerable_source[:start] + vulnerable_source[end:]
    assert "function getBuyInfo(" not in stripped

    res = grade(ngp_task, stripped)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    # BOTH ABI checks must notice, and the grade records them separately.
    assert res.hidden.tests[ABI_TEST].status == "Failure"
    assert "getBuyInfo" in (res.hidden.tests[ABI_TEST].reason or "")
    assert res.hidden.tests[DISPATCH_TEST].status == "Failure"
    assert "getBuyInfo" in (res.hidden.tests[DISPATCH_TEST].reason or "")
    assert res.abi_invariants["bytecode_selectors"] == "Failure"
    assert res.abi_invariants["dispatch_selectors"] == "Failure"
    # the two guards that prove the checks are not tautologies must still pass
    assert res.hidden.tests[VACUITY_TEST].status == "Success"
    assert res.hidden.tests[CONTROL_TEST].status == "Success"
    assert res.abi_invariants["not_vacuous"] == "Success"
    assert res.abi_invariants["dispatch_control"] == "Success"


def test_abi_invariants_all_green_on_a_valid_patch(ngp_task, reference_patch):
    res = grade(ngp_task, reference_patch)
    assert res.abi_invariants == {"bytecode_selectors": "Success",
                                  "dispatch_selectors": "Success",
                                  "dispatch_control": "Success",
                                  "not_vacuous": "Success"}


# ---------------------------------------------------------------------- canaries live
def test_out_of_scope_edit_canary(ngp_task, reference_patch):
    res = sandbox.compute_reward(ngp_task, {"test/poc.t.sol": "// neutered"}, backend="local")
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert any(c.startswith("out_of_scope_edit") for c in res.canaries)
    assert not res.diff_in_scope
    assert res.poc is None or not res.poc.ran, "an out-of-scope edit must short-circuit"


def test_empty_patch_canary(ngp_task, vulnerable_source):
    res = grade(ngp_task, vulnerable_source)      # byte-identical to what was shipped
    assert "empty_patch" in res.canaries
    assert res.score == 0.0


def test_harness_hash_lock_detects_tampering(tmp_path, ngp_task, reference_patch):
    import shutil
    dst = tmp_path / "tampered"
    shutil.copytree(ngp_task, dst)
    poc = dst / "tests" / "poc.t.sol"
    poc.write_text(poc.read_text().replace("assertGt(profit, PROFIT_THRESHOLD",
                                           "assertLt(profit, PROFIT_THRESHOLD"))
    res = sandbox.compute_reward(dst, {TOKEN_REL: reference_patch}, backend="local")
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert any(c.startswith("poc_tampered") for c in res.canaries)


# ------------------------------------------------------------------ receipt machinery
def test_canonical_grade_is_reproducible_on_this_host(ngp_task, reference_patch):
    """Two independent episodes of the same input must produce the same canonical grade.
    Different ports, different uuid workdirs, different timings — same hash."""
    a = grade(ngp_task, reference_patch)
    b = grade(ngp_task, reference_patch)
    assert a.canonical_sha256() == b.canonical_sha256()
    assert a.outcome == b.outcome == sandbox.OUTCOME_SOLVED


def test_episodes_do_not_share_a_port_or_workdir(ngp_task, reference_patch):
    """Concurrent episodes must not collide on :8545 or on a pid+second workdir."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: grade(ngp_task, reference_patch), range(3)))
    assert [r.outcome for r in results] == [sandbox.OUTCOME_SOLVED] * 3
    assert len({r.canonical_sha256() for r in results}) == 1
