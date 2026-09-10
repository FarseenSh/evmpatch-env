"""The ten scorer probes.

Synthetic forge runs in the shapes a reward hack or an infrastructure fault takes, fed
through the real parser and the real scorer. FOUR of them are shapes a naive scorer (text
log, bare test names, "some hidden tests passed") accepts as `solved` with reward 1.0;
here every one of them must score 0:

    poc_rpc_failure                    an RPC failure of testExploit read as "exploit blocked"
    missing_expected_hidden_tests      one unrelated passing test satisfied the hidden gate
    partial_suite_before_runner_crash  a truncated suite before a crash satisfied it too
    duplicate_name_overwrites_failure  a later PASS overwrote an earlier same-named FAIL

Each probe below asserts the outcome AND, where the run is inconclusive, the specific
reason code. Exactly one case — `valid_looking_control` — may be `solved`.

Nothing here runs Foundry, Docker, an RPC or an EVM: the probes feed synthetic
`forge test --json` payloads through the real parser and the real (pure) scorer, so they
test the shipped code path rather than a re-implementation of it.
"""
from __future__ import annotations

import json
import shutil

import pytest

from conftest import REPO
from evmpatch_env import sandbox

ORACLE = "test/poc.t.sol:PoC:testExploit()"
HIDDEN_IDS = [
    "test/hidden/h.t.sol:H:testTransfer()",
    "test/hidden/h.t.sol:H:testAllowance()",
    "test/hidden/h.t.sol:H:testOwner()",
    "test/hidden/h.t.sol:H:testConservation()",
    "test/hidden/h.t.sol:H:testAccounting()",
]


def manifest(poc_ids=None, hidden_ids=None, oracle=ORACLE) -> dict:
    poc_ids = poc_ids or [ORACLE]
    hidden_ids = HIDDEN_IDS if hidden_ids is None else hidden_ids
    return {
        "version": 1,
        "id_format": "<test file path>:<contract>:<function signature>",
        "poc": {"exploit_oracle": oracle, "tests": sorted(poc_ids), "count": len(poc_ids),
                "accepted_block_kinds": ["assertion", "revert"],
                "recognised_block_reasons": ["*assertion failed*",
                                             "BEP20: transfer amount exceeds balance"]},
        "hidden": {"tests": sorted(hidden_ids), "count": len(hidden_ids)},
    }


def report(*suites) -> str:
    """Build a `forge test --json` payload. Each suite is (name, {fn: (status, reason)})."""
    out = {}
    for name, tests in suites:
        out[name] = {
            "duration": "1ms",
            "test_results": {
                fn: {"status": status, "reason": reason, "counterexample": None,
                     "logs": [], "decoded_logs": [], "kind": {"Unit": {"gas": 1}},
                     "traces": [], "labeled_addresses": {}, "duration": "1ms",
                     "breakpoints": {}, "gas_snapshots": {}}
                for fn, (status, reason) in tests.items()
            },
            "warnings": [],
        }
    return json.dumps(out)


def poc_report(status: str, reason=None) -> str:
    return report(("test/poc.t.sol:PoC", {"testExploit()": (status, reason)}))


HIDDEN_ALL_PASS = report(("test/hidden/h.t.sol:H",
                          {i.split(":")[-1]: ("Success", None) for i in HIDDEN_IDS}))

# The exact reason string forge emits when the profit assertion trips.
BLOCKED_REASON = "assertion failed: attacker_profit > threshold"


def run(stdout: str, rc: int = 0) -> sandbox.ForgeRun:
    return sandbox.parse_forge_json(stdout, "", rc)


def judge(poc: sandbox.ForgeRun, hidden: sandbox.ForgeRun, mf: dict,
          canaries=()) -> sandbox.RewardResult:
    return sandbox.score(poc, hidden, mf, ["src/contracts/Token.sol"], list(canaries),
                         "probe", task_id="probe")


# --------------------------------------------------------------------------- the ten
def test_1_valid_looking_control():
    """The only case that may be accepted: oracle failed on its assertion, every manifest
    hidden test passed, the runner exited cleanly."""
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_SOLVED
    assert res.score == 1.0
    assert res.poc_blocked and res.poc_failure_kind == "assertion"
    assert res.tests_match_manifest and res.hidden_all_pass


def test_2_poc_rpc_failure_is_inconclusive():
    """NAIVE SCORER ACCEPTS (1.0). An infrastructure failure of the exploit test is not
    evidence that the exploit was blocked."""
    res = judge(run(poc_report("Failure", "RPC error: unrecorded eth_getStorageAt"), 1),
                run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_UNRECORDED_RPC
    assert res.score == 0.0 and not res.poc_blocked
    assert res.poc_failure_kind == "infra"


def test_3_missing_expected_hidden_tests_is_inconclusive():
    """NAIVE SCORER ACCEPTS (1.0). One unrelated passing test satisfies a `passed>0,
    failed==0` gate; the manifest match does not."""
    hidden = report(("test/hidden/h.t.sol:H", {"testUnrelated()": ("Success", None)}))
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(hidden, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_MISSING_TESTS
    assert not res.tests_match_manifest and res.score == 0.0


def test_4_partial_suite_before_runner_crash_is_inconclusive():
    """NAIVE SCORER ACCEPTS (1.0). Without the return code, a suite truncated by a crashing
    runner looks like a clean partial pass."""
    hidden = report(("test/hidden/h.t.sol:H", {"testTransfer()": ("Success", None)}))
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(hidden, 134), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_RUNNER_CRASH
    assert res.score == 0.0


def test_5_duplicate_name_does_not_overwrite_failure():
    """NAIVE SCORER ACCEPTS (1.0). Two suites both define `testInvariant()`; keyed on the
    bare function name, suite B's PASS would erase suite A's FAIL."""
    ids = ["test/hidden/a.t.sol:A:testInvariant()", "test/hidden/b.t.sol:B:testInvariant()"]
    hidden = report(("test/hidden/a.t.sol:A", {"testInvariant()": ("Failure", "invariant violation")}),
                    ("test/hidden/b.t.sol:B", {"testInvariant()": ("Success", None)}))
    hrun = run(hidden, 1)
    assert set(hrun.tests) == set(ids), "fully-qualified ids must keep both results"
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), hrun,
                manifest(hidden_ids=ids))
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert res.score == 0.0
    assert not res.hidden_all_pass
    assert "bricked" in res.canaries      # exploit "blocked" while a hidden test fails


def test_6_no_hidden_tests_is_inconclusive():
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run("{}", 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_MISSING_TESTS


def test_7_hidden_behaviour_failure_is_not_solved():
    hidden = report(("test/hidden/h.t.sol:H",
                     {**{i.split(":")[-1]: ("Success", None) for i in HIDDEN_IDS[1:]},
                      "testTransfer()": ("Failure", "transfer reverted")}))
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(hidden, 1), manifest())
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert res.score == 0.0
    assert not res.hidden_all_pass and "bricked" in res.canaries


def test_8_compilation_failure_is_inconclusive():
    """forge prints the solc diagnostic on stdout and exits 1; there is no JSON report."""
    solc = ("Compiler run failed:\nError (2314): Expected identifier but got 'is'\n"
            "   --> src/contracts/Token.sol:362:6:\n")
    res = judge(run(solc, 1), run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_COMPILE_FAILED
    assert not res.compiled and res.score == 0.0


def test_9_poc_still_succeeds_is_not_solved():
    res = judge(run(poc_report("Success"), 0), run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert not res.poc_blocked and res.poc_failure_kind == "none"


def test_10_scope_violation_is_not_solved():
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(HIDDEN_ALL_PASS, 0),
                manifest(), canaries=["out_of_scope_edit:test/poc.t.sol"])
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert not res.diff_in_scope and res.score == 0.0


# ------------------------------------------------------------------ summary + extras
# The four probe shapes a naive scorer accepts as `solved`, with the outcome and reason
# code each must produce here.
NAIVE_SCORER_ACCEPTS = {
    "poc_rpc_failure": (sandbox.OUTCOME_INCONCLUSIVE, sandbox.R_UNRECORDED_RPC),
    "missing_expected_hidden_tests": (sandbox.OUTCOME_INCONCLUSIVE, sandbox.R_MISSING_TESTS),
    "partial_suite_before_runner_crash": (sandbox.OUTCOME_INCONCLUSIVE, sandbox.R_RUNNER_CRASH),
    "duplicate_name_overwrites_failure": (sandbox.OUTCOME_NOT_SOLVED, ""),
}


def test_exactly_one_probe_is_accepted():
    """Whole-set check: of the ten probes, exactly `valid_looking_control` is `solved`."""
    cases = {
        "valid_looking_control": judge(run(poc_report("Failure", BLOCKED_REASON), 1),
                                       run(HIDDEN_ALL_PASS, 0), manifest()),
        "poc_rpc_failure": judge(run(poc_report("Failure", "RPC error: unrecorded eth_getStorageAt"), 1),
                                 run(HIDDEN_ALL_PASS, 0), manifest()),
        "missing_expected_hidden_tests": judge(
            run(poc_report("Failure", BLOCKED_REASON), 1),
            run(report(("test/hidden/h.t.sol:H", {"testUnrelated()": ("Success", None)})), 0),
            manifest()),
        "partial_suite_before_runner_crash": judge(
            run(poc_report("Failure", BLOCKED_REASON), 1),
            run(report(("test/hidden/h.t.sol:H", {"testTransfer()": ("Success", None)})), 134),
            manifest()),
        "duplicate_name_overwrites_failure": judge(
            run(poc_report("Failure", BLOCKED_REASON), 1),
            run(report(("test/hidden/a.t.sol:A", {"testInvariant()": ("Failure", "invariant violation")}),
                       ("test/hidden/b.t.sol:B", {"testInvariant()": ("Success", None)})), 1),
            manifest(hidden_ids=["test/hidden/a.t.sol:A:testInvariant()",
                                 "test/hidden/b.t.sol:B:testInvariant()"])),
        "no_hidden_tests": judge(run(poc_report("Failure", BLOCKED_REASON), 1),
                                 run("{}", 0), manifest()),
        "hidden_behavior_failure": judge(
            run(poc_report("Failure", BLOCKED_REASON), 1),
            run(report(("test/hidden/h.t.sol:H",
                        {**{i.split(":")[-1]: ("Success", None) for i in HIDDEN_IDS[1:]},
                         "testTransfer()": ("Failure", "transfer reverted")})), 1),
            manifest()),
        "compilation_failure": judge(run("Compiler run failed:\nError (2314): boom\n", 1),
                                     run(HIDDEN_ALL_PASS, 0), manifest()),
        "poc_still_succeeds": judge(run(poc_report("Success"), 0), run(HIDDEN_ALL_PASS, 0),
                                    manifest()),
        "scope_violation": judge(run(poc_report("Failure", BLOCKED_REASON), 1),
                                 run(HIDDEN_ALL_PASS, 0), manifest(),
                                 canaries=["out_of_scope_edit:test/poc.t.sol"]),
    }
    assert len(cases) == 10
    accepted = {n for n, r in cases.items() if r.solved}
    assert accepted == {"valid_looking_control"}, f"unexpected accepts: {accepted}"
    assert all(r.score == 0.0 for n, r in cases.items() if n != "valid_looking_control")
    for name, (outcome, reason) in NAIVE_SCORER_ACCEPTS.items():
        assert cases[name].outcome == outcome, name
        if reason:
            assert cases[name].reason == reason, name


def test_text_fallback_can_never_be_solved():
    """The human-log parser is a fallback for reading old runs, not a scoring path."""
    text_poc = sandbox.parse_forge_text(
        "Compiler run successful!\n[FAIL: assertion failed] testExploit() (gas: 1)\n", "", 1)
    text_hidden = sandbox.parse_forge_text(
        "Compiler run successful!\n" +
        "".join(f"[PASS] {i.split(':')[-1]} (gas: 1)\n" for i in HIDDEN_IDS), "", 0)
    assert not text_poc.structured and not text_hidden.structured
    res = judge(text_poc, text_hidden, manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_NO_REPORT
    assert res.score == 0.0


def test_setup_failure_is_inconclusive_not_blocked():
    """A suite whose setUp() reverted reports a pseudo-test `setUp()`. A scorer that only
    looked for a `testExploit` entry would see none and fall through; this one stops here."""
    poc = run(report(("test/poc.t.sol:PoC", {"setUp()": (
        "Failure", "vm.createSelectFork: could not instantiate forked environment; "
                   "Connection refused (os error 61)")})), 1)
    res = judge(poc, run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_UNRECORDED_RPC     # infra-flavoured setUp failure
    assert res.score == 0.0


def test_unexpected_extra_test_is_inconclusive():
    hidden = report(("test/hidden/h.t.sol:H",
                     {**{i.split(":")[-1]: ("Success", None) for i in HIDDEN_IDS},
                      "testSmuggled()": ("Success", None)}))
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(hidden, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_UNEXPECTED_TESTS


def test_skipped_graded_test_is_inconclusive():
    hidden = report(("test/hidden/h.t.sol:H",
                     {**{i.split(":")[-1]: ("Success", None) for i in HIDDEN_IDS[1:]},
                      "testTransfer()": ("Skipped", "skipped")}))
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(hidden, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_TESTS_SKIPPED


def test_unrecorded_rpc_miss_makes_the_run_inconclusive():
    """Even with a perfect-looking report, a non-benign proxy miss voids the episode."""
    poc = run(poc_report("Failure", BLOCKED_REASON), 1)
    poc.rpc_misses = [{"method": "eth_getStorageAt", "params": "[]", "benign": False}]
    res = judge(poc, run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_UNRECORDED_RPC


def test_benign_probe_miss_does_not_void_the_run():
    poc = run(poc_report("Failure", BLOCKED_REASON), 1)
    poc.benign_rpc_misses = 2          # e.g. eth_getAccountInfo, which no upstream answers
    res = judge(poc, run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_SOLVED


def test_missing_manifest_refuses_to_score():
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(HIDDEN_ALL_PASS, 0), None)
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_MANIFEST_MISSING


@pytest.mark.parametrize("reason,kind", [
    ("assertion failed: attacker_profit > threshold", "assertion"),
    ("BEP20: transfer amount exceeds balance", "revert"),
    ("OFFLINE: unrecorded eth_getStorageAt [...]", "infra"),
    ("backend: failed to get account for 0x...", "infra"),
    ("vm.createSelectFork: could not instantiate forked environment", "infra"),
    (None, "revert"),
])
def test_failure_reason_classification(reason, kind):
    assert sandbox.classify_failure_reason(reason) == kind


def test_unrecognised_failure_reason_is_not_read_as_blocked():
    """ADDENDUM RULE. The oracle failed, the reason is not infrastructure-shaped, but the
    task never declared it as an 'exploit blocked' signal. A naive scorer would call that a
    repair; this one flags it for a human."""
    res = judge(run(poc_report("Failure", "Ownable: caller is not the owner"), 1),
                run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_UNRECOGNISED
    assert res.reason_family == "unrecognised_failure"
    assert res.score == 0.0 and not res.poc_blocked


def test_declared_revert_reason_is_read_as_blocked():
    """The counterpart: the reference patch's observed revert string IS declared, so the
    same shape of failure is a repair rather than a mystery."""
    res = judge(run(poc_report("Failure", "BEP20: transfer amount exceeds balance"), 1),
                run(HIDDEN_ALL_PASS, 0), manifest())
    assert res.outcome == sandbox.OUTCOME_SOLVED
    assert res.poc_blocked and res.poc_failure_kind == "revert"


def test_every_inconclusive_reason_has_a_family():
    for code, family in sandbox.REASON_FAMILY.items():
        assert family in {"compile_failed", "anvil_start_failed", "unrecorded_rpc",
                          "runner_crash", "manifest_mismatch", "timeout",
                          "unrecognised_failure"}, (code, family)
    declared = {v for k, v in vars(sandbox).items() if k.startswith("R_") and isinstance(v, str)}
    assert declared == set(sandbox.REASON_FAMILY), "a reason code has no family mapping"


def test_abi_invariants_are_recorded_separately():
    """ADDENDUM RULE: the bytecode scan and the behavioural dispatch probe are two distinct
    results in the grade, not one merged verdict."""
    hidden = report(("test/hidden/invariants_auto.t.sol:AutoInvariants", {
        "test_abi_selectors_preserved()": ("Success", None),
        "test_abi_selectors_dispatch()": ("Failure", "ABI broken: contract does not dispatch foo()"),
        "test_unknown_selector_is_rejected()": ("Success", None),
        "test_selector_check_is_not_vacuous()": ("Success", None),
    }))
    ids = ["test/hidden/invariants_auto.t.sol:AutoInvariants:" + f for f in (
        "test_abi_selectors_preserved()", "test_abi_selectors_dispatch()",
        "test_unknown_selector_is_rejected()", "test_selector_check_is_not_vacuous()")]
    res = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(hidden, 1),
                manifest(hidden_ids=ids))
    assert res.abi_invariants == {
        "bytecode_selectors": "Success",
        "dispatch_selectors": "Failure",
        "dispatch_control": "Success",
        "not_vacuous": "Success",
    }
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED, (
        "a contract whose bytecode still contains the selector but which no longer "
        "dispatches it must not be scored solved")


def test_canonical_grade_drops_volatile_fields():
    a = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(HIDDEN_ALL_PASS, 0), manifest())
    b = judge(run(poc_report("Failure", BLOCKED_REASON), 1), run(HIDDEN_ALL_PASS, 0), manifest())
    b.poc.stdout_tail = "totally different log text"
    b.poc.returncode = 1
    b.backend = "docker"
    assert a.canonical_sha256() == b.canonical_sha256()
    assert a.canonical_sha256(core_only=True) == b.canonical_sha256(core_only=True)
    for blob in (a.canonical_json(), a.canonical_json(core_only=True)):
        for volatile in ("duration", "gas", "stdout_tail", "returncode", "backend"):
            assert volatile not in blob
    # the CORE form carries outcome + per-test pass/fail only; the STRICT form adds the
    # revert/assertion reason strings.
    assert "attacker_profit" not in a.canonical_json(core_only=True)
    assert "attacker_profit" in a.canonical_json()


# ------------------------------------------- security obligations and patch-key probes
# Each of these pins one reward-hack shape: an incomplete repair that blocks the PoC, and
# a patch key that escapes the allow-listed source. The first block is pure; the second
# touches the filesystem (a task copy in tmp_path) but still runs no forge, no Docker, no
# RPC and no EVM.
BLOCK = "ERC20: transfer amount exceeds allowance"
SEC_ID = "test/hidden/h.t.sol:H:testAllowance()"


def _manifest_with_security():
    m = manifest()
    m["poc"]["recognised_block_reasons"] = ["*assertion failed*", BLOCK]
    m["hidden"]["security_tests"] = [SEC_ID]
    return m


def _hidden_with(failing: str) -> str:
    return report(("test/hidden/h.t.sol:H", {
        tid.split(":")[-1]: (("Failure", "assertion failed") if tid == failing
                             else ("Success", None))
        for tid in HIDDEN_IDS}))


def test_security_test_failure_is_residual_vulnerability_not_bricked():
    """Incomplete repair: a pair-only allowance fix blocks the PoC and leaves the bypass
    standing for every non-pair holder. A hidden test the manifest declares a SECURITY
    obligation catches it, and the grade says which kind of failure it was: the contract is not
    bricked, the repair is incomplete."""
    res = judge(run(poc_report("Failure", BLOCK), 1), run(_hidden_with(SEC_ID), 1),
                _manifest_with_security())
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED and res.score == 0.0
    assert res.canaries == ["residual_vulnerability"]
    assert res.poc_blocked and not res.hidden_all_pass and res.functional_all_pass


def test_functional_test_failure_is_still_bricked():
    """The counterpart: a failure OUTSIDE the declared security set still means the patch
    broke the token, and still says `bricked`."""
    res = judge(run(poc_report("Failure", BLOCK), 1),
                run(_hidden_with("test/hidden/h.t.sol:H:testTransfer()"), 1),
                _manifest_with_security())
    assert res.canaries == ["bricked"]
    assert not res.functional_all_pass


def test_a_task_without_security_tests_is_unchanged():
    res = judge(run(poc_report("Failure", BLOCK), 1),
                run(_hidden_with(SEC_ID), 1), manifest())
    assert res.canaries == ["bricked"], "the split must not change tasks that do not use it"


@pytest.mark.parametrize("key", [
    "src/contracts/../../test/poc.t.sol",   # the demonstrated traversal
    "src/contracts/../../../etc/passwd",
    "/etc/passwd",
    "src/contracts/./../tests/manifest.json",
    "..",
    "src\\contracts\\..\\..\\test\\poc.t.sol",
])
def test_escaping_patch_keys_are_rejected(key):
    """A key that can leave `project/` is rejected outright rather
    than normalised and then glob-matched."""
    assert sandbox.normalise_patch_key(key) is None


@pytest.mark.parametrize("key,ok", [
    ("src/contracts/Token.sol", True),
    ("src/contracts/Other.sol", True),
    ("src/contracts/nested/Token.sol", False),   # `*` must not cross a separator
    ("test/poc.t.sol", False),
    ("src/contractsXToken.sol", False),
])
def test_glob_matches_per_segment(key, ok):
    assert sandbox.glob_match(key, "src/contracts/*.sol") is ok


def test_plain_fnmatch_would_have_accepted_the_traversal():
    """Why the segment-aware matcher exists, stated as an executable fact."""
    import fnmatch as _fn
    assert _fn.fnmatch("src/contracts/../../test/poc.t.sol", "src/contracts/*.sol")
    assert not sandbox.glob_match("test/poc.t.sol", "src/contracts/*.sol")


# --------------------------------------------------------- filesystem-level probes
MCAI = REPO / "tasks" / "mcai_2025_01"


@pytest.fixture()
def task_copy(tmp_path):
    dst = tmp_path / "mcai_copy"
    shutil.copytree(MCAI, dst)
    return dst


def test_traversal_key_raises_a_hard_canary(task_copy):
    """End to end at the scope check: a traversal key is an out-of-scope edit, recorded as
    a change attempt (not an empty patch) and decided before any forge run."""
    poc = (task_copy / "tests" / "poc.t.sol").read_text()
    changed, canaries = sandbox.check_scope_and_canaries(
        task_copy, {"src/contracts/../../test/poc.t.sol": poc + "\n// tampered\n"})
    assert changed == ["src/contracts/../../test/poc.t.sol"]
    assert canaries == ["out_of_scope_edit:src/contracts/../../test/poc.t.sol"]
    assert any(c.split(":")[0] in sandbox.HARD_CANARIES for c in canaries)


def test_absolute_key_raises_a_hard_canary(task_copy, tmp_path):
    changed, canaries = sandbox.check_scope_and_canaries(
        task_copy, {str(tmp_path / "evil.sol"): "// anything"})
    assert canaries and canaries[0].startswith("out_of_scope_edit:")


def test_symlink_out_of_the_project_is_rejected(task_copy, tmp_path):
    """A patchable-looking key whose path leaves `project/` through a symlink."""
    outside = tmp_path / "outside"
    outside.mkdir()
    link = task_copy / "project" / "src" / "contracts" / "escape"
    link.symlink_to(outside, target_is_directory=True)
    changed, canaries = sandbox.check_scope_and_canaries(
        task_copy, {"src/contracts/escape/Token.sol": "// anything"})
    assert canaries == ["out_of_scope_edit:src/contracts/escape/Token.sol(symlink escape)"]


def test_assemble_workdir_refuses_an_escaping_key(task_copy, tmp_path):
    """Defence in depth: the step that actually writes re-derives the safe key itself."""
    with pytest.raises(ValueError):
        sandbox.assemble_workdir(task_copy, {"../../escape.sol": "// anything"},
                                 tmp_path / "work")


def test_workdir_harness_is_reverified_after_the_patch(task_copy, tmp_path):
    """`check_scope_and_canaries` hashes the TASK directory, which
    the agent cannot reach; this re-hashes the copies the tests actually run against, so a
    write that ever lands on a harness file inside the episode workdir is caught."""
    work = sandbox.assemble_workdir(task_copy, None, tmp_path / "work")
    assert sandbox.verify_workdir_harness(task_copy, work) == []
    (work / "test" / "poc.t.sol").write_text("// overwritten inside the workdir\n")
    canaries = sandbox.verify_workdir_harness(task_copy, work)
    assert canaries == ["poc_tampered:tests/poc.t.sol(workdir copy differs)"]
    assert canaries[0].split(":")[0] in sandbox.HARD_CANARIES
    (work / "test" / "hidden" / "regression.t.sol").unlink()
    assert any("harness_tampered:tests/hidden/regression.t.sol" in c
               for c in sandbox.verify_workdir_harness(task_copy, work))
