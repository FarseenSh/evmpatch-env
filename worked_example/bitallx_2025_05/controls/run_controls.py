#!/usr/bin/env python3
"""Worked example, bitallx_2025_05: grade the reference repair, an alternative complete repair,
the shipped vulnerable source and a set of INCOMPLETE / NON-REPAIR / DESTRUCTIVE /
INFRASTRUCTURE controls through the unmodified grader, and record every grade (canonical
JSON, core+strict SHA-256, full result) under controls/<name>/.

Everything runs offline through the task's fail-closed replay proxy; nothing here needs a
network, an API key or a paid resource. Run from the repository root:

    uv run --no-project --python 3.12 python worked_example/bitallx_2025_05/controls/run_controls.py

Each variant is DERIVED from the shipped source (or from the reference repair) by this
script, never hand-edited, so the control set is reproducible from the task directory alone.
The exact bytes graded are written next to each grade (Token.sol) with a unified diff against
the shipped file.

Why this control set exists. `incomplete_fix__first_element_only` (bound only `amount[0]` by
`totalSendAmount`) blocks the shipped one-element PoC, so an exploit oracle alone would grade
it exactly like the reference repair. `tests/hidden/security.t.sol` (three obligations listed
under `hidden.security_tests` in the manifest) states the declared class, "the payout must be
bounded by what was funded", instead of the single shape the PoC uses. The controls below pin
both directions: two complete repairs with different implementations must score 1.0, and two
incomplete repairs of the same class must score 0.0 with the `residual_vulnerability` canary.
"""
from __future__ import annotations

import difflib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from evmpatch_env import build_task, sandbox  # noqa: E402

TASK = REPO / "tasks" / "bitallx_2025_05"
REL = "src/contracts/Token.sol"
SHIPPED = (TASK / "project" / REL).read_text()
REFERENCE = build_task.apply_unified_diff(SHIPPED, (TASK / "reference_patch.sol.diff").read_text())
assert REFERENCE != SHIPPED

# The single statement every derivation below anchors on: the first line of BitallxPayOut.
_ANCHOR = ('        require(wallet.length == amount.length, '
           '"The length of 2 arrays should be the same");\n')
# The reference repair's bound.
_REF_REQUIRE = ('        require(requested == totalSendAmount, '
                '"Payout total does not match the funded amount");\n')
# The unbounded payout loop of the shipped source.
_PAYOUT_LOOP = """        for (uint256 i = 0; i < wallet.length; i++) {
            IBEP20(tokencontract).transfer(wallet[i], amount[i]);
        }
"""
# The declared block reason. tests/manifest.json lists this literal under
# `recognised_block_reasons`, so a repair that reverts must use it to be READ as a block;
# a repair that instead pays nothing is recognised through `*exploit did not yield profit*`
# and is free to use any string (see `alt_complete_fix__capped_payout`).
_DECLARED_REASON = "Payout total does not match the funded amount"


def _after_anchor(src: str, insert: str) -> str:
    assert src.count(_ANCHOR) == 1, "BitallxPayOut length-check anchor not found"
    return src.replace(_ANCHOR, _ANCHOR + insert)


# ------------------------------------------------------- complete repairs (must score 1.0)
def alt_complete_fix_sum_bounded(src: str) -> str:
    """ALTERNATIVE COMPLETE REPAIR #1, written against the SHIPPED source rather than
    derived from the reference: sum the requested amounts and require the sum to be
    BOUNDED BY (not equal to) the funded total. Payers who over-fund keep the change in the
    contract, which the reference's equality forbids; both are complete repairs of the
    declared class, and the security obligations must credit either."""
    return _after_anchor(src, """        uint256 payoutTotal;
        for (uint256 i = 0; i < amount.length; i++) {
            payoutTotal += amount[i];
        }
        require(payoutTotal <= totalSendAmount, "%s");
""" % _DECLARED_REASON)


def alt_complete_fix_capped_payout(src: str) -> str:
    """ALTERNATIVE COMPLETE REPAIR #2, a different REMEDY as well as a different
    implementation: instead of reverting, pay out at most what was funded. The exploit then
    yields nothing rather than reverting, and the oracle recognises it through
    `*exploit did not yield profit*`. This is the control for the security obligations'
    'revert OR pay nothing' phrasing — a repair must not be penalised for capping."""
    assert src.count(_PAYOUT_LOOP) == 1, "payout loop not found"
    return src.replace(_PAYOUT_LOOP, """        uint256 remaining = totalSendAmount;
        for (uint256 i = 0; i < wallet.length; i++) {
            uint256 pay = amount[i] <= remaining ? amount[i] : remaining;
            remaining -= pay;
            IBEP20(tokencontract).transfer(wallet[i], pay);
        }
""")


# ---------------------------------------------------- incomplete repairs (must score 0.0)
def incomplete_fix_first_element_only(src: str) -> str:
    """Incomplete repair, the load-bearing one. Bound only `amount[0]` by the funded total.
    The shipped PoC passes a ONE-element array, so it is blocked and an exploit oracle alone
    would grade this like the reference repair; a two-element array `[0, treasury]` with
    `totalSendAmount = 0` still drains the contract. The exact analogue of MCAI's
    `pair_only_allowance_fix`."""
    return _after_anchor(src, '        require(amount.length == 0 || amount[0] <= totalSendAmount,\n'
                              '                "%s");\n' % _DECLARED_REASON)


def incomplete_fix_each_element_bounded(src: str) -> str:
    """The same class one step further out: bound EVERY element by the funded total, but
    never the SUM. `[total, total]` funded once passes every per-element check and pays
    twice, so the second element comes out of the contract's own treasury."""
    return _after_anchor(src, """        for (uint256 i = 0; i < amount.length; i++) {
            require(amount[i] <= totalSendAmount, "%s");
        }
""" % _DECLARED_REASON)


# ------------------------------------------- non-repair the PoC itself still catches (0.0)
def non_repair_bound_only_when_funded(reference: str) -> str:
    """The reference bound, applied only when `totalSendAmount > 0`. The whole attack is
    `totalSendAmount = 0`, so this changes nothing about the incident it claims to fix —
    and the shipped PoC catches it without any help from the security suite."""
    assert reference.count(_REF_REQUIRE) == 1, "reference require not found"
    return reference.replace(_REF_REQUIRE, """        if (totalSendAmount > 0) {
            require(requested == totalSendAmount, "%s");   // VARIANT: never fires for the attack
        }
""" % _DECLARED_REASON)


# ------------------------------------------------------------- destructive controls (0.0)
def recognised_reason_payout_always_reverts(src: str) -> str:
    """RECOGNISED REASON IN THE WRONG PLACE. `BitallxPayOut` always reverts with the string
    the task declares as 'exploit blocked', so nobody can be paid at all. The oracle looks
    blocked; the legitimate-use suite says the contract is broken."""
    return _after_anchor(src, '        revert("%s");   // VARIANT\n' % _DECLARED_REASON)


def fix_plus_storage_slot_shift(reference: str) -> str:
    """The reference repair PLUS one inserted state variable. It compiles, it keeps the ABI,
    and it blocks the exploit — but the grader etches the patched code onto the LIVE address
    and keeps the LIVE storage, so every state variable below the insertion now reads the
    wrong slot. `task.json` names this constraint explicitly; this control proves the
    regression suite enforces it."""
    anchor = "    IBEP20 public BSCUSDTTokenContract;\n"
    assert reference.count(anchor) == 1, "state variable anchor not found"
    return reference.replace(anchor, "    uint256 private _pad;   // VARIANT: shifts every "
                                     "state variable below it by one slot\n" + anchor)


# ---------------------------------------------------------- infrastructure control (0.0)
def compile_error(reference: str) -> str:
    out = reference.replace("    function claimReward(", "    this line is not solidity;\n    function claimReward(", 1)
    assert out != reference
    return out


# ---------------------------------------------------------------------------- plumbing
def diff_text(a: str, b: str, name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True),
                                        fromfile=f"shipped/{name}", tofile=f"variant/{name}"))


def record(name: str, kind: str, expected: str, res: sandbox.RewardResult,
           files: dict[str, str] | None, note: str, task_dir: Path = TASK) -> dict:
    d = HERE / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "grade_canonical.json").write_text(json.dumps(res.canonical(), sort_keys=True, indent=2) + "\n")
    (d / "grade_full.json").write_text(res.to_json() + "\n")
    (d / "sha256.txt").write_text(f"core   {res.canonical_sha256(core_only=True)}\n"
                                  f"strict {res.canonical_sha256(core_only=False)}\n")
    if files:
        for rel, content in files.items():
            base = Path(rel).name
            (d / base).write_text(content)
            key = sandbox.normalise_patch_key(rel)
            shipped = (task_dir / "project" / key) if (key and key.startswith("src/")) else None
            if shipped and shipped.is_file():
                (d / (base + ".diff")).write_text(
                    diff_text(shipped.read_text(), content, base) or "(identical to shipped)\n")
    (d / "NOTE.md").write_text(f"# {name}\n\n**kind:** {kind}  \n**expected:** {expected}\n\n"
                               + note + "\n")
    failing = sorted(t.id for t in (res.hidden.tests.values() if res.hidden and res.hidden.tests else [])
                     if t.status != "Success")
    manifest = sandbox.load_manifest(task_dir) or {}
    security = set(manifest.get("hidden", {}).get("security_tests") or [])
    oracle_id = manifest.get("poc", {}).get("exploit_oracle")
    oracle = res.poc.tests.get(oracle_id) if res.poc and res.poc.tests else None
    # A non-benign RPC miss means the frozen state is incomplete for this variant, which
    # would make the grade an infrastructure artefact rather than a judgement on the patch.
    misses = sum(len(r.rpc_misses) for r in (res.poc, res.hidden) if r is not None)
    benign = sum(r.benign_rpc_misses for r in (res.poc, res.hidden) if r is not None)
    row = dict(name=name, kind=kind, expected=expected, outcome=res.outcome,
               non_benign_rpc_misses=misses, benign_rpc_misses=benign,
               reason=res.reason or "", score=res.score, poc_blocked=res.poc_blocked,
               hidden_all_pass=res.hidden_all_pass, functional_all_pass=res.functional_all_pass,
               compiled=res.compiled, diff_in_scope=res.diff_in_scope,
               tests_match_manifest=res.tests_match_manifest, canaries=sorted(res.canaries),
               abi_invariants=res.abi_invariants, failing_hidden=failing,
               failing_security=sorted(set(failing) & security),
               oracle_status=oracle.status if oracle else None,
               oracle_reason=oracle.reason if oracle else None,
               core_sha256=res.canonical_sha256(core_only=True),
               strict_sha256=res.canonical_sha256(core_only=False),
               detail=res.reason_detail or res.detail)
    print(f"[{name}] {res.outcome} score={res.score} poc_blocked={res.poc_blocked} "
          f"functional_all_pass={res.functional_all_pass} canaries={sorted(res.canaries)} "
          f"failing_security={len(row['failing_security'])}", flush=True)
    return row


def grade(task_dir: Path, files: dict[str, str] | None, backend: str = "local", **kw) -> sandbox.RewardResult:
    return sandbox.compute_reward(task_dir, files, backend=backend, **kw)


def poc_verbose_log(task_dir: Path, files: dict[str, str] | None) -> str:
    """Re-run ONLY the PoC suite with -vv so the attacker-profit log line is visible. Same
    replay proxy, same workdir assembly as the grader; this is documentation, not the grade."""
    root = Path(tempfile.mkdtemp(prefix="bitallx_poc_vv_"))
    port_file, miss_file = root / "proxy.port", root / "rpc_misses.json"
    proxy = subprocess.Popen([sys.executable, str(sandbox.RPC_REPLAY), "replay",
                              str(task_dir / "state" / "rpc_log.json"), "0",
                              "--port-file", str(port_file), "--miss-file", str(miss_file)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        bound = sandbox._await_proxy(proxy, port_file, 20.0)
        assert bound, "proxy did not bind"
        work = sandbox.assemble_workdir(task_dir, files, root / "work")
        out = subprocess.run(["forge", "test", "--match-path", "test/poc.t.sol", "-vv"],
                             cwd=work, capture_output=True, text=True,
                             env=sandbox.forge_env(f"http://127.0.0.1:{bound}"), timeout=300)
        return out.stdout + out.stderr
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except Exception:
            proxy.kill()
        shutil.rmtree(root, ignore_errors=True)


# The control set, as data: (name, kind, expected, source-or-None, note). Imported by
# tests/test_controls_bitallx_2025_05.py and by the state re-recording script, so the
# tests, the recording and the documented controls cannot drift apart.
def variants() -> dict[str, str | None]:
    return {
        "unpatched": None,
        "reference": REFERENCE,
        "alt_complete_fix__sum_bounded": alt_complete_fix_sum_bounded(SHIPPED),
        "alt_complete_fix__capped_payout": alt_complete_fix_capped_payout(SHIPPED),
        "incomplete_fix__first_element_only": incomplete_fix_first_element_only(SHIPPED),
        "incomplete_fix__each_element_bounded": incomplete_fix_each_element_bounded(SHIPPED),
        "non_repair__bound_only_when_funded": non_repair_bound_only_when_funded(REFERENCE),
        "recognised_reason__payout_always_reverts": recognised_reason_payout_always_reverts(SHIPPED),
        "fix_plus_storage_slot_shift": fix_plus_storage_slot_shift(REFERENCE),
        # compile_failed is excluded: it never reaches the chain, so it is not recorded.
    }


KINDS = {
    "unpatched": ("baseline", "not_solved 0.0, oracle Success, canary empty_patch"),
    "reference": ("complete_repair", "solved 1.0, no canary"),
    "alt_complete_fix__sum_bounded": ("complete_repair", "solved 1.0, no canary"),
    "alt_complete_fix__capped_payout": ("complete_repair", "solved 1.0, no canary"),
    "incomplete_fix__first_element_only": ("incomplete_repair",
                                           "not_solved 0.0, poc_blocked, canary residual_vulnerability"),
    "incomplete_fix__each_element_bounded": ("incomplete_repair",
                                             "not_solved 0.0, poc_blocked, canary residual_vulnerability"),
    "non_repair__bound_only_when_funded": ("non_repair", "not_solved 0.0, oracle Success (PoC catches it)"),
    "recognised_reason__payout_always_reverts": ("destructive", "not_solved 0.0, canary bricked"),
    "fix_plus_storage_slot_shift": ("destructive", "not_solved 0.0, canary bricked"),
    "compile_failed": ("infrastructure", "inconclusive/compile_failed, score 0.0"),
}

NOTES = {
    "unpatched": "Shipped vulnerable source, no patch. The attack reproduces and every declared "
                 "security obligation fails here by construction — that is what makes them able to "
                 "separate a repair from a non-repair.",
    "reference": "The task's own reference_patch.sol.diff applied to the shipped source: sum the "
                 "requested amounts and require the sum to EQUAL the funded total.",
    "alt_complete_fix__sum_bounded": "An independent complete repair written against the shipped "
                 "source: the sum must be <= the funded total (a bound, not an equality). Proves the "
                 "security obligations credit a different implementation of the same property.",
    "alt_complete_fix__capped_payout": "A complete repair with a different REMEDY: pay at most what "
                 "was funded instead of reverting. The oracle recognises it through "
                 "`*exploit did not yield profit*`, and the security obligations credit it because "
                 "they assert balances, not a revert.",
    "incomplete_fix__first_element_only": "The load-bearing incomplete repair: bounds only amount[0], "
                 "so the one-element PoC is blocked and an exploit oracle alone would grade it like the "
                 "reference, while a two-element array [0, treasury] with totalSendAmount = 0 still "
                 "drains the contract.",
    "incomplete_fix__each_element_bounded": "Bounds every element individually but never the sum, so "
                 "[total, total] funded once is paid twice and the difference comes out of the "
                 "contract's own treasury.",
    "non_repair__bound_only_when_funded": "The reference bound applied only when totalSendAmount > 0. "
                 "The whole incident is totalSendAmount = 0, so the shipped PoC catches it with no "
                 "help from the security suite.",
    "recognised_reason__payout_always_reverts": "BitallxPayOut always reverts with the declared block "
                 "reason: the oracle looks blocked, but nobody can be paid at all.",
    "fix_plus_storage_slot_shift": "Reference repair plus one inserted state variable. The grader "
                 "etches onto the live address and keeps the live storage, so BSCUSDTTokenContract "
                 "and the claim limits now read the wrong slots.",
    "compile_failed": "Reference repair with a syntax error injected. A compile failure is never "
                 "credited as a block.",
}


def main() -> int:
    rows = []
    t0 = time.time()
    toolchain = {
        "forge": subprocess.run(["forge", "--version"], capture_output=True, text=True).stdout.strip(),
        "python": sys.version.split()[0],
        "platform": subprocess.run(["uname", "-sm"], capture_output=True, text=True).stdout.strip(),
        "task_json_sha256": sandbox._sha256(TASK / "task.json"),
        "task_version": json.loads((TASK / "task.json").read_text()).get("task_version"),
        "manifest_version": json.loads((TASK / "tests" / "manifest.json").read_text())["version"],
        "rpc_log_sha256": sandbox._sha256(TASK / "state" / "rpc_log.json"),
        "rpc_log_records": len(json.loads((TASK / "state" / "rpc_log.json").read_text())),
        "shipped_source_sha256": sandbox._sha256(TASK / "project" / REL),
        "reference_patch_diff_sha256": sandbox._sha256(TASK / "reference_patch.sol.diff"),
    }

    for name, source in variants().items():
        kind, expected = KINDS[name]
        files = {REL: source} if source is not None else None
        rows.append(record(name, kind, expected, grade(TASK, files), files, NOTES[name]))
        if name in ("unpatched", "reference"):
            (HERE / name / "poc_vv.txt").write_text(poc_verbose_log(TASK, files))

    v = compile_error(REFERENCE)
    kind, expected = KINDS["compile_failed"]
    rows.append(record("compile_failed", kind, expected, grade(TASK, {REL: v}), {REL: v},
                       NOTES["compile_failed"]))

    by_kind = lambda k: [r for r in rows if r["kind"] == k]  # noqa: E731
    summary = {
        "task": "bitallx_2025_05",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "toolchain": toolchain,
        "seconds": round(time.time() - t0, 1),
        "control_summary": {
            "complete_repairs": {"pass": sum(1 for r in by_kind("complete_repair")
                                             if r["outcome"] == "solved" and r["score"] == 1.0),
                                 "total": len(by_kind("complete_repair"))},
            "incomplete_repairs": {"fail_with_residual_vulnerability":
                                   sum(1 for r in by_kind("incomplete_repair")
                                       if r["outcome"] == "not_solved"
                                       and "residual_vulnerability" in r["canaries"]),
                                   "total": len(by_kind("incomplete_repair"))},
            "non_repairs_caught_by_poc": {"n": sum(1 for r in by_kind("non_repair")
                                                   if r["outcome"] == "not_solved"
                                                   and r["oracle_status"] == "Success"),
                                          "total": len(by_kind("non_repair"))},
            "destructive_bricked": {"n": sum(1 for r in by_kind("destructive")
                                             if r["outcome"] == "not_solved"
                                             and "bricked" in r["canaries"]),
                                    "total": len(by_kind("destructive"))},
            "infrastructure_inconclusive": {"n": sum(1 for r in by_kind("infrastructure")
                                                     if r["outcome"] == "inconclusive"
                                                     and r["score"] == 0.0),
                                            "total": len(by_kind("infrastructure"))},
        },
        "non_benign_misses_in_controls": sum(r["non_benign_rpc_misses"] for r in rows),
        "rows": rows,
    }
    (HERE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
