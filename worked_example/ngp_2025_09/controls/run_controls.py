#!/usr/bin/env python3
"""Worked example, ngp_2025_09: grade the reference repair, an ALTERNATIVE complete repair, the
shipped vulnerable source and a set of INCOMPLETE / NON-REPAIR / DESTRUCTIVE / INFRASTRUCTURE
controls through the unmodified grader, and record every grade (canonical JSON, core+strict
SHA-256, full result) under controls/<name>/.

Everything runs offline through the task's fail-closed replay proxy; nothing here needs a
network, an API key or a paid resource. Run from the repository root:

    uv run --no-project --python 3.12 python worked_example/ngp_2025_09/controls/run_controls.py

Add `--repeat 2` to run the whole set twice and write determinism.json (every control's core
sha256 must be identical between runs).

Each variant is DERIVED from the shipped source by this script (never hand-edited), so the
control set is reproducible from the task directory alone. The exact bytes graded are written
next to each grade (Token.sol) together with a unified diff against the shipped file.

Why this set. The exploit needs both halves of the bug, so a patch that deletes only the
mid-transfer `pair.sync()` and keeps the mid-transfer drain of the pair into the treasury and
reward addresses (`incomplete_fix__sync_only_removed`) blocks the shipped PoC; an exploit
oracle alone would grade it exactly like the reference repair. tests/hidden/security.t.sol
(four obligations, listed in the manifest under `hidden.security_tests`) states the
vulnerability class, so an incomplete repair scores 0.0 with canary `residual_vulnerability`
while the two complete repairs below still score 1.0.
"""
from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from evmpatch_env import build_task, sandbox  # noqa: E402

TASK = REPO / "tasks" / "ngp_2025_09"
REL = "src/contracts/Token.sol"
SHIPPED = (TASK / "project" / REL).read_text()
REFERENCE = build_task.apply_unified_diff(SHIPPED, (TASK / "reference_patch.sol.diff").read_text())
assert REFERENCE != SHIPPED

# The vulnerable block, verbatim from the shipped source: the treasury and reward fees on a
# sell are moved OUT OF THE PAIR inside the seller's own transfer, and `sync()` then re-prices
# the reserves against the balance that drain just created.
DRAIN_BLOCK = """            uint poolAmount = this.balanceOf(mainPair);
            if (poolAmount > burnPoolAmount) {
                // treasury pool
                super._update(mainPair, treasuryAddress, treasuryAmount);
                // reward pool
                super._update(mainPair, rewardPoolAddress, rewardAmount);
                IUniswapV2Pair(mainPair).sync();
            }
"""
SYNC_LINE = "                IUniswapV2Pair(mainPair).sync();\n"
VALUE_LINE = "            value = value - totalFee;\n"


# ----------------------------------------------------------------- complete repairs
def alt_fix_fees_charged_to_seller(src: str) -> str:
    """ALTERNATIVE COMPLETE REPAIR, different implementation from the reference. The treasury
    and reward fees are still collected — they are simply charged to the SELLER like the market
    and burn fees already are, instead of being pulled out of the pair. Nothing leaves the pool
    inside someone else's transfer, so no mid-transfer `sync()` is needed and the AMM invariant
    holds. Must grade `solved` 1.0: a verifier that only accepted the reference's shape would be
    rewarding one implementation rather than the repair."""
    assert src.count(DRAIN_BLOCK) == 1, "drain block not found"
    assert src.count(VALUE_LINE) == 1, "fee subtraction not found"
    out = src.replace(DRAIN_BLOCK,
                      "            // ALT FIX: the treasury and reward fees are taken from the SELLER,\n"
                      "            // never out of the pair, so the pool is never debited mid-transfer\n"
                      "            // and no sync() is needed.\n"
                      "            super._update(from, treasuryAddress, treasuryAmount);\n"
                      "            super._update(from, rewardPoolAddress, rewardAmount);\n")
    return out.replace(VALUE_LINE, "            value = value - totalFee - burnPoolAmount;\n")


# --------------------------------------------------------------- incomplete repairs
def incomplete_fix_sync_only_removed(src: str) -> str:
    """Incomplete repair, the load-bearing one. Delete only the mid-transfer
    `IUniswapV2Pair(mainPair).sync()` and keep the mid-transfer drain of the pair into the
    treasury and reward addresses. The PoC's re-pricing needs the sync, so the PoC is blocked
    and an exploit oracle alone would grade this like the reference repair; a seller still
    empties the pair inside their own transfer, which IS the declared class."""
    assert src.count(SYNC_LINE) == 1
    return src.replace(SYNC_LINE, "                // VARIANT: sync removed, pool drain kept\n")


def incomplete_fix_drain_capped(src: str) -> str:
    """A SECOND incomplete repair of the same class: the mid-transfer re-price is gone and the
    drain is bounded to 1% of the pool per sell — the shape of "make the bug un-exploitable
    rather than remove it". The cap never binds on an ordinary trade (1% of ~46M NGP against a
    fee on a ~500 NGP sell), so an ordinary seller still pays the treasury and the reward pool
    OUT OF THE PAIR. Must grade `not_solved` with canary `residual_vulnerability`."""
    assert src.count(DRAIN_BLOCK) == 1
    return src.replace(DRAIN_BLOCK,
                       "            uint poolAmount = this.balanceOf(mainPair);\n"
                       "            if (poolAmount > burnPoolAmount) {\n"
                       "                // VARIANT: drain bounded and sync removed; the pair is still debited.\n"
                       "                uint256 drainCap = poolAmount / 100;\n"
                       "                if (treasuryAmount > drainCap) treasuryAmount = drainCap;\n"
                       "                if (rewardAmount > drainCap) rewardAmount = drainCap;\n"
                       "                super._update(mainPair, treasuryAddress, treasuryAmount);\n"
                       "                super._update(mainPair, rewardPoolAddress, rewardAmount);\n"
                       "            }\n")


# ------------------------------------------------------------------- non-repairs
def non_repair_cosmetic_rename(src: str) -> str:
    """A source change with no semantic effect: the local `poolAmount` is renamed. The exploit
    still works, so the PoC oracle itself catches it. Expected: not_solved, oracle Success."""
    assert src.count("uint poolAmount = this.balanceOf(mainPair);") == 1
    assert src.count("if (poolAmount > burnPoolAmount) {") == 1
    return (src.replace("uint poolAmount = this.balanceOf(mainPair);",
                        "uint pairTokenBalance = this.balanceOf(mainPair);   // renamed, nothing else")
               .replace("if (poolAmount > burnPoolAmount) {",
                        "if (pairTokenBalance > burnPoolAmount) {"))


# ------------------------------------------------------------------- destructive
def recognised_reason_approve_reverts(src: str) -> str:
    """RECOGNISED REASON IN THE WRONG PLACE. `approve` reverts with a string the task declares
    as 'exploit blocked'; the PoC calls approve inside its flash-loan callback. Caught because
    the AMM round-trip regression fails too: canary `bricked`."""
    anchor = "contract Token is ERC20, TokenAccessControl {"
    assert src.count(anchor) == 1
    return src.replace(anchor, anchor + """
    function approve(address spender, uint256 value) public override returns (bool) {
        spender; value;
        revert("BEP20: transfer amount exceeds balance");   // VARIANT
    }
""")


def fix_plus_sell_path_disabled(reference: str) -> str:
    """The reference repair PLUS closing the sell side outright: 'fix' the AMM bug by making
    every sell revert. `sellState` is left true in storage so the flags invariant still passes;
    only the round-trip regression can catch it. Expected: not_solved, canary `bricked`."""
    anchor = '            require(sellState, "Sell not allowed");\n'
    assert reference.count(anchor) == 1
    return reference.replace(anchor, '            require(false, "Sell not allowed");   // VARIANT\n')


# ---------------------------------------------------------------- infrastructure
def compile_error(reference: str) -> str:
    anchor = "    function _update(\n"
    assert reference.count(anchor) == 1
    return reference.replace(anchor, "    this line is not solidity;\n" + anchor)


# Every graded source, by control name. `None` means "no patch at all" (the shipped source).
VARIANT_SOURCES: dict[str, str | None] = {
    "unpatched": None,
    "reference": REFERENCE,
    "alt_fix__fees_charged_to_seller": alt_fix_fees_charged_to_seller(SHIPPED),
    "incomplete_fix__sync_only_removed": incomplete_fix_sync_only_removed(SHIPPED),
    "incomplete_fix__drain_capped": incomplete_fix_drain_capped(SHIPPED),
    "non_repair__cosmetic_rename": non_repair_cosmetic_rename(SHIPPED),
    "noop_identical": SHIPPED,
    "recognised_reason__approve_reverts": recognised_reason_approve_reverts(SHIPPED),
    "fix_plus_sell_path_disabled": fix_plus_sell_path_disabled(REFERENCE),
    "compile_failed": compile_error(REFERENCE),
}

# kind, the grade this control is asserted to produce, and why it is in the set.
CONTROLS: list[tuple[str, str, str, str]] = [
    ("unpatched", "baseline", "not_solved / oracle Success / canary empty_patch",
     "Shipped vulnerable source, no patch. The exploit must still reproduce, every "
     "legitimate-use hidden test must pass, and every declared security obligation must FAIL "
     "(that is what makes them able to separate a repair from a non-repair)."),
    ("reference", "complete_repair", "solved 1.0",
     "The task's own reference_patch.sol.diff: the mid-transfer drain and sync are removed and "
     "the seller-side market and burn fees stay. Must score 1.0."),
    ("alt_fix__fees_charged_to_seller", "complete_repair", "solved 1.0",
     "A DIFFERENT complete repair: the treasury and reward fees are charged to the seller "
     "instead of being pulled out of the pair. Proves the security obligations state the CLASS "
     "and do not merely fingerprint the reference implementation."),
    ("incomplete_fix__sync_only_removed", "incomplete_repair",
     "not_solved 0.0 / poc_blocked / canary residual_vulnerability",
     "The load-bearing incomplete repair: only the mid-transfer sync() is deleted, so the PoC "
     "is blocked and an exploit oracle alone would grade it like the reference, while the pair "
     "is still drained inside a seller's own transfer."),
    ("incomplete_fix__drain_capped", "incomplete_repair",
     "not_solved 0.0 / poc_blocked / canary residual_vulnerability",
     "A second incomplete repair of the same class: the drain is bounded to 1% of the pool and "
     "the sync is removed. The cap never binds on an ordinary trade, so the pair is still the "
     "source of the treasury and reward fees."),
    ("non_repair__cosmetic_rename", "non_repair", "not_solved 0.0 / oracle Success",
     "A source change with no semantic effect. The PoC itself is the control here: the exploit "
     "still succeeds, so no security obligation is needed to reject it."),
    ("noop_identical", "non_repair", "not_solved 0.0 / canary empty_patch",
     "An explicit patch byte-identical to the shipped source. Must be rejected as vacuous "
     "before it can be credited for 'blocking' anything."),
    ("recognised_reason__approve_reverts", "destructive", "not_solved 0.0 / canary bricked",
     "approve() reverts with a string the task lists in "
     "recognised_block_reasons, and the PoC calls approve inside its flash-loan callback. The "
     "AMM round-trip regression fails too, so this reads as a broken contract, not a repair."),
    ("fix_plus_sell_path_disabled", "destructive", "not_solved 0.0 / canary bricked",
     "The reference repair plus closing the sell side outright — 'fix' the AMM bug by making "
     "every sell revert, with sellState left true so the flags invariant still passes."),
    ("compile_failed", "infrastructure", "inconclusive / compile_failed / score 0",
     "The reference repair with a syntax error injected. An infrastructure fault must never be "
     "credited as a block and must never score 1.0."),
]


def diff_text(a: str, b: str, name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True),
                                        fromfile=f"shipped/{name}", tofile=f"variant/{name}"))


def record(name: str, res: sandbox.RewardResult, source: str | None, kind: str,
           expected: str, note: str) -> dict:
    d = HERE / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "grade_canonical.json").write_text(json.dumps(res.canonical(), sort_keys=True, indent=2) + "\n")
    (d / "grade_full.json").write_text(res.to_json() + "\n")
    (d / "sha256.txt").write_text(f"core   {res.canonical_sha256(core_only=True)}\n"
                                  f"strict {res.canonical_sha256(core_only=False)}\n")
    if source is not None:
        (d / "Token.sol").write_text(source)
        (d / "Token.sol.diff").write_text(diff_text(SHIPPED, source, "Token.sol")
                                          or "(identical to shipped)\n")
    (d / "NOTE.md").write_text(f"# {name}\n\n**kind:** {kind}\n\n**expected:** {expected}\n\n{note}\n")
    failing = sorted(t.id for t in (res.hidden.tests.values() if res.hidden and res.hidden.tests else [])
                     if t.status != "Success")
    manifest = sandbox.load_manifest(TASK) or {}
    oracle_id = manifest.get("poc", {}).get("exploit_oracle")
    oracle = res.poc.tests.get(oracle_id) if (res.poc and res.poc.tests) else None
    row = dict(name=name, kind=kind, expected=expected, outcome=res.outcome,
               reason=res.reason or "", score=res.score, poc_blocked=res.poc_blocked,
               hidden_all_pass=res.hidden_all_pass, functional_all_pass=res.functional_all_pass,
               compiled=res.compiled, diff_in_scope=res.diff_in_scope,
               tests_match_manifest=res.tests_match_manifest, canaries=sorted(res.canaries),
               abi_invariants=res.abi_invariants, failing_hidden=failing,
               oracle_status=oracle.status if oracle else None,
               oracle_reason=oracle.reason if oracle else None,
               core_sha256=res.canonical_sha256(core_only=True),
               strict_sha256=res.canonical_sha256(core_only=False),
               detail=res.reason_detail or res.detail)
    print(f"[{name}] {res.outcome} reason={res.reason!r} score={res.score} "
          f"poc_blocked={res.poc_blocked} functional_all_pass={res.functional_all_pass} "
          f"canaries={sorted(res.canaries)} oracle={oracle.status if oracle else None}/"
          f"{oracle.reason if oracle else None!r}", flush=True)
    return row


def grade_all() -> list[dict]:
    rows = []
    for name, kind, expected, note in CONTROLS:
        source = VARIANT_SOURCES[name]
        started = time.monotonic()
        res = sandbox.compute_reward(TASK, {REL: source} if source is not None else None,
                                     backend="local")
        row = record(name, res, source, kind, expected, note)
        row["seconds"] = round(time.monotonic() - started, 1)
        rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=1,
                    help="run the whole control set N times and write determinism.json")
    args = ap.parse_args()

    t0 = time.time()
    toolchain = {
        "forge": subprocess.run(["forge", "--version"], capture_output=True, text=True).stdout.strip(),
        "python": sys.version.split()[0],
        "platform": subprocess.run(["uname", "-sm"], capture_output=True, text=True).stdout.strip(),
        "task_json_sha256": sandbox._sha256(TASK / "task.json"),
        "rpc_log_sha256": sandbox._sha256(TASK / "state" / "rpc_log.json"),
        "rpc_log_records": len(json.loads((TASK / "state" / "rpc_log.json").read_text())),
        "shipped_source_sha256": sandbox._sha256(TASK / "project" / REL),
        "reference_patch_diff_sha256": sandbox._sha256(TASK / "reference_patch.sol.diff"),
        "security_suite_sha256": sandbox._sha256(TASK / "tests" / "hidden" / "security.t.sol"),
    }

    runs = [grade_all() for _ in range(max(1, args.repeat))]
    rows = runs[-1]
    if len(runs) > 1:
        per_run = [{r["name"]: r["core_sha256"] for r in run} for run in runs]
        identical = all(h == per_run[0] for h in per_run[1:])
        (HERE / "determinism.json").write_text(json.dumps(
            {"runs": len(runs), "all_core_hashes_identical": identical,
             "core_sha256_by_run": per_run}, indent=2, sort_keys=True) + "\n")
        print(f"determinism: {len(runs)} runs, all core hashes identical = {identical}")

    summary = {"task": "ngp_2025_09",
               "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "toolchain": toolchain, "seconds": round(time.time() - t0, 1), "rows": rows}
    (HERE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
