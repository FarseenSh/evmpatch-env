#!/usr/bin/env python3
"""Worked example, goldreserve_2025_02: grade the reference repair, an ALTERNATIVE complete
repair, the shipped vulnerable source and a set of INCOMPLETE / DESTRUCTIVE / INFRASTRUCTURE
controls through the unmodified grader, and record every grade (canonical JSON, core+strict
SHA-256, full result) under controls/<name>/.

Everything runs offline through the task's fail-closed replay proxy; nothing here needs a
network, an API key or a paid resource. Run from the repository root:

    uv run --no-project --python 3.12 python worked_example/goldreserve_2025_02/controls/run_controls.py

Each variant is DERIVED from the shipped source by this script (never hand-edited), so the
control set is reproducible from the task directory alone. The exact bytes graded are written
next to each grade (Token.sol) together with a unified diff against the shipped file.

Why this set. `incomplete_fix__debt_on_transfer_only` (settle the claim debt on transfers but
not on mints) blocks the shipped PoC, so an exploit oracle alone would grade it exactly like
the reference repair. tests/hidden/security.t.sol, listed in the manifest under
`hidden.security_tests`, states the vulnerability class, so incomplete repairs score 0.0 with
canary `residual_vulnerability` while complete repairs with other implementations score 1.0.
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

TASK = REPO / "tasks" / "goldreserve_2025_02"
REL = "src/contracts/Token.sol"
SHIPPED = (TASK / "project" / REL).read_text()
REFERENCE = build_task.apply_unified_diff(SHIPPED, (TASK / "reference_patch.sol.diff").read_text())
assert REFERENCE != SHIPPED

# The reference patch inserts its _update() override immediately before this member; every
# alternative repair and every adversarial _update variant below is inserted at the same anchor,
# so the controls differ from the reference only in the repair itself.
_ANCHOR = "    function _balanceOfAllNFTs(address account) internal view returns (uint256) {"
_CLAIM_HEAD = "    function claimProfit() external nonReentrant {\n"
_TO_CLAIM = ("        uint256 toClaim = totalEntitlement - claimedProfitPerAddress[msg.sender];\n"
             '        require(toClaim > 0, "Nada a reclamar");\n')
_BASE_URI = '    string public baseURI = "https://bafybeifdufm6dv3unfkamcqyletrs4mogtiyft43lybqmfawv6uolayw2u.ipfs.dweb.link/";\n'


def _insert_update(src: str, body: str, tag: str) -> str:
    """Insert an _update(address,address,uint256[],uint256[]) override at the reference's anchor."""
    assert src.count(_ANCHOR) == 1, "the _balanceOfAllNFTs anchor moved"
    override = (f"    // {tag}\n"
                "    function _update(\n"
                "        address from,\n"
                "        address to,\n"
                "        uint256[] memory ids,\n"
                "        uint256[] memory values\n"
                "    ) internal virtual override {\n"
                f"{body}"
                "    }\n\n")
    return src.replace(_ANCHOR, override + _ANCHOR)


_MOVED = ("        uint256 moved = 0;\n"
          "        for (uint256 i = 0; i < values.length; i++) {\n"
          "            moved += values[i];\n"
          "        }\n")
_SETTLE = ("            uint256 debt = (moved * accumulatedProfitPerNFT) / 1e18;\n"
           "            if (to != address(0)) {\n"
           "                claimedProfitPerAddress[to] += debt;\n"
           "            }\n"
           "            if (from != address(0)) {\n"
           "                uint256 owed = claimedProfitPerAddress[from];\n"
           "                claimedProfitPerAddress[from] = owed > debt ? owed - debt : 0;\n"
           "            }\n")


# ------------------------------------------------------------------ COMPLETE repairs
def alt_settle_before_super(src: str) -> str:
    """ALTERNATIVE COMPLETE REPAIR #1. Same ledger as the reference, written the other way
    round: the debt is settled BEFORE super._update() rather than after, and the early
    `return` is replaced by a guard so a zero-value transfer still reaches super. A repair
    is not required to be byte-identical to the reference to be correct, and the grader must
    credit this one."""
    body = (_MOVED
            + "        if (moved > 0) {\n" + _SETTLE + "        }\n"
            + "        super._update(from, to, ids, values);\n")
    return _insert_update(src, body, "ALTERNATIVE COMPLETE REPAIR: settle the debt, then call super.")


def alt_separate_debt_mapping(src: str) -> str:
    """ALTERNATIVE COMPLETE REPAIR #2, a genuinely different implementation: the debt is
    carried in a NEW internal mapping instead of being folded into claimedProfitPerAddress,
    and claimProfit() subtracts both. The public `claimedProfitPerAddress(address)` getter —
    and therefore the ABI — is untouched, and the new slot is appended after every existing
    state variable so the fork's storage layout is preserved under vm.etch."""
    assert src.count(_BASE_URI) == 1, "the baseURI declaration moved"
    out = src.replace(_BASE_URI, _BASE_URI
                      + "\n    // ALTERNATIVE COMPLETE REPAIR: profit that accrued before the caller held\n"
                        "    // the token, carried with the token instead of with the address.\n"
                        "    mapping(address => uint256) internal _profitDebt;\n")
    body = (_MOVED
            + "        if (moved > 0) {\n"
              "            uint256 debt = (moved * accumulatedProfitPerNFT) / 1e18;\n"
              "            if (to != address(0)) {\n"
              "                _profitDebt[to] += debt;\n"
              "            }\n"
              "            if (from != address(0)) {\n"
              "                uint256 owed = _profitDebt[from];\n"
              "                _profitDebt[from] = owed > debt ? owed - debt : 0;\n"
              "            }\n"
              "        }\n"
              "        super._update(from, to, ids, values);\n")
    out = _insert_update(out, body, "ALTERNATIVE COMPLETE REPAIR: a separate debt ledger.")
    assert out.count(_TO_CLAIM) == 1, "the claimProfit entitlement arithmetic moved"
    return out.replace(_TO_CLAIM,
                       "        uint256 settled = claimedProfitPerAddress[msg.sender] + _profitDebt[msg.sender];\n"
                       "        uint256 toClaim = totalEntitlement > settled ? totalEntitlement - settled : 0;\n"
                       '        require(toClaim > 0, "Nada a reclamar");\n')


# ---------------------------------------------------------------- INCOMPLETE repairs
def debt_on_transfer_only(ref: str) -> str:
    """Incomplete repair, the load-bearing one. Settle the claim debt on transfers but not on
    mints, so a freshly minted NFT still inherits every unit of profit accrued before it
    existed. It blocks the shipped PoC, so an exploit oracle alone would grade it like the
    reference repair."""
    anchor = "        if (moved == 0) {\n            return;\n        }\n"
    assert ref.count(anchor) == 1
    return ref.replace(anchor, anchor + "        if (from == address(0)) {\n"
                                        "            return;   // VARIANT: mints inherit accrued profit\n"
                                        "        }\n")


def debt_on_mint_only(ref: str) -> str:
    """The other half of the same incomplete class: settle on MINTS but not on transfers.
    This one blocks the PoC at its very first claim (the eight NFTs are minted after the
    deposit, so they now inherit nothing), while the address-hopping half of the
    vulnerability — the step the incident repeated 22 times — is untouched."""
    anchor = "        if (moved == 0) {\n            return;\n        }\n"
    assert ref.count(anchor) == 1
    return ref.replace(anchor, anchor + "        if (from != address(0)) {\n"
                                        "            return;   // VARIANT: transfers keep resetting the debt\n"
                                        "        }\n")


# -------------------------------------------------------------------- NON-repair
def settle_on_burn_only(src: str) -> str:
    """A non-repair that LOOKS like the fix: an _update override that settles the debt only
    when the tokens are burned. Neither half of the vulnerability is touched, so the PoC
    still drains the contract and the exploit oracle simply passes."""
    body = ("        super._update(from, to, ids, values);\n\n"
            "        if (to != address(0)) {\n"
            "            return;   // VARIANT: only burns settle, so nothing real is settled\n"
            "        }\n"
            + _MOVED
            + "        if (moved > 0) {\n"
              "            uint256 debt = (moved * accumulatedProfitPerNFT) / 1e18;\n"
              "            if (from != address(0)) {\n"
              "                uint256 owed = claimedProfitPerAddress[from];\n"
              "                claimedProfitPerAddress[from] = owed > debt ? owed - debt : 0;\n"
              "            }\n"
              "        }\n")
    return _insert_update(src, body, "NON-REPAIR: settlement on burns only.")


# ------------------------------------------------------------------- DESTRUCTIVE
def claim_always_reverts(src: str) -> str:
    """RECOGNISED REASON IN THE WRONG PLACE. claimProfit() always reverts with the string
    the task declares as 'exploit blocked'."""
    assert src.count(_CLAIM_HEAD) == 1
    return src.replace(_CLAIM_HEAD, _CLAIM_HEAD + '        revert("Nada a reclamar");   // VARIANT\n')


def fix_plus_abi_drop_set_mint_price(ref: str) -> str:
    """The reference fix PLUS deleting a public function that no interface requires
    (setMintPrice). It compiles and it blocks the exploit, so only the ABI-preservation
    invariants can catch it."""
    out = ref.replace("    function setMintPrice(uint256 newPrice) external onlyOwner {",
                      "    function setMintPriceRenamed(uint256 newPrice) external onlyOwner {", 1)
    assert out != ref
    return out


def compile_error(ref: str) -> str:
    out = ref.replace("    function claimProfit() external nonReentrant {",
                      "    this line is not solidity;\n    function claimProfit() external nonReentrant {", 1)
    assert out != ref
    return out


# --------------------------------------------------------------------------- plumbing
def diff_text(a: str, b: str, name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True),
                                        fromfile=f"shipped/{name}", tofile=f"variant/{name}"))


def record(name: str, res: sandbox.RewardResult, files: dict[str, str] | None, note: str,
           kind: str, expected: str, seconds: float, task_dir: Path = TASK) -> dict:
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
            shipped = (task_dir / "project" / key) if key and key.startswith("src/") else None
            if shipped and shipped.is_file():
                (d / (base + ".diff")).write_text(
                    diff_text(shipped.read_text(), content, base) or "(identical to shipped)\n")
    (d / "NOTE.md").write_text(f"# {name}\n\n**kind:** {kind}\n\n**expected:** {expected}\n\n{note}\n")
    row = dict(name=name, kind=kind, expected=expected, outcome=res.outcome,
               reason=res.reason or "", score=res.score, poc_blocked=res.poc_blocked,
               hidden_all_pass=res.hidden_all_pass, functional_all_pass=res.functional_all_pass,
               compiled=res.compiled, diff_in_scope=res.diff_in_scope,
               tests_match_manifest=res.tests_match_manifest, canaries=sorted(res.canaries),
               abi_invariants=res.abi_invariants,
               failing_hidden=sorted(t.id for t in (res.hidden.tests.values() if res.hidden and res.hidden.tests else []) if t.status != "Success"),
               oracle_status=(res.poc.tests.get(ORACLE).status if res.poc and res.poc.tests.get(ORACLE) else None),
               oracle_reason=(res.poc.tests.get(ORACLE).reason if res.poc and res.poc.tests.get(ORACLE) else None),
               core_sha256=res.canonical_sha256(core_only=True),
               strict_sha256=res.canonical_sha256(core_only=False),
               seconds=round(seconds, 1), detail=res.reason_detail or "")
    print(f"[{name}] {res.outcome} score={res.score} poc_blocked={res.poc_blocked} "
          f"functional_all_pass={res.functional_all_pass} canaries={sorted(res.canaries)} "
          f"oracle={row['oracle_reason']!r}")
    return row


ORACLE = "test/poc.t.sol:GoldReserve_PoC:testExploit()"


def grade(files: dict[str, str] | None, task_dir: Path = TASK, backend: str = "local"):
    started = time.monotonic()
    res = sandbox.compute_reward(task_dir, files, backend=backend)
    return res, time.monotonic() - started


# The control set, as data: (name, kind, expected, source, note).
def cases() -> list[tuple]:
    return [
        ("unpatched", "baseline", "not_solved 0.0, oracle Success, canary empty_patch", None,
         "The shipped vulnerable source, no patch. The PoC reproduces the incident: 120 BNB is "
         "flash-borrowed, deposited as profit, eight NFTs are minted that instantly 'own' it, and "
         "the same NFTs are walked through 22 addresses claiming each time."),
        ("noop_identical", "baseline", "not_solved 0.0, oracle Success, canary empty_patch", SHIPPED,
         "An explicit patch whose content is byte-identical to the shipped source."),
        ("reference", "complete_repair", "solved 1.0", REFERENCE,
         "The task's own reference_patch.sol.diff: the claim debt is settled in _update() for "
         "mints and transfers alike, after super._update()."),
        ("alt_settle_before_super", "complete_repair", "solved 1.0", alt_settle_before_super(SHIPPED),
         "A complete repair with a different implementation: the same settlement placed BEFORE "
         "super._update(), with a guard instead of an early return. A correct repair that is not "
         "the reference must still be credited."),
        ("alt_separate_debt_mapping", "complete_repair", "solved 1.0", alt_separate_debt_mapping(SHIPPED),
         "A complete repair that keeps the debt in a NEW internal mapping and subtracts it in "
         "claimProfit(), instead of folding it into claimedProfitPerAddress. Different storage, "
         "different arithmetic, same property; the public ABI is unchanged."),
        ("incomplete_fix__debt_on_transfer_only", "incomplete_repair",
         "not_solved 0.0, canary residual_vulnerability, PoC blocked", debt_on_transfer_only(REFERENCE),
         "The load-bearing incomplete repair: settles on transfers but not on mints, so the PoC is "
         "blocked and an exploit oracle alone would grade it like the reference, while the "
         "mint-inheritance half of the vulnerability survives, the half the incident used first."),
        ("incomplete_fix__debt_on_mint_only", "incomplete_repair",
         "not_solved 0.0, canary residual_vulnerability, PoC blocked", debt_on_mint_only(REFERENCE),
         "The mirror-image incomplete repair: settles on mints but not on transfers. It blocks the "
         "PoC at its first claim, so the exploit oracle alone would credit it, while the "
         "address-hopping half the incident repeated 22 times is untouched."),
        ("non_repair__settle_on_burn_only", "non_repair", "not_solved 0.0, oracle Success",
         settle_on_burn_only(SHIPPED),
         "A patch shaped like the fix that settles the debt only on burns. Neither half of the "
         "vulnerability is touched, so the PoC itself still catches it."),
        ("recognised_reason__claim_always_reverts", "destructive",
         "not_solved 0.0, canary bricked", claim_always_reverts(SHIPPED),
         "RECOGNISED REASON IN THE WRONG PLACE: claimProfit() always reverts with 'Nada a reclamar', "
         "a string the task declares as 'exploit blocked'. Nobody can ever be paid, which is what "
         "the contract exists for, so the legitimate-use regression rejects it."),
        ("fix_plus_abi_drop_setMintPrice", "destructive", "not_solved 0.0, canary bricked",
         fix_plus_abi_drop_set_mint_price(REFERENCE),
         "The reference fix PLUS renaming public setMintPrice(uint256), which no interface requires, "
         "so it compiles and blocks the exploit. Only the ABI-preservation invariants can reject it."),
        ("compile_failed", "infrastructure", "inconclusive/compile_failed, score 0",
         compile_error(REFERENCE),
         "The reference fix with a syntax error injected. A compile failure is never credited as a "
         "block; it must be inconclusive with a typed reason, never 1.0 and never not_solved."),
    ]


def main() -> int:
    t0 = time.time()
    toolchain = {
        "forge": subprocess.run(["forge", "--version"], capture_output=True, text=True).stdout.strip().splitlines()[0],
        "python": sys.version.split()[0],
        "platform": subprocess.run(["uname", "-sm"], capture_output=True, text=True).stdout.strip(),
        "task_json_sha256": sandbox._sha256(TASK / "task.json"),
        "rpc_log_sha256": sandbox._sha256(TASK / "state" / "rpc_log.json"),
        "rpc_log_records": len(json.loads((TASK / "state" / "rpc_log.json").read_text())),
        "shipped_source_sha256": sandbox._sha256(TASK / "project" / REL),
        "reference_patch_diff_sha256": sandbox._sha256(TASK / "reference_patch.sol.diff"),
        "security_tests_sha256": sandbox._sha256(TASK / "tests" / "hidden" / "security.t.sol"),
    }
    rows = []
    for name, kind, expected, source, note in cases():
        files = {REL: source} if source is not None else None
        res, seconds = grade(files)
        rows.append(record(name, res, files, note, kind, expected, seconds))

    summary = {"task": "goldreserve_2025_02",
               "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "toolchain": toolchain, "seconds": round(time.time() - t0, 1), "rows": rows}
    (HERE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
