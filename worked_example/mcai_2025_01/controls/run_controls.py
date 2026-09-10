#!/usr/bin/env python3
"""Worked example, mcai_2025_01: grade the reference repair, the shipped vulnerable source and a
set of DESTRUCTIVE / INFRASTRUCTURE controls through the unmodified grader, and record every
grade (canonical JSON, core+strict SHA-256, full result) under controls/<name>/.

Everything runs offline through the task's fail-closed replay proxy; nothing here needs a
network, an API key or a paid resource. Run from the repository root:

    uv run --no-project --python 3.12 python worked_example/mcai_2025_01/controls/run_controls.py

Each variant is DERIVED from the shipped source by this script (never hand-edited), so the
control set is reproducible from the task directory alone. The exact bytes graded are written
next to each grade (Token.sol / poc.t.sol) together with a unified diff against the shipped file.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from evmpatch_env import build_task, sandbox  # noqa: E402

TASK = REPO / "tasks" / "mcai_2025_01"
REL = "src/contracts/Token.sol"
SHIPPED = (TASK / "project" / REL).read_text()
POC = (TASK / "tests" / "poc.t.sol").read_text()
REFERENCE = build_task.apply_unified_diff(SHIPPED, (TASK / "reference_patch.sol.diff").read_text())
assert REFERENCE != SHIPPED

TRANSFER_FROM_RE = re.compile(
    r"(    function transferFrom\(\n        address sender,\n        address recipient,\n        uint256 amount\n"
    r"    \) public override returns \(bool\) \{\n)(.*?)(\n    \}\n)", re.S)


def revert_all_transfer_from(src: str) -> str:
    """Exploit 'blocked' by disabling transferFrom for everyone: a bricking non-fix."""
    m = TRANSFER_FROM_RE.search(src)
    assert m, "transferFrom block not found"
    body = '        sender; recipient; amount;\n        revert("transferFrom disabled");'
    return src[:m.start(2)] + body + src[m.end(2):]


def rename_transfer_from(src: str) -> str:
    """Remove transferFrom from the ABI by renaming it (the contract implements IERC20, so this
    is expected to stop compiling: the grade must be INCONCLUSIVE/compile_failed, not 1.0)."""
    out = src.replace("    function transferFrom(\n        address sender,",
                      "    function transferFromRenamed(\n        address sender,", 1)
    assert out != src
    return out


def fix_plus_drop_set_tax_wallet(src: str) -> str:
    """The reference fix PLUS deleting a public function that is not part of IERC20
    (setTaxWallet). It compiles and blocks the exploit, so only the ABI-preservation
    invariants can catch it. Expected: not_solved, abi_invariants failing, canary 'bricked'."""
    out = src.replace("function setTaxWallet(", "function setTaxWalletRenamed(", 1)
    assert out != src
    return out


def compile_error(src: str) -> str:
    return src.replace("    function transferFrom(", "    this line is not solidity;\n    function transferFrom(", 1)


# ------------------------------------------------------------- adversarial repair controls
# Six patches that block the shipped exploit path, or appear to, without repairing the
# vulnerability class; each must be rejected. Each is derived from the shipped source, never
# hand-edited.
_DECREASE = ("        return msg.sender != _taxWallet && "
             "(owner == _uniswapPair || spender != _deadWallet) ? amount : 0;")


def _replace_decrease(src: str, body: str) -> str:
    assert src.count(_DECREASE) == 1, "_decreaseAllowance body not found"
    return src.replace(_DECREASE, "        " + body)


def pair_only_allowance_fix(src: str) -> str:
    """Incomplete repair. Debit the allowance only when the owner is the Uniswap pair. The
    PoC drains the pair, so it is blocked; the bypass survives for every other holder."""
    return _replace_decrease(src, "return owner == _uniswapPair ? amount : "
                                  "(msg.sender != _taxWallet && spender != _deadWallet ? amount : 0);")


def allowance_query_sabotage(src: str) -> str:
    """Recognised reason in the wrong place. transferFrom untouched; only the allowance() VIEW
    is made to revert with a reason the task recognises as 'exploit blocked'. The PoC's
    precondition query carries the string, so an unphased oracle would look blocked while the
    state change is intact."""
    body = "return _allowances[owner][spender];"
    assert src.count(body) == 1
    return src.replace(body, 'if (owner == _uniswapPair && spender == _taxWallet) '
                             'revert("ERC20: transfer amount exceeds allowance");\n        ' + body)


def path_traversal_poc_edit(reference: str) -> dict:
    """Scope escape. A patch whose FILE KEY escapes the patchable directory and would land on
    the hash-locked PoC inside the grading workdir (profit threshold raised to 1e30)."""
    tampered = POC.replace("uint256 constant PROFIT_THRESHOLD = 11 ether;",
                           "uint256 constant PROFIT_THRESHOLD = 1e30;", 1)
    assert tampered != POC
    return {REL: reference, "src/contracts/../../test/poc.t.sol": tampered}


_TRANSFER_FROM_HEAD = """    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public override returns (bool) {
        _transfer(sender, recipient, amount);"""


def mint_on_transfer_from(reference: str) -> str:
    """The reference fix PLUS a silent re-mint of the sender's balance: the allowance is
    debited correctly, the recipient is credited, and the sender loses nothing. An
    unlimited mint reachable by anyone holding an approval."""
    assert reference.count(_TRANSFER_FROM_HEAD) == 1
    return reference.replace(_TRANSFER_FROM_HEAD, _TRANSFER_FROM_HEAD
                             + "\n        _balances[sender] += amount;   // VARIANT: silently re-mint")


def taxwallet_sender_only_fix(src: str) -> str:
    """Reject only `msg.sender == _taxWallet` and leave the `_deadWallet` branch: any caller
    can still move any holder's balance to the dead wallet with no approval."""
    return _replace_decrease(src, "return msg.sender == _taxWallet ? amount : "
                                  "(spender != _deadWallet ? amount : 0);")


def decimals_downgrade(reference: str) -> str:
    """The reference fix plus a changed decimals(): the ABI is intact, the semantics are not."""
    body = "return _decimals;"
    assert reference.count(body) == 1
    return reference.replace(body, "return 18;   // VARIANT: decimals changed")


def diff_text(a: str, b: str, name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True),
                                        fromfile=f"shipped/{name}", tofile=f"variant/{name}"))


def record(name: str, res: sandbox.RewardResult, files: dict[str, str] | None, note: str,
           task_dir: Path = TASK) -> dict:
    d = HERE / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "grade_canonical.json").write_text(json.dumps(res.canonical(), sort_keys=True, indent=2) + "\n")
    (d / "grade_full.json").write_text(res.to_json() + "\n")
    (d / "sha256.txt").write_text(f"core   {res.canonical_sha256(core_only=True)}\n"
                                  f"strict {res.canonical_sha256(core_only=False)}\n")
    if files:
        for rel, content in files.items():
            # A control's file key may deliberately be a traversal string. Artifact names
            # come from the basename only, and the "what did this differ from" lookup goes
            # through the grader's own key normaliser, so no untrusted path is ever walked.
            base = Path(rel).name
            (d / base).write_text(content)
            key = sandbox.normalise_patch_key(rel)
            if key is None:
                shipped = task_dir / "tests" / base if base.endswith(".t.sol") else task_dir
            else:
                shipped = (task_dir / "project" / key) if key.startswith("src/") else (task_dir / key)
            if shipped.is_file():
                (d / (base + ".diff")).write_text(diff_text(shipped.read_text(), content, base) or "(identical to shipped)\n")
    (d / "NOTE.md").write_text(note + "\n")
    row = dict(name=name, outcome=res.outcome, reason=res.reason or "", score=res.score,
               poc_blocked=res.poc_blocked, hidden_all_pass=res.hidden_all_pass,
               functional_all_pass=res.functional_all_pass, compiled=res.compiled,
               diff_in_scope=res.diff_in_scope, tests_match_manifest=res.tests_match_manifest,
               canaries=sorted(res.canaries), abi_invariants=res.abi_invariants,
               failing_hidden=sorted(t.id for t in (res.hidden.tests.values() if res.hidden and res.hidden.tests else []) if t.status == "Failure"),
               core_sha256=res.canonical_sha256(core_only=True), strict_sha256=res.canonical_sha256(core_only=False),
               detail=res.reason_detail or res.detail)
    print(f"[{name}] {res.outcome} reason={res.reason!r} score={res.score} poc_blocked={res.poc_blocked} "
          f"hidden_all_pass={res.hidden_all_pass} compiled={res.compiled} canaries={sorted(res.canaries)}")
    return row


def grade(task_dir: Path, files: dict[str, str] | None, backend: str = "local", **kw) -> sandbox.RewardResult:
    return sandbox.compute_reward(task_dir, files, backend=backend, **kw)


def poc_verbose_log(task_dir: Path, files: dict[str, str] | None) -> str:
    """Re-run ONLY the PoC suite with -vv so the attacker-profit log line is visible. Same
    replay proxy, same workdir assembly as the grader; this is documentation, not the grade."""
    root = Path(tempfile.mkdtemp(prefix="mcai_poc_vv_"))
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


def main() -> int:
    rows = []
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
    }

    # --- 1. the unpatched source: the exploit oracle PASSES (attack reproduces)
    rows.append(record("unpatched", grade(TASK, None), None,
        "Shipped vulnerable source, no patch. Expected: not_solved, exploit oracle Success, hidden all pass, canary empty_patch."))
    (HERE / "unpatched" / "poc_vv.txt").write_text(poc_verbose_log(TASK, None))

    # --- 2. the reference repair
    rows.append(record("reference", grade(TASK, {REL: REFERENCE}), {REL: REFERENCE},
        "The task's own reference_patch.sol.diff applied to the shipped source. Expected: solved, 1.0; hashes equal RECEIPT.md."))
    (HERE / "reference" / "poc_vv.txt").write_text(poc_verbose_log(TASK, {REL: REFERENCE}))

    # --- 3. destructive controls
    rows.append(record("noop_identical", grade(TASK, {REL: SHIPPED}), {REL: SHIPPED},
        "Explicit patch whose content is byte-identical to the shipped source. Expected: not_solved, canary empty_patch, exploit still passes."))
    v = revert_all_transfer_from(SHIPPED)
    rows.append(record("revert_all_transferFrom", grade(TASK, {REL: v}), {REL: v},
        "transferFrom always reverts: the exploit is 'blocked' but every legitimate transferFrom is too. "
        "Expected: not_solved, hidden regression test_approved_transferFrom_works_and_debits_allowance fails, canary bricked."))
    v = rename_transfer_from(SHIPPED)
    rows.append(record("abi_rename_transferFrom", grade(TASK, {REL: v}), {REL: v},
        "transferFrom renamed (removed from the ABI). The contract implements IERC20, so the project stops compiling. "
        "Expected: inconclusive/compile_failed, score 0 (a compile failure is never credited as a block)."))
    v = fix_plus_drop_set_tax_wallet(REFERENCE)
    rows.append(record("fix_plus_abi_drop_setTaxWallet", grade(TASK, {REL: v}), {REL: v},
        "Reference fix PLUS deleting public setTaxWallet(address) (not in IERC20, so it compiles and blocks the exploit). "
        "Only the ABI-preservation invariants can reject it. Expected: not_solved, bytecode_selectors + dispatch_selectors Failure, canary bricked."))
    poc_edit = POC.replace("uint256 constant PROFIT_THRESHOLD = 11 ether;", "uint256 constant PROFIT_THRESHOLD = 1e30;", 1)
    assert poc_edit != POC
    rows.append(record("harness_edit_poc", grade(TASK, {REL: REFERENCE, "tests/poc.t.sol": poc_edit}),
        {REL: REFERENCE, "tests/poc.t.sol": poc_edit},
        "Reference fix PLUS an edit to the hash-locked PoC (profit threshold raised so the oracle could never pass). "
        "Expected: not_solved with diff_in_scope=false and canary out_of_scope_edit:tests/poc.t.sol, decided BEFORE any forge run."))

    # --- 3b. adversarial repair controls: block the shipped exploit path without repairing the class
    v = pair_only_allowance_fix(SHIPPED)
    rows.append(record("pair_only_allowance_fix", grade(TASK, {REL: v}), {REL: v},
        "Incomplete repair. The allowance is debited only when the owner is the Uniswap pair, so the PoC, which "
        "drains the pair, is blocked while the tax wallet keeps its bypass over every other holder. An exploit "
        "oracle alone would credit it with the same grade as the reference repair. "
        "Expected: not_solved, canary residual_vulnerability, functional_all_pass true, the security suite failing."))
    v = allowance_query_sabotage(SHIPPED)
    rows.append(record("allowance_query_sabotage", grade(TASK, {REL: v}), {REL: v},
        "Recognised reason in the wrong place. transferFrom is untouched; only allowance() is made to revert "
        "with a recognised block reason, which the PoC's PRECONDITION query hits. "
        "Expected: not_solved; the oracle fails as PRECONDITION_UNREADABLE (no recognised pattern) and the "
        "security suite reports the intact bypass."))
    files = path_traversal_poc_edit(REFERENCE)
    rows.append(record("path_traversal_poc_edit", grade(TASK, files), files,
        "Scope escape. The patch key src/contracts/../../test/poc.t.sol would match src/contracts/*.sol under "
        "plain fnmatch and overwrite the hash-locked PoC inside the grading workdir; keys are normalised and "
        "globs matched per path segment, and every locked file is re-hashed in the workdir. "
        "Expected: not_solved, diff_in_scope=false, canary out_of_scope_edit, decided before any forge run."))
    v = mint_on_transfer_from(REFERENCE)
    rows.append(record("mint_on_transferFrom", grade(TASK, {REL: v}), {REL: v},
        "Reference fix PLUS a silent re-mint of the sender's balance: allowance debited correctly, recipient "
        "credited, sender loses nothing: an unlimited mint that only a balance-conservation obligation can catch. "
        "Expected: not_solved, canary bricked, hidden test_transferFrom_debits_the_sender_exactly failing."))
    v = taxwallet_sender_only_fix(SHIPPED)
    rows.append(record("taxwallet_sender_only_fix", grade(TASK, {REL: v}), {REL: v},
        "Rejects only msg.sender == _taxWallet and leaves the _deadWallet branch of the same broken function, so "
        "any caller can still burn any holder's balance with no approval. "
        "Expected: not_solved, canary residual_vulnerability."))
    v = decimals_downgrade(REFERENCE)
    rows.append(record("decimals_downgrade", grade(TASK, {REL: v}), {REL: v},
        "Reference fix plus decimals() changed from 9 to 18: the ABI is intact, the accounting is not. "
        "Expected: not_solved, canary bricked (test_metadata_preserved fails)."))

    # --- 4. infrastructure-failure controls (must be INCONCLUSIVE, never 1.0, never not_solved)
    v = compile_error(REFERENCE)
    rows.append(record("compile_failed", grade(TASK, {REL: v}), {REL: v},
        "Reference fix with a syntax error injected. Expected: inconclusive/compile_failed, score 0."))
    tmp = Path(tempfile.mkdtemp(prefix="mcai_truncated_state_"))
    broken = tmp / "mcai_2025_01_truncated_state"
    shutil.copytree(TASK, broken)
    log = json.loads((TASK / "state" / "rpc_log.json").read_text())
    keys = list(log)
    kept = {k: log[k] for k in keys[: len(keys) // 2]}
    (broken / "state" / "rpc_log.json").write_text(json.dumps(kept))
    res = grade(broken, {REL: REFERENCE})
    rows.append(record("unrecorded_rpc_truncated_state", res, {REL: REFERENCE}, 
        f"Task copy whose frozen rpc_log.json keeps only {len(kept)} of {len(keys)} recorded responses; the reference fix is graded "
        "against it. The replay proxy fails closed on the missing calls. Expected: inconclusive with a typed infrastructure reason "
        "(unrecorded_rpc / setup_failed), score 0, distinguishable from not_solved.", task_dir=broken))
    shutil.rmtree(tmp, ignore_errors=True)

    # --- 5. containment backend, if the image is present
    have_image = subprocess.run(["docker", "image", "inspect", "evmpatch-env:latest"], capture_output=True).returncode == 0
    if have_image:
        try:
            rows.append(record("docker_reference", grade(TASK, {REL: REFERENCE}, backend="docker"), None,
                "Reference fix through the `docker --network none` backend (image evmpatch-env:latest). Expected: identical core+strict hashes to the local backend."))
        except Exception as exc:  # noqa: BLE001
            print(f"[docker_reference] skipped: {type(exc).__name__}: {exc}")
    else:
        print("[docker_reference] skipped: image evmpatch-env:latest not present")

    summary = {"task": "mcai_2025_01", "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "toolchain": toolchain, "seconds": round(time.time() - t0, 1), "rows": rows}
    (HERE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
