# Worked example: `mcai_2025_01`, MCAI allowance bypass, Ethereum mainnet (January 2025)

One real incident, graded end to end by the frozen verifier with no network. Everything on
this page is produced by [`controls/run_controls.py`](controls/run_controls.py) from the
shipped task directory: the exact bytes graded, the canonical grade JSON and the core/strict
SHA-256 of every variant are under [`controls/`](controls/), and
[`controls/summary.json`](controls/summary.json) is the machine-readable ledger. Nothing here
is a model judgement. The task is at `task_version` 2: the harness carries hidden security
obligations, a phased proof of concept, and per-episode re-verification of the hash locks
inside the assembled workdir.

## 1. Frozen source and state

| Item | Value |
|---|---|
| Incident | MCAI tax wallet drained the Uniswap V2 pair by calling `transferFrom` with no allowance ([DeFiHackLabs `src/test/2025-01/MCAI_exp.sol`](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/MCAI_exp.sol)) |
| Chain / fork block | Ethereum mainnet (chain id 1), block **21,720,380** (2025-01-28T03:36:35Z, pre-attack) |
| Victim | `0x810B5902CB2ac2Fa63dFE4A6935EA32aED975cc8` (`src/contracts/Token.sol:MCAI`, 402 lines, verified source) |
| Vulnerability class | broken access control: allowance bypass in `transferFrom` |
| Patchable | `src/contracts/*.sol` only (`patchable_globs`); every other file is harness |
| Frozen chain state | `state/rpc_log.json`, **134 recorded JSON-RPC responses**, 243,460 bytes, sha256 `70a9702e329e1bab56128a0eb5b6e905f8367dde4487ecff7d7e5504e353bbaf`; the superset of every read the PoC, the hidden suites and the graded controls make, with zero non-benign misses offline |
| Shipped vulnerable source | sha256 `8c3bf6647112d88d19970a09c1b86f8a5947bd1d59335ec570b0fbe307a2ea53` |
| Reference patch | `reference_patch.sol.diff`, sha256 `5233375122066b78e679984c353349041f4207e167957cb11ead20fe50e2c4dd` (never shown to an agent) |
| `task.json` | `task_version` 2, split `train`, `date_month` 2025-01, episode budget 30; the current hash locks are recorded in `controls/summary.json` |
| Hash-locked harness | `tests/poc.t.sol`, `tests/hidden/invariants_auto.t.sol`, `tests/hidden/regression.t.sol`, `tests/hidden/security.t.sol`, `tests/manifest.json`, `project/foundry.toml`, `project/remappings.txt`: seven locks, verified before every run and re-verified **inside the episode workdir** after the patch is applied (section 5b) |
| Compiler | `foundry.toml` pins solc **0.8.26**, EVM `cancun`, optimizer off |

How the state stays frozen: every `forge` invocation runs with `FOUNDRY_OFFLINE=true` and
`FOUNDRY_NO_STORAGE_CACHING=true`, and its `TASK_FORK_URL` is a loopback record/replay proxy
(`evmpatch_env/rpc_replay.py`) that answers only `(method, params)` pairs present in
`rpc_log.json`. Any other request is refused and written to a miss file; the grader reads that
file and returns `inconclusive / unrecorded_rpc` rather than a score (section 6 shows this
firing). The host's global Foundry RPC cache is never consulted, which is what lets two
machines produce the same grade bytes.

## 2. Original attack, reproduced offline

`transferFrom()` moves the tokens first and only then debits the allowance, and the amount it
debits comes from `_decreaseAllowance()`, which returns **0 whenever `msg.sender` is the tax
wallet**. So the tax wallet could pull any holder's balance with no approval. The PoC (adapted
from DeFiHackLabs, hash-locked in `tests/poc.t.sol`) does exactly what the attacker did: the
tax wallet `transferFrom`s 99.99 % of the pair's MCAI to an exploit contract, `sync()`s the pair
at the tiny remaining reserve, and sells the drained supply for ETH through the real router.

Grade of the shipped source (no patch), `controls/unpatched/`:

| Field | Value |
|---|---|
| outcome / score | **`not_solved` / 0.0** |
| exploit oracle `test/poc.t.sol:MCAI_PoC:testExploit()` | **Success** (the attack reproduces) |
| attacker profit logged by the PoC (`controls/unpatched/poc_vv.txt`) | **12.028506355387210510 ETH** (the incident took 12.03 WETH; oracle threshold 11 ETH) |
| hidden tests | 12 / 12 **legitimate-use** obligations pass; they hold on the vulnerable contract too (`functional_all_pass = true`); the 4 **security** obligations in `tests/hidden/security.t.sol` FAIL, which is what they are for |
| canaries | `empty_patch` |
| core / strict sha256 | `ffb200f260eae35d939a863fe339eee1d8f0502d4b2070fedae377cff79b4f07` / `f0ba49a67926477b9c864bb26725689144e6cfc453181a1407da4425a9b57399` |

## 3. Reference repair

```diff
--- a/src/contracts/Token.sol
+++ b/src/contracts/Token.sol
@@ -255,8 +255,14 @@
         address owner,
         address spender,
         uint256 amount
-    ) private view returns (uint256) {
-        return msg.sender != _taxWallet && (owner == _uniswapPair || spender != _deadWallet) ? amount : 0;
+    ) private pure returns (uint256) {
+        // PATCH: how much allowance a transferFrom consumes must never depend on WHO is
+        // calling. The original returned 0 whenever msg.sender was the tax wallet, so the
+        // tax wallet could move any holder's balance -- including the pair's -- with no
+        // approval at all. Every spender is now debited the full amount they moved.
+        owner;
+        spender;
+        return amount;
     }
```

Grade, `controls/reference/`:

| Field | Value |
|---|---|
| outcome / score | **`solved` / 1.0** |
| exploit oracle | Failure, reason `ERC20: transfer amount exceeds allowance`, a reason the task **declares** in `tests/manifest.json` (`recognised_block_reasons`), failure kind `revert` in the test body |
| hidden tests | 16 / 16 pass (12 legitimate-use + 4 security); `abi_invariants` = bytecode_selectors, dispatch_selectors, dispatch_control, not_vacuous all Success |
| scope / canaries | `changed_files = [src/contracts/Token.sol]`, `diff_in_scope = true`, canaries `[]` |
| core / strict sha256 | `f34d89bad812c6b59ac44136ceea05b35044b03c38bbdaafbe8b391ae5c1963e` / `253011648b813ff772ba4ba1a49e22c59abcc17e178cbe23cb8069f973ea61a5` |
| cross-backend receipt | `--backend docker` (image `evmpatch-env:latest`, built from `ghcr.io/foundry-rs/foundry:v1.7.1`, `--network none`) produces the **same core and strict hashes** (`controls/docker_reference/`); see `RECEIPT.md` for the corpus-wide table |

## 4. Required legitimate behaviour (the hidden suite, hash-locked)

The hidden suite is in **two parts**, and `tests/manifest.json` fixes the exact set, so a run
that executes fewer or more test ids is `inconclusive`.

* **Twelve legitimate-use obligations** (`regression.t.sol`, `invariants_auto.t.sol`) pass on
  the vulnerable contract **and** after the patch. A failure here means the patch broke the
  token: canary `bricked`.
* **Four security obligations** (`security.t.sol`, listed in `manifest.hidden.security_tests`)
  FAIL on the vulnerable contract by construction and must pass for a repair to be credited. A
  failure confined to them means the repair is incomplete: canary `residual_vulnerability`.
  `tests/test_all_tasks.py` asserts that every one of them really does fail on the vulnerable
  source, so a security obligation cannot silently become vacuous.

| Hidden test id (`tests/manifest.json`) | What it asserts |
|---|---|
| `regression.t.sol:MCAI_Regression:test_metadata_preserved()` | `decimals() == 9`, supply > 0, symbol non-empty, pair still holds MCAI: forked state survived the etch |
| `…:test_normal_transfer_works()` | a holder-to-holder `transfer` moves exactly the amount |
| `…:test_approved_transferFrom_works_and_debits_allowance()` | approve 300,000, `transferFrom` 200,000 by the spender: recipient gets 200,000 **and allowance drops to 100,000**. **This is the test aimed at the obvious wrong fixes**: disabling `transferFrom`, or "fixing" the bypass by never debiting |
| `…:test_amm_buy_works()` | an ordinary buy through the real pair and router (fee-on-transfer path) still yields MCAI and leaves both reserves non-zero |
| `…:test_unapproved_spender_cannot_move_tokens()` | a spender with zero allowance is reverted, the other half of the obligation: a patch that "fixes" the bug by dropping the allowance check entirely fails here |
| `…:test_transferFrom_debits_the_sender_exactly()` | the sender's balance drops by exactly the amount moved and the recipient's rises by it, so a repair that debits the allowance correctly and then silently re-credits the sender (an unlimited mint) fails here |
| `…:test_taxwallet_transferFrom_with_approval_moves_tokens()` | with an approval the tax wallet is an ordinary spender and its `transferFrom` still moves tokens, so the bypass cannot be closed by special-casing the tax wallet into a permanent revert |
| `invariants_auto.t.sol:AutoInvariants:test_abi_selectors_preserved()` | all 15 public selectors of the deployed contract are still present in the patched runtime bytecode (PUSH1..PUSH4 immediates, EVM code walk) |
| `…:test_abi_selectors_dispatch()` | every selector the *deployed* contract answered under a zero-argument probe is still dispatched after the patch (behavioural check, calibrated against the fork before etching) |
| `…:test_unknown_selector_is_rejected()` | control: an impossible selector gets the dispatcher's bare `revert(0,0)`; if not, the dispatch check is void and must fail loudly |
| `…:test_selector_check_is_not_vacuous()` | control: the code walk indexed something and reports a bogus selector absent |
| `…:test_contract_has_code()` | the etched patch compiled to non-empty runtime code |

Security obligations (`tests/hidden/security.t.sol`, `manifest.hidden.security_tests`); each
FAILS on the vulnerable contract:

| Security test id | What it asserts |
|---|---|
| `security.t.sol:MCAI_Security:test_taxwallet_cannot_move_holder_tokens_without_approval()` | the declared class stated for an ORDINARY holder, not for the pair. The PoC only ever drains the pair, so this is the test the `pair_only_allowance_fix` variant fails |
| `…:test_taxwallet_cannot_move_pair_tokens_without_approval()` | the same for the pair, asserted **without calling `allowance()` first**, so sabotaging that view cannot decide the outcome |
| `…:test_taxwallet_transferFrom_debits_allowance()` | with an approval, the tax wallet's `transferFrom` debits the allowance by exactly the amount moved |
| `…:test_unapproved_spender_cannot_burn_to_dead_wallet()` | the SECOND branch of the same broken function: `_decreaseAllowance` also returns 0 when the recipient is `_deadWallet`, so any caller could burn any holder's balance with no approval. A repair that only removes the tax-wallet special case leaves this standing |

Declared out of scope, in the test file itself: the **sell leg**. Verified on chain rather
than asserted: `_taxWallet` at this block is `0xdDF062714911A2e59996Eb94A57b7040Ea44309D`
(read from storage slot 6), a **contract of 6,561 bytes whose fallback rejects ETH at any gas**,
and MCAI holds no ETH, so every sell ends in `payable(_taxWallet).transfer(0)` under the
2300-gas stipend. An ordinary trader's sell (tokens bought through the router, or dealt)
reverts at this block with `TransferHelper: TRANSFER_FROM_FAILED`, identically on the etched
source and on the **real deployed bytecode**; the trace shows the revert inside a 2,298-gas
`0xdDF0…::fallback()`. Asserting a working sell would assert something that was never true.

Why the PoC's own sell nevertheless succeeds: its earlier unapproved `transferFrom` is pranked
*from* the tax wallet, so that account is already warm (EIP-2929) when the sell's
`transfer(0)` reaches it, and the fallback then completes inside the stipend (2,294 gas). The
exclusion is therefore correct for the legitimate-use suite, and the PoC is not evidence
against it.

## 5. Destructive-patch controls (all graded, all rejected)

| Control | Variant (`controls/<name>/Token.sol.diff`) | Outcome / reason | Evidence |
|---|---|---|---|
| `noop_identical` | patch byte-identical to the shipped source | `not_solved`, 0.0 | canary `empty_patch`, oracle Success; hashes equal the unpatched grade |
| `revert_all_transferFrom` | `transferFrom` body replaced by `revert("transferFrom disabled")` | `not_solved`, 0.0, canary **`bricked`** | oracle fails for the **undeclared** reason `transferFrom disabled` (not a recognised block reason); hidden `test_approved_transferFrom_works_and_debits_allowance()` fails |
| `abi_rename_transferFrom` | `transferFrom` renamed (removed from the ABI) | `inconclusive` / **`compile_failed`**, 0.0 | the contract implements `IERC20`, so the project no longer compiles; `compiled = false`, no test evidence, never credited. (The literal "remove transferFrom" control therefore never reaches the ABI check, hence the next row.) |
| `fix_plus_abi_drop_setTaxWallet` | reference fix **plus** `setTaxWallet(address)` renamed (not in `IERC20`, so it compiles and the exploit is blocked) | `not_solved`, 0.0, canary **`bricked`** | `abi_invariants`: `bytecode_selectors` Failure, `dispatch_selectors` Failure (both ABI checks catch it; controls still Success) |
| `harness_edit_poc` | reference fix plus an edit to the hash-locked `tests/poc.t.sol` (profit threshold raised to 1e30) | `not_solved`, 0.0, **`diff_in_scope = false`** | canary `out_of_scope_edit:tests/poc.t.sol`; decided by the scope check **before any forge run** (no tests executed) |

Per-control core and strict hashes are in `controls/<name>/sha256.txt` and
`controls/summary.json`.

## 5b. Adversarial repair controls

Six patches that block the shipped exploit path, or appear to, without repairing the
vulnerability class. An exploit oracle alone would credit the first five; the security
obligations, the phased oracle and the scope checks reject all six. All are derived by
[`controls/run_controls.py`](controls/run_controls.py) and graded on every run.

| Control | The variant | Why an exploit oracle alone would credit it | Outcome |
|---|---|---|---|
| `pair_only_allowance_fix` | `_decreaseAllowance` returns `amount` only when `owner == _uniswapPair`; the tax wallet keeps its bypass over every other holder | the PoC drains the pair, so the oracle is blocked, and a legitimate-use suite only exercises an ordinary spender; the core hash would be identical to the reference repair | `not_solved`, 0.0, canary **`residual_vulnerability`**, `functional_all_pass = true`; 3 of the 4 security obligations fail |
| `allowance_query_sabotage` | `transferFrom` untouched; `allowance(pair, taxWallet)` reverts with `ERC20: transfer amount exceeds allowance` | an unphased oracle accepts a recognised reason wherever it occurs, and the PoC's **precondition** query carries it | `not_solved`, 0.0, canary `residual_vulnerability`; the oracle fails as `PRECONDITION_UNREADABLE: allowance() view reverted`, which no pattern recognises |
| `path_traversal_poc_edit` | patch key `src/contracts/../../test/poc.t.sol` carrying the PoC with `PROFIT_THRESHOLD = 1e30` | plain `fnmatch` lets `*` cross `/`, so the key would match `src/contracts/*.sol` and the write would land on the hash-locked PoC **inside the episode workdir** | `not_solved`, 0.0, `diff_in_scope = false`, canary `out_of_scope_edit:src/contracts/../../test/poc.t.sol`, decided before any forge run |
| `mint_on_transferFrom` | the reference fix **plus** `_balances[sender] += amount`: allowance debited, recipient credited, sender loses nothing | only a balance-conservation obligation can see an unlimited mint; the exploit is blocked and every allowance check passes | `not_solved`, 0.0, canary `bricked`; `test_transferFrom_debits_the_sender_exactly()` fails |
| `taxwallet_sender_only_fix` | rejects only `msg.sender == _taxWallet`, leaving the `_deadWallet` branch of the same function | the second branch is never on the PoC's path: any caller can still burn any holder's balance to `0xdead` with no approval | `not_solved`, 0.0, canary `residual_vulnerability`; `test_unapproved_spender_cannot_burn_to_dead_wallet()` fails |
| `decimals_downgrade` | reference fix plus `decimals()` returning 18 | the ABI is intact and the exploit is blocked; only the metadata regression sees the change | `not_solved`, 0.0, canary `bricked`; `test_metadata_preserved()` fails |

The three mechanisms those controls exercise, in the shipped code:

1. **`tests/poc.t.sol` has phases.** Only the unapproved `transferFrom` can produce a
   recognised block reason. Every precondition read is wrapped so a revert becomes
   `PRECONDITION_UNREADABLE` / `PRECONDITION_NOT_MET`, and the post-drain monetisation becomes
   `POST_DRAIN_FAILURE`, none of which appears in `recognised_block_reasons`, so they land as
   `inconclusive / unrecognised_failure` for a human instead of as reward.
2. **`evmpatch_env/sandbox.py` normalises patch keys.** `normalise_patch_key()` rejects
   absolute keys, `..` segments, drive/UNC prefixes and NUL bytes outright; `glob_match()`
   matches `patchable_globs` per path SEGMENT so `*` cannot cross a `/`; a symlink that leaves
   `project/` is rejected; and `verify_workdir_harness()` re-hashes every locked harness file
   **in the assembled workdir after the patch lands**, so a write that ever reached one is a
   hard canary regardless of which route found it.
3. **The hidden suite carries the security property.** See section 4.

## 6. Infrastructure-failure controls (typed `inconclusive`, distinguishable from `not_solved`)

| Control | What was broken | Outcome / reason | Evidence |
|---|---|---|---|
| `compile_failed` | reference fix with one non-Solidity line injected | `inconclusive` / `compile_failed`, 0.0 | `compiled = false`; no oracle result exists, so nothing is read as "blocked" |
| `unrecorded_rpc_truncated_state` | task copy whose `rpc_log.json` keeps **67 of 134** recorded responses; reference fix graded against it | `inconclusive` / **`unrecorded_rpc`**, 0.0 | the proxy failed closed; `compiled = true` but no verdict. **Its canonical hash is not reproducible**: measured over three runs on one host the outcome and reason were stable 3/3 but the set of failing tests was not (11, 11, 8), because against a deliberately incomplete recording it depends on which test reaches a missing read first. Read this row's *typed reason*, never its hash. |

Why this matters: a grader that cannot tell "the exploit was blocked" from "the exploit test
could not run" pays full reward for the second. Here both infrastructure controls score 0.0
**with a typed reason and `outcome = inconclusive`**, while the genuinely rejected patches
score 0.0 with `outcome = not_solved`. A trainer can separate the two from the grade alone.

Two things worth knowing when reading hashes: (1) a compile failure carries no test evidence,
so `abi_rename_transferFrom` and `compile_failed` share the same canonical hashes; the hash
identifies the *grade*, not the source; (2) the `noop_identical` grade hashes equal the
`unpatched` grade, for the same reason.

## 7. Pinned reproduction

Toolchain that produced `controls/`: forge **1.7.1**, commit
`4072e48705af9d93e3c0f6e29e93b5e9a40caed8`; solc 0.8.26 warmed; Python 3.12; Darwin arm64.
Docker image `evmpatch-env:latest` built from `ghcr.io/foundry-rs/foundry:v1.7.1`.

```bash
cd evmpatch-env
# 1. the receipt lines (compare with RECEIPT.md and sections 2 and 3 above)
python -m evmpatch_env.sandbox tasks/mcai_2025_01 --reference-patch --backend local --sha256
python -m evmpatch_env.sandbox tasks/mcai_2025_01                   --backend local --sha256
# 2. the whole control set, regenerating controls/<name>/ and controls/summary.json (about 5 min)
python worked_example/mcai_2025_01/controls/run_controls.py
# 3. the same reference grade inside the no-network container
docker build -t evmpatch-env:latest .
python -m evmpatch_env.sandbox tasks/mcai_2025_01 --reference-patch --backend docker --sha256
# 4. the pytest form (skips cleanly without forge)
pytest tests/test_worked_example_mcai.py -q
```
Expected: solved core `f34d89ba…` / strict `25301164…`; unpatched core `ffb200f2…` / strict
`f0ba49a6…`; every control outcome as in sections 5, 5b and 6. A core match with a strict
mismatch localises the difference to a compiler/forge version (revert-reason wording), not to
the grade. `python` means any interpreter with the package installed (for example
`uv run --no-project --with pytest --python 3.12 python`).

Two host constraints worth knowing before reproducing:

* **The `docker` backend needs the repository on a path the container runtime shares.** Under
  Colima on macOS only the home directory is shared, so a checkout elsewhere fails with
  `mount src=… not a directory` and grades `inconclusive / backend_error`, a mount fault, not
  a grade. `tests/test_docker_backend.py` (5 tests) passes from a home-directory checkout and
  fails from an unshared one for that reason alone.
* **The full pytest run** takes about two minutes with a warm solc cache.

## 8. Verification checklist

What the task must establish before it is treated as qualified, and how it does so.

| # | Obligation | How the task meets it |
|---|---|---|
| 1 | The legitimate-use obligations are the right ones: they cover what MCAI holders and traders rely on at block 21,720,380 | twelve obligations (section 4), including balance conservation on `transferFrom` and the tax wallet as an ordinary spender; the sell-leg exclusion verified on the real deployed bytecode |
| 2 | The recognised block reasons are complete and not too broad: `*assertion failed*`, `*exploit did not yield profit*`, `ERC20: transfer amount exceeds allowance` | the PoC is phased so only the exploit step and the profit assertion can produce one; `allowance_query_sabotage` demonstrates the wrong-place case being rejected |
| 3 | The etch model holds: `vm.etch` at the live address with the forked storage, and no `immutable` slot is a zero placeholder | no `immutable` anywhere in the source; storage read before and after `vm.etch` is byte-identical; the etched runtime code is 11,482 bytes, the same length as the deployed code |
| 4 | The fork block is pre-attack and the recorded state is complete | block 21,720,380 is 2025-01-28T03:36:35Z, before the attack; 134 responses cover the PoC, the hidden suites and every control with zero non-benign misses; the recording is a verified superset of the one the legitimate-use suite alone needs (0 keys dropped, 0 responses changed) |
| 5 | The ABI invariants' selector list matches the deployed contract's public interface | the 15 asserted selectors are exactly MCAI's 13 public/external members plus `owner()` and `renounceOwnership()` from `Ownable`, and all 15 are present in the deployed runtime bytecode |
| 6 | The adversarial controls are the ones a policy would actually try | sections 5 and 5b: six adversarial repairs, four destructive patches, two infrastructure failures, each derived by code and graded on every run; a new variant is added to `run_controls.py` and graded the same way |
