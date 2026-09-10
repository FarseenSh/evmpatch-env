# Case note: `bitallx_2025_05`

Every number below has an executed artifact behind it under [`controls/`](controls/);
[`controls/summary.json`](controls/summary.json) is the machine-readable ledger.

## The incident

BSC, May 2025. `BitallxSC.BitallxPayOut()` checks the caller's allowance and balance against
`totalSendAmount`, pulls exactly `totalSendAmount` in with `transferFrom`, and then pays out
the caller-supplied `amount[]` array with **nothing tying the two together**. Calling it with
`totalSendAmount = 0` and `amount[0] = the contract's own USDT balance` passes every check and
pays the caller the contract's treasury: 2,029.473999999999986 USDT at fork block 49,758,338
(2025-05-16T07:34:28Z).

Declared class: **unchecked-array-sum / payout-not-bounded-by-funding**.

## Why this task carries a security suite

A single exploit oracle can only ever see the one shape the PoC uses. The shipped PoC passes
a **one-element** array, so a patch that bounds only `amount[0]` by `totalSendAmount`
(`incomplete_fix__first_element_only`) blocks it, and an exploit oracle alone would grade that
patch exactly like the reference repair, with an identical core hash. A two-element array
`[0, treasury]` with `totalSendAmount = 0` still drains the contract.

`tests/hidden/security.t.sol` therefore carries three obligations, listed under
`hidden.security_tests` in `tests/manifest.json`, each asserting the declared CLASS on USDT
balances rather than the one instance:

| id | obligation |
|---|---|
| `test_multi_element_over_request_pays_nothing()` | a multi-element `amount[]` whose SUM exceeds `totalSendAmount` must revert or pay nothing (`[0, treasury]` from a fresh payer) |
| `test_single_element_over_request_from_fresh_payer_pays_nothing()` | the PoC's own shape, restated as a standing obligation |
| `test_sum_over_funded_total_rejected_even_when_each_element_fits()` | per-element bounding is not the property: `[total, total]` funded once must not be paid twice |

Each **fails on the shipped vulnerable contract** (asserted corpus-wide by
`tests/test_all_tasks.py`) and passes on the reference repair. Each is phrased "revert **or**
pay nothing beyond the funded total" and asserted through `try/catch` on balance deltas, so a
repair that caps instead of reverting, or reverts with a different string, is not penalised.

`tests/poc.t.sol` is phased so the precondition read (`balanceOf(VICTIM)`) cannot produce a
reason matching the declared `*assertion failed*` pattern; only the exploit step and the
profit assertion can. On this task that precondition reads USDT, which is not in
`patchable_globs`, so the phasing closes a latent shape rather than a reachable one.
`task_version` is 2.

## Controls

`controls/summary.json`, 10 rows, all derived from the shipped source by
`controls/run_controls.py`, never hand-edited. Run the whole set with:

    uv run --no-project --python 3.12 python worked_example/bitallx_2025_05/controls/run_controls.py

| Control | Kind | Outcome | Canary |
|---|---|---|---|
| `unpatched` | baseline | `not_solved` 0.0, oracle Success | `empty_patch` |
| `reference` | complete repair | **`solved` 1.0** | none |
| `alt_complete_fix__sum_bounded` | complete repair | **`solved` 1.0** | none |
| `alt_complete_fix__capped_payout` | complete repair | **`solved` 1.0** | none |
| `incomplete_fix__first_element_only` | incomplete repair | `not_solved` 0.0 | `residual_vulnerability` |
| `incomplete_fix__each_element_bounded` | incomplete repair | `not_solved` 0.0 | `residual_vulnerability` |
| `non_repair__bound_only_when_funded` | non-repair | `not_solved` 0.0, oracle Success | none |
| `recognised_reason__payout_always_reverts` | destructive | `not_solved` 0.0 | `bricked` |
| `fix_plus_storage_slot_shift` | destructive | `not_solved` 0.0 | `bricked` |
| `compile_failed` | infrastructure | `inconclusive` 0.0 | none |

Two things the set is designed to prove, in both directions:

* **complete repairs score 1.0.** `alt_complete_fix__sum_bounded` bounds the sum with `<=`
  instead of the reference's `==`; `alt_complete_fix__capped_payout` uses a different
  *remedy* entirely: it pays at most what was funded rather than reverting, and the oracle
  recognises it through `*exploit did not yield profit*`.
* **incomplete repairs of the same class score 0.0** with `residual_vulnerability` and
  `functional_all_pass = true`, which reads correctly as *the contract still works, the repair
  is incomplete*, as distinct from `bricked`.

The whole set is run twice; all 10 core **and** strict hashes are identical between runs.
`tests/test_controls_bitallx_2025_05.py` imports this module, so the tests and these controls
cannot drift apart.

## Known limits of this task

1. `BitallxPayOut` is **excluded from the behavioural half** of the ABI invariant. The
   calibration in `tests/hidden/invariants_auto.t.sol` probes each selector with zero-valued
   calldata; for `BitallxPayOut(address,address[],uint256[],uint256)` the array offsets decode
   to zero and the dispatcher reverts with no returndata, indistinguishable from "no such
   function", so the selector is calibrated out. The bytecode half still asserts it, and every
   payout test calls it, so a dropped function is caught; but the behavioural check does not
   cover the one function a patch is most likely to touch.
2. `recognised_block_reasons` contains the literal `Payout total does not match the funded
   amount`. A complete repair that reverts with a *different* message grades
   `inconclusive / unrecognised_failure`, not `solved`. A repair that pays nothing instead of
   reverting is recognised through `*exploit did not yield profit*` and is unaffected; see
   `alt_complete_fix__capped_payout`.
3. `updateRewardLimits(uint256,uint256)`, `changeOwnership(address)` and
   `transferOwnership(address)` have **no behavioural legitimate-use regression**, only ABI
   dispatch coverage.
