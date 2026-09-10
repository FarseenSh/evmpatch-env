# Worked example: `ngp_2025_09` (BSC, AMM reserve manipulation / mid-transfer sync)

Every number below has an executed artifact behind it under [`controls/`](controls/);
[`controls/summary.json`](controls/summary.json) is the machine-readable ledger and
[`controls/determinism.json`](controls/determinism.json) records the repeat run.

## The bug

`Token._update`, sell branch (`to == mainPair`). Inside an ordinary seller's own transfer the
contract moves `treasuryRate + rewardRate` (70 % of the sell) **out of the pair** to
`treasuryAddress` and `rewardPoolAddress`, then calls `IUniswapV2Pair(mainPair).sync()`, so
the seller re-prices the pool's reserves mid-sell. The reference repair removes both the drain
and the sync; the seller-side market and burn fees stay.

## Why this task carries a security suite

The exploit needs BOTH halves of the bug, so a single exploit oracle carries only half the
security signal. Deleting only the `sync()` and keeping the drain
(`incomplete_fix__sync_only_removed`) blocks the PoC and passes every legitimate-use test; an
exploit oracle alone would grade it exactly like the reference repair, with an identical core
hash. With the security obligations it grades `not_solved` 0.0 with canary
`residual_vulnerability`.

`tests/hidden/security.t.sol` holds four obligations that **fail on the shipped vulnerable
contract by construction** and are listed in `tests/manifest.json` under
`hidden.security_tests`. They are written against the `Transfer` event log because
conservation-style assertions are vacuous on this token: the fees are proportional, so the
pair still *nets a gain* of about 25 % on every sell.

`tests/poc.t.sol` is phased: the flash-loan callback's `approve()` calls and its `balanceOf()`
read surface as `PRECONDITION_UNREADABLE:` reasons that match no recognised pattern, so only
the router swaps, the flash-loan repayment and the profit assertion can produce a recognised
block reason.

## The controls

`controls/run_controls.py` derives every variant from the shipped source by code and grades it
through the unmodified grader, offline. `controls/summary.json` has the 10 rows;
`controls/determinism.json` records that the whole set was run twice with identical core
hashes. Reproduce with:

    uv run --no-project --python 3.12 python worked_example/ngp_2025_09/controls/run_controls.py --repeat 2

| Control | Kind | Outcome | Canary |
|---|---|---|---|
| `unpatched` | baseline | `not_solved` 0.0, oracle Success | `empty_patch` |
| `reference` | complete repair | **`solved` 1.0** | none |
| `alt_fix__fees_charged_to_seller` | complete repair | **`solved` 1.0** | none |
| `incomplete_fix__sync_only_removed` | incomplete repair | `not_solved` 0.0 | `residual_vulnerability` |
| `incomplete_fix__drain_capped` | incomplete repair | `not_solved` 0.0 | `residual_vulnerability` |
| `non_repair__cosmetic_rename` | non-repair | `not_solved` 0.0, oracle Success | none |
| `noop_identical` | non-repair | `not_solved` 0.0 | `empty_patch` |
| `recognised_reason__approve_reverts` | destructive | `not_solved` 0.0 | `bricked` |
| `fix_plus_sell_path_disabled` | destructive | `not_solved` 0.0 | `bricked` |
| `compile_failed` | infrastructure | `inconclusive` 0.0 | none |

The load-bearing row is `alt_fix__fees_charged_to_seller`: a **different** complete repair
(charge the treasury and reward fees to the seller rather than dropping them) that must also
score 1.0. Without it, the obligations could be fingerprinting the reference implementation
instead of stating the vulnerability class. `incomplete_fix__drain_capped` is the second
incomplete repair of the class: the drain is bounded to 1 % of the pool and the sync removed,
and since the cap never binds on an ordinary trade, the pair is still the source of the
treasury and reward fees.

`tests/test_controls_ngp_2025_09.py` imports this module and builds its variants with the same
functions, so the tests and these documented controls cannot drift apart.
