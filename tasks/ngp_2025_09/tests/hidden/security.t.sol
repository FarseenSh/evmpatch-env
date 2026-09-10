// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. Security obligations: these fail on the
// vulnerable contract by construction and must pass for a repair to be credited.
//
// SECURITY OBLIGATIONS, not legitimate-use invariants. Unlike hidden/regression.t.sol and
// hidden/amm_regression.t.sol, every test in this file FAILS on the shipped vulnerable
// contract: each one asserts a property the NGP bug actually violates. `tests/manifest.json`
// lists them under `hidden.security_tests`, which is what lets the grade distinguish an
// INCOMPLETE repair (canary `residual_vulnerability`) from a BROKEN one (canary `bricked`).
//
// Why they exist. The shipped PoC needs BOTH halves of the bug — the mid-transfer drain of
// the pair AND the `pair.sync()` that re-prices the reserves against it — so blocking either
// half blocks the PoC. The gap these close: `incomplete_fix__sync_only_removed` deletes only
// `IUniswapV2Pair(mainPair).sync()`, keeps the drain, blocks the PoC and passes every
// legitimate-use test in hidden/regression.t.sol and hidden/amm_regression.t.sol, so
// without these obligations it would grade exactly like the reference repair. The declared class is
// "amm-reserve-manipulation / mid-transfer-sync": inside an ordinary seller's own transfer the
// token moves tokens OUT OF THE PAIR to the treasury and reward addresses. These tests assert
// that class, not the one instance the PoC happens to use.
//
// Why the instrument is the event log and not a balance conservation check. On this token the
// fees are proportional to the sell: the pair receives `value - 5%` and the contract pulls
// `70%` back out, so the pair still NETS A GAIN of ~25% of every sell. "The pair's balance must
// not fall", "tokens are conserved" and "the seller paid exactly `value`" are therefore all
// TRUE on the vulnerable contract — vacuous as obligations. What is observably wrong is the
// SOURCE of the treasury and reward fees: during a sell the pair's only role is `to`, and the
// vulnerable contract makes it `from`. That is visible in the `Transfer` logs and nowhere else,
// so tests 1, 2 and 4 read `vm.recordLogs()`.
//
// A complete repair may charge the treasury and reward fees FROM THE SELLER instead (then no
// `sync()` is needed and the pair's reserves stay honest); that repair passes every test here,
// which is checked as a graded control (`alt_fix__fees_charged_to_seller`) in
// worked_example/ngp_2025_09/controls/. The reference repair — which drops the treasury and
// reward legs on the sell path entirely — also passes. Only a repair that leaves the pair being
// debited inside someone else's transfer fails.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface INGP {
    function transferCooldown() external view returns (uint256);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external;
}

contract NGP_Security is Test {
    address constant VICTIM = 0xd2F26200cD524dB097Cf4ab7cC2E5C38aB6ae5c9;
    address constant PAIR = 0x20cAb54946D070De7cc7228b62f213Fccf3ffb1E;
    // The fee sinks the deployed contract was configured with at the fork block, read from
    // its own storage through the task's frozen state (probe: 0 RPC misses). They are pinned
    // here rather than queried at test time so that a patch which sabotages the
    // `treasuryAddress()` / `rewardPoolAddress()` views cannot decide the outcome of the
    // obligation that names them.
    address constant TREASURY = 0x9b97699f2273BD1CaAAF2CAa7B3daFB9313cd3ed;
    address constant REWARD_POOL = 0x0544E68E4eb515EBf52C65681ab5D9Ea3e5429b1;
    uint256 constant FORK_BLOCK = 61515894;

    // Transfer(address indexed from, address indexed to, uint256 value)
    bytes32 constant TRANSFER_SIG = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;

    IERC20 ngp = IERC20(VICTIM);
    IERC20 usdt = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    // Same size as the amm_regression round trip: an ordinary trade, far below the token's
    // own 10_000 USDT per-buy cap and tiny next to the ~46M NGP / ~2.2M USDT pool.
    uint256 constant BUY_USDT = 1_000e18;

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:Token"));
    }

    // ------------------------------------------------------------------ helpers

    /// Buy NGP with USDT through the same router and pair the incident used, then wait out
    /// the token's own transfer cooldown. Returns the amount bought.
    function _buyAndWait(address user) internal returns (uint256) {
        deal(address(usdt), user, BUY_USDT);
        vm.startPrank(user);
        usdt.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(usdt);
        path[1] = address(ngp);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            BUY_USDT, 0, path, user, block.timestamp
        );
        vm.stopPrank();
        uint256 bought = ngp.balanceOf(user);
        assertGt(bought, 0, "setup: buy through the pair produced no NGP");
        vm.warp(block.timestamp + INGP(VICTIM).transferCooldown() + 1);
        return bought;
    }

    /// Sell `amount` NGP back through the router. Caller must have called vm.recordLogs().
    function _sell(address user, uint256 amount) internal {
        vm.startPrank(user);
        ngp.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(ngp);
        path[1] = address(usdt);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, user, block.timestamp
        );
        vm.stopPrank();
    }

    /// Total NGP moved OUT of `who` by Transfer events the NGP contract emitted, and total
    /// moved IN. Only logs whose emitter is the token itself are considered, so the pair's
    /// own Sync/Swap events and the USDT leg are ignored.
    function _flows(Vm.Log[] memory logs, address who)
        internal pure returns (uint256 out_, uint256 in_)
    {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != VICTIM) continue;
            if (logs[i].topics.length != 3 || logs[i].topics[0] != TRANSFER_SIG) continue;
            address from = address(uint160(uint256(logs[i].topics[1])));
            address to = address(uint160(uint256(logs[i].topics[2])));
            uint256 value = abi.decode(logs[i].data, (uint256));
            if (from == who) out_ += value;
            if (to == who) in_ += value;
        }
    }

    /// Total NGP the pair paid to `sink` in this batch of logs.
    function _paidFromPairTo(Vm.Log[] memory logs, address sink) internal pure returns (uint256 v) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != VICTIM) continue;
            if (logs[i].topics.length != 3 || logs[i].topics[0] != TRANSFER_SIG) continue;
            if (address(uint160(uint256(logs[i].topics[1]))) != PAIR) continue;
            if (address(uint160(uint256(logs[i].topics[2]))) != sink) continue;
            v += abi.decode(logs[i].data, (uint256));
        }
    }

    // ------------------------------------------------------------- the obligations

    /// OBLIGATION 1 — the declared class, stated for an ordinary user's sell through the
    /// router. In a sell the pair's only role is the RECIPIENT: the seller sends tokens in
    /// and the pair sends the counter-asset (USDT) back. No NGP may leave the pair inside
    /// the seller's own transfer. The vulnerable contract moves `treasuryRate + rewardRate`
    /// (70% of the sell) out of the pair here, which is the whole vulnerability; the
    /// `sync()` that follows is only what lets an attacker monetise it, so an obligation
    /// written about `sync()` alone would miss `incomplete_fix__sync_only_removed`.
    function test_ordinary_sell_moves_no_tokens_out_of_the_pair() public {
        address user = address(0x5EC0DE11);
        uint256 bought = _buyAndWait(user);

        vm.recordLogs();
        _sell(user, bought / 2);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        (uint256 outOfPair, uint256 intoPair) = _flows(logs, PAIR);
        // Not vacuous: the sell really did reach the `to == mainPair` branch.
        assertGt(intoPair, 0, "no NGP reached the pair: the sell did not happen");
        assertEq(outOfPair, 0,
                 "a sell moved NGP OUT of the pair: the seller is draining the pool inside "
                 "their own transfer (amm-reserve-manipulation)");
    }

    /// OBLIGATION 2 — the same class named at the incident's two sinks. The treasury and the
    /// reward pool may be paid, but not out of the pair: a fee must be funded by the party
    /// making the trade. Narrower than obligation 1 on purpose — it is the statement that
    /// stays exactly true to the declared class if some future repair has a legitimate reason
    /// to move tokens out of the pair for something else.
    function test_treasury_and_reward_are_not_funded_out_of_the_pair() public {
        address user = address(0x5EC0DE12);
        uint256 bought = _buyAndWait(user);

        vm.recordLogs();
        _sell(user, bought / 2);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        (, uint256 intoPair) = _flows(logs, PAIR);
        assertGt(intoPair, 0, "no NGP reached the pair: the sell did not happen");
        assertEq(_paidFromPairTo(logs, TREASURY), 0,
                 "the treasury fee on a sell was taken out of the pair, not out of the seller");
        assertEq(_paidFromPairTo(logs, REWARD_POOL), 0,
                 "the reward-pool fee on a sell was taken out of the pair, not out of the seller");
    }

    /// OBLIGATION 3 — the same property asserted on BALANCES rather than on events, so a
    /// repair that stopped emitting the drain's `Transfer` events instead of stopping the
    /// drain would still be caught. The pair must end the sell holding every token the seller
    /// sent it: whatever the patch's fee schedule is, `balanceOf(pair)` must rise by exactly
    /// the amount credited to the pair by the transfer itself.
    function test_pair_keeps_every_token_an_ordinary_sell_sends_it() public {
        address user = address(0x5EC0DE13);
        uint256 bought = _buyAndWait(user);

        uint256 pairBefore = ngp.balanceOf(PAIR);
        assertGt(pairBefore, 0, "pair holds no NGP at this block");

        vm.recordLogs();
        _sell(user, bought / 2);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        (, uint256 intoPair) = _flows(logs, PAIR);
        assertGt(intoPair, 0, "no NGP reached the pair: the sell did not happen");
        assertEq(ngp.balanceOf(PAIR) - pairBefore, intoPair,
                 "the pair did not keep everything the sell sent it: tokens leaked out of the "
                 "pool during the seller's transfer");
    }

    /// OBLIGATION 4 — the class stated for a DIFFERENT entry into the same branch. The PoC and
    /// the tests above reach `_update`'s `to == mainPair` branch through the PancakeSwap
    /// router; a plain `transfer()` straight to the pair (the add-liquidity shape) reaches it
    /// too. A repair that special-cases the router — the analogue of MCAI's
    /// `pair_only_allowance_fix` — would pass the tests above and fail this one.
    function test_direct_transfer_to_the_pair_moves_nothing_out_of_it() public {
        address holder = address(0x5EC0DE14);
        uint256 amount = 10_000e18;
        deal(VICTIM, holder, amount);
        assertEq(ngp.balanceOf(holder), amount, "setup: holder was not funded");

        vm.recordLogs();
        vm.prank(holder);
        ngp.transfer(PAIR, amount);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        (uint256 outOfPair, uint256 intoPair) = _flows(logs, PAIR);
        assertGt(intoPair, 0, "no NGP reached the pair: the transfer did not happen");
        assertEq(outOfPair, 0,
                 "a direct transfer to the pair moved NGP OUT of it: the pool is still being "
                 "drained inside someone else's transfer");
    }
}
