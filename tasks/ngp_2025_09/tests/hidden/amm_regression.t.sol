// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. The agent must NOT edit this file.
//
// AMM SELL-PATH regression.
//
// The NGP bug lives in exactly one branch of `_update`: `to == mainPair`, i.e. the sell /
// add-liquidity path. The generated regression tests never enter that branch — they only
// do an EOA->EOA transfer and read some views — so without this test a patch could delete
// or brick the whole sell path and still be scored as "functionality preserved". It exercises the
// real thing: a fresh user buys NGP with USDT through the SAME PancakeSwap V2 router and
// pair the incident used, waits out the token's own transfer cooldown, and sells part of
// it back. It must PASS on the vulnerable contract and on the reference patch, and it
// must FAIL if the sell path is disabled, reverted, or drained.
//
// Everything is served from the task's frozen state: no network at reward time.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface INGP {
    function buyState() external view returns (bool);
    function sellState() external view returns (bool);
    function transferCooldown() external view returns (uint256);
    function maxBuyAmountInUsdt() external view returns (uint256);
    function getPrice() external view returns (uint256);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external;
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract NGP_AmmRegression is Test {
    address constant VICTIM = 0xd2F26200cD524dB097Cf4ab7cC2E5C38aB6ae5c9;
    uint256 constant FORK_BLOCK = 61515894;

    IERC20 ngp = IERC20(VICTIM);
    IERC20 usdt = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address pair = 0x20cAb54946D070De7cc7228b62f213Fccf3ffb1E;

    // Small next to the pool (~2.2M USDT / ~46M NGP at the fork block): a genuinely
    // ordinary trade, nowhere near the token's own 10_000 USDT per-buy cap.
    uint256 constant BUY_USDT = 1_000e18;

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:Token"));
    }

    /// Trading must still be switched on in the patched contract's own view of storage —
    /// a patch that hard-codes `buyState`/`sellState` to false "fixes" the exploit by
    /// closing the market, which is not a fix.
    function test_trading_flags_still_open() public view {
        assertTrue(INGP(VICTIM).buyState(), "patch closed the buy side");
        assertTrue(INGP(VICTIM).sellState(), "patch closed the sell side");
    }

    /// Normal use, end to end, through the pair the incident used: buy, wait out the
    /// contract's own cooldown, sell back. The sell leg is the branch that contained the
    /// bug, so this is the test that stops "delete the sell path" from scoring.
    function test_amm_buy_then_sell_round_trip() public {
        address user = address(0xB0BB1E);
        uint256 pairNgpBefore = ngp.balanceOf(pair);
        assertGt(pairNgpBefore, 0, "pair holds no NGP at the fork block");

        deal(address(usdt), user, BUY_USDT);
        vm.startPrank(user);
        usdt.approve(address(router), type(uint256).max);

        // --- buy leg: USDT -> NGP, recipient is a plain EOA (not whitelisted), so this
        //     really goes through `_update`'s `from == mainPair` branch.
        address[] memory path = new address[](2);
        path[0] = address(usdt);
        path[1] = address(ngp);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            BUY_USDT, 0, path, user, block.timestamp
        );
        uint256 bought = ngp.balanceOf(user);
        assertGt(bought, 0, "buy through the pair produced no NGP");

        // The token imposes a transfer cooldown after a buy; a normal user waits it out.
        vm.warp(block.timestamp + INGP(VICTIM).transferCooldown() + 1);

        // --- sell leg: NGP -> USDT. This is the `to == mainPair` branch of `_update`,
        //     the branch the exploit abused and the branch the patch edits.
        ngp.approve(address(router), type(uint256).max);
        uint256 sellAmount = bought / 2;
        assertGt(sellAmount, 0, "nothing to sell");
        path[0] = address(ngp);
        path[1] = address(usdt);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            sellAmount, 0, path, user, block.timestamp
        );
        vm.stopPrank();

        assertGt(usdt.balanceOf(user), 0, "sell through the pair returned no USDT");
        assertEq(ngp.balanceOf(user), bought - sellAmount, "seller's NGP accounting is wrong");

        // The pool must still be a pool afterwards: a patch may change how fees are taken
        // but must not leave the pair empty or its reserves unreadable.
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
        assertGt(uint256(r0), 0, "pair reserve0 wiped by the sell path");
        assertGt(uint256(r1), 0, "pair reserve1 wiped by the sell path");
        assertGt(ngp.balanceOf(pair), 0, "pair NGP balance wiped by the sell path");
    }
}
