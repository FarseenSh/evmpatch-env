// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. Security obligations: these fail on the
// vulnerable contract by construction and must pass for a repair to be credited.
//
// SECURITY OBLIGATIONS, not legitimate-use invariants. Unlike hidden/regression.t.sol,
// every test in this file FAILS on the shipped vulnerable contract: each one asserts a
// property the MCAI bug actually violates. `tests/manifest.json` lists them under
// `hidden.security_tests`, which is what lets the grade distinguish an INCOMPLETE repair
// (canary `residual_vulnerability`) from a BROKEN one (canary `bricked`).
//
// Why they exist. The PoC drains the *pair*, so the single exploit oracle only ever
// exercises one holder. The gap these close: a repair that debits the allowance correctly
// for the pair and keeps the bypass for every other holder (`_decreaseAllowance`
// returning `amount` only when `owner == _uniswapPair`; control `pair_only_allowance_fix`)
// blocks the PoC and passes every legitimate-use test in hidden/regression.t.sol, so
// without these obligations it would grade exactly like the reference repair. The
// vulnerability class is "the tax wallet moves any holder's balance without approval";
// these tests assert the class, not the one instance the PoC happens to use, and they do
// it without going through the PoC's `allowance()` view, which a hostile variant can
// sabotage (control `allowance_query_sabotage`).
//
// The declared vulnerability class covers a second case in the same function: the
// original `_decreaseAllowance` also returns 0 whenever the RECIPIENT is `_deadWallet`
// (`transferFrom` passes the recipient as its `spender` argument), so any caller could burn
// any holder's balance with no approval. A repair that only removes the tax-wallet branch
// leaves it, so it is asserted here too.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract MCAI_Security is Test {
    address constant MCAI = 0x810B5902CB2ac2Fa63dFE4A6935EA32aED975cc8;
    address constant PAIR = 0x660a6619574e87d12Ba7Fa3F5679D5D7F587A4fE;
    // The tax wallet the deployed contract was configured with at this block.
    address constant TAX_WALLET = 0xdDF062714911A2e59996Eb94A57b7040Ea44309D;
    // `_deadWallet` in the deployed source: address(0xdead).
    address constant DEAD_WALLET = 0x000000000000000000000000000000000000dEaD;
    uint256 constant FORK_BLOCK = 21720380;

    IERC20 mcai = IERC20(MCAI);

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("mainnet"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(MCAI, vm.getDeployedCode("Token.sol:MCAI"));
    }

    /// The bug, stated for an ORDINARY holder rather than for the pair. This is the test
    /// the `pair_only_allowance_fix` variant fails and no legitimate-use test can supply.
    function test_taxwallet_cannot_move_holder_tokens_without_approval() public {
        address holder = address(0x5EC0DE01);
        address to = address(0x5EC0DE02);
        deal(MCAI, holder, 400_000e9);
        assertEq(mcai.allowance(holder, TAX_WALLET), 0, "unexpected pre-existing allowance");

        vm.prank(TAX_WALLET);
        vm.expectRevert();
        mcai.transferFrom(holder, to, 100_000e9);
    }

    /// The same property for the pair, asserted WITHOUT calling `allowance()` first, so a
    /// patch that sabotages that view (the `allowance_query_sabotage` variant) cannot make
    /// this test's outcome depend on the view instead of on the state change.
    function test_taxwallet_cannot_move_pair_tokens_without_approval() public {
        address to = address(0x5EC0DE03);
        uint256 pairBefore = mcai.balanceOf(PAIR);
        assertGt(pairBefore, 0, "pair holds no MCAI at this block");

        vm.prank(TAX_WALLET);
        vm.expectRevert();
        mcai.transferFrom(PAIR, to, pairBefore / 2);
    }

    /// The positive half: WITH an approval the tax wallet may spend, and the allowance must
    /// be debited by exactly the amount moved. The vulnerable contract moves the tokens but
    /// debits nothing, so this fails before a repair — that is why it is a security
    /// obligation and not a legitimate-use one.
    function test_taxwallet_transferFrom_debits_allowance() public {
        address holder = address(0x5EC0DE04);
        address to = address(0x5EC0DE05);
        deal(MCAI, holder, 500_000e9);

        vm.prank(holder);
        mcai.approve(TAX_WALLET, 300_000e9);
        vm.prank(TAX_WALLET);
        mcai.transferFrom(holder, to, 200_000e9);

        assertEq(mcai.allowance(holder, TAX_WALLET), 100_000e9,
                 "the tax wallet's allowance was not debited by the amount it moved");
    }

    /// The second branch of the same broken function: `_decreaseAllowance` is called as
    /// `_decreaseAllowance(sender, recipient, amount)`, and returns 0 whenever the
    /// RECIPIENT is `_deadWallet`. So on the vulnerable contract any caller can burn any
    /// holder's balance with no approval. A repair that only removes the tax-wallet
    /// special case leaves this one standing.
    function test_unapproved_spender_cannot_burn_to_dead_wallet() public {
        address holder = address(0x5EC0DE06);
        address thief = address(0x5EC0DE07);
        deal(MCAI, holder, 400_000e9);
        assertEq(mcai.allowance(holder, thief), 0, "unexpected pre-existing allowance");

        vm.prank(thief);
        vm.expectRevert();
        mcai.transferFrom(holder, DEAD_WALLET, 100_000e9);
    }
}
