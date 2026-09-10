// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. Hand-written NORMAL-USE invariants for MCAI.
// These must PASS on the vulnerable contract AND on a correct patch. They exist so that a
// patch cannot "fix" the allowance bypass by breaking the token: every test here is
// something an ordinary holder or trader does.

import "forge-std/Test.sol";

interface IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IUniswapV2Router {
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external;
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract MCAI_Regression is Test {
    address constant MCAI = 0x810B5902CB2ac2Fa63dFE4A6935EA32aED975cc8;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant PAIR = 0x660a6619574e87d12Ba7Fa3F5679D5D7F587A4fE;
    address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    // The tax wallet the deployed contract was configured with at this block (the address
    // the incident's attacker controlled). `_taxWallet` is private, so it is pinned here
    // rather than read through a getter a patch could redefine.
    address constant TAX_WALLET = 0xdDF062714911A2e59996Eb94A57b7040Ea44309D;
    uint256 constant FORK_BLOCK = 21720380;

    IERC20 mcai = IERC20(MCAI);

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("mainnet"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(MCAI, vm.getDeployedCode("Token.sol:MCAI"));
    }

    function test_metadata_preserved() public view {
        assertEq(mcai.decimals(), 9, "decimals changed");
        assertGt(mcai.totalSupply(), 0, "supply zeroed");
        assertGt(bytes(mcai.symbol()).length, 0, "symbol wiped");
        assertGt(mcai.balanceOf(PAIR), 0, "pair reserve wiped (state not preserved)");
    }

    /// A plain holder-to-holder transfer must keep working.
    function test_normal_transfer_works() public {
        address a = address(0xA11CE);
        address b = address(0xB0B);
        deal(MCAI, a, 1_000_000e9);
        uint256 before = mcai.balanceOf(b);
        vm.prank(a);
        mcai.transfer(b, 1_000_000e9);
        assertEq(mcai.balanceOf(b) - before, 1_000_000e9, "normal transfer broken by patch");
    }

    /// The intended approve -> transferFrom flow must keep working for an ordinary spender,
    /// and must debit the allowance by exactly the amount moved. A patch that "fixes" the
    /// bypass by disabling transferFrom, or by never debiting, fails here.
    function test_approved_transferFrom_works_and_debits_allowance() public {
        address owner = address(0x0117E4);
        address spender = address(0x5DE4DE4);
        address to = address(0xD00D);
        deal(MCAI, owner, 500_000e9);

        vm.prank(owner);
        mcai.approve(spender, 300_000e9);
        assertEq(mcai.allowance(owner, spender), 300_000e9, "approve() did not record");

        vm.prank(spender);
        mcai.transferFrom(owner, to, 200_000e9);

        assertEq(mcai.balanceOf(to), 200_000e9, "transferFrom moved the wrong amount");
        assertEq(mcai.allowance(owner, spender), 100_000e9,
                 "allowance was not debited by the amount moved");
    }

    /// The buy leg an ordinary trader does, through the exact pair and router the incident
    /// used. The token takes a fee on the way in, so this also proves the fee path works.
    ///
    /// NOTE, deliberately: there is no sell leg here. At this fork block `_taxWallet` is
    /// already the attacker's contract, and `_transfer`'s sell branch ends in
    /// `payable(_taxWallet).transfer(...)`, which hits that contract's non-payable fallback
    /// and reverts under the 2300-gas stipend. Every sell therefore reverts on-chain at
    /// this block, before any patch exists. Asserting a working sell would be asserting
    /// something that was never true, so the sell path is out of scope for this task and
    /// the allowance path below carries the legitimate-use weight instead.
    function test_amm_buy_works() public {
        address user = address(0xB0BB1E);
        vm.deal(user, 1 ether);
        uint256 pairMcaiBefore = mcai.balanceOf(PAIR);

        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = MCAI;
        vm.prank(user);
        IUniswapV2Router(ROUTER).swapExactETHForTokensSupportingFeeOnTransferTokens{value: 1 ether}(
            0, path, user, block.timestamp
        );

        assertGt(mcai.balanceOf(user), 0, "buy through the pair produced no MCAI");
        assertLt(mcai.balanceOf(PAIR), pairMcaiBefore, "pair did not release any MCAI");
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(PAIR).getReserves();
        assertGt(uint256(r0), 0, "pair reserve0 wiped");
        assertGt(uint256(r1), 0, "pair reserve1 wiped");
    }

    /// The other half of the legitimate-use story for THIS bug: a spender with no approval
    /// must not be able to move a holder's balance. It holds on the vulnerable contract for
    /// ordinary spenders (only the tax wallet was exempted), and must still hold after a
    /// patch -- a patch that "fixes" the bypass by removing the allowance check entirely
    /// would fail here.
    function test_unapproved_spender_cannot_move_tokens() public {
        address owner = address(0x0FFEE);
        address thief = address(0x7471E5);
        deal(MCAI, owner, 400_000e9);
        assertEq(mcai.allowance(owner, thief), 0, "unexpected pre-existing allowance");

        vm.prank(thief);
        vm.expectRevert();
        mcai.transferFrom(owner, thief, 100_000e9);
    }

    /// `transferFrom` must take the tokens OUT of the sender: the sender's balance drops by
    /// exactly the amount moved. Without this assertion a "repair" that debits the
    /// allowance correctly and then silently credits the sender back -- an unlimited mint
    /// reachable by anyone with an approval (control `mint_on_transferFrom`) -- would pass
    /// every other functionality test. This is normal-use accounting, so it holds on the
    /// vulnerable contract too: `_transfer` always executes
    /// `_balances[from] = _balances[from].sub(amount)`.
    function test_transferFrom_debits_the_sender_exactly() public {
        address owner = address(0xC0FFEE01);
        address spender = address(0xC0FFEE02);
        address to = address(0xC0FFEE03);
        deal(MCAI, owner, 500_000e9);
        uint256 ownerBefore = mcai.balanceOf(owner);
        uint256 toBefore = mcai.balanceOf(to);

        vm.prank(owner);
        mcai.approve(spender, 300_000e9);
        vm.prank(spender);
        mcai.transferFrom(owner, to, 200_000e9);

        assertEq(ownerBefore - mcai.balanceOf(owner), 200_000e9,
                 "transferFrom did not debit the sender by the amount moved");
        assertEq(mcai.balanceOf(to) - toBefore, 200_000e9,
                 "transferFrom did not credit the recipient by the amount moved");
    }

    /// The functional half of the tax-wallet obligation: WITH an
    /// approval the tax wallet is an ordinary spender and its transferFrom must work. This
    /// holds on the vulnerable contract (which lets it through unconditionally) and must
    /// keep holding after a repair, so a patch cannot close the bypass by special-casing
    /// the tax wallet into a permanent revert. The matching *debit* obligation fails on the
    /// vulnerable contract and therefore lives in hidden/security.t.sol.
    function test_taxwallet_transferFrom_with_approval_moves_tokens() public {
        address taxWallet = TAX_WALLET;
        address owner = address(0xC0FFEE04);
        address to = address(0xC0FFEE05);
        deal(MCAI, owner, 500_000e9);
        uint256 toBefore = mcai.balanceOf(to);

        vm.prank(owner);
        mcai.approve(taxWallet, 300_000e9);
        vm.prank(taxWallet);
        mcai.transferFrom(owner, to, 200_000e9);

        assertEq(mcai.balanceOf(to) - toBefore, 200_000e9,
                 "an APPROVED transferFrom by the tax wallet must still move the tokens");
    }
}
