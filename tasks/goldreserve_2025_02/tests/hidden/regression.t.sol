// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. Hand-written NORMAL-USE invariants for
// GoldReserve. Every test here is something an ordinary collector does, and each must PASS
// on the vulnerable contract AND on a correct patch.
//
// The load-bearing one is `test_mint_then_deposit_then_claim_pays_the_holder`: the whole
// point of this contract is that NFT holders can claim their share of deposited profit, so
// a patch that "fixes" the double-claim by making claimProfit() always revert, or by
// zeroing entitlements, dies here.

import "forge-std/Test.sol";

interface IGoldReserve {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function mintPrice() external view returns (uint256);
    function circulatingSupply() external view returns (uint256);
    function mintedPerId(uint256) external view returns (uint256);
    function accumulatedProfitPerNFT() external view returns (uint256);
    function claimedProfitPerAddress(address) external view returns (uint256);
    function balanceOf(address, uint256) external view returns (uint256);
    function owner() external view returns (address);
    function uri(uint256) external view returns (string memory);
    function mint(uint256 id, uint256 amount) external payable;
    function depositProfit() external payable;
    function claimProfit() external;
    function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes calldata data) external;
}

contract GoldReserve_Regression is Test {
    address constant VICTIM = 0x7c77576a2b48504EBD9fF0810D799651f68742d3;
    uint256 constant FORK_BLOCK = 46278330;
    uint256 constant FREE_ID = 10;      // 0 minted at this block

    IGoldReserve gold = IGoldReserve(VICTIM);

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:GoldReserve"));
    }

    function test_metadata_preserved() public view {
        assertEq(gold.symbol(), "GOLD", "symbol changed");
        assertGt(bytes(gold.name()).length, 0, "name wiped");
        assertGt(gold.mintPrice(), 0, "mint price zeroed by the patch");
        assertGt(gold.circulatingSupply(), 0, "circulating supply wiped (state not preserved)");
        assertTrue(gold.owner() != address(0), "ownership renounced by the patch");
        assertGt(bytes(gold.uri(0)).length, 0, "uri() broke");
    }

    /// Minting at the listed price must keep working, and must move the accounting.
    function test_mint_works() public {
        address user = address(0xC0113C704);
        vm.deal(user, 10 ether);
        uint256 price = gold.mintPrice();
        uint256 supplyBefore = gold.circulatingSupply();

        vm.prank(user);
        gold.mint{value: price * 2}(FREE_ID, 2);

        assertEq(gold.balanceOf(user, FREE_ID), 2, "mint did not credit the NFTs");
        assertEq(gold.mintedPerId(FREE_ID), 2, "mintedPerId not updated");
        assertEq(gold.circulatingSupply(), supplyBefore + 2, "circulatingSupply not updated");
    }

    /// An ordinary holder-to-holder NFT transfer.
    function test_nft_transfer_works() public {
        address a = address(0xA11CE);
        address b = address(0xB0B);
        vm.deal(a, 10 ether);
        uint256 price = gold.mintPrice();      // read BEFORE the prank: vm.prank only
        vm.prank(a);                           // covers the next call, and an argument
        gold.mint{value: price * 3}(FREE_ID, 3);   // expression is a call too.

        vm.prank(a);
        gold.safeTransferFrom(a, b, FREE_ID, 2, "");
        assertEq(gold.balanceOf(a, FREE_ID), 1, "sender balance wrong after transfer");
        assertEq(gold.balanceOf(b, FREE_ID), 2, "receiver balance wrong after transfer");
    }

    /// THE ONE THAT MATTERS: the contract's whole purpose. A holder who owned NFTs BEFORE
    /// profit was deposited must be able to claim their pro-rata share, exactly once.
    function test_mint_then_deposit_then_claim_pays_the_holder() public {
        address user = address(0xB0BB1E);
        address benefactor = address(0xDEEDBEEF);
        vm.deal(user, 10 ether);
        vm.deal(benefactor, 100 ether);

        // hold first...
        uint256 price = gold.mintPrice();
        vm.prank(user);
        gold.mint{value: price * 2}(FREE_ID, 2);
        uint256 supply = gold.circulatingSupply();

        // ...then profit arrives.
        uint256 deposit = 15.4 ether;
        vm.prank(benefactor);
        gold.depositProfit{value: deposit}();

        uint256 expected = (2 * ((deposit * 1e18) / supply)) / 1e18;
        assertGt(expected, 0, "test setup produced a zero entitlement");

        uint256 before = user.balance;
        vm.prank(user);
        gold.claimProfit();
        uint256 paid = user.balance - before;

        assertEq(paid, expected, "holder was not paid their pro-rata share of the deposit");

        // ...and claiming again pays nothing more.
        vm.prank(user);
        vm.expectRevert();
        gold.claimProfit();
    }
}
