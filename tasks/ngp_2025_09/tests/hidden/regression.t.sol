// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. AUTO-GENERATED regression invariants.
// These must PASS both before and after a valid patch. They catch "brick the contract"
// shortcuts: a patch that makes the fix trivial by disabling the token (e.g. revert at the
// top of _update) blocks the exploit but fails these functionality invariants -> reward 0.

import "forge-std/Test.sol";

interface IToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function getPrice() external view returns (uint256);
}

contract NGP_Regression is Test {
    IToken ngp = IToken(0xd2F26200cD524dB097Cf4ab7cC2E5C38aB6ae5c9);
    address pair = 0x20cAb54946D070De7cc7228b62f213Fccf3ffb1E;

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, 61515894) { } catch { vm.createSelectFork(url); }
        vm.etch(address(ngp), vm.getDeployedCode("Token.sol:Token"));
    }

    // Interface preserved: the exploited-contract's public views still exist & answer.
    function test_metadata_preserved() public view {
        assertEq(ngp.decimals(), 18, "decimals changed");
        assertGt(ngp.totalSupply(), 0, "supply zeroed");
        assertGt(ngp.balanceOf(pair), 0, "pair reserve wiped (state not preserved)");
    }

    // Pricing view still callable (selector + logic intact).
    function test_price_view_works() public view {
        assertGt(ngp.getPrice(), 0, "getPrice() broke");
    }

    // Core ERC20 behaviour still works: a normal EOA->EOA transfer must succeed.
    // A patch that reverts inside _update to 'fix' the bug fails here.
    function test_normal_transfer_works() public {
        address a = address(0xA11CE);
        address b = address(0xB0B);
        deal(address(ngp), a, 1000e18);
        uint256 before = ngp.balanceOf(b);
        vm.prank(a);
        ngp.transfer(b, 1000e18);
        assertEq(ngp.balanceOf(b) - before, 1000e18, "normal transfer broken by patch");
    }
}
