// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. Hand-written NORMAL-USE invariants for BitallxSC.
// Each must PASS on the vulnerable contract AND on a correct patch: they are what the
// contract is FOR, so a patch that "fixes" the drain by disabling the payout dies here.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
}

interface IBitallxSC {
    function owner() external view returns (address);
    function BSCUSDTTokenContract() external view returns (address);
    function BitallxPayOut(address tokencontract, address[] calldata wallet,
                           uint256[] calldata amount, uint256 totalSendAmount) external;
    function claimReward(address wallet, uint256 amount) external;
    function updateRewardLimits(uint256 newMinimum, uint256 newMaximum) external;
    function verifyCTreasury(address tokencontract, address wallet, uint256 amount) external returns (bool);
}

contract Bitallx_Regression is Test {
    address constant VICTIM = 0xa5f3728767F834C591eE99C8C5854b752F39C385;
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
    uint256 constant FORK_BLOCK = 49758338;

    IBitallxSC bit = IBitallxSC(VICTIM);
    IERC20 usdt = IERC20(USDT);

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:BitallxSC"));
    }

    /// The etched code must still read the LIVE storage correctly. `_owner` is slot 0 and
    /// `_publisher` slot 1 of Ownable; a patch that inserts or reorders state variables
    /// would silently re-point every one of them at the wrong live value, so this is a
    /// real requirement of the task and not just a metadata check.
    function test_live_storage_still_readable() public view {
        assertTrue(bit.owner() != address(0), "owner() reads empty: storage layout changed");
        assertEq(bit.BSCUSDTTokenContract(), USDT, "configured USDT contract moved");
        assertGt(usdt.balanceOf(VICTIM), 0, "victim treasury wiped (state not preserved)");
    }

    /// The contract's actual purpose: a funded payer distributes a batch. The whole batch
    /// is covered by totalSendAmount, so this is the legitimate shape of the call.
    function test_funded_batch_payout_distributes_correctly() public {
        address payer = address(0xFA4E4);
        address a = address(0xA11CE);
        address b = address(0xB0B);
        uint256 amtA = 40 ether;
        uint256 amtB = 60 ether;

        deal(USDT, payer, 1_000 ether);
        uint256 treasuryBefore = usdt.balanceOf(VICTIM);

        vm.startPrank(payer);
        usdt.approve(VICTIM, type(uint256).max);
        address[] memory wallets = new address[](2);
        wallets[0] = a; wallets[1] = b;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amtA; amounts[1] = amtB;
        bit.BitallxPayOut(USDT, wallets, amounts, amtA + amtB);
        vm.stopPrank();

        assertEq(usdt.balanceOf(a), amtA, "recipient A was not paid");
        assertEq(usdt.balanceOf(b), amtB, "recipient B was not paid");
        assertEq(usdt.balanceOf(VICTIM), treasuryBefore,
                 "a fully funded batch must not touch the contract's own treasury");
    }

    /// An unfunded payer must be refused. True before and after any patch.
    function test_payout_rejects_an_unfunded_payer() public {
        address payer = address(0xB40CE);
        deal(USDT, payer, 0);
        address[] memory wallets = new address[](1);
        wallets[0] = address(0xA11CE);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10 ether;

        vm.prank(payer);
        vm.expectRevert();
        bit.BitallxPayOut(USDT, wallets, amounts, 10 ether);
    }

    /// The publisher's reward path must keep working, within its configured limits.
    function test_publisher_can_still_pay_a_reward() public {
        address publisher = address(uint160(uint256(vm.load(VICTIM, bytes32(uint256(1))))));
        assertTrue(publisher != address(0), "publisher slot reads empty: storage layout changed");
        address winner = address(0x1E77E4);
        uint256 before = usdt.balanceOf(winner);

        vm.prank(publisher);
        bit.claimReward(winner, 50 ether);
        assertEq(usdt.balanceOf(winner) - before, 50 ether, "publisher reward path broken");
    }

    /// The owner's treasury sweep must keep working, and only for the owner.
    function test_owner_treasury_path_still_works() public {
        address owner = bit.owner();
        address to = address(0x7EA5);
        vm.prank(owner);
        assertTrue(bit.verifyCTreasury(USDT, to, 25 ether), "owner treasury path broken");
        assertEq(usdt.balanceOf(to), 25 ether, "owner treasury transfer did not land");

        vm.prank(address(0xBAD));
        vm.expectRevert();
        bit.verifyCTreasury(USDT, to, 1 ether);
    }
}
