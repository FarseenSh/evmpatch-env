// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. Security obligations: these fail on the
// vulnerable contract by construction and must pass for a repair to be credited.
//
// SECURITY OBLIGATIONS, not legitimate-use invariants. Unlike hidden/regression.t.sol,
// every test in this file FAILS on the shipped vulnerable contract: each one asserts a
// property the BitallxSC bug actually violates. `tests/manifest.json` lists them under
// `hidden.security_tests`, which is what lets the grade distinguish an INCOMPLETE repair
// (canary `residual_vulnerability`) from a BROKEN one (canary `bricked`).
//
// Why they exist. The shipped PoC drains the contract with a ONE-element `amount[]` and
// `totalSendAmount = 0`, so the single exploit oracle only ever exercises that one shape.
// The gap these close: a repair that bounds only `amount[0]` by `totalSendAmount`
// (`incomplete_fix__first_element_only`) blocks the PoC yet leaves the contract
// drainable with a two-element array `[0, treasury]`; without these obligations it
// would grade exactly like the reference repair. The declared vulnerability class is
// "unchecked-array-sum / payout-not-bounded-by-funding" — the SUM of the caller-supplied
// `amount[]` is never tied to the `totalSendAmount` that every check and the inbound
// `transferFrom` are against. These tests assert that class, not the one instance the PoC
// happens to use.
//
// How they are asserted. On USDT BALANCES — the contract's own treasury and the payout
// recipients' — never on a return value or a view the patch could sabotage. Each
// obligation is "revert OR pay nothing beyond the funded total": the call is wrapped in
// try/catch and the balance deltas are asserted afterwards, so a legitimate alternative
// repair that reverts with a different string, or one that caps the payout instead of
// reverting, is not penalised for choosing a different remedy.
//
// The two invariants every test below asserts:
//   (a) the contract's own USDT treasury must NOT fall — a payout is funded by the caller,
//       never by the contract;
//   (b) the recipients must not receive more than `totalSendAmount` in aggregate.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IBitallxSC {
    function BitallxPayOut(address tokencontract, address[] calldata wallet,
                           uint256[] calldata amount, uint256 totalSendAmount) external;
}

contract Bitallx_Security is Test {
    address constant VICTIM = 0xa5f3728767F834C591eE99C8C5854b752F39C385;
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
    uint256 constant FORK_BLOCK = 49758338;

    IBitallxSC bit_ = IBitallxSC(VICTIM);
    IERC20 usdt = IERC20(USDT);

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:BitallxSC"));
    }

    /// @dev Attempt a payout as `payer` and return the contract's treasury before/after and
    ///      what the two recipients gained. The call is allowed to revert: an obligation
    ///      phrased "revert or pay nothing" must accept either remedy, so the assertion is
    ///      always on the balances and never on whether the call succeeded.
    function _attempt(address payer, address[] memory wallets, uint256[] memory amounts,
                      uint256 totalSendAmount)
        internal
        returns (uint256 treasuryBefore, uint256 treasuryAfter, uint256 paidOut)
    {
        treasuryBefore = usdt.balanceOf(VICTIM);
        uint256[] memory before = new uint256[](wallets.length);
        for (uint256 i = 0; i < wallets.length; i++) {
            before[i] = usdt.balanceOf(wallets[i]);
        }

        vm.prank(payer);
        try bit_.BitallxPayOut(USDT, wallets, amounts, totalSendAmount) { } catch { }

        treasuryAfter = usdt.balanceOf(VICTIM);
        for (uint256 i = 0; i < wallets.length; i++) {
            paidOut += usdt.balanceOf(wallets[i]) - before[i];
        }
    }

    /// S1 — THE CLASS, in the shape an `incomplete_fix__first_element_only` repair survives.
    /// A multi-element `amount[]` whose SUM exceeds `totalSendAmount` must not be paid out
    /// of the contract's own money. `amount[0] = 0` satisfies any per-first-element bound,
    /// and `amount[1]` then takes the treasury. Nothing was funded (`totalSendAmount = 0`,
    /// which BSC USDT accepts as a zero-value transferFrom with no allowance), so nothing
    /// may leave.
    function test_multi_element_over_request_pays_nothing() public {
        address payer = address(0x5EC0DE11);
        address decoy = address(0x5EC0DE12);
        address thief = address(0x5EC0DE13);

        uint256 treasury = usdt.balanceOf(VICTIM);
        assertGt(treasury, 0, "contract holds no USDT at this block (state not preserved)");
        deal(USDT, payer, 0);
        deal(USDT, decoy, 0);
        deal(USDT, thief, 0);

        address[] memory wallets = new address[](2);
        wallets[0] = decoy; wallets[1] = thief;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 0; amounts[1] = treasury;

        (uint256 before_, uint256 after_, uint256 paidOut) = _attempt(payer, wallets, amounts, 0);
        assertGe(after_, before_,
                 "unfunded multi-element payout drained the contract's own USDT treasury");
        assertEq(paidOut, 0, "an unfunded payout paid the recipients");
    }

    /// S2 — the PoC's own shape, restated as a standing obligation rather than left to the
    /// single exploit oracle: a ONE-element over-request from a payer who funded nothing.
    /// Stated here so the property survives any future change to the PoC.
    function test_single_element_over_request_from_fresh_payer_pays_nothing() public {
        address payer = address(0x5EC0DE14);
        address thief = address(0x5EC0DE15);

        uint256 treasury = usdt.balanceOf(VICTIM);
        assertGt(treasury, 0, "contract holds no USDT at this block (state not preserved)");
        deal(USDT, payer, 0);
        deal(USDT, thief, 0);

        address[] memory wallets = new address[](1);
        wallets[0] = thief;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = treasury;

        (uint256 before_, uint256 after_, uint256 paidOut) = _attempt(payer, wallets, amounts, 0);
        assertGe(after_, before_,
                 "unfunded single-element payout drained the contract's own USDT treasury");
        assertEq(paidOut, 0, "an unfunded payout paid the recipient");
    }

    /// S3 — bounding each element individually is NOT the property. Every element here is
    /// `<= totalSendAmount`, so a per-element check passes, yet the batch is funded ONCE
    /// and paid TWICE: the second element comes out of the contract's treasury. The
    /// obligation is on the SUM.
    function test_sum_over_funded_total_rejected_even_when_each_element_fits() public {
        address payer = address(0x5EC0DE16);
        address a = address(0x5EC0DE17);
        address b = address(0x5EC0DE18);
        uint256 fund = 100 ether;

        uint256 treasury = usdt.balanceOf(VICTIM);
        assertGt(treasury, fund, "contract treasury too small for this obligation to bite");
        deal(USDT, payer, fund);
        deal(USDT, a, 0);
        deal(USDT, b, 0);
        vm.prank(payer);
        usdt.approve(VICTIM, type(uint256).max);

        address[] memory wallets = new address[](2);
        wallets[0] = a; wallets[1] = b;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = fund; amounts[1] = fund;

        (uint256 before_, uint256 after_, uint256 paidOut) = _attempt(payer, wallets, amounts, fund);
        assertGe(after_, before_,
                 "a batch funded once and paid twice drained the contract's own USDT treasury");
        assertLe(paidOut, fund, "the recipients were paid more than the funded total");
    }
}
