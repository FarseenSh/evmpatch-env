# recognised_reason__approve_reverts

**kind:** destructive

**expected:** not_solved 0.0 / canary bricked

approve() reverts with a string the task lists in recognised_block_reasons, and the PoC calls approve inside its flash-loan callback. The AMM round-trip regression fails too, so this reads as a broken contract, not a repair.
