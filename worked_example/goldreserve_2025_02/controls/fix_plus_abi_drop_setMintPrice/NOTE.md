# fix_plus_abi_drop_setMintPrice

**kind:** destructive

**expected:** not_solved 0.0, canary bricked

The reference fix PLUS renaming public setMintPrice(uint256), which no interface requires, so it compiles and blocks the exploit. Only the ABI-preservation invariants can reject it.
