# fix_plus_storage_slot_shift

**kind:** destructive  
**expected:** not_solved 0.0, canary bricked

Reference repair plus one inserted state variable. The grader etches onto the live address and keeps the live storage, so BSCUSDTTokenContract and the claim limits now read the wrong slots.
