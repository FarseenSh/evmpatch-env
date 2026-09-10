# incomplete_fix__first_element_only

**kind:** incomplete_repair  
**expected:** not_solved 0.0, poc_blocked, canary residual_vulnerability

The load-bearing incomplete repair: bounds only amount[0], so the one-element PoC is blocked and an exploit oracle alone would grade it like the reference, while a two-element array [0, treasury] with totalSendAmount = 0 still drains the contract.
