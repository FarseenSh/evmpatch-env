# recognised_reason__claim_always_reverts

**kind:** destructive

**expected:** not_solved 0.0, canary bricked

RECOGNISED REASON IN THE WRONG PLACE: claimProfit() always reverts with 'Nada a reclamar', a string the task declares as 'exploit blocked'. Nobody can ever be paid, which is what the contract exists for, so the legitimate-use regression rejects it.
