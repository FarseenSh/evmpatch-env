# incomplete_fix__debt_on_mint_only

**kind:** incomplete_repair

**expected:** not_solved 0.0, canary residual_vulnerability, PoC blocked

The mirror-image incomplete repair: settles on mints but not on transfers. It blocks the PoC at its first claim, so the exploit oracle alone would credit it, while the address-hopping half the incident repeated 22 times is untouched.
