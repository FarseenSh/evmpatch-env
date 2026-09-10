# alt_separate_debt_mapping

**kind:** complete_repair

**expected:** solved 1.0

A complete repair that keeps the debt in a NEW internal mapping and subtracts it in claimProfit(), instead of folding it into claimedProfitPerAddress. Different storage, different arithmetic, same property; the public ABI is unchanged.
