# alt_complete_fix__capped_payout

**kind:** complete_repair  
**expected:** solved 1.0, no canary

A complete repair with a different REMEDY: pay at most what was funded instead of reverting. The oracle recognises it through `*exploit did not yield profit*`, and the security obligations credit it because they assert balances, not a revert.
