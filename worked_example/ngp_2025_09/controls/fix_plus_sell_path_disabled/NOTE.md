# fix_plus_sell_path_disabled

**kind:** destructive

**expected:** not_solved 0.0 / canary bricked

The reference repair plus closing the sell side outright — 'fix' the AMM bug by making every sell revert, with sellState left true so the flags invariant still passes.
