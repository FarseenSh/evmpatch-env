# unpatched

**kind:** baseline

**expected:** not_solved 0.0, oracle Success, canary empty_patch

The shipped vulnerable source, no patch. The PoC reproduces the incident: 120 BNB is flash-borrowed, deposited as profit, eight NFTs are minted that instantly 'own' it, and the same NFTs are walked through 22 addresses claiming each time.
