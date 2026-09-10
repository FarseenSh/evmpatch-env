# Grading receipt

A grade is a property of the frozen task, not of the machine that runs it. This file records the
canonical grade hashes of the shipped corpus, what the hashes cover, and how to reproduce them.

## Receipts: 16 of 16 hashes identical across the two backends

Every task, in both source variants and both hash forms, graded through the `local` backend and
through `docker run --network none`. Toolchain: forge 1.7.1 (commit `4072e48705af9d93e3c0f6e29e93b5e9a40caed8`), Python 3.12, macOS arm64.
The same procedure reproduced an earlier task version of this corpus
byte-identically on a second host (Linux x86_64, Ubuntu, Python 3.10); the current task version
has been reproduced across the two backends on one host.

| task | variant | form | local | docker --network none | equal |
|---|---|---|---|---|---|
| `bitallx_2025_05` | reference | core | `6ab3606f6d0fc6d017bbef39da2bbcfcd52537bef89758c46518aca84418ba55` | `6ab3606f6d0fc6d017bbef39da2bbcfcd52537bef89758c46518aca84418ba55` | identical |
| `bitallx_2025_05` | reference | strict | `0164491d777793056c490d3b59b18ef370c9bd996886082bc0574925ae83fc92` | `0164491d777793056c490d3b59b18ef370c9bd996886082bc0574925ae83fc92` | identical |
| `bitallx_2025_05` | unpatched | core | `3311aff59a575e5a2ed71286559664b284ba7580c0e1c282e7ea2a5d760a9fe0` | `3311aff59a575e5a2ed71286559664b284ba7580c0e1c282e7ea2a5d760a9fe0` | identical |
| `bitallx_2025_05` | unpatched | strict | `c398bbc218f55cdf118c8e4f8f4767017f2662b0b3087dc8f2d682cc1177ec7c` | `c398bbc218f55cdf118c8e4f8f4767017f2662b0b3087dc8f2d682cc1177ec7c` | identical |
| `goldreserve_2025_02` | reference | core | `fd82c8e0842b0c008a5161adbd27bb8458668f208c1d4ab576f89da73ed4e0ea` | `fd82c8e0842b0c008a5161adbd27bb8458668f208c1d4ab576f89da73ed4e0ea` | identical |
| `goldreserve_2025_02` | reference | strict | `fedc3b17c6e10f680349ce36d7dbac716571cd395ae109e733b5f2003f396868` | `fedc3b17c6e10f680349ce36d7dbac716571cd395ae109e733b5f2003f396868` | identical |
| `goldreserve_2025_02` | unpatched | core | `546fc03a14c547127f0cf075289f844bee4cd8faf7cc0ef1b77453df3a15b866` | `546fc03a14c547127f0cf075289f844bee4cd8faf7cc0ef1b77453df3a15b866` | identical |
| `goldreserve_2025_02` | unpatched | strict | `74c9d6f8c892afd4030de452d9997993c6ba45bc41b9adb7da9edcd4a28d8026` | `74c9d6f8c892afd4030de452d9997993c6ba45bc41b9adb7da9edcd4a28d8026` | identical |
| `mcai_2025_01` | reference | core | `f34d89bad812c6b59ac44136ceea05b35044b03c38bbdaafbe8b391ae5c1963e` | `f34d89bad812c6b59ac44136ceea05b35044b03c38bbdaafbe8b391ae5c1963e` | identical |
| `mcai_2025_01` | reference | strict | `253011648b813ff772ba4ba1a49e22c59abcc17e178cbe23cb8069f973ea61a5` | `253011648b813ff772ba4ba1a49e22c59abcc17e178cbe23cb8069f973ea61a5` | identical |
| `mcai_2025_01` | unpatched | core | `ffb200f260eae35d939a863fe339eee1d8f0502d4b2070fedae377cff79b4f07` | `ffb200f260eae35d939a863fe339eee1d8f0502d4b2070fedae377cff79b4f07` | identical |
| `mcai_2025_01` | unpatched | strict | `f0ba49a67926477b9c864bb26725689144e6cfc453181a1407da4425a9b57399` | `f0ba49a67926477b9c864bb26725689144e6cfc453181a1407da4425a9b57399` | identical |
| `ngp_2025_09` | reference | core | `cb637d0428a31635a00386ccd3ce65430aa1cd71a4cda05752a6806225465b94` | `cb637d0428a31635a00386ccd3ce65430aa1cd71a4cda05752a6806225465b94` | identical |
| `ngp_2025_09` | reference | strict | `65466943ed575d6709a890c84423e1e0abe1290d881c15cb919aa5dc391c6464` | `65466943ed575d6709a890c84423e1e0abe1290d881c15cb919aa5dc391c6464` | identical |
| `ngp_2025_09` | unpatched | core | `25b53d32310daa49483bc7f910779928be9c4b3639bcd78029c391de1cab77df` | `25b53d32310daa49483bc7f910779928be9c4b3639bcd78029c391de1cab77df` | identical |
| `ngp_2025_09` | unpatched | strict | `a79700ceb81bcee8c9894ba3413dd9a9d5d58691ec8163fea4f60b7a2d9f17f3` | `a79700ceb81bcee8c9894ba3413dd9a9d5d58691ec8163fea4f60b7a2d9f17f3` | identical |

Task inputs at receipt time:

| task | task_version | task.json sha256 | state/rpc_log.json sha256 | records |
|---|---|---|---|---|
| `bitallx_2025_05` | 2 | `3ed4ee24312754396ec37bd920e9a9bb586f6d33cb85550271a96cdd4958c83f` | `830142c4019ba9a61d1597288ea8e29e941f9012d3229adbe29493940a7b8615` | 79 |
| `goldreserve_2025_02` | 2 | `84db927e41ddb0bdb4ad0e79bae4430aeefeeef08ef4b781f2d4953f55345633` | `02b95ebb01b77e2f921031bb2259926e63ba66ad4186e0d088059b8e49b624ff` | 1020 |
| `mcai_2025_01` | 2 | `5fd0ac58af5472a53e22b86f178e2de6e1b0dad330d50c28db1e9cd88b0afba2` | `70a9702e329e1bab56128a0eb5b6e905f8367dde4487ecff7d7e5504e353bbaf` | 134 |
| `ngp_2025_09` | 2 | `0cab8856e681d608bbc1c68e6b19f195542a510535ddc61fc9404c99b9175adb` | `e6da2c723ef906b78bd9aec23151727feaeb302dfadb694ed8bf068fc577c8b2` | 139 |

Command, per task and backend:

```bash
python -m evmpatch_env.sandbox tasks/<task> --reference-patch --backend {local|docker} --sha256
python -m evmpatch_env.sandbox tasks/<task>                   --backend {local|docker} --sha256
```

The reference patch grades `solved` (reward 1.0) and the shipped vulnerable source grades
`not_solved` (reward 0.0) on every task. The container does no judging: it emits a raw payload
(stdout, stderr, return code, RPC misses per suite) and the host parses and scores it with the
same functions the local backend uses, so the two backends cannot drift.

## What is hashed, and what is deliberately not

`RewardResult.canonical()` in `evmpatch_env/sandbox.py`. Two forms:

**core** (`--sha256` first line, `--canonical --core`): the decision and the evidence, nothing else:

- `schema`, `task_id`
- `outcome` (`solved` / `not_solved` / `inconclusive`), `score`
- `reason` (typed code) and `reason_family` (coarse bucket)
- `poc_blocked`, `poc_failure_kind`, `hidden_all_pass`, `compiled`, `tests_match_manifest`, `diff_in_scope`
- `abi_invariants`: the four ABI-preservation checks, recorded separately
- `canaries` (sorted), `changed_files` (sorted)
- `poc_tests` and `hidden_tests`: fully qualified test id to `Success` / `Failure` / `Skipped`

**strict** (`--sha256` second line, default `--canonical`): the core fields plus the revert or assertion
reason string of every failing test and of any `setUp()` failure. Strict pins *why* each test failed,
not only that it did. Core survives a toolchain difference, so a core match with a strict mismatch
localises the difference to a compiler or forge version rather than to the grade.

Excluded from both, on purpose, because they are properties of the run rather than of the grade:

| dropped | why |
|---|---|
| durations, gas figures | machine-dependent |
| the replay proxy's port | chosen by the OS per episode (bind `:0`) |
| the episode workdir path | uuid-named per episode; the temp root differs by OS |
| forge stdout / stderr tails | contain absolute paths and timings |
| subprocess return codes | consumed by the scorer, not part of the decision |
| the backend name (`local` / `docker`) | the point is that both agree |
| wall-clock timestamps | never recorded in the grade |

The grade is a function of the executed test ids and their outcomes, so a harness change that alters
no outcome (a comment, a refactor of a check with the same verdicts) moves no hash. The failing
security-obligation ids are part of the grade, which is why an incomplete repair and the reference
repair never share a core hash.

## Why the hashes can match

Three properties make it possible; without any one of them two runs would diverge.

1. **`FOUNDRY_NO_STORAGE_CACHING=true` on every forge invocation.** Foundry otherwise serves fork
   reads from the host's global `~/.foundry/cache/rpc/<chain>/<block>`, which would be a second data
   source that differs between machines. With it, the task's own `state/rpc_log.json` is the sole
   source of chain data, and the replay proxy fails closed on anything it does not contain. Every task
   is built by recording until an offline replay reports zero non-benign RPC misses.
2. **The expected-test manifest.** Each `tasks/<id>/tests/manifest.json` fixes the exact set of fully
   qualified test ids that must execute, so "the same grade" means the same tests, not a similar tally.
3. **A pinned toolchain.** Grades are produced with forge 1.7.1, and the Docker image pins
   `ghcr.io/foundry-rs/foundry:v1.7.1` rather than `:latest`. A forge upgrade can change revert-reason
   wording and would move the strict hash; that is a deliberate, reviewable event, not a silent one.

## Reproducing

```bash
python -m evmpatch_env.sandbox tasks/<id> --reference-patch --backend local --sha256
```

on any host with forge 1.7.1 and the pinned solc builds (0.8.30, 0.8.26, 0.8.16) warmed. A mismatch
means one of the three properties above has been broken; start with `--canonical` on both hosts and
diff the JSON, which localises the disagreement to a single test id. If the core hashes match and only
the strict ones differ, the disagreement is in a revert-reason string and therefore in the toolchain,
not in the grade.
