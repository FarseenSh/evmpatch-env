# Task build log

How the tasks in this directory are built and verified, what the corpus contains as of
version 0.2.0, and the constraints found while building it. Commands run from the repository
root with Foundry 1.7.1 (`forge`/`anvil`, commit `4072e48705`) on PATH; every grade runs
offline against frozen chain state.

## Offline mechanism

`anvil --load-state` does not work for forked state on these chains:

```
$ anvil --load-state state/anvil_state.json --chain-id 56 ...
Error: failed to load init state
Context: Rpc error ... "Best hash not found for best number 61515894"
```

The tasks therefore use a record/replay JSON-RPC proxy (`evmpatch_env/rpc_replay.py`). At
build time, with a network, it records every `(method, params) -> result` the suite touches;
at reward time it replays from `state/rpc_log.json` and answers anything unrecorded with a
JSON-RPC error. It fails closed, so a patch cannot reach the real chain. Foundry's own RPC
cache (`state/rpc_cache/`, with `FOUNDRY_OFFLINE=true`) is kept as a secondary fallback where
present, and `FOUNDRY_NO_STORAGE_CACHING=true` on every forge invocation keeps a grade from
ever being served out of the host's global RPC cache.

The reward model uses `vm.etch(victim, vm.getDeployedCode("Token.sol:Token"))`: the agent's
source is compiled and overlaid on the live forked address while the real storage (balances,
reserves, whitelists, trade flags) is preserved, so a source patch governs whether the exploit
still works.

## Build procedure, per task

1. Assemble `project/` from the verified source and its libraries
   (`build_task.scaffold_project`), with `foundry.toml` pinning the compiler the deployed
   contract used.
2. Write `tests/poc.t.sol` from the DeFiHackLabs proof of concept, rewired to the etch and
   replay model. The exploit oracle is phased: precondition reads surface as
   `PRECONDITION_UNREADABLE` / `PRECONDITION_NOT_MET` and the post-attack monetisation as
   `POST_DRAIN_FAILURE`, none of which matches a recognised block reason, so only the exploit
   step and the profit assertion can be read as a block.
3. Write the hidden suites: legitimate-use obligations (`regression.t.sol` and per-task
   suites), security obligations (`security.t.sol`, listed under `hidden.security_tests` in
   `tests/manifest.json`; they fail on the vulnerable contract by construction and must pass
   for credit), and the generated `invariants_auto.t.sol` (ABI preservation, two independent
   checks).
4. Record the frozen state with a network available, once per source variant the controls
   grade, so the recording is a superset of everything the PoC, the hidden suites and every
   control need:

   ```
   python -m evmpatch_env.rpc_replay record env:BSC_RPC_URL state/rpc_log.json 8545 &
   TASK_FORK_URL=http://127.0.0.1:8545 forge test -vv
   ```

   `record` takes `env:NAME` so an archive endpoint never appears in a process listing.
   Replay offline until zero non-benign RPC misses are reported. A recording that covers only
   the PoC is not enough: a hidden test that touches a fresh balance slot fails offline with
   `OFFLINE: unrecorded eth_getStorageAt ...`.
5. Finalize: `python -m evmpatch_env.build_task finalize tasks/<id>` regenerates the ABI
   invariants from the original selectors, derives `tests/manifest.json` from a real offline
   run of the whole suite, hash-locks every harness file and writes `task.json` (metadata,
   split label, locks, `patchable_globs`, `task_version`).

## The reward flips, verified offline (`ngp_2025_09`)

Replay proxy on 127.0.0.1, `FOUNDRY_OFFLINE=true`:

| Source | Exploit oracle | Hidden suite |
|---|---|---|
| shipped vulnerable | `[PASS] testExploit()`, attacker USDT profit 493,467.02 | legitimate-use tests pass; security obligations fail |
| reference patch | `[FAIL: BEP20: transfer amount exceeds balance]` (the attacker cannot repay the flash loan) | all pass |

Through the grader:

```
$ python -m evmpatch_env.sandbox tasks/ngp_2025_09 --backend local --canonical --core
  outcome=not_solved score=0.0 poc=[Success] canaries=['empty_patch']
$ python -m evmpatch_env.sandbox tasks/ngp_2025_09 --reference-patch --backend local --canonical --core
  outcome=solved     score=1.0 poc=[Failure] canaries=[]
```

Canaries: `out_of_scope_edit:tests/poc.t.sol` (decided before any forge run), `bricked` (a
`revert()` injected into `_update` blocks the exploit but breaks a normal transfer),
`empty_patch` (no source change), and the hash locks `poc_tampered` / `harness_tampered` for
any edit to `tests/**`, `foundry.toml` or `remappings.txt`. A full verifiers episode
(`list_files`, `read_file`, `apply_patch`, `run_tests`) that applies the reference fix returns
reward 1.0.

## Corpus

| task | chain | fork block | month | class | PoC / hidden (legitimate-use + security) |
|---|---|---|---|---|---|
| `ngp_2025_09` | BSC | 61,515,894 | 2025-09 | AMM reserve manipulation / mid-transfer sync | 1 / 14 (10 + 4) |
| `mcai_2025_01` | Ethereum | 21,720,380 | 2025-01 | allowance bypass in `transferFrom` | 1 / 16 (12 + 4) |
| `goldreserve_2025_02` | BSC | 46,278,330 | 2025-02 | reward accounting / claim debt not carried | 1 / 12 (9 + 3) |
| `bitallx_2025_05` | BSC | 49,758,338 | 2025-05 | payout not bounded by the funded total | 1 / 13 (10 + 3) |

All four carry `split = "train"` (incidents dated 2025-12 or earlier) and `task_version` 2.
Recorded state: 139 / 134 / 1,020 / 79 responses for ngp / mcai / goldreserve / bitallx.
Each legitimate-use suite includes a test aimed at the obvious wrong fix for that bug (disable
the function, close the sell path, never debit); each security suite states the vulnerability
class rather than the one shape the PoC uses.

## Graded controls

`worked_example/<task>/controls/run_controls.py` derives every variant from the shipped
source by code, grades it through the unmodified grader offline, and writes the graded bytes,
a diff against the shipped file, the canonical grade JSON and the core/strict SHA-256 under
`controls/<name>/`; `controls/summary.json` is the machine-readable ledger and
`tests/test_controls_<task>.py` asserts the same variants. Every set includes:

- complete repairs: the reference and at least one alternative implementation of the same
  property, which must score 1.0 (the security obligations state the class, not a fingerprint
  of the reference);
- incomplete repairs: at least two patches that block the shipped exploit path but leave the
  class open, which must score 0.0 with canary `residual_vulnerability` and
  `functional_all_pass = true`;
- non-repairs that the exploit oracle itself catches;
- destructive patches (a recognised block reason in the wrong place, a disabled entry point, a
  dropped public function, a shifted storage slot), which must score 0.0 with `bricked`;
- an infrastructure failure (`compile_failed`), which must be `inconclusive`, never 1.0 and
  never `not_solved`.

Each set is run twice with identical core hashes (`determinism.json` where recorded).

## Constraints found while building the corpus

* `anvil --load-state` on forked state: see above; not retried.
* Contracts with `immutable` variables cannot be etched. `vm.etch(vm.getDeployedCode(...))`
  writes the artifact's `deployedBytecode`, whose immutable slots are zero placeholders. A
  PTM (2025-03) task was fully built and then dropped: 5 immutables including
  `uniswapV2Pair` and `distributor`, so the etched contract reported `decimals() == 0` and
  reverted everywhere. Screen candidates for `immutable` first.
* Proxies are out for the same reason (the logic lives behind `delegatecall`), which excluded
  MyCoinMaster (2025-08).
* Unverified source is out: UPENG (2025-07) is the closest structural twin of the NGP bug and
  cannot be used because the victim's source was never published.
* A scripted screen over every 2025 DeFiHackLabs proof of concept (single fork, named victim,
  at most 160 PoC lines, single-file Sourcify-verified source, no `immutable`) keeps 2 of
  about 90 candidates. The binding constraint is source verification, not PoC complexity;
  multi-file sources and immutable-bearing contracts (constructor-argument redeploy instead of
  etch) are the next build-pipeline steps.
* solc strips leading zero bytes from push constants, so `balanceOf(address,uint256)` =
  `0x00fdd58e` is emitted as `PUSH3 0xfdd58e`. The bytecode selector scan indexes
  PUSH1..PUSH4 for this reason.
* The dispatch probe needs a baseline. "Call fails with no returndata" is both the
  dispatcher's "no such function" answer and what a function produces when it reverts with no
  reason. `setUp()` probes the contract deployed on the fork before etching, and the test
  asserts that every selector the deployed contract dispatches is still dispatched after the
  patch. The probe can calibrate out a function whose zero-word probe reverts bare: on
  `bitallx_2025_05`, `BitallxPayOut(address,address[],uint256[],uint256)` is excluded from the
  behavioural half, while the bytecode half and every payout test still cover it.
* A recording can be silently incomplete if the recorder relies on interpreter shutdown to
  flush its log; writes are closed and fsynced, and every task is built by recording until an
  offline replay reports zero non-benign misses.
* The shipped sources are recompilations of verified source, not the deployed bytecode: NGP's
  etched runtime is 9,364 bytes against 9,559 deployed; GoldReserve's is 7,712 against 7,674,
  and five entry points answer differently before and after `vm.etch`. The etch model's
  guarantee is behavioural (no `immutable`s, storage byte-identical across the etch), not
  bytecode identity, and receipts should be read that way.
* `recognised_block_reasons` are literal. A correct repair that makes the exploit fail with an
  undeclared message grades `inconclusive`, never `not_solved`; a repair that pays nothing
  instead of reverting is recognised through `*exploit did not yield profit*` and is
  unaffected.
* A core grade hash identifies a grade, not a patch. Two patches that produce the same test
  outcomes share a hash; the failing security-obligation ids are part of the grade, which is
  what separates an incomplete repair from the reference.

## Containment backend

`docker build -t evmpatch-env:latest .` pins `ghcr.io/foundry-rs/foundry:v1.7.1` (`:latest`
is 1.8.1, and a silent toolchain bump changes revert-reason wording and therefore strict
hashes). The container does no judging: it emits a raw payload (stdout, stderr, return code,
RPC misses per suite) and the host parses and scores it with the same functions the local
backend uses, so the two cannot drift; `tests/test_docker_backend.py` checks that the
container has no network and that both backends produce the same canonical hash. On macOS,
Docker Desktop and Colima share only the home directory, and a bind mount of an unshared path
appears as an empty directory without an error; episode roots for the docker backend
therefore default to `~/.cache/evmpatch-episodes`, and the entrypoint reports `backend_error`
when `/work` is not there. Receipts: [`../RECEIPT.md`](../RECEIPT.md).
