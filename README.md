# evmpatch-env

An execution-verified RL environment for **repairing real smart-contract exploits**, built
for Prime Intellect's [`verifiers`](https://github.com/PrimeIntellect-ai/verifiers) with an
[OpenEnv](https://github.com/meta-pytorch/OpenEnv)-compatible adapter.

Each task is a contract that was exploited on-chain. The policy is given the verified
source and a description of the incident, and must edit the source so that the held-out
proof-of-concept exploit no longer succeeds, while the contract still compiles, still
dispatches every function it dispatched before, and passes hidden functionality and
security tests. The reward is not a model judgement: the patch is compiled and the actual
exploit is re-run against chain state frozen at the exploit block, inside a sandbox with no
network.

**Version 0.2.0 (10 September 2026).** Four incidents (MCAI, NGP, GoldReserve, Bitallx; all
2025), every task at `task_version` 2 with hidden security obligations and phased
proof-of-concept tests. Tested on verifiers 0.3.1: 113 tests pass without Docker, 118 with
the `docker --network none` backend built. Version-2 grades reproduce byte-for-byte across
the `local` and Docker backends on one host, and the earlier task version was reproduced
across two hosts (macOS arm64 and Linux x86_64); see [`RECEIPT.md`](RECEIPT.md).

---

## Layout
```
evmpatch-env/
├── evmpatch_env/
│   ├── __init__.py          # load_environment(...) -> EvmPatchEnv (verifiers StatefulToolEnv)
│   ├── sandbox.py           # container build + execution reward + canaries (structured result)
│   ├── build_task.py        # PoC + verified source -> task dir (task.json, auto invariants)
│   ├── openenv_adapter.py   # OpenEnv Environment/Action/Observation/State + FastAPI app
│   └── rpc_replay.py        # fail-closed record/replay JSON-RPC proxy (offline forking)
├── tasks/
│   ├── ngp_2025_09/         # one of four tasks
│   │   ├── task.json        #   metadata, split label, SHA-256 hash-locks, allow-list, task_version
│   │   ├── project/         #   Foundry project the agent edits (src/, foundry.toml, lib/)
│   │   ├── tests/           #   harness (hash-locked): poc.t.sol, manifest.json, hidden/
│   │   ├── state/           #   frozen chain state: rpc_log.json (+ rpc_cache/)
│   │   └── reference_patch.sol.diff   # known-good fix, CI self-test only (never shown to the agent)
│   └── BUILD_LOG.md         # task build procedure, corpus table, constraints found while building
├── worked_example/          # per-task case notes and graded control patches
├── tests/                   # pytest: scorer probes, offline flip checks, controls, docker
├── Dockerfile + reward_entry.sh   # foundry+anvil, non-root, no network at runtime
├── RECEIPT.md               # reproducibility receipts (grade hashes and method)
├── .github/workflows/ci.yml # probes, offline flip check and controls for every task
├── pyproject.toml           # verifiers-convention package (name, tags, deps, hatchling)
├── HUB.md                   # Environments Hub listing notes and push steps
└── OPENENV.md               # OpenEnv usage and how the adapter maps to the OpenEnv contract
```

## Quick start
```bash
pip install -e .                       # verifiers>=0.3.1, datasets
# Foundry must be on PATH for the reward: curl -L https://foundry.paradigm.xyz | bash && foundryup
# The committed grades were produced with forge 1.7.1 (pinned in CI).

python -c "import evmpatch_env; e=evmpatch_env.load_environment(split='train'); print(len(e.dataset))"

# score a patch through the sandbox, offline:
python -m evmpatch_env.sandbox tasks/ngp_2025_09 --patch <your Token.sol> --backend local

# self-test any task against its own reference fix and print the canonical grade hash:
python -m evmpatch_env.sandbox tasks/ngp_2025_09 --reference-patch --backend local --sha256

# containment backend (no network inside the container at all):
docker build -t evmpatch-env:latest .
python -m evmpatch_env.sandbox tasks/ngp_2025_09 --reference-patch --backend docker

pytest tests/                          # 118 tests; the 5 docker tests skip without the image
```
`load_environment(tasks_dir=None, split="train", backend="local", max_turns=30, task_ids=None)`
returns a verifiers `Environment`; use it with `vf-eval`, `prime eval run` or prime-rl like
any Hub environment. Evaluate with a model:
```bash
uv run vf-eval evmpatch-env -m <model> -n 4 -a '{"split":"train","backend":"local"}'
```

---

## The task
A task is a Foundry project snapshot with (1) a vulnerable contract's verified source and
(2) a proof-of-concept exploit test that currently succeeds. The agent edits the source
through four tools (`list_files`, `read_file`, `apply_patch`, `run_tests`) within a turn
budget, and the patch qualifies when:

- **(a)** the exploit test fails for a reason the task declares (the exploit is blocked),
- **(b)** the hidden functionality tests pass (legitimate use preserved),
- **(c)** the hidden security obligations pass (the repair is complete),
- **(d)** the project compiles and every originally dispatched selector is still dispatched,
- **(e)** the diff touches only allow-listed source (never tests, `foundry.toml`, the harness).

## Reward: three-valued, conjunctive
Computed by `evmpatch_env/sandbox.py`. The outcome is one of:

| outcome | reward | meaning |
|---|---|---|
| `solved` | 1.0 | (a) to (e) hold and no canary fired, on valid evidence |
| `not_solved` | 0.0 | the run produced valid evidence and the patch does not qualify |
| `inconclusive` | 0.0 | the run produced no valid evidence; flagged with a typed reason |

`inconclusive` separates "the exploit was blocked" from "the exploit test could not run";
the second never earns reward. Reason codes: `compile_failed`, `proxy_start_failed`,
`setup_failed`, `unrecorded_rpc`, `runner_crash`, `no_structured_report`, `missing_tests`,
`unexpected_tests`, `tests_skipped`, `timeout`, `manifest_missing`, `backend_error`,
`unrecognised_failure`; each carries a coarse `reason_family` for triage. Training code
should treat `inconclusive` as a missing observation, not a negative label.

Scoring reads `forge test --json` and the subprocess return code, never the human log (the
text parser survives only as a fallback that sets `structured=False` and can never yield
`solved`). Test ids are fully qualified `<file>:<contract>:<fn(sig)>`, and the executed set
must exactly match the task's expected-test manifest (`tasks/<id>/tests/manifest.json`,
itself hash-locked). `poc_blocked` requires the exploit oracle to have failed in the test
body for a reason listed in the task's `recognised_block_reasons`; an undeclared failure is
`unrecognised_failure`, not a reward.

`RewardResult` exposes every component (`poc_blocked`, `poc_failure_kind`, `hidden_all_pass`,
`compiled`, `tests_match_manifest`, `diff_in_scope`, `abi_invariants`, `canaries`,
`changed_files`, the parsed hidden run with per-test status and reason) so training can inspect why a patch
failed without changing the scalar. `RewardResult.canonical()` gives a host-independent view
of the grade for cross-machine receipts.

The exploit oracle lives in the proof-of-concept test itself: `testExploit()` is phased
(preconditions, attack, profit assertion), and only a failure in the attack or profit phase
counts as a block; a precondition failure is `inconclusive`. The vulnerable contract's
patchable bytecode is `vm.etch`'d onto the live forked address, so the agent's source edit,
not a mocked contract, governs whether the exploit still works.

## Containment
- **No network at reward time.** The Docker backend runs the grader inside
  `docker run --network none`. Frozen chain state is served by an in-container record/replay
  proxy (`rpc_replay.py`) that fails closed: any JSON-RPC call not in the recording returns an
  error, so a patch cannot reach the real chain. The `local` backend uses the same proxy and
  `FOUNDRY_OFFLINE=true`.
- **Harness is read-only and hash-locked.** `tests/**`, `foundry.toml` and `remappings.txt`
  have their SHA-256 pinned in `task.json`. Every episode reassembles the project from the
  task and applies the agent's patch only to `project/src`, so the policy cannot edit the
  oracle. Hashes are re-verified before each run.
- **Least privilege.** Non-root user (uid 1000), read-only state mount, wall-clock timeout,
  a uuid-named work directory and an OS-assigned port per episode.

## Canaries
Each forces score 0 and is recorded in `RewardResult.canaries`:

| canary | what it catches |
|---|---|
| `poc_tampered` | `poc.t.sol` hash differs from the lock: deleting, skipping or neutering the PoC |
| `harness_tampered` | `foundry.toml`, `remappings.txt` or any hidden test hash mismatch |
| `out_of_scope_edit` | patch changed a path outside `patchable_globs` (short-circuits before forge) |
| `bricked` | exploit "fails" only because the contract was disabled (a hidden functionality test also fails) |
| `residual_vulnerability` | exploit blocked and legitimate use intact, but a hidden security obligation (`manifest.hidden.security_tests`) still fails: an incomplete repair |
| `empty_patch` | no source change at all |

The auto-generated `tests/hidden/invariants_auto.t.sol` checks ABI preservation two
independent ways, recorded separately in `RewardResult.abi_invariants`:

* `bytecode_selectors` walks the patched runtime bytecode as EVM code (skipping PUSH
  immediates) and requires every original selector to appear as a PUSH1..PUSH4 immediate,
  i.e. in the dispatch table;
* `dispatch_selectors` calls every original function and requires the contract not to answer
  with the dispatcher's "no such function" (fail with empty returndata). `setUp` calibrates
  this against the contract deployed on the fork before etching, so the assertion is
  "everything the real contract dispatches, the patch still dispatches".

Two guards keep those from decaying into tautologies: `not_vacuous` (impossible selectors
must be reported absent) and `dispatch_control` (an impossible selector must get the "no such
function" answer, or the contract has a catch-all fallback and the probe proves nothing).

## Controls
Every task ships with graded control patches under `worked_example/<task>/controls/`, and
`tests/test_controls_<task>.py` asserts them: the reference repair and an alternative
complete repair grade `solved`; two demonstrated incomplete repairs grade `not_solved` with
the `residual_vulnerability` canary; a compile failure grades `inconclusive`; two runs of the
same patch produce identical canonical hashes. `tests/test_scorer_probes.py` holds ten
synthetic scorer probes (RPC failure, missing or extra tests, runner crash, name collisions,
compile failure, scope violation) plus regression tests for
path-traversal patch keys, unrecorded RPC misses and the security-obligation canary; they run
without Foundry and gate CI.

## Splits and contamination
- Each task carries a split label derived from its incident month
  (`build_task.py::split_for_month`, re-checked in `load_environment`): `train` for incidents
  dated 2025-12 or earlier, `test` for 2026-03 to 2026-08, with 2026-01 and 2026-02
  quarantined. **All four tasks in this release are 2025 incidents and carry `split="train"`;
  the held-out split is empty until 2026 incidents are added.**
- EVMBench's 40 contest codebases are out of scope for tasks. This is a corpus rule applied
  when incidents are selected, not a check in `load_environment`; the four shipped tasks are
  DeFiHackLabs incident contracts, not contest codebases.
- Provenance: proof-of-concept tests derive from DeFiHackLabs (Apache-2.0; see `NOTICE`),
  and contract sources are reproduced from public block-explorer verification. Only derived
  task artifacts (frozen state, harness, task metadata) are shipped.

## Scope and limits
- The etched bytecode is a recompilation of the verified source, not the deployed bytecode;
  sizes differ (for NGP, 9,364 bytes etched against 9,559 deployed), so a grade is a property
  of the task's recompiled contract, and the receipts should be read that way.
- Contracts with `immutable` variables, proxies and unverified sources are outside the
  current build pipeline (`tasks/BUILD_LOG.md` records the screened-out cases); verified
  single-file sources are the binding constraint on corpus growth.
- `recognised_block_reasons` are literal: a correct repair that makes the exploit fail with
  an undeclared message grades `inconclusive`, never `not_solved`, and should be triaged.
- Version-2 grades have single-host cross-backend receipts; a second-host receipt is
  pending. Foundry is pinned to 1.7.1 in CI because the report parser and the committed
  hashes are verified against it.
- The reward runs Foundry locally or in the bundled Docker image. A verifiers v1 taskset
  (`Task.setup` / `finalize` / `@reward` / `apply_gold_patch` / `validate`) with the Foundry
  image on Prime sandboxes, grading material withheld from the agent's runtime until scoring,
  is the next release; this package stays the `load_environment` entry point.

## Task build
`evmpatch_env/build_task.py` documents and implements the pipeline:
1. Assemble `project/` from verified source and libraries.
2. Write `tests/poc.t.sol` from the DeFiHackLabs proof of concept, rewired to the etch and
   state-replay model with a phased exploit oracle that flips PASS to FAIL on a fix.
3. Auto-generate `tests/hidden/invariants_auto.t.sol` from the original contract's selectors
   (ABI invariance) plus a compile gate, and write the hidden functionality and security
   suites and `tests/manifest.json`.
4. Warm frozen state with the network once: `rpc_replay.py record <rpc> state/rpc_log.json`
   while running the whole suite, then replay offline until zero non-benign RPC misses.
5. Emit `task.json`: metadata, split label, SHA-256 hash-locks of every harness file, the
   `patchable_globs` allow-list and `task_version`.

Finalize an assembled task directory: `python -m evmpatch_env.build_task finalize tasks/<id>`.

## Environments Hub
```bash
prime env install <prime-username>/evmpatch-env
```
See [`HUB.md`](HUB.md) for the listing notes. Nothing in this repository pushes on its own.

## OpenEnv
See [`OPENENV.md`](OPENENV.md): either auto-wrap the verifiers environment with
`openenv import .`, or serve the native `EvmPatchEnvironment` adapter directly.

## Licence
Apache-2.0 (see `LICENSE` and `NOTICE`). Copyright 2026 Farseen Shaikh, SCAR.
