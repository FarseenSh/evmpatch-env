# Environments Hub listing

Publishing is a deliberate step run by the repository owner. This file is the runbook and
the listing text.

## Prerequisites
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install prime          # or run it without installing: uvx --from prime prime ...
prime login
```
The package follows the Hub convention: a `[project]` block with `name`, `version`, `tags`,
`dependencies`, a hatchling build backend, and a top-level module exposing
`load_environment(...)`. `prime` reads `pyproject.toml` directly.

## Local validation before pushing
```bash
pip install -e .
pytest tests/ -q                                   # 125 tests (the docker-backed ones skip without the image)
uv run validate evmpatch-env --runtime.type docker --taskset.image evmpatch-env:latest -c 2
python -m evmpatch_env.sandbox tasks/ngp_2025_09 --reference-patch --backend local --sha256
uv run vf-eval evmpatch-env -m <model> -n 4 -a '{"split":"train","backend":"local"}'
```

## Wheel check
The wheel must contain the frozen state or the reward cannot run offline:
```bash
uv build
unzip -l dist/evmpatch_env-*.whl | grep -E 'tasks/(mcai_2025_01|ngp_2025_09|goldreserve_2025_02|bitallx_2025_05)/(task.json|state/rpc_log.json|tests/poc.t.sol|tests/manifest.json)'
unzip -l dist/evmpatch_env-*.whl | grep -E 'LICENSE|NOTICE'
```
The bundled forge-std under `tasks/*/project/lib/forge-std` is needed to compile; keep it.

## Push
```bash
prime env push --visibility public       # from the repo root (the dir with pyproject.toml)
```
The package declares `verifiers>=0.3.1` and exports a v1 taskset, so the Hub lists it as a
v1 (taskset) package by default; `--runtime v1` states it explicitly.
```bash
```
The Hub renders `README.md` on the listing.

## Listing metadata
- **Name:** `evmpatch-env`
- **Title:** Execution-verified repair of real smart-contract exploits
- **Tags:** `tool-use`, `multi-turn`, `agent`, `code`, `security`, `smart-contracts`,
  `solidity`, `evm`, `sandbox`, `eval`, `train`
- **Runtime:** verifiers v1 taskset (`EvmPatchTaskset`; bash or codex harness on a
  container runtime), plus the legacy `load_environment` multi-turn tool environment.
- **Task type:** multi-turn tool environment (`list_files`, `read_file`, `apply_patch`,
  `run_tests`), three-valued conjunctive reward, 30-turn budget.
- **Tasks:** four incidents (MCAI, NGP, GoldReserve, Bitallx; 2025), `task_version` 2, all
  `split="train"`; the held-out split fills as 2026 incidents are added.
- **Requires:** Foundry (`forge`/`anvil`, grades committed with 1.7.1) on PATH for the
  `local` backend; Docker for the `--network none` backend.
- **Safety:** reward runs with no network; harness hash-locked; canaries logged. Nothing
  touches a live chain; every episode replays frozen historical state.
- **Licence:** Apache-2.0; proof-of-concept tests derive from DeFiHackLabs (Apache-2.0).

## Short description (150 words, for the listing or a bounty form)
> **evmpatch-env: execution-verified repair of real smart-contract exploits.** Each task is
> a contract that was exploited on-chain: the DeFiHackLabs proof of concept plus the verified
> source, with chain state frozen at the exploit block behind a fail-closed record/replay RPC
> proxy. The policy edits the source through tools; the reward recompiles the patch and
> re-runs the genuine exploit against that frozen state inside a `--network none` sandbox.
> Outcomes are three-valued (solved, not solved, inconclusive) so an infrastructure failure
> never earns reward, and a patch qualifies only if the exploit is blocked for a declared
> reason, hidden functionality and security tests pass, every original selector is still
> dispatched, and the diff stays in the allow-listed source. Hash-locked harness files and six
> canaries block the usual reward hacks. Four incidents ship with graded control patches and
> cross-backend receipts; the corpus grows by replaying more proofs of concept.
