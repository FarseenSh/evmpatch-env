# OpenEnv compatibility

[OpenEnv](https://github.com/meta-pytorch/OpenEnv) is the Gymnasium-style standard for
agentic execution environments: `reset()` / `step(action)` / `state`, with pydantic
`Action` / `Observation` / `State` models, served over HTTP/WebSocket from a Docker
container and driven by an `EnvClient`. This repo exposes the evmpatch task as an OpenEnv in
two ways.

## Option 1 — auto-wrap the verifiers env (recommended, zero code)
OpenEnv's CLI understands the `verifiers` `load_environment(...)` convention directly (per
the OpenEnv README: `openenv import <source> ... Verifiers`):
```bash
pip install openenv                 # meta-pytorch/OpenEnv
openenv import . --name evmpatch_env --output-dir build/openenv
openenv serve                       # local server, or `openenv build` for the image
```
This turns `evmpatch_env/__init__.py` into an OpenEnv server + typed client with no extra
code — the same tools (list_files/read_file/apply_patch/run_tests) and the same
execution-verified reward.

## Option 2 — the native adapter (`evmpatch_env/openenv_adapter.py`)
When you want the OpenEnv contract directly (custom Action/Observation types, the FastAPI
server, the web debugger), use `EvmPatchEnvironment`. It is written against
`openenv.core.env_server` (`Environment`, `Action`, `Observation`, `State`,
`create_fastapi_app`) and reuses the exact same tool bodies and
`evmpatch_env.sandbox` reward, so the two paths agree.

### Mapping to the OpenEnv contract
| OpenEnv | evmpatch adapter |
|---|---|
| `Action` | `EvmPatchAction(tool, path?, find?, replace?)` — one tool call; `tool` ∈ {`list_files`,`read_file`,`apply_patch`,`run_tests`,`submit`} |
| `Observation` | `EvmPatchObservation(output, turn, max_turns, done, reward)` — tool output; terminal step carries the scalar reward |
| `State` | `EvmPatchState(task_id, turn, changed_files, episode_id, step_count)` |
| `reset()` | loads the vulnerable working tree, returns the task prompt (`done=False`, `reward=None`) |
| `step(action)` | runs one tool; on `submit` or turn-budget exhaustion sets `done=True` and computes the execution-verified reward via `evmpatch_env.sandbox` |
| `state` | current episode state (turn count, files changed vs shipped source) |

### Serve it
```python
from evmpatch_env.openenv_adapter import build_openenv_app
app = build_openenv_app("tasks/ngp_2025_09", backend="docker", max_turns=30)
# uvicorn evmpatch_env.server:app  (behind the repo Dockerfile)
```

### Client usage (shape)
```python
from openenv.core.env_client import EnvClient   # or the generated typed client
async with SomeClient(base_url="http://localhost:8000") as env:
    obs = await env.reset()
    obs = await env.step(EvmPatchAction(tool="read_file", path="src/contracts/Token.sol"))
    obs = await env.step(EvmPatchAction(tool="apply_patch", path="src/contracts/Token.sol",
                                        find="<vulnerable block>", replace="<fix>"))
    obs = await env.step(EvmPatchAction(tool="run_tests"))
    obs = await env.step(EvmPatchAction(tool="submit"))   # obs.reward is the scalar
```

## Notes
- `openenv_adapter.py` imports OpenEnv **lazily**: the package works without `openenv`
  installed, and the adapter raises a clear error only if you actually build/serve it. Run
  `python -m evmpatch_env.openenv_adapter` to check — without openenv it prints a notice and
  exits 0; with openenv it runs a `reset()`/`step()` smoke test.
- The reward is identical across verifiers and OpenEnv because both call
  `evmpatch_env.sandbox.compute_reward`. Containment (`--network none`, hash-locked harness,
  canaries) is a property of the sandbox, so it holds no matter which front-end drives it.
- **Status:** the adapter is written and imports cleanly against the current OpenEnv core
  API; a live OpenEnv server round-trip has not been exercised in this release. The
  verifiers path is fully verified — see `tasks/BUILD_LOG.md`.
