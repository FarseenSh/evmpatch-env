"""The verifiers v1 taskset (evmpatch_env/v1.py).

The loading tests need only the package. The docker-gated test runs the real `validate`
path (setup, then the gold-patch and no-op checks) through a `DockerRuntime` for two
tasks; it skips when Docker or the image is unavailable. The image tag comes from
`EVMPATCH_IMAGE` (default `evmpatch-env:latest`, built from the repository's Dockerfile).
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess

import pytest

from conftest import REPO

vf = pytest.importorskip("verifiers.v1")

from evmpatch_env.v1 import EvmPatchConfig, EvmPatchTask, EvmPatchTaskset  # noqa: E402

IMAGE = os.environ.get("EVMPATCH_IMAGE", "evmpatch-env:latest")


def _docker_image_available() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True)
    return probe.returncode == 0


requires_image = pytest.mark.skipif(
    not _docker_image_available(), reason=f"docker or the {IMAGE} image is unavailable"
)


def test_taskset_loads_every_train_task():
    tasks = list(EvmPatchTaskset(EvmPatchConfig(id="evmpatch-env")))
    names = [t.data.name for t in tasks]
    assert names == sorted(p.name for p in (REPO / "tasks").glob("*_2025_*") if p.is_dir())
    assert len({t.key for t in tasks}) == len(tasks)
    for t in tasks:
        assert isinstance(t, EvmPatchTask)
        assert type(t).NEEDS_CONTAINER
        assert t.data.workdir == "/work"
        assert t.data.reference_diff.strip()
        assert "run_poc.sh" in t.data.prompt_text
        assert t.data.name in t.data.tasks_dir or t.data.tasks_dir.endswith("tasks")


def test_task_ids_and_split_filters():
    one = list(EvmPatchTaskset(EvmPatchConfig(id="evmpatch-env", task_ids=["ngp_2025_09"])))
    assert [t.data.name for t in one] == ["ngp_2025_09"]
    with pytest.raises(ValueError):
        list(EvmPatchTaskset(EvmPatchConfig(id="evmpatch-env", split="test")))


def test_plugin_loader_resolves_the_package():
    taskset = vf.load_taskset(EvmPatchConfig(id="evmpatch-env"))
    assert isinstance(taskset, EvmPatchTaskset)
    assert [f.__name__ for f in next(iter(taskset)).hooks("reward")] == ["solved"]


def test_setup_bundle_withholds_the_hidden_suites():
    import io
    import tarfile

    task = next(iter(EvmPatchTaskset(EvmPatchConfig(id="evmpatch-env", task_ids=["mcai_2025_01"]))))
    with tarfile.open(fileobj=io.BytesIO(task._setup_bundle()), mode="r:gz") as tar:
        names = tar.getnames()
    assert "project/test/poc.t.sol" in names
    assert "state/rpc_log.json" in names and "rpc_replay.py" in names and "run_poc.sh" in names
    assert not any("hidden" in n or n.endswith("manifest.json") for n in names)
    assert not any("/out/" in n or "/cache/" in n for n in names)


@requires_image
@pytest.mark.parametrize("task_id", ["mcai_2025_01", "bitallx_2025_05"])
def test_validate_gold_and_noop_on_the_docker_runtime(task_id, tmp_path):
    from verifiers.v1.cli.validate import run_validate
    from verifiers.v1.configs.cli.validate import ValidateConfig

    config = ValidateConfig(
        taskset=EvmPatchConfig(id="evmpatch-env", task_ids=[task_id], image=IMAGE),
        runtime=vf.DockerConfig(image=IMAGE),
        only_gold=True,
        max_concurrent=1,
        rich=False,
        output_dir=tmp_path,
    )
    rows = asyncio.run(run_validate(config))
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["name"] == task_id
    assert row["valid"] is True, json.dumps(row, indent=1)
