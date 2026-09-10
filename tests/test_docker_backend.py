"""The `docker run --network none` backend.

Two-stage design: the fork/replay SETUP stage (recording chain state, assembling the
episode workdir) runs on the HOST and is the only stage that ever needed a network; the
GRADED stage — compile the agent's patch, run the exploit, run the hidden tests — runs
inside a container with no network interface at all.

Skipped when Docker or the image is unavailable, so the rest of the suite still runs.
Build the image first:  docker build -t evmpatch-env:latest .
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from evmpatch_env import sandbox

from conftest import TOKEN_REL

IMAGE = "evmpatch-env:latest"


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    out = subprocess.run(["docker", "image", "inspect", IMAGE],
                         capture_output=True, text=True)
    return out.returncode == 0


requires_docker = pytest.mark.skipif(
    not _image_present(), reason=f"docker or the {IMAGE} image is unavailable")

pytestmark = requires_docker


def test_container_really_has_no_network():
    """The containment claim, checked rather than asserted: inside `--network none` there
    is no interface but loopback, and an outbound connect fails."""
    probe = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(3)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 443)); print('REACHED')\n"
        "except Exception as e: print('BLOCKED', type(e).__name__)\n"
    )
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python3",
         IMAGE, "-c", probe],
        capture_output=True, text=True, timeout=120)
    assert out.stdout.startswith("BLOCKED"), out.stdout + out.stderr


def test_docker_backend_grades_the_reference_patch(ngp_task, reference_patch):
    res = sandbox.compute_reward(ngp_task, {TOKEN_REL: reference_patch},
                                 backend="docker", image=IMAGE)
    assert res.outcome == sandbox.OUTCOME_SOLVED, (res.reason, res.reason_detail)
    assert res.score == 1.0 and res.backend == "docker"
    # The hidden count is the manifest's, not a literal: task_version 2 added four
    # security obligations to ngp_2025_09's suite (10 -> 14).
    expected = sandbox.load_manifest(ngp_task)["hidden"]["count"]
    assert res.hidden.passed == expected and res.hidden.failed == 0
    assert res.abi_invariants == {"bytecode_selectors": "Success",
                                  "dispatch_selectors": "Success",
                                  "dispatch_control": "Success",
                                  "not_vacuous": "Success"}


def test_docker_backend_grades_the_vulnerable_source(ngp_task):
    res = sandbox.compute_reward(ngp_task, None, backend="docker", image=IMAGE)
    assert res.outcome == sandbox.OUTCOME_NOT_SOLVED
    assert res.score == 0.0 and not res.poc_blocked


def test_docker_and_local_agree_on_the_canonical_grade(ngp_task, reference_patch):
    """The two backends run the same forge invocations and the SAME parser and scorer
    (the container emits a raw payload and does no judging), so their canonical grades
    must be identical."""
    local = sandbox.compute_reward(ngp_task, {TOKEN_REL: reference_patch}, backend="local")
    docker = sandbox.compute_reward(ngp_task, {TOKEN_REL: reference_patch},
                                    backend="docker", image=IMAGE)
    assert local.canonical() == docker.canonical()
    assert local.canonical_sha256() == docker.canonical_sha256()


def test_unshared_bind_mount_is_named_not_mistaken_for_a_grade(ngp_task, reference_patch,
                                                               monkeypatch, tmp_path):
    """A host path the container runtime does not share mounts as an EMPTY directory with
    no error. Without the mount check that looks like "forge found nothing"; it must be
    reported as a backend error and never scored."""
    empty = tmp_path / "not_a_task"
    (empty).mkdir()
    payload = json.dumps({"proxy_up": None, "mount_error": ["/work/foundry.toml"]})

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, f"BEGIN_RESULT\n{payload}\nEND_RESULT\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = sandbox.reward_docker(ngp_task, {TOKEN_REL: reference_patch}, image=IMAGE)
    assert res.outcome == sandbox.OUTCOME_INCONCLUSIVE
    assert res.reason == sandbox.R_BACKEND_ERROR
    assert res.reason_family == "runner_crash"
