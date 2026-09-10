"""Grading through a live verifiers runtime.

The `local` and `docker` backends in `sandbox.py` bind-mount an assembled episode
workdir into a fresh `docker run --network none` container. A verifiers v1 runtime is a
long-lived container with no mounts, so the same graded step travels as a tarball:

1. the host assembles the episode workdir (project + hash-locked harness + the agent's
   patch) and re-verifies every harness hash inside it (`sandbox.assemble_workdir`,
   `sandbox.verify_workdir_harness`);
2. the workdir, the frozen chain state and the replay proxy are uploaded into a fresh
   uuid-named directory of the runtime, never into the agent's working tree;
3. an in-container script starts the fail-closed replay proxy on loopback, runs the
   proof-of-concept and the hidden suites with `forge test --json`, and prints one raw
   payload between `BEGIN_RESULT` and `END_RESULT`;
4. the host parses and scores that payload with the same functions every other backend
   uses (`sandbox.parse_forge_json`, `sandbox.score`).

The container does no judging, so a container the agent has touched cannot talk its way
to a reward: the harness it grades against is re-staged from the host copy, and the only
thing the agent contributes is the patchable source read back at finalize time.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import shlex
import shutil
import tarfile
import tempfile
import uuid
from pathlib import Path

from . import sandbox
from .sandbox import (
    HARD_CANARIES,
    R_BACKEND_ERROR,
    R_MANIFEST_MISSING,
    R_PROXY_START,
    R_TIMEOUT,
    ForgeRun,
    RewardResult,
    assemble_workdir,
    check_scope_and_canaries,
    load_manifest,
    parse_forge_json,
    score,
    verify_workdir_harness,
)

BACKEND = "runtime"
GRADE_ROOT = "/tmp/evmpatch-grade"
EXCLUDED_DIRS = {"out", "cache", "__pycache__", ".git"}

# Runs inside the runtime with `python3 grade_entry.py <dir>`. Mirrors reward_entry.sh with
# directories in place of mounts: <dir>/work is the assembled episode workdir,
# <dir>/state/rpc_log.json the frozen state, <dir>/rpc_replay.py the replay proxy.
GRADE_SCRIPT = r'''
import json, os, socket, subprocess, sys, time

ROOT = sys.argv[1]
WORK = os.path.join(ROOT, "work")
STATE = os.path.join(ROOT, "state", "rpc_log.json")
REPLAY = os.path.join(ROOT, "rpc_replay.py")
PORT_FILE = os.path.join(ROOT, "proxy.port")
MISS_FILE = os.path.join(ROOT, "rpc_misses.json")


def emit(payload):
    print("BEGIN_RESULT")
    print(json.dumps(payload))
    print("END_RESULT")
    sys.stdout.flush()


missing = [p for p in (os.path.join(WORK, "foundry.toml"), os.path.join(WORK, "test", "poc.t.sol"),
                       STATE, REPLAY) if not os.path.exists(p)]
if missing:
    emit({"proxy_up": None, "missing": missing})
    sys.exit(0)

proxy = subprocess.Popen(
    [sys.executable, REPLAY, "replay", STATE, "0", "--port-file", PORT_FILE, "--miss-file", MISS_FILE],
    stdout=subprocess.DEVNULL, stderr=open(os.path.join(ROOT, "replay.log"), "wb"),
)


def port_open(p):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", p))
        return True
    except Exception:
        return False
    finally:
        s.close()


bound = None
deadline = time.time() + 20
while time.time() < deadline:
    if proxy.poll() is not None:
        break
    if os.path.exists(PORT_FILE):
        try:
            p = int(open(PORT_FILE).read().strip())
        except Exception:
            p = 0
        if p and port_open(p):
            bound = p
            break
    time.sleep(0.05)

if bound is None:
    proxy.kill()
    emit({"proxy_up": False})
    sys.exit(0)

env = dict(os.environ)
env["TASK_FORK_URL"] = "http://127.0.0.1:%d" % bound
env["FOUNDRY_OFFLINE"] = "true"
env["FOUNDRY_NO_STORAGE_CACHING"] = "true"
env["NO_COLOR"] = "1"


def misses(since):
    try:
        data = json.load(open(MISS_FILE))
    except Exception:
        return [], since
    m = data.get("misses", [])
    return m[since:], len(m)


def run(match_path, cursor):
    out = subprocess.run(["forge", "test", "--match-path", match_path, "--json"],
                         cwd=WORK, capture_output=True, text=True, env=env)
    fresh, cursor = misses(cursor)
    return {"returncode": out.returncode,
            "stdout": out.stdout[-400000:], "stderr": out.stderr[-40000:],
            "misses": fresh}, cursor


cursor = 0
poc, cursor = run("test/poc.t.sol", cursor)
hidden, cursor = run("test/hidden/*", cursor)
proxy.terminate()
emit({"proxy_up": True, "poc": poc, "hidden": hidden})
'''


def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if any(part in EXCLUDED_DIRS for part in Path(info.name).parts):
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def make_tar(root: Path, arcname: str = ".") -> bytes:
    """gzip tarball of `root` with build artifacts left out and ownership neutralised."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(str(root), arcname=arcname, filter=_tar_filter)
    return buf.getvalue()


def _bundle(task_dir: Path, patched_src, manifest, changed, canaries, task_id):
    """Assemble and verify the episode on the host; return the bundle bytes or a grade."""
    empty = ForgeRun(ran=False)
    host = Path(tempfile.mkdtemp(prefix="evmpatch-grade-"))
    try:
        work = host / "work"
        try:
            assemble_workdir(task_dir, patched_src, work)
        except ValueError as exc:                      # unsafe key that the scope check missed
            return score(empty, empty, manifest, changed,
                         list(canaries) + [f"out_of_scope_edit:{exc}"], BACKEND, task_id)
        tampered = verify_workdir_harness(task_dir, work)
        if tampered:
            return score(empty, empty, manifest, changed, list(canaries) + tampered, BACKEND, task_id)
        (host / "state").mkdir()
        shutil.copy2(task_dir / "state" / "rpc_log.json", host / "state" / "rpc_log.json")
        shutil.copy2(sandbox.RPC_REPLAY, host / "rpc_replay.py")
        (host / "grade_entry.py").write_text(GRADE_SCRIPT)
        return make_tar(host)
    finally:
        shutil.rmtree(host, ignore_errors=True)


async def grade_in_runtime(task_dir, patched_src, runtime, *, root: str = GRADE_ROOT,
                           timeout_s: float = 900.0) -> RewardResult:
    """Grade `patched_src` (project-relative path -> content, or None for the shipped
    source) for the task at `task_dir` inside `runtime`, and return the same
    `RewardResult` the local and docker backends produce."""
    task_dir = Path(task_dir).resolve()
    task_id = json.loads((task_dir / "task.json").read_text()).get("task_id", task_dir.name)
    changed, canaries = check_scope_and_canaries(task_dir, patched_src)
    empty = ForgeRun(ran=False)
    if any(c.split(":")[0] in HARD_CANARIES for c in canaries):
        return score(empty, empty, None, changed, canaries, BACKEND, task_id)
    try:
        manifest = load_manifest(task_dir)
    except Exception as exc:
        return score(empty, empty, None, changed, canaries, BACKEND, task_id,
                     infra_reason=R_MANIFEST_MISSING, infra_detail=str(exc))

    bundle = await asyncio.to_thread(_bundle, task_dir, patched_src, manifest, changed, canaries, task_id)
    if isinstance(bundle, RewardResult):
        return bundle

    def infra(reason: str, detail: str) -> RewardResult:
        return score(empty, empty, manifest, changed, canaries, BACKEND, task_id,
                     infra_reason=reason, infra_detail=detail)

    remote = f"{root}/{uuid.uuid4().hex}"
    try:
        await runtime.write(f"{remote}/bundle.tgz", bundle)
        staged = await runtime.run(
            ["sh", "-c", f"cd {shlex.quote(remote)} && tar -xzf bundle.tgz && rm -f bundle.tgz"], {})
        if staged.exit_code:
            return infra(R_BACKEND_ERROR,
                         f"staging the graded workdir failed: {(staged.stderr or staged.stdout).strip()[-500:]}")
        try:
            out = await asyncio.wait_for(
                runtime.run(["python3", f"{remote}/grade_entry.py", remote], {}), timeout_s)
        except asyncio.TimeoutError:
            return infra(R_TIMEOUT, "grading exceeded its wall clock inside the runtime")
    finally:
        with contextlib.suppress(Exception):
            await runtime.run(["rm", "-rf", remote], {})

    m = re.search(r"BEGIN_RESULT\n(.*)\nEND_RESULT", out.stdout, re.S)
    if not m:
        return infra(R_BACKEND_ERROR,
                     f"runtime produced no result payload (rc={out.exit_code}): "
                     + (out.stdout + out.stderr)[-500:])
    payload = json.loads(m.group(1))
    if payload.get("missing"):
        return infra(R_BACKEND_ERROR,
                     "graded workdir incomplete inside the runtime; missing: " + ", ".join(payload["missing"]))
    if payload.get("proxy_up") is False:
        return infra(R_PROXY_START, "in-runtime replay proxy did not bind")
    runs = {}
    for label in ("poc", "hidden"):
        raw = payload.get(label) or {}
        run = parse_forge_json(raw.get("stdout", ""), raw.get("stderr", ""), raw.get("returncode"))
        misses = raw.get("misses") or []
        run.rpc_misses = [x for x in misses if not x.get("benign")]
        run.benign_rpc_misses = len(misses) - len(run.rpc_misses)
        runs[label] = run
    return score(runs["poc"], runs["hidden"], manifest, changed, canaries, BACKEND, task_id)
