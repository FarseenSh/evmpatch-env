#!/bin/sh
# In-container reward entrypoint. Runs with NO network (`docker run --network none`).
#
# Mounts (see sandbox.reward_docker):
#   /work              = episode workdir (project + hash-locked tests), assembled on the
#                        HOST during the fork/replay SETUP stage — this stage is the only
#                        one that ever needed a network, and it has already finished.
#   /state             = the task's frozen state (read-only): rpc_log.json
#   /opt/rpc_replay.py = the fail-closed replay proxy (read-only)
#
# It starts the replay proxy on a FREE loopback port, runs the PoC and hidden suites with
# `forge test --json`, and prints ONE RAW payload between BEGIN_RESULT/END_RESULT:
#
#   {"proxy_up": bool,
#    "poc":    {"returncode": int, "stdout": str, "stderr": str, "misses": [...]},
#    "hidden": {... same ...}}
#
# It deliberately does NO parsing and NO scoring. sandbox.py parses this payload with the
# same parse_forge_json()/score() functions the local backend uses, so the two backends
# cannot drift apart and a container cannot talk its way to a reward.
set -eu

exec python3 - <<'PY'
import json, os, socket, subprocess, sys, time

STATE = "/state/rpc_log.json"
PORT_FILE = "/tmp/proxy.port"
MISS_FILE = "/tmp/rpc_misses.json"

# A bind mount of a host path the container runtime does not share does NOT error: the
# mount point is simply empty (macOS Docker Desktop only shares a configured set of host
# paths). Name that failure instead of letting it surface as "forge found nothing".
missing = [p for p in ("/work/foundry.toml", "/work/test/poc.t.sol", STATE)
           if not os.path.exists(p)]
if missing:
    print("BEGIN_RESULT")
    print(json.dumps({"proxy_up": None, "mount_error": missing}))
    print("END_RESULT")
    sys.exit(0)

proxy = subprocess.Popen(
    ["python3", "/opt/rpc_replay.py", "replay", STATE, "0",
     "--port-file", PORT_FILE, "--miss-file", MISS_FILE],
    stdout=subprocess.DEVNULL, stderr=open("/tmp/replay.log", "wb"),
)


def port_open(p):
    s = socket.socket(); s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", p)); return True
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
    print("BEGIN_RESULT"); print(json.dumps({"proxy_up": False})); print("END_RESULT")
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
                         cwd="/work", capture_output=True, text=True, env=env)
    fresh, cursor = misses(cursor)
    return {"returncode": out.returncode,
            "stdout": out.stdout[-400000:], "stderr": out.stderr[-40000:],
            "misses": fresh}, cursor


cursor = 0
poc, cursor = run("test/poc.t.sol", cursor)
hidden, cursor = run("test/hidden/*", cursor)
proxy.terminate()

print("BEGIN_RESULT")
print(json.dumps({"proxy_up": True, "poc": poc, "hidden": hidden}))
print("END_RESULT")
PY
