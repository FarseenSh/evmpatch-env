#!/usr/bin/env python3
"""Record-and-replay JSON-RPC proxy for offline fork replay.

BUILD TIME (network):  rpc_replay.py record  <upstream> <log.json> [port] [opts]
REWARD TIME (no net):  rpc_replay.py replay   <log.json>      [port] [opts]

<upstream> is a URL, or the literal form `env:NAME` to read it from environment variable
NAME. Archive endpoints carry an API key in the path, and an argv element is world-readable
in `ps`; `env:NAME` keeps the key out of the process listing. Prefer it when recording.

Keys responses by (method, canonical(params)). In replay mode the process makes
NO outbound connections; an unrecorded request returns a JSON-RPC error so the
sandbox fails closed rather than silently reaching the network.

Options (both modes):
  --port-file PATH   write the actually-bound port to PATH. Pass port 0 to let the OS
                     choose a free port — this is how the sandbox avoids the shared
                     :8545 collision under concurrency.
  --miss-file PATH   in replay mode, record every unrecorded (method, params) request
                     to PATH as JSON. The grader reads this file: a miss means the
                     frozen state was incomplete, which makes the episode INCONCLUSIVE
                     rather than letting an infrastructure failure look like a blocked
                     exploit. Some methods are pure capability probes that no
                     upstream answers (see BENIGN_PROBE_METHODS); they are still failed
                     closed but are flagged `benign` so the grader can ignore them.
"""
import json, sys, hashlib, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request, urllib.error

# Methods a modern Foundry probes for optimistically and degrades from gracefully when
# the upstream does not implement them. They are never present in a recording made
# against a public endpoint, so treating their absence as "incomplete frozen state"
# would make every episode inconclusive. They are still answered with an error
# (fail-closed); they are only exempted from the grader's completeness check.
BENIGN_PROBE_METHODS = {
    "eth_getAccountInfo",
    "eth_getProof",
    "otterscan_getApiLevel",
    "erigon_getHeaderByNumber",
    "debug_getRawHeader",
}

_argv = sys.argv[1:]
_opts: dict[str, str] = {}
_pos: list[str] = []
_i = 0
while _i < len(_argv):
    if _argv[_i] in ("--port-file", "--miss-file"):
        _opts[_argv[_i]] = _argv[_i + 1]
        _i += 2
    else:
        _pos.append(_argv[_i])
        _i += 1

MODE = _pos[0]
if MODE == "record":
    UPSTREAM, LOG = _pos[1], _pos[2]
    if UPSTREAM.startswith("env:"):          # keep the key out of the process listing
        _var = UPSTREAM[4:]
        UPSTREAM = os.environ.get(_var, "")
        if not UPSTREAM:
            sys.stderr.write(f"[rpc_replay:record] ${_var} is unset\n")
            sys.exit(2)
    PORT = int(_pos[3]) if len(_pos) > 3 else 8545
else:
    LOG = _pos[1]
    PORT = int(_pos[2]) if len(_pos) > 2 else 8545
    UPSTREAM = None
PORT_FILE = _opts.get("--port-file")
MISS_FILE = _opts.get("--miss-file")

_lock = threading.Lock()
_miss_lock = threading.Lock()
CACHE = {}
MISSES: list = []
HITS = 0
if MODE == "replay" or (MODE == "record" and os.path.exists(LOG)):
    try:
        CACHE = json.load(open(LOG))
    except Exception:
        CACHE = {}


def key(method, params):
    return hashlib.sha256((method + "|" + json.dumps(params, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


def _flush_misses():
    if not MISS_FILE:
        return
    try:
        tmp = MISS_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"hits": HITS, "misses": MISSES}, fh)
        os.replace(tmp, MISS_FILE)
    except Exception:
        pass


def _record_miss(method, params):
    with _miss_lock:
        MISSES.append({
            "method": method,
            "params": json.dumps(params)[:200],
            "benign": method in BENIGN_PROBE_METHODS,
        })
        _flush_misses()


def upstream_call(payload):
    last = None
    for attempt in range(5):
        try:
            req = urllib.request.Request(UPSTREAM, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/json",
                                                  "User-Agent": "Mozilla/5.0 (compatible; foundry-anvil)"})
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="ignore")
            try:  # a JSON-RPC error body is a valid response, return it
                return json.loads(body)
            except Exception:
                last = f"HTTP {e.code}"
                if e.code in (429, 503, 502, 500):  # transient: back off and retry
                    time.sleep(1.5 * (attempt + 1)); continue
                break
        except Exception as e:
            last = type(e).__name__; time.sleep(1.0 * (attempt + 1)); continue
    return {"error": {"code": -32000, "message": f"upstream failed: {last}"}}


def handle_one(obj):
    global HITS
    m, p, rid = obj.get("method"), obj.get("params", []), obj.get("id")
    k = key(m, p)
    if k in CACHE:
        with _miss_lock:
            HITS += 1
        return {"jsonrpc": "2.0", "id": rid, "result": CACHE[k]}
    if MODE == "replay":
        _record_miss(m, p)
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32000, "message": f"OFFLINE: unrecorded {m} {json.dumps(p)[:80]}"}}
    resp = upstream_call(obj)
    if "result" in resp:
        with _lock:
            CACHE[k] = resp["result"]
            tmp = LOG + ".tmp"
            # Explicit close + fsync before the rename. Relying on refcount GC to flush
            # `open(tmp, "w")` before os.replace is a silent data-loss hazard for a
            # recording that must be COMPLETE to be usable.
            with open(tmp, "w") as fh:
                json.dump(CACHE, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, LOG)
    return resp


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n).decode())
            out = [handle_one(o) for o in body] if isinstance(body, list) else handle_one(body)
            data = json.dumps(out).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            try:
                data = json.dumps({"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32603, "message": f"proxy: {e}"}}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers()
                self.wfile.write(data)
            except Exception:
                pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    bound = srv.server_address[1]
    if MISS_FILE:
        _flush_misses()          # create the file immediately so a reader never races it
    if PORT_FILE:
        tmp = PORT_FILE + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(str(bound))
        os.replace(tmp, PORT_FILE)
    sys.stderr.write(f"[rpc_replay:{MODE}] :{bound} entries={len(CACHE)}\n"); sys.stderr.flush()
    srv.serve_forever()
