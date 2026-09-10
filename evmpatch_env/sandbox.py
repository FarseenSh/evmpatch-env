#!/usr/bin/env python3
"""
sandbox.py — execution-verified reward + containment for evmpatch tasks.

THE SCORER.  The grade is a three-valued OUTCOME, not a bare boolean:

    solved        reward 1.0   the patch really blocked the exploit and kept the contract working
    not_solved    reward 0.0   the run produced valid evidence and the patch does not qualify
    inconclusive  reward 0.0   the run produced NO valid evidence (infrastructure fault,
                               compile fault, crashed runner, incomplete frozen state,
                               missing/extra tests, timeout).  `reason` says which.

`inconclusive` exists so that "the exploit was blocked" is never confused with "the
exploit test blew up".  Anything that is not positive evidence of a repair lands here, is
flagged, and is never rewarded.

A patch is `solved` iff ALL hold:
  (a) the PoC exploit oracle EXECUTED and FAILED in its body   (the exploit is blocked)
  (b) every hidden test named in the manifest PASSED           (functionality preserved)
  (c) the project COMPILED and forge produced a machine-readable report
  (d) the executed test-id set EXACTLY equals the task manifest (no missing, no extra)
  (e) the diff touches ONLY allow-listed source
  (f) no canary fired, no unrecorded RPC, and the runner exited cleanly

Reward-hack and fault shapes the scorer closes (tests/test_scorer_probes.py pins each
with a synthetic probe):
  1. An RPC / setup / unrecorded-storage failure of `testExploit` is not a blocked
     exploit.  `poc_blocked` requires the oracle test to have run to a *body* failure
     (assertion, or a revert on the exploit path such as an unrepayable flash loan); a
     setUp failure or an infrastructure-flavoured revert reason is `inconclusive` instead.
  2. "Some hidden tests passed and none failed" is not the hidden gate.  Scoring requires
     an exact-set match against `tasks/<id>/tests/manifest.json`, plus the subprocess
     return code.
  3. Test ids are fully qualified `<file>:<contract>:<fn>`, so a PASS in one suite can
     never overwrite a FAIL of the same name in another.
  4. The grade is read from `forge test --json` (verified against forge 1.7.1); the text
     parser survives only as a fallback that sets `structured=False` and can therefore
     NEVER yield `solved`.

Containment (production `docker` backend):
  * reward runs in `docker run --network none` — the container has NO network. The
    frozen chain state is served by an in-container record/replay proxy (rpc_replay.py
    in `replay` mode) that fails CLOSED: any RPC the recording does not contain returns
    a JSON-RPC error, so a patch cannot reach the real chain to fake a fix.  Every miss
    is counted, and a non-benign miss makes the episode `inconclusive`.
  * harness files (tests/**, tests/manifest.json, foundry.toml, remappings.txt) are
    hash-locked from task.json and reassembled read-only for every episode — the agent's
    patch is applied ONLY to project/src, so it can never edit the oracle.
  * non-root user, read-only state mount, wall-clock timeout.
  * `FOUNDRY_NO_STORAGE_CACHING=true` on every forge invocation, so a grade can never be
    served out of the *host's* global `~/.foundry/cache/rpc` — the shipped
    `state/rpc_log.json` is the only source of chain data.  This is what makes the same
    task grade byte-identically on two different machines (see RECEIPT.md).

Canaries (each forces score 0 and is recorded in result.canaries):
  * poc_tampered      — poc.t.sol hash != task.json lock (delete/skip/neuter the PoC)
  * harness_tampered  — foundry.toml / remappings / manifest / any hidden test mismatch
  * out_of_scope_edit — patch changed a path outside patchable_globs
  * bricked           — PoC "fails" only because the contract was bricked (functional hidden
                        test fails too)
  * residual_vulnerability — the PoC was blocked but a hidden test the manifest declares as a
                        SECURITY obligation still fails: the repair is incomplete, not broken
  * empty_patch       — no source change at all (vacuous)

Two further shapes, closed by the patch-key and security-obligation checks:
  5. A patch key is never matched against `patchable_globs` with plain `fnmatch`, whose
     `*` crosses `/` (under it `src/contracts/../../test/poc.t.sol` would match
     `src/contracts/*.sol` and the write would land on the hash-locked PoC inside the
     episode workdir: a `solved` for a patch that rewrote the oracle). Patch keys are
     normalised and REJECTED outright if they are absolute or contain a `..` segment
     (`normalise_patch_key`), the glob is matched per path SEGMENT (`glob_match`), a symlink
     that leaves `project/` is rejected, and after the workdir is assembled every hash-locked
     harness file is re-verified IN THE WORKDIR (`verify_workdir_harness`) — so a write that
     ever reached a harness file is caught even if the key check missed it.
  6. An INCOMPLETE repair and a BROKEN contract are reported differently. `tests/manifest.json`
     may list `hidden.security_tests` (a subset of `hidden.tests`); those are the ones that
     fail on the vulnerable contract, and a failure confined to them is
     `residual_vulnerability` rather than `bricked`. `RewardResult.functional_all_pass` is
     the "the contract still works" half.

The `local` backend runs the identical forge pipeline directly on localhost with the
replay proxy bound to a free port (still no outbound network — the proxy fails closed).
It exists for CI/dev verification on a box without Docker; the `docker` backend is the
production containment path. `RewardResult.backend` records which ran.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RPC_REPLAY = HERE / "rpc_replay.py"
# The container entrypoint ships inside the package in an installed wheel and at the
# repository root in a source checkout.
REWARD_ENTRY = (HERE / "reward_entry.sh") if (HERE / "reward_entry.sh").exists() \
    else HERE.parent / "reward_entry.sh"

# ----------------------------------------------------------------------- reason codes
# Every `inconclusive` grade carries exactly one of these.
R_COMPILE_FAILED = "compile_failed"          # solc rejected the project
R_NO_REPORT = "no_structured_report"         # forge produced no machine-readable report
R_RUNNER_CRASH = "runner_crash"              # forge died / exited with an unexpected code
R_SETUP_FAILED = "setup_failed"              # a suite's setUp() reverted (fork, etch, ...)
R_UNRECORDED_RPC = "unrecorded_rpc"          # the frozen state did not cover the run
R_PROXY_START = "proxy_start_failed"         # replay proxy never came up
R_MISSING_TESTS = "missing_tests"            # manifest ids absent from the report
R_UNEXPECTED_TESTS = "unexpected_tests"      # report contains ids not in the manifest
R_TESTS_SKIPPED = "tests_skipped"            # a graded test was skipped
R_TIMEOUT = "timeout"                        # wall-clock budget exhausted
R_MANIFEST_MISSING = "manifest_missing"      # task ships no usable tests/manifest.json
R_BACKEND_ERROR = "backend_error"            # docker/container plumbing failed
R_UNRECOGNISED = "unrecognised_failure"      # oracle failed for a reason the task never declared

# The precise codes above roll up into the coarse vocabulary an operator triages on.
REASON_FAMILY = {
    R_COMPILE_FAILED: "compile_failed",
    R_PROXY_START: "anvil_start_failed",
    R_UNRECORDED_RPC: "unrecorded_rpc",
    R_RUNNER_CRASH: "runner_crash",
    R_NO_REPORT: "runner_crash",
    R_BACKEND_ERROR: "runner_crash",
    R_MISSING_TESTS: "manifest_mismatch",
    R_UNEXPECTED_TESTS: "manifest_mismatch",
    R_TESTS_SKIPPED: "manifest_mismatch",
    R_MANIFEST_MISSING: "manifest_mismatch",
    R_SETUP_FAILED: "anvil_start_failed",
    R_TIMEOUT: "timeout",
    R_UNRECOGNISED: "unrecognised_failure",
}

OUTCOME_SOLVED = "solved"
OUTCOME_NOT_SOLVED = "not_solved"
OUTCOME_INCONCLUSIVE = "inconclusive"

# Failure reasons that mean "the harness broke", not "the exploit was blocked".
# Matched case-insensitively against the forge `reason` string of a failing test.
_INFRA_REASON_PATTERNS = [
    r"unrecorded",
    r"\brpc\b",
    r"json-?rpc",
    r"could not instantiate forked",
    r"error sending request",
    r"connection (refused|reset|closed)",
    r"failed to get (account|storage|block|code|transaction|nonce|balance)",
    r"failed to (fetch|load|resolve)",
    r"backend:",
    r"provider error",
    r"middleware error",
    r"deserialization error",
    r"transport error",
    r"could not (fetch|instantiate|create)",
    r"no such file",
    r"getDeployedCode",
    r"timed out",
    r"operation timed out",
]
_INFRA_REASON_RE = re.compile("|".join(_INFRA_REASON_PATTERNS), re.I)
_ASSERTION_RE = re.compile(r"assertion failed|assertGt|assertEq|assertTrue|assertLt", re.I)


# ----------------------------------------------------------------------------- results
@dataclass
class TestOutcome:
    """One executed test, addressed by a FULLY QUALIFIED id."""
    id: str                 # "test/poc.t.sol:NGP_PoC:testExploit()"
    suite: str              # "test/poc.t.sol:NGP_PoC"
    name: str               # "testExploit()"
    status: str             # "Success" | "Failure" | "Skipped"
    reason: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "Success"


@dataclass
class ForgeRun:
    """The result of ONE `forge test` invocation, structured."""
    ran: bool = False                 # the subprocess was launched
    structured: bool = False          # a machine-readable report was parsed
    compiled: bool = False
    returncode: int | None = None
    timed_out: bool = False
    tests: dict = field(default_factory=dict)           # fq id -> TestOutcome
    setup_failures: dict = field(default_factory=dict)  # suite -> reason
    rpc_misses: list = field(default_factory=list)      # non-benign only
    benign_rpc_misses: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""

    # -- convenience -----------------------------------------------------------------
    @property
    def passed(self) -> int:
        return sum(1 for t in self.tests.values() if t.status == "Success")

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tests.values() if t.status == "Failure")

    @property
    def skipped(self) -> int:
        return sum(1 for t in self.tests.values() if t.status == "Skipped")

    @property
    def ids(self) -> set:
        return set(self.tests)

    def by_name(self) -> dict:
        """Legacy short-name view, for human-facing tool output ONLY. Never scored on:
        two suites can share a function name and this view loses one of them."""
        return {t.name.rstrip("()"): t.passed for t in self.tests.values()}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["passed"], d["failed"], d["skipped"] = self.passed, self.failed, self.skipped
        return d


@dataclass
class RewardResult:
    score: float
    outcome: str                       # solved | not_solved | inconclusive
    backend: str
    task_id: str = ""
    reason: str = ""                   # reason code; "" when the run was conclusive
    reason_family: str = ""            # coarse triage bucket for `reason`
    reason_detail: str = ""
    solved: bool = False               # == (outcome == "solved"); kept for old callers
    poc_blocked: bool = False          # (a)
    hidden_all_pass: bool = False      # (b)
    # (b') the FUNCTIONAL half of (b): every hidden test that is not declared a security
    # obligation. It holds on the vulnerable contract too, so `functional_all_pass and not
    # hidden_all_pass` is exactly "the contract still works, the repair is incomplete".
    # Deliberately NOT part of canonical(): adding a field there would change the receipt
    # hash of every task.
    functional_all_pass: bool = False
    compiled: bool = False             # (c)
    tests_match_manifest: bool = False  # (d)
    diff_in_scope: bool = False        # (e)
    canaries: list = field(default_factory=list)
    changed_files: list = field(default_factory=list)
    poc_failure_kind: str = ""         # assertion | revert | setup | infra | none
    # The ABI-preservation evidence, recorded as TWO independent checks.
    # A PUSH4 immediate in the runtime bytecode is necessary but not sufficient (dead
    # data, proxy/fallback dispatch), so the hidden suite also CALLS every required
    # function and checks the contract does not answer "no such function".
    abi_invariants: dict = field(default_factory=dict)   # check name -> status
    poc: object = None                 # ForgeRun | None
    hidden: object = None              # ForgeRun | None
    detail: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["poc"] = self.poc.to_dict() if self.poc else None
        d["hidden"] = self.hidden.to_dict() if self.hidden else None
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    # ------------------------------------------------------------------ receipt form
    def canonical(self, core_only: bool = False) -> dict:
        """Host-independent view of the grade, for cross-machine reproducibility.

        Everything volatile is dropped: timings, gas, ports, temp paths, raw logs,
        the backend name, return codes. What remains is the decision and the evidence
        it was made from — outcome, reason, component booleans, canaries, changed
        files, and the per-test id -> (status, reason) map. Two hosts that agree on
        this dict agree on the grade.
        """
        def tests_of(run) -> dict:
            if run is None:
                return {}
            return {tid: [t.status, t.reason or ""] for tid, t in sorted(run.tests.items())}

        def setups_of(run) -> dict:
            if run is None:
                return {}
            return dict(sorted((run.setup_failures or {}).items()))

        core = {
            "schema": "evmpatch.grade/1",
            "task_id": self.task_id,
            "outcome": self.outcome,
            "score": self.score,
            "reason": self.reason,
            "reason_family": self.reason_family,
            "poc_blocked": self.poc_blocked,
            "poc_failure_kind": self.poc_failure_kind,
            "hidden_all_pass": self.hidden_all_pass,
            "compiled": self.compiled,
            "tests_match_manifest": self.tests_match_manifest,
            "diff_in_scope": self.diff_in_scope,
            "abi_invariants": dict(sorted(self.abi_invariants.items())),
            "canaries": sorted(self.canaries),
            "changed_files": sorted(self.changed_files),
            "poc_tests": {k: v[0] for k, v in tests_of(self.poc).items()},
            "hidden_tests": {k: v[0] for k, v in tests_of(self.hidden).items()},
        }
        if core_only:
            return core
        # The strict form additionally pins the revert/assertion REASON of every failing
        # test and of any setUp failure. Two hosts on the same toolchain agree on these;
        # a mismatch between the core and strict hashes localises a toolchain difference
        # rather than a grade difference.
        return {
            **core,
            "schema": "evmpatch.grade/1+reasons",
            "poc_tests": tests_of(self.poc),
            "hidden_tests": tests_of(self.hidden),
            "poc_setup_failures": setups_of(self.poc),
            "hidden_setup_failures": setups_of(self.hidden),
        }

    def canonical_json(self, core_only: bool = False) -> str:
        return json.dumps(self.canonical(core_only), sort_keys=True, separators=(",", ":"))

    def canonical_sha256(self, core_only: bool = False) -> str:
        return hashlib.sha256(self.canonical_json(core_only).encode()).hexdigest()


# ---------------------------------------------------------------------------- helpers
def _sha256(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def episode_root(for_docker: bool = False) -> Path:
    """Where a per-episode workdir lives. Always uuid-named underneath.

    `EVMPATCH_EPISODE_ROOT` overrides. The docker default is deliberately NOT the system
    temp dir: on macOS, Docker Desktop only shares a fixed set of host paths (typically
    just /Users), and `tempfile.gettempdir()` returns a per-user /var/folders path that is
    NOT shared. Bind-mounting an unshared path does not error — the container simply sees
    an EMPTY directory, which would otherwise surface as an unexplained grade. Defaulting to a
    directory under $HOME keeps the mount real on macOS and Linux alike.
    """
    override = os.environ.get("EVMPATCH_EPISODE_ROOT")
    if override:
        root = Path(override)
    elif for_docker:
        root = Path.home() / ".cache" / "evmpatch-episodes"
    else:
        root = Path(tempfile.gettempdir())
    root.mkdir(parents=True, exist_ok=True)
    return root


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def classify_failure_reason(reason) -> str:
    """'infra' | 'assertion' | 'revert' for the reason string of a FAILING test."""
    if not reason:
        return "revert"
    if _INFRA_REASON_RE.search(reason):
        return "infra"
    if _ASSERTION_RE.search(reason):
        return "assertion"
    return "revert"


# ------------------------------------------------------------------------- manifest
def load_manifest(task_dir) -> dict | None:
    """tasks/<id>/tests/manifest.json — the expected-test contract for a task.

    {
      "version": 1,
      "id_format": "<test file>:<contract>:<function signature>",
      "poc":    {"exploit_oracle": "<id>", "tests": ["<id>", ...], "count": N,
                 "accepted_block_kinds": ["assertion", "revert"]},
      "hidden": {"tests": ["<id>", ...], "count": N,
                 "security_tests": ["<id>", ...]}     # optional, subset of hidden.tests
    }

    `hidden.security_tests` names the hidden tests that assert the SECURITY property rather
    than legitimate use: they fail on the vulnerable contract by construction and must pass
    for a repair to be credited. Splitting them out is what lets the grade say
    `residual_vulnerability` (an incomplete fix) instead of `bricked` (a broken contract).
    """
    p = Path(task_dir) / "tests" / "manifest.json"
    if not p.exists():
        return None
    m = json.loads(p.read_text())
    for section in ("poc", "hidden"):
        ids = m.get(section, {}).get("tests", [])
        declared = m.get(section, {}).get("count")
        if declared is not None and declared != len(ids):
            raise ValueError(f"manifest {section}.count={declared} but {len(ids)} ids listed")
        if len(set(ids)) != len(ids):
            raise ValueError(f"manifest {section}.tests contains duplicate ids")
    if m["poc"]["exploit_oracle"] not in m["poc"]["tests"]:
        raise ValueError("manifest poc.exploit_oracle is not listed in poc.tests")
    stray = sorted(set(m["hidden"].get("security_tests") or []) - set(m["hidden"]["tests"]))
    if stray:
        raise ValueError(f"manifest hidden.security_tests not listed in hidden.tests: {stray}")
    return m


# ------------------------------------------------------------------- patch path keys
_UNSAFE_DISPLAY_RE = re.compile(r"[\x00-\x1f\x7f]")


def _display(rel) -> str:
    """A patch key is untrusted text. It ends up in canary strings and in the grade JSON,
    never in a filesystem path, and never with control characters in it."""
    return _UNSAFE_DISPLAY_RE.sub("?", str(rel))[:120]


def normalise_patch_key(rel):
    """Project-relative POSIX key for one patch entry, or None when the key escapes.

    An agent addresses a patchable file by a path relative to `project/`. Anything that can
    leave that directory — an absolute path, a Windows drive or UNC prefix, any `..`
    segment, an embedded NUL — is REJECTED rather than normalised away: a key that needs
    normalising to be safe is never a legitimate patch, and normalising-and-accepting is
    exactly how a key such as `src/contracts/../../test/poc.t.sol` would reach the
    hash-locked PoC. `.` segments and duplicate slashes are cosmetic and are collapsed.
    """
    if not isinstance(rel, str) or not rel or "\x00" in rel:
        return None
    key = rel.replace("\\", "/")
    if key.startswith("/") or key.startswith("//") or re.match(r"^[A-Za-z]:", key):
        return None
    parts = [p for p in key.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def glob_match(key: str, pattern: str) -> bool:
    """Match a normalised patch key against a `patchable_globs` pattern, PER SEGMENT.

    `fnmatch` treats the whole key as one string, so its `*` crosses `/`: that is why
    `src/contracts/*.sol` accepted `src/contracts/../../test/poc.t.sol` (and would accept
    `src/contracts/nested/dir/evil.sol`). Here `*` and `?` never cross a `/`; `**` is
    supported as "any number of segments" so a task may still opt into a subtree.
    """
    return _seg_match(key.split("/"), pattern.replace("\\", "/").split("/"))


def _seg_match(key_parts, pat_parts) -> bool:
    if not pat_parts:
        return not key_parts
    if pat_parts[0] == "**":
        return any(_seg_match(key_parts[i:], pat_parts[1:])
                   for i in range(len(key_parts) + 1))
    if not key_parts:
        return False
    return (fnmatch.fnmatchcase(key_parts[0], pat_parts[0])
            and _seg_match(key_parts[1:], pat_parts[1:]))


def _escapes(root: Path, candidate: Path) -> bool:
    """True when `candidate` resolves outside `root` (symlinks followed, tail may not exist)."""
    try:
        root_real = Path(os.path.realpath(root))
        real = Path(os.path.realpath(candidate))
    except OSError:
        return True
    return real != root_real and root_real not in real.parents


# ------------------------------------------------------------------------- parsing
def parse_forge_json(stdout: str, stderr: str, returncode) -> ForgeRun:
    """Parse `forge test --json`.

    forge 1.7.1 emits a single JSON object on stdout:
        {"<file>:<Contract>": {"duration": ..., "test_results":
             {"<fn(sig)>": {"status": "Success"|"Failure"|"Skipped", "reason": ...}},
          "warnings": [...]}}
    A suite whose setUp() reverted reports a single pseudo-test named `setUp()`.
    On a compile error stdout is NOT JSON (it is the solc diagnostic), so the caller
    gets structured=False and the compile markers decide the reason.
    """
    run = ForgeRun(ran=True, returncode=returncode,
                   stdout_tail=stdout[-4000:], stderr_tail=stderr[-2000:])
    blob = _extract_json_object(stdout)
    if blob is None:
        run.structured = False
        run.compiled = not _looks_like_compile_failure(stdout, stderr)
        return run
    run.structured = True
    run.compiled = True           # tests cannot run without a successful compile
    for suite, sdata in blob.items():
        results = (sdata or {}).get("test_results") or {}
        for fn, tdata in results.items():
            status = (tdata or {}).get("status") or "Failure"
            reason = (tdata or {}).get("reason")
            if fn.startswith("setUp("):
                if status != "Success":
                    run.setup_failures[suite] = reason or "setUp() failed"
                continue
            tid = f"{suite}:{fn}"
            run.tests[tid] = TestOutcome(id=tid, suite=suite, name=fn,
                                         status=status, reason=reason)
    return run


def _extract_json_object(stdout: str):
    """forge --json prints one object; be tolerant of a leading banner line."""
    s = (stdout or "").strip()
    if not s:
        return None
    candidates = [s] + [ln.strip() for ln in s.splitlines() if ln.strip().startswith("{")]
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    i, j = s.find("{"), s.rfind("}")
    if i >= 0 and j > i:
        try:
            obj = json.loads(s[i:j + 1])
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    return None


def _looks_like_compile_failure(stdout: str, stderr: str) -> bool:
    both = (stdout or "") + "\n" + (stderr or "")
    return bool(re.search(r"Compiler run failed|Compilation failed|Error \(\d+\)|"
                          r"failed to compile|ParserError|DeclarationError", both))


def parse_forge_text(stdout: str, stderr: str = "", returncode=None) -> ForgeRun:
    """FALLBACK ONLY. Parses the human-readable `-vv` log.

    It cannot recover suite names, so its test ids are bare function names and can
    collide across suites, which would let a later PASS mask an earlier FAIL of the same
    name. It therefore always sets structured=False, and `score()` refuses to return
    `solved` for a run that is not structured. Kept so a human can still read a grade
    off an old log, never so a grade can be *awarded* from one.
    """
    both = (stdout or "") + "\n" + (stderr or "")
    run = ForgeRun(ran=True, structured=False, returncode=returncode,
                   stdout_tail=(stdout or "")[-4000:], stderr_tail=(stderr or "")[-2000:])
    run.compiled = not _looks_like_compile_failure(stdout, stderr)
    for m in re.finditer(r"\[(PASS|FAIL[^\]]*)\]\s+(\w+\([^)]*\))", both):
        raw, fn = m.group(1), m.group(2)
        status = "Success" if raw == "PASS" else "Failure"
        reason = raw[len("FAIL:"):].strip() if raw.startswith("FAIL:") else None
        tid = f"?:?:{fn}"
        run.tests[tid] = TestOutcome(id=tid, suite="?:?", name=fn, status=status, reason=reason)
    return run


def read_miss_file(path, since: int = 0):
    """Return (non-benign misses recorded after index `since`, new cursor)."""
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return [], since
    misses = data.get("misses", [])
    fresh = misses[since:]
    return [m for m in fresh if not m.get("benign")], len(misses)


# --------------------------------------------------------------- workdir + scope check
def assemble_workdir(task_dir, patched_src, work: Path) -> Path:
    """Build a fresh episode workdir: project/ + hash-locked tests/ overlaid into test/.

    patched_src maps a project-relative path (e.g. 'src/contracts/Token.sol') to new
    content; None keeps the shipped (vulnerable) source. The harness (tests/**) always
    comes from the task, never from the agent.
    """
    task_dir = Path(task_dir)
    work = Path(work)
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(task_dir / "project", work)
    tdst = work / "test"
    tdst.mkdir(exist_ok=True)
    shutil.copy2(task_dir / "tests" / "poc.t.sol", tdst / "poc.t.sol")
    hdst = tdst / "hidden"
    hdst.mkdir(exist_ok=True)
    for f in sorted((task_dir / "tests" / "hidden").glob("*.sol")):
        shutil.copy2(f, hdst / f.name)
    if patched_src:
        for rel, content in patched_src.items():
            # Defence in depth. check_scope_and_canaries() already rejected an escaping key
            # with a hard canary and the caller never gets here, but a workdir write is the
            # step that actually does damage, so it re-derives the safe key itself and
            # refuses rather than trusting the caller to have checked.
            key = normalise_patch_key(rel)
            if key is None:
                raise ValueError(f"unsafe patch key refused: {_display(rel)}")
            dst = work / key
            if _escapes(work, dst):
                raise ValueError(f"patch key resolves outside the workdir: {_display(rel)}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(content)
    return work


# task-relative hash-lock path -> where that file lives inside an assembled workdir
def _workdir_lock_path(work: Path, rel: str):
    if rel == "tests/poc.t.sol":
        return work / "test" / "poc.t.sol"
    if rel.startswith("tests/hidden/"):
        return work / "test" / "hidden" / Path(rel).name
    if rel.startswith("project/"):
        return work / rel[len("project/"):]
    return None      # e.g. tests/manifest.json — read from the task dir, never shipped in


def verify_workdir_harness(task_dir, work) -> list:
    """Re-hash every locked harness file AS IT EXISTS IN THE WORKDIR, after the patch landed.

    `check_scope_and_canaries()` hashes the files in the TASK directory, which the agent
    cannot reach; it therefore cannot see a write that landed on the workdir's *copy* of a
    harness file. That is exactly the route a path-traversal key takes. This runs after
    `assemble_workdir()` and returns the same canary strings, so a tampered oracle is a
    hard canary no matter which route reached it.
    """
    meta = json.loads((Path(task_dir) / "task.json").read_text())
    work = Path(work)
    out = []
    for rel, want in sorted(meta.get("hash_locks", {}).items()):
        p = _workdir_lock_path(work, rel)
        if p is None:
            continue
        tag = "poc_tampered" if rel.endswith("poc.t.sol") else "harness_tampered"
        if not p.exists():
            out.append(f"{tag}:{rel}(missing from workdir)")
        elif _sha256(p) != want:
            out.append(f"{tag}:{rel}(workdir copy differs)")
    return out


def check_scope_and_canaries(task_dir, patched_src):
    """Return (changed_files, canaries). Verifies hash-locks + allow-list BEFORE running."""
    task_dir = Path(task_dir)
    meta = json.loads((task_dir / "task.json").read_text())
    canaries = []

    for rel, want in meta["hash_locks"].items():
        f = task_dir / rel
        if not f.exists():
            canaries.append(f"harness_tampered:{rel}(missing)")
            continue
        if _sha256(f) != want:
            tag = "poc_tampered" if rel.endswith("poc.t.sol") else "harness_tampered"
            canaries.append(f"{tag}:{rel}")

    globs = meta["patchable_globs"]
    project = task_dir / "project"
    changed = []
    if patched_src:
        for rel, content in patched_src.items():
            key = normalise_patch_key(rel)
            if key is None:
                # An escaping key is a change ATTEMPT and is recorded as one, so the grade
                # never reads as an empty patch.
                changed.append(_display(rel))
                canaries.append(f"out_of_scope_edit:{_display(rel)}")
                continue
            orig = project / key
            if _escapes(project, orig):          # a symlink inside project/ leaving it
                changed.append(key)
                canaries.append(f"out_of_scope_edit:{key}(symlink escape)")
                continue
            orig_txt = orig.read_text() if orig.is_file() else None
            if orig_txt == content:
                continue
            changed.append(key)
            if not any(glob_match(key, g) for g in globs):
                canaries.append(f"out_of_scope_edit:{key}")
    if not changed:
        canaries.append("empty_patch")
    return changed, canaries


HARD_CANARIES = {"poc_tampered", "harness_tampered", "out_of_scope_edit"}


# ------------------------------------------------------------------------ forge runner
def forge_env(fork_url: str) -> dict:
    env = dict(os.environ)
    env["TASK_FORK_URL"] = fork_url
    env["FOUNDRY_OFFLINE"] = "true"              # never fetch deps/compilers
    # Never serve chain reads out of the HOST's global ~/.foundry/cache/rpc — the task's
    # own rpc_log.json must be the sole source of chain data, or the same task grades
    # differently on a warm box than on a cold one.
    env["FOUNDRY_NO_STORAGE_CACHING"] = "true"
    env["NO_COLOR"] = "1"
    return env


def _run_forge(workdir: Path, match_path: str, fork_url: str, timeout_s: int,
               miss_file=None, miss_since: int = 0):
    """Run one forge suite. Returns (ForgeRun, new miss-file cursor)."""
    try:
        out = subprocess.run(
            ["forge", "test", "--match-path", match_path, "--json"],
            cwd=workdir, capture_output=True, text=True,
            env=forge_env(fork_url), timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return ForgeRun(ran=True, structured=False, compiled=False, timed_out=True,
                        stderr_tail="TIMEOUT"), miss_since
    except FileNotFoundError as exc:
        return ForgeRun(ran=False, structured=False, stderr_tail=f"forge not found: {exc}"), miss_since

    run = parse_forge_json(out.stdout, out.stderr, out.returncode)
    if miss_file is not None:
        fresh, cursor = read_miss_file(miss_file, miss_since)
        run.rpc_misses = fresh
        run.benign_rpc_misses = max(0, (cursor - miss_since) - len(fresh))
        miss_since = cursor
    return run, miss_since


# ------------------------------------------------------------------------- the scorer
# The ABI-preservation evidence is TWO independent checks and the grade
# records them separately. A PUSH4 immediate in the runtime bytecode is necessary but not
# sufficient (dead data, proxy/fallback dispatch), so the hidden suite also *calls* every
# required public function and asserts the contract does not answer "no such function".
ABI_CHECKS = {
    "bytecode_selectors": "test_abi_selectors_preserved()",
    "dispatch_selectors": "test_abi_selectors_dispatch()",
    "dispatch_control": "test_unknown_selector_is_rejected()",
    "not_vacuous": "test_selector_check_is_not_vacuous()",
}


def abi_invariants(hidden: ForgeRun) -> dict:
    """{check name -> Success|Failure|Skipped|absent} for the ABI-preservation tests."""
    out = {}
    for name, fn in ABI_CHECKS.items():
        hits = [t for t in (hidden.tests or {}).values() if t.name == fn]
        out[name] = hits[0].status if hits else "absent"
    return out


def score(poc: ForgeRun, hidden: ForgeRun, manifest, changed, canaries, backend: str,
          task_id: str = "", infra_reason: str = "", infra_detail: str = "") -> RewardResult:
    """Turn two ForgeRuns + the task manifest into a three-valued grade.

    Pure function — no filesystem, no subprocess, no clock. tests/test_scorer_probes.py
    drives it directly with synthetic ForgeRuns.
    """
    canaries = list(canaries)

    def make(outcome: str, reason: str = "", detail: str = "", **kw) -> RewardResult:
        res = RewardResult(
            score=1.0 if outcome == OUTCOME_SOLVED else 0.0,
            outcome=outcome, solved=outcome == OUTCOME_SOLVED, backend=backend,
            task_id=task_id, reason=reason, reason_family=REASON_FAMILY.get(reason, ""),
            reason_detail=detail, canaries=canaries, changed_files=list(changed),
            poc=poc, hidden=hidden, abi_invariants=abi_invariants(hidden), **kw,
        )
        res.detail = detail or outcome
        return res

    # ---- 0. plumbing the caller already knows failed (proxy down, docker error, ...)
    if infra_reason:
        return make(OUTCOME_INCONCLUSIVE, infra_reason, infra_detail)

    # ---- 1. hard canaries: tampering / out-of-scope. Conclusive rejection, no run needed.
    hard = [c for c in canaries if c.split(":")[0] in HARD_CANARIES]
    if hard:
        return make(OUTCOME_NOT_SOLVED, "", "out-of-scope/harness edit: " + ", ".join(hard),
                    diff_in_scope=False)
    diff_in_scope = True

    # ---- 2. the run must have produced evidence at all.
    for label, run in (("poc", poc), ("hidden", hidden)):
        if run.timed_out:
            return make(OUTCOME_INCONCLUSIVE, R_TIMEOUT, f"{label} suite exceeded its wall clock")
        if not run.ran:
            return make(OUTCOME_INCONCLUSIVE, R_BACKEND_ERROR,
                        f"{label} suite never ran: {run.stderr_tail[-300:]}")
    for label, run in (("poc", poc), ("hidden", hidden)):
        if not run.structured:
            if not run.compiled:
                return make(OUTCOME_INCONCLUSIVE, R_COMPILE_FAILED,
                            f"{label} suite did not compile", compiled=False)
            return make(OUTCOME_INCONCLUSIVE, R_NO_REPORT,
                        f"{label} suite produced no machine-readable report "
                        f"(a text-fallback run can never be scored `solved`)")
        # forge exits 0 (all green) or 1 (a test failed / compile error). Anything else —
        # a signal, an OOM kill, an internal panic — means the suite did not complete.
        if run.returncode is not None and run.returncode not in (0, 1):
            return make(OUTCOME_INCONCLUSIVE, R_RUNNER_CRASH,
                        f"{label} runner exited with code {run.returncode}")
    compiled = poc.compiled and hidden.compiled

    # ---- 3. the frozen state must have covered the whole run.
    for label, run in (("poc", poc), ("hidden", hidden)):
        if run.rpc_misses:
            methods = sorted({m.get("method", "?") for m in run.rpc_misses})
            return make(OUTCOME_INCONCLUSIVE, R_UNRECORDED_RPC,
                        f"{label} suite hit {len(run.rpc_misses)} unrecorded RPC call(s): "
                        f"{', '.join(methods)}", compiled=compiled)

    # ---- 4. setUp must have succeeded, or nothing that follows means anything.
    for label, run in (("poc", poc), ("hidden", hidden)):
        if run.setup_failures:
            suite, why = sorted(run.setup_failures.items())[0]
            reason = R_UNRECORDED_RPC if classify_failure_reason(why) == "infra" else R_SETUP_FAILED
            return make(OUTCOME_INCONCLUSIVE, reason,
                        f"{label} setUp() failed in {suite}: {why}", compiled=compiled,
                        poc_failure_kind="setup" if label == "poc" else "")

    # ---- 5. exact-set match against the task's expected-test manifest.
    if manifest is None:
        return make(OUTCOME_INCONCLUSIVE, R_MANIFEST_MISSING,
                    "task ships no tests/manifest.json; refusing to score", compiled=compiled)
    poc_expect = set(manifest["poc"]["tests"])
    hidden_expect = set(manifest["hidden"]["tests"])
    oracle_id = manifest["poc"]["exploit_oracle"]
    missing = sorted((poc_expect - poc.ids) | (hidden_expect - hidden.ids))
    extra = sorted((poc.ids - poc_expect) | (hidden.ids - hidden_expect))
    if missing:
        return make(OUTCOME_INCONCLUSIVE, R_MISSING_TESTS,
                    f"{len(missing)} expected test(s) did not execute: {', '.join(missing[:6])}",
                    compiled=compiled, tests_match_manifest=False)
    if extra:
        return make(OUTCOME_INCONCLUSIVE, R_UNEXPECTED_TESTS,
                    f"{len(extra)} unexpected test id(s) in the report: {', '.join(extra[:6])}",
                    compiled=compiled, tests_match_manifest=False)
    graded = [poc.tests[i] for i in poc_expect] + [hidden.tests[i] for i in hidden_expect]
    skipped = sorted(t.id for t in graded if t.status == "Skipped")
    if skipped:
        return make(OUTCOME_INCONCLUSIVE, R_TESTS_SKIPPED,
                    f"graded test(s) skipped: {', '.join(skipped[:6])}",
                    compiled=compiled, tests_match_manifest=True)
    tests_match_manifest = True

    # ---- 6. the exploit oracle. A FAILING oracle only counts as "blocked" when the
    #         failure happened in the test BODY — an assertion, or a revert on the
    #         exploit path (e.g. the flash loan can no longer be repaid). An
    #         infrastructure-shaped reason is not evidence of a repair.
    # Hidden functionality is evaluated FIRST, because it decides whether an odd PoC
    # failure is ambiguous or already explained. A patch that breaks the contract has
    # produced positive evidence against itself: that is `not_solved` + `bricked`, a clean
    # negative for training, not an `inconclusive` an operator has to look at.
    hidden_all_pass = all(hidden.tests[i].status == "Success" for i in hidden_expect)
    # The functional half: everything the manifest does NOT declare a security obligation.
    # Those hold on the vulnerable contract too, so their failure means the patch broke the
    # token; a failure confined to the security set means the repair is incomplete.
    security_ids = set(manifest["hidden"].get("security_tests") or []) & hidden_expect
    functional_ids = hidden_expect - security_ids
    functional_all_pass = all(hidden.tests[i].status == "Success" for i in functional_ids)

    def hidden_failure_canary() -> str:
        return "bricked" if not functional_all_pass else "residual_vulnerability"

    oracle = poc.tests[oracle_id]
    accepted = set(manifest["poc"].get("accepted_block_kinds", ["assertion", "revert"]))
    # The task declares which failure reasons are KNOWN to mean "the exploit was blocked".
    # A failure the task never declared is not silently read as a repair: it is flagged
    # `unrecognised_failure` for a human, because "the PoC failed for a reason nobody has
    # seen before" is the shape of both a novel bug in the harness and a novel reward hack.
    recognised = manifest["poc"].get("recognised_block_reasons") or ["*assertion failed*"]
    if oracle.status == "Success":
        poc_failure_kind, poc_blocked = "none", False
    else:
        poc_failure_kind = classify_failure_reason(oracle.reason)
        if poc_failure_kind == "infra":
            return make(OUTCOME_INCONCLUSIVE, R_UNRECORDED_RPC,
                        "exploit oracle failed for an infrastructure reason, not a repair: "
                        f"{oracle.reason}", compiled=compiled, tests_match_manifest=True,
                        diff_in_scope=diff_in_scope, poc_failure_kind="infra")
        why = oracle.reason or ""
        known = any(fnmatch.fnmatchcase(why, pat) for pat in recognised)
        if poc_failure_kind not in accepted or not known:
            if not hidden_all_pass:
                # Not ambiguous at all: a hidden obligation already failed, and the exploit
                # "failed" alongside it. Score it as the reward hack it is.
                canaries.append(hidden_failure_canary())
                return make(OUTCOME_NOT_SOLVED, "",
                            "hidden invariants failing; exploit oracle failed for an "
                            f"undeclared reason ({why!r}); canaries: {','.join(canaries)}",
                            compiled=compiled, tests_match_manifest=True,
                            diff_in_scope=diff_in_scope, hidden_all_pass=False,
                            functional_all_pass=functional_all_pass,
                            poc_failure_kind=poc_failure_kind)
            return make(OUTCOME_INCONCLUSIVE, R_UNRECOGNISED,
                        "exploit oracle failed for a reason this task does not recognise as "
                        f"'exploit blocked' (kind={poc_failure_kind}): {why!r}",
                        compiled=compiled, tests_match_manifest=True, hidden_all_pass=True,
                        functional_all_pass=True,
                        diff_in_scope=diff_in_scope, poc_failure_kind=poc_failure_kind)
        poc_blocked = True

    # ---- 7. hidden functionality (computed above), plus its canary.
    if poc_blocked and not hidden_all_pass:
        canaries.append(hidden_failure_canary())

    solved = bool(poc_blocked and hidden_all_pass and compiled and tests_match_manifest
                  and diff_in_scope and not canaries)
    if solved:
        return make(OUTCOME_SOLVED, "", "solved", poc_blocked=True, hidden_all_pass=True,
                    functional_all_pass=True,
                    compiled=True, tests_match_manifest=True, diff_in_scope=True,
                    poc_failure_kind=poc_failure_kind)
    detail = "; ".join(filter(None, [
        "" if poc_blocked else "poc still exploitable",
        "" if hidden_all_pass else ("hidden invariants failing" if not functional_all_pass
                                    else "security obligations failing (incomplete repair)"),
        ("canaries: " + ",".join(canaries)) if canaries else "",
    ]))
    return make(OUTCOME_NOT_SOLVED, "", detail or "not solved",
                poc_blocked=poc_blocked, hidden_all_pass=hidden_all_pass,
                functional_all_pass=functional_all_pass, compiled=compiled,
                tests_match_manifest=tests_match_manifest, diff_in_scope=diff_in_scope,
                poc_failure_kind=poc_failure_kind)


# ------------------------------------------------------------------- local backend
def reward_local(task_dir, patched_src=None, port=None, timeout_s: int = 300,
                 keep_workdir: bool = False) -> RewardResult:
    """Run the reward with the replay proxy on a FREE loopback port (no outbound network
    — the proxy fails closed). Identical forge pipeline to the docker backend.

    The port is chosen by the OS (bind :0) and the episode workdir is uuid-named,
    so concurrent episodes on one box cannot collide.
    """
    task_dir = Path(task_dir)
    task_id = json.loads((task_dir / "task.json").read_text()).get("task_id", task_dir.name)
    changed, canaries = check_scope_and_canaries(task_dir, patched_src)
    empty = ForgeRun(ran=False)
    if any(c.split(":")[0] in HARD_CANARIES for c in canaries):
        return score(empty, empty, None, changed, canaries, "local", task_id)
    try:
        manifest = load_manifest(task_dir)
    except Exception as exc:
        return score(empty, empty, None, changed, canaries, "local", task_id,
                     infra_reason=R_MANIFEST_MISSING, infra_detail=str(exc))

    root = episode_root() / f"evmpatch_ep_{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    work = root / "work"
    port_file = root / "proxy.port"
    miss_file = root / "rpc_misses.json"
    proxy = None
    try:
        proxy = subprocess.Popen(
            [sys.executable, str(RPC_REPLAY), "replay",
             str(task_dir / "state" / "rpc_log.json"), str(port if port else 0),
             "--port-file", str(port_file), "--miss-file", str(miss_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        bound = _await_proxy(proxy, port_file, deadline_s=20.0)
        if bound is None:
            return score(empty, empty, manifest, changed, canaries, "local", task_id,
                         infra_reason=R_PROXY_START,
                         infra_detail="replay proxy did not bind within 20s")
        try:
            assemble_workdir(task_dir, patched_src, work)
        except ValueError as exc:                     # unsafe key that the scope check missed
            return score(empty, empty, manifest, changed,
                         canaries + [f"out_of_scope_edit:{exc}"], "local", task_id)
        tampered = verify_workdir_harness(task_dir, work)
        if tampered:
            return score(empty, empty, manifest, changed, canaries + tampered,
                         "local", task_id)
        fork_url = f"http://127.0.0.1:{bound}"
        cursor = 0
        poc, cursor = _run_forge(work, "test/poc.t.sol", fork_url, timeout_s, miss_file, cursor)
        hidden, cursor = _run_forge(work, "test/hidden/*", fork_url, timeout_s, miss_file, cursor)
        return score(poc, hidden, manifest, changed, canaries, "local", task_id)
    finally:
        if proxy is not None:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except Exception:
                proxy.kill()
        if not keep_workdir:
            shutil.rmtree(root, ignore_errors=True)


def _await_proxy(proxy, port_file: Path, deadline_s: float):
    end = time.time() + deadline_s
    while time.time() < end:
        if proxy.poll() is not None:
            return None
        if port_file.exists():
            try:
                bound = int(port_file.read_text().strip())
            except Exception:
                bound = 0
            if bound and _port_open(bound):
                return bound
        time.sleep(0.05)
    return None


# ------------------------------------------------------------------- docker backend
def reward_docker(task_dir, patched_src=None, image: str = "evmpatch-env:latest",
                  timeout_s: int = 900, keep_workdir: bool = False) -> RewardResult:
    """Production containment: assemble the episode workdir on the host (the fork/replay
    SETUP stage), then run the graded step inside `docker run --network none` so the
    process that executes the agent's code has no network at all.

    The container entrypoint (reward_entry.sh) starts rpc_replay.py in replay mode on
    loopback, runs the two forge invocations with --json, and emits a RAW payload
    (stdout / stderr / return code / rpc misses per suite) between BEGIN_RESULT and
    END_RESULT. All parsing and all scoring happen HERE, in the same functions the
    local backend uses, so the two backends cannot drift apart.
    """
    task_dir = Path(task_dir).resolve()      # docker -v refuses relative host paths
    task_id = json.loads((task_dir / "task.json").read_text()).get("task_id", task_dir.name)
    changed, canaries = check_scope_and_canaries(task_dir, patched_src)
    empty = ForgeRun(ran=False)
    if any(c.split(":")[0] in HARD_CANARIES for c in canaries):
        return score(empty, empty, None, changed, canaries, "docker", task_id)
    try:
        manifest = load_manifest(task_dir)
    except Exception as exc:
        return score(empty, empty, None, changed, canaries, "docker", task_id,
                     infra_reason=R_MANIFEST_MISSING, infra_detail=str(exc))

    root = episode_root(for_docker=True) / f"evmpatch_ep_{uuid.uuid4().hex}"
    work = root / "work"
    root.mkdir(parents=True, exist_ok=True)
    try:
        assemble_workdir(task_dir, patched_src, work)
    except ValueError as exc:                         # unsafe key that the scope check missed
        shutil.rmtree(root, ignore_errors=True)
        return score(empty, empty, manifest, changed,
                     canaries + [f"out_of_scope_edit:{exc}"], "docker", task_id)
    tampered = verify_workdir_harness(task_dir, work)
    if tampered:
        shutil.rmtree(root, ignore_errors=True)
        return score(empty, empty, manifest, changed, canaries + tampered, "docker", task_id)
    for p in (root, work):
        try:
            os.chmod(p, 0o777)
        except Exception:
            pass
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{work}:/work",
        "-v", f"{task_dir / 'state'}:/state:ro",
        "-v", f"{RPC_REPLAY}:/opt/rpc_replay.py:ro",
        "-v", f"{REWARD_ENTRY}:/opt/reward_entry.sh:ro",
        "-e", "FOUNDRY_OFFLINE=true",
        "-e", "FOUNDRY_NO_STORAGE_CACHING=true",
        "-e", "NO_COLOR=1",
        "--entrypoint", "/bin/sh",
        image, "/opt/reward_entry.sh",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return score(empty, empty, manifest, changed, canaries, "docker", task_id,
                     infra_reason=R_TIMEOUT, infra_detail="docker run exceeded its wall clock")
    finally:
        if not keep_workdir:
            shutil.rmtree(root, ignore_errors=True)

    m = re.search(r"BEGIN_RESULT\n(.*)\nEND_RESULT", out.stdout, re.S)
    if not m:
        return score(empty, empty, manifest, changed, canaries, "docker", task_id,
                     infra_reason=R_BACKEND_ERROR,
                     infra_detail=(f"container produced no result payload (rc={out.returncode}): "
                                   + (out.stdout + out.stderr)[-500:]))
    payload = json.loads(m.group(1))
    if payload.get("mount_error"):
        return score(empty, empty, manifest, changed, canaries, "docker", task_id,
                     infra_reason=R_BACKEND_ERROR,
                     infra_detail="bind mount not visible inside the container (the host "
                                  "path is not shared by the container runtime); missing: "
                                  + ", ".join(payload["mount_error"]))
    if payload.get("proxy_up") is False:
        return score(empty, empty, manifest, changed, canaries, "docker", task_id,
                     infra_reason=R_PROXY_START,
                     infra_detail="in-container replay proxy did not bind")
    runs = {}
    for label in ("poc", "hidden"):
        raw = payload.get(label) or {}
        run = parse_forge_json(raw.get("stdout", ""), raw.get("stderr", ""), raw.get("returncode"))
        misses = raw.get("misses") or []
        run.rpc_misses = [x for x in misses if not x.get("benign")]
        run.benign_rpc_misses = len(misses) - len(run.rpc_misses)
        runs[label] = run
    return score(runs["poc"], runs["hidden"], manifest, changed, canaries, "docker", task_id)


def compute_reward(task_dir, patched_src=None, backend: str = "local", **kw) -> RewardResult:
    """Single entrypoint used by the verifiers env. backend in {'local','docker'}."""
    if backend == "docker":
        return reward_docker(Path(task_dir), patched_src, **kw)
    return reward_local(Path(task_dir), patched_src, **kw)


# ---------------------------------------------------------------------------- CLI
def _main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Grade a patch against an evmpatch task.")
    ap.add_argument("task_dir")
    ap.add_argument("--patch", help="path to a replacement source file")
    ap.add_argument("--reference-patch", action="store_true",
                    help="grade the task's own reference_patch.sol.diff (CI self-test and "
                         "the cross-host receipt: identical command on every machine)")
    ap.add_argument("--rel", default="src/contracts/Token.sol",
                    help="project-relative destination of --patch")
    ap.add_argument("--backend", default="local", choices=["local", "docker"])
    ap.add_argument("--image", default="evmpatch-env:latest", help="docker backend image")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--canonical", action="store_true",
                    help="print only the host-independent canonical grade JSON")
    ap.add_argument("--sha256", action="store_true",
                    help="print SHA-256 of the canonical grade JSON (core and strict)")
    ap.add_argument("--core", action="store_true",
                    help="with --canonical/--sha256, use the CORE form (no revert reasons)")
    a = ap.parse_args(argv)
    if a.reference_patch:
        from .build_task import apply_unified_diff
        src = Path(a.task_dir) / "project" / a.rel
        diff = Path(a.task_dir) / "reference_patch.sol.diff"
        patched = {a.rel: apply_unified_diff(src.read_text(), diff.read_text())}
    else:
        patched = {a.rel: Path(a.patch).read_text()} if a.patch else None
    kw = {}
    if a.backend == "docker":
        kw["image"] = a.image
    if a.timeout:
        kw["timeout_s"] = a.timeout
    res = compute_reward(a.task_dir, patched, backend=a.backend, **kw)
    if a.sha256:
        print(f"core   {res.canonical_sha256(core_only=True)}")
        print(f"strict {res.canonical_sha256(core_only=False)}")
    elif a.canonical:
        print(json.dumps(res.canonical(core_only=a.core), sort_keys=True, indent=2))
    else:
        print(res.to_json())
    return 0 if res.solved else 1


if __name__ == "__main__":
    sys.exit(_main())
