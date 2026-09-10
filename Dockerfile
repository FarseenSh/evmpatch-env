# evmpatch-env reward sandbox: Foundry (forge + anvil) + python3, non-root, NO network at
# runtime. The graded `docker run` is launched with `--network none` (see
# evmpatch_env/sandbox.py::reward_docker), so the container cannot reach any chain RPC;
# frozen chain state is served by an in-container record/replay proxy that fails closed.
#
# Build:  docker build -t evmpatch-env:latest .
# The image is generic across tasks — the per-episode workdir and per-task state/ are
# bind-mounted at run time (read-only state), never baked in.
#
# TWO STAGES, one image. The fork/replay SETUP stage (recording chain state, assembling
# the episode workdir) runs on the HOST and is the only stage that ever needs a network.
# The graded stage — compile the agent's patch, run the exploit, run the hidden tests —
# runs here with `--network none`. Nothing the agent produced is ever executed with a
# route to the internet.

# Pinned, not :latest. :latest is forge 1.8.1 today; the grader's report parser and the
# committed receipt hashes are verified against 1.7.1, and a silent toolchain bump would
# change grades. Bump this deliberately, then re-run tests/ and RECEIPT.md.
FROM ghcr.io/foundry-rs/foundry:v1.7.1

USER root

# Minimal python for the replay proxy + entrypoint, and curl so a verifiers v1 harness can
# bootstrap its tooling at setup time. (Foundry image is Ubuntu 22.04.)
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# The base image already ships a non-root `foundry` user at uid 1000; reuse it rather
# than creating a second uid-1000 account.
COPY reward_entry.sh /opt/reward_entry.sh
RUN chmod 0555 /opt/reward_entry.sh

# /work is the agent's working tree and /grade a scratch root for grading on a verifiers
# v1 runtime; both must be writable by the non-root user (a WORKDIR created implicitly
# would belong to root).
RUN mkdir -p /work /grade && chown foundry:foundry /work /grade

USER foundry
WORKDIR /work

# Warm the solc builds the tasks need INTO THE IMAGE, while the network is still
# available. At reward time FOUNDRY_OFFLINE=true and there is no network, so an
# un-warmed compiler version would surface as a compile failure that has nothing to do
# with the agent's patch. Add a version here when a task needs one.
ARG SOLC_VERSIONS="0.8.30 0.8.26 0.8.16"
RUN set -eu; \
    mkdir -p /tmp/warm/src && cd /tmp/warm; \
    printf '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n' > foundry.toml; \
    for v in $SOLC_VERSIONS; do \
      printf '// SPDX-License-Identifier: UNLICENSED\npragma solidity %s;\ncontract W { function f() external pure returns (uint256) { return 1; } }\n' "$v" > src/W.sol; \
      forge build --use "$v" >/dev/null; \
    done; \
    cd /; rm -rf /tmp/warm

# forge/anvil must never phone home for compilers or deps at reward time, and a grade must
# never be served out of a warm host RPC cache.
ENV FOUNDRY_OFFLINE=true \
    FOUNDRY_NO_STORAGE_CACHING=true \
    NO_COLOR=1

# reward_docker() invokes /opt/reward_entry.sh explicitly (and bind-mounts the current
# copy over it, so an edit to the script does not require a rebuild). Declaring it here
# supports `docker run evmpatch-env` for a smoke test.
ENTRYPOINT ["/opt/reward_entry.sh"]
