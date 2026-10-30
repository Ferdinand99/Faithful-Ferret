# Builder image for the Ferret core. Built on the LANBox Docker host by
# scripts/lanbox.sh and tagged ferret-core-builder:<hash of this file>.
# Every tool is pinned. Nothing here ships in a release.
FROM rust:1.99-bookworm

LABEL owner=ferret-core

ARG CARGO_DENY_VERSION=0.20.2
ARG CARGO_VET_VERSION=0.10.3
ARG CARGO_FUZZ_VERSION=0.13.2
ARG CARGO_LLVM_COV_VERSION=0.9.1
ARG WASM_PACK_VERSION=0.15.0
# The nightly toolchain for cargo-fuzz and branch coverage. Keep it equal to
# fuzz/NIGHTLY: the fuzz and coverage scripts name this toolchain.
ARG NIGHTLY_TOOLCHAIN=nightly-2026-10-29
ARG WASM_BINDGEN_CLI_VERSION=0.2.129
ARG WASM_TOOLS_VERSION=1.262.0
ARG NODE_VERSION=22.23.4
ARG NODE_SHA256=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce
ARG BINARYEN_VERSION=version_133
ARG BINARYEN_SHA256=2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# The project toolchain (rust-toolchain.toml says channel "1.99"), with the
# components and targets the checks need, plus a pinned nightly for cargo-fuzz and
# cargo llvm-cov --branch.
RUN rustup toolchain install 1.99 --profile minimal \
        -c clippy -c rustfmt -c llvm-tools -t wasm32-unknown-unknown \
 && rustup default 1.99 \
 && rustup toolchain install "${NIGHTLY_TOOLCHAIN}" --profile minimal -c rust-src -c llvm-tools

# Node 22 (WASM tests in Node, ct scripts).
RUN curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
 && tar -xJ -C /usr/local --strip-components=1 -f /tmp/node.tar.xz \
 && rm /tmp/node.tar.xz

# binaryen (wasm-opt).
RUN curl -fsSL -o /tmp/binaryen.tar.gz "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/binaryen-${BINARYEN_VERSION}-x86_64-linux.tar.gz" \
 && echo "${BINARYEN_SHA256}  /tmp/binaryen.tar.gz" | sha256sum -c - \
 && tar -xz -C /usr/local --strip-components=1 -f /tmp/binaryen.tar.gz \
 && rm /tmp/binaryen.tar.gz

# uv, for the constant-time analyzer (pinned image tag).
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv

# Cargo tools, compiled from the crates.io sources with their lock files.
# Two layers so the checks needed first are cached on their own.
RUN cargo install --locked --root /usr/local \
        "cargo-deny@${CARGO_DENY_VERSION}" "cargo-vet@${CARGO_VET_VERSION}" \
 && rm -rf /usr/local/cargo/registry /usr/local/cargo/git
RUN cargo install --locked --root /usr/local \
        "cargo-fuzz@${CARGO_FUZZ_VERSION}" "cargo-llvm-cov@${CARGO_LLVM_COV_VERSION}" \
        "wasm-pack@${WASM_PACK_VERSION}" "wasm-bindgen-cli@${WASM_BINDGEN_CLI_VERSION}" \
        "wasm-tools@${WASM_TOOLS_VERSION}" \
 && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# Constant-time checks (ct/): the assembly is emitted for arm64 as well as
# x86_64, and Python runs the Trail of Bits `ct_analyzer` (no dependencies).
# The three files come from trailofbits/skills at a fixed commit and are
# checked against their SHA-256 (the repository is CC-BY-SA-4.0, so the
# files are fetched here and not copied into this repository). The triage in
# ct/TRIAGE.md names the commit it was made with.
ARG CT_ANALYZER_COMMIT=123037ec8aed26f0d86327cc39137ee5043e5deb
ARG CT_ANALYZER_INIT_SHA256=b74759da227e85d90cc6929cde54817a0960c716b7f2ae9319ec0c759dc698da
ARG CT_ANALYZER_MAIN_SHA256=68a17ca12f17c05dc0e9e2ff49bf7ddae061eabcec12058f276d89fc23a1ab0c
ARG CT_ANALYZER_SCRIPTS_SHA256=d64df7dd7010c0355ec652df6e72fc1892f17173cb57fedba669d5ecf470613c
# The constant-time results are results of one compiler: the build stops if
# the toolchain "1.99" is no longer rustc 1.99.1 (the results in ct/ name it),
# and the Python of Debian bookworm is pinned to its version.
ARG RUSTC_EXPECTED="rustc 1.99.1 (58cf8f9c3 2026-10-13)"
RUN test "$(rustc --version)" = "${RUSTC_EXPECTED}"
RUN apt-get update  && apt-get install -y --no-install-recommends python3=3.11.2-1+b1  && rm -rf /var/lib/apt/lists/*  && rustup target add --toolchain 1.99 aarch64-unknown-linux-gnu  && mkdir -p /opt/ct-analyzer/ct_analyzer  && base="https://raw.githubusercontent.com/trailofbits/skills/${CT_ANALYZER_COMMIT}/plugins/constant-time-analysis/ct_analyzer"  && curl -fsSL -o /opt/ct-analyzer/ct_analyzer/__init__.py "$base/__init__.py"  && curl -fsSL -o /opt/ct-analyzer/ct_analyzer/analyzer.py "$base/analyzer.py"  && curl -fsSL -o /opt/ct-analyzer/ct_analyzer/script_analyzers.py "$base/script_analyzers.py"  && echo "${CT_ANALYZER_INIT_SHA256}  /opt/ct-analyzer/ct_analyzer/__init__.py" | sha256sum -c -  && echo "${CT_ANALYZER_MAIN_SHA256}  /opt/ct-analyzer/ct_analyzer/analyzer.py" | sha256sum -c -  && echo "${CT_ANALYZER_SCRIPTS_SHA256}  /opt/ct-analyzer/ct_analyzer/script_analyzers.py" | sha256sum -c -

WORKDIR /src
