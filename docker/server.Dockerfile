# syntax=docker/dockerfile:1
#
# The Faithful Ferret server: one static musl binary on Alpine with the web
# vault built into it. Build from the repository root:
#
#   docker build -f docker/server.Dockerfile -t ferret-server .
#
# Needs BuildKit. Every base image is pinned by digest, so a rebuilt tag
# upstream cannot change the image. To move to a newer one, look up the digest
# of the new tag (docker buildx imagetools inspect <image>) and change the tag
# and the digest together.
#
# FEATURES is a list of cargo features for the server, empty for a release.

ARG RUST_IMAGE=rust:1.99-alpine@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d
ARG NODE_IMAGE=node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
ARG ALPINE_IMAGE=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

# WASM_LOCAL=1 builds the web vault against web/wasm.local.tar.gz instead of the
# published WebAssembly package. For test stacks only (see the web stage). Empty
# by default; no release build sets it.
ARG WASM_LOCAL=""

# --- Web vault ---------------------------------------------------------------
# Builds web/dist, the static files the server embeds. The build fetches the
# pinned WebAssembly package of the crypto core and checks its SHA-256
# (web/wasm.lock.json).
#
# A test stack may build against a package made from the sources of the same
# commit (scripts/lanbox-wasm.sh and scripts/package-release.sh) instead of the
# published one. That takes the build argument WASM_LOCAL=1 and the archive at
# web/wasm.local.tar.gz, with its checksum in web/wasm.lock.json (the archive and
# the lock change stay in the working tree). The build prints a warning, and the
# image carries the label ferret.wasm.local=1. Without the argument the archive is
# deleted before the build, so a stray file or a changed lock can only fail the
# checksum of the published package, never change the image.
FROM ${NODE_IMAGE} AS web
ARG WASM_LOCAL
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web ./
RUN if [ "$WASM_LOCAL" = "1" ]; then \
      test -f wasm.local.tar.gz || { echo "WASM_LOCAL=1 but web/wasm.local.tar.gz is missing" >&2; exit 1; }; \
      echo "WARNING: the web vault is built against the local WebAssembly package wasm.local.tar.gz, not the published one" >&2; \
      FERRET_WASM_TAR=wasm.local.tar.gz node scripts/build.mjs; \
    elif [ -n "$WASM_LOCAL" ]; then \
      echo "WASM_LOCAL is empty or 1" >&2; exit 1; \
    else \
      rm -f wasm.local.tar.gz; \
      node scripts/build.mjs; \
    fi

# --- Server ------------------------------------------------------------------
FROM ${RUST_IMAGE} AS build

# build-base: C toolchain for the bundled SQLite and aws-lc-rs (rustls crypto).
# The apk packages here and in the runtime stage are not pinned to a version:
# Alpine drops old package versions from its repository, so a pinned build would
# break within weeks. The base images are pinned by digest, and the packages come
# from the signed repository index of that Alpine release.
RUN apk add --no-cache build-base

ARG FEATURES=""

ENV CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_TERM_COLOR=never

WORKDIR /src
# What the server build reads: the workspace manifest and lock (the crypto core
# inherits its package fields from it), the crates, the constant-time helpers
# that the core includes, and the built web vault.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY ct/harness ./ct/harness
COPY --from=web /src/web/dist ./web/dist
# The hand-over page of the admin origin is compiled into the binary from here.
COPY --from=web /src/web/admin ./web/admin

RUN --mount=type=cache,id=ferret-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=ferret-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=ferret-server-target,target=/src/crates/ferret-server/target,sharing=locked \
    cargo build --release --locked \
        --manifest-path crates/ferret-server/Cargo.toml \
        --features "$FEATURES" \
    && install -m 0755 crates/ferret-server/target/release/ferret /usr/local/bin/ferret

# --- Runtime -----------------------------------------------------------------
FROM ${ALPINE_IMAGE} AS runtime
ARG WASM_LOCAL

LABEL org.opencontainers.image.title="Faithful Ferret server" \
      org.opencontainers.image.source="https://github.com/Ferdinand99/Faithful-Ferret" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      ferret.wasm.local="${WASM_LOCAL:-0}"

# ca-certificates: TLS trust store for outgoing HTTPS.
# su-exec: the entrypoint drops from root to `ferret` after fixing /data.
# The unprivileged user `ferret` (uid/gid 1000) owns /data and runs the server.
RUN apk add --no-cache ca-certificates su-exec \
    && addgroup -S -g 1000 ferret \
    && adduser -S -D -H -u 1000 -G ferret -h /data -s /sbin/nologin ferret \
    && mkdir -p /data \
    && chown ferret:ferret /data

# World-readable and without file capabilities: the server checks that its
# secret files belong to the user it runs as, so it must run as that user.
COPY --from=build --chmod=755 /usr/local/bin/ferret /usr/local/bin/ferret
COPY --chmod=755 docker/ferret-entrypoint.sh /usr/local/bin/ferret-entrypoint.sh

ENV FERRET_DATA_DIR=/data

# No USER on purpose: the entrypoint starts as root only to fix the ownership
# of /data, then runs the server as `ferret` through su-exec.
WORKDIR /data
VOLUME ["/data"]
EXPOSE 3040 3041

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${FERRET_VAULT_PORT:-3041}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/ferret-entrypoint.sh"]
