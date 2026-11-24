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

# --- Web vault ---------------------------------------------------------------
# Builds web/dist, the static files the server embeds. WASM_SOURCE says where the
# WebAssembly package of the crypto core comes from (web/scripts/build.mjs has the rules):
#
#   lock     (the default) the published package named in web/wasm.lock.json; the build
#            fetches it and checks its SHA-256.
#   release  the package that the release run of this commit built: wasm-package/ holds
#            its ferret-core-wasm-web-*.tar.gz and WASM_SHA256 is its entry in that run's
#            SHA256SUMS. The release workflow does this.
#   tree     a test build: wasm-package/ holds a package built from the commit
#            (scripts/wasm-tree.sh) and WASM_COMMIT names that commit. Never together with a
#            REVISION: a release image is not built from a package that no release signed.
#
# The image says which one it carries in `ferret --build-info` (the line `wasm:`).
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web ./
# The package of the second and third source, when there is one: the glob matches nothing otherwise.
COPY web/wasm.lock.json wasm-package* /wasm-in/
ARG WASM_SOURCE=lock
ARG WASM_SHA256=""
ARG WASM_COMMIT=""
ARG REVISION=""
RUN set -eu; \
    case "$WASM_SOURCE" in \
      lock) node scripts/build.mjs ;; \
      release | tree) \
        set -- /wasm-in/ferret-core-wasm-web-*.tar.gz; \
        if [ "$#" != 1 ] || [ ! -f "$1" ]; then echo "wasm-package/ must hold exactly one ferret-core-wasm-web-*.tar.gz" >&2; exit 1; fi; \
        if [ "$WASM_SOURCE" = release ]; then \
          node scripts/build.mjs --wasm release --wasm-tar "$1" --wasm-sha256 "$WASM_SHA256"; \
        else \
          if [ -n "$REVISION" ]; then echo "a release image (REVISION is set) cannot carry a WebAssembly package built from the tree" >&2; exit 1; fi; \
          node scripts/build.mjs --wasm tree --wasm-tar "$1" --wasm-commit "$WASM_COMMIT"; \
        fi ;; \
      *) echo "WASM_SOURCE is lock, release or tree, not $WASM_SOURCE" >&2; exit 1 ;; \
    esac

# --- Server ------------------------------------------------------------------
FROM ${RUST_IMAGE} AS build

# build-base: C toolchain for the bundled SQLite and aws-lc-rs (rustls crypto).
# The apk packages here and in the runtime stage are not pinned to a version:
# Alpine drops old package versions from its repository, so a pinned build would
# break within weeks. The base images are pinned by digest, and the packages come
# from the signed repository index of that Alpine release.
RUN apk add --no-cache build-base

ARG FEATURES=""
# At most this many parallel jobs in the server build (empty: cargo's default, one
# per CPU). A test stack on a shared build host sets it.
ARG CARGO_JOBS=""
# A build that gets a revision is a release build (the release workflow and the deploy drill set
# it): the server's build script then refuses a web vault built with a WebAssembly package from
# the tree. Empty in every other build.
ARG REVISION=""

ENV CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_TERM_COLOR=never \
    FERRET_RELEASE_BUILD=${REVISION:+1}

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
        ${CARGO_JOBS:+--jobs "$CARGO_JOBS"} \
        --manifest-path crates/ferret-server/Cargo.toml \
        --features "$FEATURES" \
    && install -m 0755 crates/ferret-server/target/release/ferret /usr/local/bin/ferret

# --- Runtime -----------------------------------------------------------------
FROM ${ALPINE_IMAGE} AS runtime

LABEL org.opencontainers.image.title="Faithful Ferret server" \
      org.opencontainers.image.source="https://github.com/Ferdinand99/Faithful-Ferret" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

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
# The licence texts travel with the binary: the AGPL text and the licences of the Rust crates
# and the font inside it (made by scripts/notices.sh, checked in CI).
COPY --chmod=644 LICENSE THIRD-PARTY-NOTICES /usr/share/doc/ferret/
COPY --chmod=755 docker/ferret-entrypoint.sh /usr/local/bin/ferret-entrypoint.sh

# What a release image says about itself: the version and the commit it was built from.
# The deploy script of a stack with real data (scripts/ferret-home.sh) compares the
# revision with the commit of the release tag and refuses an image that does not match.
# Empty in a local build.
ARG VERSION=""
ARG REVISION=""
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV FERRET_DATA_DIR=/data

# No USER on purpose: the entrypoint starts as root only to fix the ownership
# of /data, then runs the server as `ferret` through su-exec.
WORKDIR /data
VOLUME ["/data"]
EXPOSE 3040 3041

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${FERRET_VAULT_PORT:-3041}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/ferret-entrypoint.sh"]
