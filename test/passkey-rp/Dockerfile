# The passkey fixture container of the U4 tests: two relying parties (webauthn-rs, strict;
# @simplewebauthn/server, what many real sites use), the test pages and a test CA made at start.
# Started on the build host by scripts/lanbox-passkey-rp.sh; never part of a release.
#
# Both base images are pinned by digest. The Rust build is --locked (Cargo.lock) and the npm
# install is `npm ci` (package-lock.json). The final image has no compiler and no package manager
# cache; it runs as an unprivileged user, with a read-only root file system (the CA and the
# certificate are made in a tmpfs).
FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS rs
WORKDIR /src
COPY webauthn-rs-fixture/Cargo.toml webauthn-rs-fixture/Cargo.lock ./
COPY webauthn-rs-fixture/src ./src
RUN cargo build --release --locked -j 4

FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
LABEL owner=ferret
ARG DEBIAN_SNAPSHOT=20261104T212339Z
# openssl makes the test CA when the container starts; libssl3 is what the webauthn-rs binary links.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10snapshot \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends openssl libssl3 \
    && rm -rf /var/lib/apt/lists/*
# /work is a volume of the container (the CA and the certificate, so that a restart keeps the CA a test browser trusts).
RUN mkdir /work && chown 10001:10001 /work
WORKDIR /app/server
COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY server/*.mjs ./
COPY hosts.json /app/hosts.json
COPY pages /app/pages
COPY --from=rs /src/target/release/ferret-passkey-rp-webauthn-rs /usr/local/bin/ferret-passkey-rp-webauthn-rs
USER 10001:10001
ENV FIXTURE_RS_BIN=/usr/local/bin/ferret-passkey-rp-webauthn-rs \
    FIXTURE_WORK=/work \
    NODE_ENV=production
EXPOSE 80 443
CMD ["node", "/app/server/server.mjs"]
