# The runner of the Firefox tests of the extension (extension/test/firefox):
# two Firefox builds, geckodriver and Node, every download pinned by version and
# SHA-256. Built once on the LANBox by `scripts/lanbox-ext.sh firefox` (the tag
# follows the content of this file) and run without any network.
#
# What is pinned and where each checksum comes from:
#  * debian:trixie-slim by digest, and every Debian package from the archive
#    snapshot of the minute the base image was made (so a package that Debian
#    replaces later does not move the build).
#  * Firefox ESR 153.6.0esr: Mozilla's release archive. The SHA-256 is the line
#    for linux-x86_64/en-US/firefox-153.6.0esr.tar.xz in the SHA256SUMS of that
#    release, which verifies against SHA256SUMS.asc made by the Mozilla release
#    key 14F2 6682 D091 6CDD 81E3 7B6D 61B7 B526 D98F 0353.
#  * Firefox Release 159.0.1, the unbranded build of Mozilla's CI (add-on-devel;
#    a branded release cannot switch off signature checks). Mozilla publishes no
#    signed SHA256SUMS for it. The build is pinned by the Taskcluster task that
#    built revision 7b34a03a910d of mozilla-release (tag FIREFOX_159_0_1_RELEASE),
#    by the SHA-256 of the archive, and by the SHA-512 that the build itself wrote
#    to target.checksums. Mozilla keeps these artifacts for one year (to
#    2027-11-02); a later build of this image needs a newer pin.
#  * geckodriver 0.37.1: the GitHub release asset. SHA-256 as listed by GitHub
#    for the asset and as computed; the .asc verifies against the Mozilla release
#    key above.
#  * Node 22.23.4: nodejs.org. SHA-256 from SHASUMS256.txt, which verifies
#    against SHASUMS256.txt.asc (a Node.js release key).
#
# To move a pin, change the ARG and the checksum together, and the version that
# the tests expect in the ENV lines at the end.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG DEBIAN_SNAPSHOT=20261104T212339Z
ARG ESR_VERSION=153.6.0esr
ARG ESR_SHA256=31321cd9e2cef73df678417e810cdd1b5760aa5cc8063c8465669e5869cb8498
ARG RELEASE_VERSION=159.0.1
ARG RELEASE_TASK=QyKNOg21RX61F2Ak-F6m3A
ARG RELEASE_SHA256=10e6424a1d708682178119a6289cf6563ba5f87dfbb5f4a7fa8dfad01549b191
ARG RELEASE_SHA512=b896f4ad9b7ef87be90825b91f2e85dd54eb5f6490e8d98e0972d08a711647b8febf7bef990755bfae7d395ad0fb65abaee2e02bd43b02c54b449aee69d75029
ARG GECKODRIVER_VERSION=0.37.1
ARG GECKODRIVER_SHA256=e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e
ARG NODE_VERSION=22.23.4
ARG NODE_SHA256=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

# Packages: what Firefox needs to start (GTK and friends), Xvfb for a run with
# a window, openssl for the test certificate authority, curl and xz for the
# downloads below (curl is removed again at the end of the downloads).
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ trixie-security main" \
      > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10snapshot \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
         ca-certificates curl xz-utils openssl util-linux \
         libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 libx11-xcb1 libxtst6 libxt6t64 \
         xvfb xauth fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN test "$(uname -m)" = x86_64 \
    && cd /tmp \
    && curl -fsSL -o esr.tar.xz "https://archive.mozilla.org/pub/firefox/releases/${ESR_VERSION}/linux-x86_64/en-US/firefox-${ESR_VERSION}.tar.xz" \
    && echo "${ESR_SHA256}  esr.tar.xz" | sha256sum -c - \
    && mkdir /opt/firefox-esr && tar -xJf esr.tar.xz -C /opt/firefox-esr --strip-components=1 \
    && curl -fsSL -o release.tar.xz "https://firefox-ci-tc.services.mozilla.com/api/queue/v1/task/${RELEASE_TASK}/artifacts/public/build/target.tar.xz" \
    && echo "${RELEASE_SHA256}  release.tar.xz" | sha256sum -c - \
    && echo "${RELEASE_SHA512}  release.tar.xz" | sha512sum -c - \
    && mkdir /opt/firefox-release && tar -xJf release.tar.xz -C /opt/firefox-release --strip-components=1 \
    && curl -fsSL -o gd.tar.gz "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz" \
    && echo "${GECKODRIVER_SHA256}  gd.tar.gz" | sha256sum -c - \
    && tar -xzf gd.tar.gz -C /usr/local/bin geckodriver \
    && curl -fsSL -o node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
    && echo "${NODE_SHA256}  node.tar.xz" | sha256sum -c - \
    && tar -xJf node.tar.xz -C /usr/local --strip-components=1 --exclude='*/CHANGELOG.md' --exclude='*/README.md' --exclude='*/LICENSE' \
    && rm -f /tmp/*.tar.* \
    && apt-get purge -y -qq curl \
    && apt-get autoremove -y -qq \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin ferret \
    && mkdir -p /opt/firefox-esr/distribution /opt/firefox-release/distribution \
    && chown ferret:ferret /opt/firefox-esr/distribution /opt/firefox-release/distribution \
    && /opt/firefox-esr/firefox --version \
    && /opt/firefox-release/firefox --version \
    && geckodriver --version \
    && node --version

# The versions the tests expect to find (extension/test/firefox/harness.mjs).
ENV FERRET_FIREFOX_ESR=153.6.0 \
    FERRET_FIREFOX_RELEASE=159.0.1 \
    FERRET_GECKODRIVER=0.37.1 \
    FERRET_NODE=22.23.4 \
    MOZ_DISABLE_CONTENT_SANDBOX=1 \
    MOZ_DISABLE_GMP_SANDBOX=1 \
    MOZ_DISABLE_RDD_SANDBOX=1 \
    MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1 \
    MOZ_DISABLE_UTILITY_SANDBOX=1 \
    MOZ_CRASHREPORTER_DISABLE=1 \
    MOZ_DISABLE_AUTO_SAFE_MODE=1
