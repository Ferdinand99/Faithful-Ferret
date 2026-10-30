# The runner of the end-to-end browser tests: the Playwright image of
# scripts/lanbox-browsers.sh (same tag and digest) plus certutil, which fills the
# NSS database that Chromium reads its trusted authorities from. Built once on
# the LANBox by `scripts/lanbox-ferret-test.sh e2e-run` and removed by `e2e-down`,
# so a test run needs no package mirror.
#
# The package version is pinned. When Ubuntu replaces it in the noble archive the
# build fails and this line has to move to the new version (apt-cache policy
# libnss3-tools in the base image shows it).
FROM mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends libnss3-tools=2:3.98-1ubuntu0.3 \
    && rm -rf /var/lib/apt/lists/*
