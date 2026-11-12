# The malicious server of the end-to-end stack (docker/compose.ferret-e2e.yml,
# service ferret-e2e-evil). The build context is this folder only. It is used by
# that file and by no other: the server image (docker/server.Dockerfile) never
# has these files, and scripts/check-ferret-test-stack.sh checks that.
#
# The base image is the one of docker/server.Dockerfile, pinned by digest. The
# proxy has no dependencies: it is three files of Node's own modules.
FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
WORKDIR /app
COPY proxy.mjs modes.mjs recorder.mjs ./
USER node
CMD ["node", "proxy.mjs"]
