# Firefox test harness

Short probes of the extension's test build in real Firefox, through geckodriver,
in the runner image `docker/ext-runner.Dockerfile`.

```
scripts/lanbox-ext.sh firefox [--channel release|esr] [--manifest mv3|mv2] [--grep <name>] [--headed]
scripts/lanbox-ext.sh e2e     [--channel ...] [--manifest ...] [--grep <name>] [--no-up]
```

Both run on the LANBox build VM. The Firefox step has no network (`e2e`: only the
end-to-end stack's network). The WASM package is fetched and checked in a step of
its own. A skipped spec, or a run in which no test passed, fails the run.

## The runner image

Every download in `docker/ext-runner.Dockerfile` is pinned by version and
SHA-256. The header of the file says where each checksum comes from.

- **The unbranded Release build expires.** Mozilla keeps the artifacts of the
  pinned CI task until `RELEASE_EXPIRES` (2027-11-02). `runner.test.mjs` fails 30
  days before that day. To renew the pin: take the Taskcluster task that built
  the new release revision (index `gecko.v2.mozilla-release.revision.<rev>.firefox.linux64-add-on-devel`),
  and move `RELEASE_TASK`, `RELEASE_VERSION`, `RELEASE_SHA256`, `RELEASE_SHA512`,
  `RELEASE_EXPIRES` and the `FERRET_FIREFOX_RELEASE` line together.
- Dependabot does not see these pins. They move by hand, with their checksums.
- The content sandboxes of Firefox are switched off in the image (Docker's
  seccomp profile blocks the user namespaces they need). Anything measured here
  was measured with the sandboxes off.
- Old image tags of the runner are removed one by one when a new one is built;
  nothing is pruned.
