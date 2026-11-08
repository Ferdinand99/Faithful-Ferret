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

## The test sites

`extension/test/fixtures/sites/` holds the adversarial pages the fill engine and
the frame rules are tested against: look-alike hosts (a dash, a foreign suffix,
a Cyrillic homograph), the same host over http and on another port, a foreign
frame, frames without a usable origin (about:blank, srcdoc, sandboxes), a
private suffix (`a.github.io`, `b.github.io`), overlays, hidden and off-screen
fields, CSS on a parent (opacity, filter, transform, clip-path, mask,
mix-blend-mode, also through a shadow root), a frame that moves to a foreign
origin on request, and a page that imitates Ferret's title and icon. `pages.mjs`
lists each site with its expected outcome; `origins.mjs` names the origins.

The fixture server serves them on three listeners (https on 443, a second https
port 8443 and http on 80 in the runner; the container allows unprivileged
processes to bind them), so `https://login.example.test/` is an ordinary origin
without a port. `server.siteUrl(id)` and `server.origin(name)` give the
addresses of a run. Every host is in `test/fixtures/hosts.json`, so the runner
maps it to the server and the release check refuses it in a release. Nothing
under `test/` is ever packaged.

A password field whose verdict does not depend on the page carries
`data-fixture-expect="fill"` (a clear control field) or `"reject"` (a hidden,
covered or off-screen one that must never be filled).
