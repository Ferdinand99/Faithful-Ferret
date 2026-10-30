# Releasing

This page describes how a release is made, what it contains, how to check it, and
the things that are bumped by hand. Nothing is released automatically: a release
happens when the maintainer merges the release pull request.

## How a release is made

1. Commits on `main` use [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `chore:`, a `!` or a `BREAKING CHANGE:` footer for breaking
   changes).
2. The workflow `Release Please` (`.github/workflows/release-please.yml`) keeps one
   open pull request, "chore(main): release x.y.z". It changes the version in
   `Cargo.toml`, in `Cargo.lock` and in `fuzz/Cargo.lock`, writes `CHANGELOG.md` and
   `version.txt`, and updates `.release-please-manifest.json`. The configuration, with one component,
   is `release-please-config.json`. Before 1.0 a breaking change raises the minor
   version, not the major one.
3. Before merging, check that the Public Suffix List snapshot is fresh (below), that
   all checks on the pull request are green, and read the changelog.
4. Merging the pull request makes release-please create the tag `vX.Y.Z` and the GitHub
   release. The same workflow then calls `Release` (`.github/workflows/release.yml`).
5. `Release` builds the packages from the tag, runs its checks, signs the files and
   attaches them to the GitHub release.

No one creates tags or releases by hand. If the release workflow fails half way, fix
the cause and run `Release` again from the Actions page ("Run workflow") with the tag
(for example `v0.1.0`). It attaches the files to the existing release and replaces
files that are already there.

## What a release contains

| File | Content |
|---|---|
| `ferret-core-wasm-web-<version>.tar.gz` | `pkg-web/` (the WebAssembly module, its JavaScript wrapper and type declarations), `js/` (the worker client that loads it) and the license |
| `ferret-core-wasm-node-<version>.tar.gz` | `pkg-node/` and the license |
| `ferret-core-wasm-<version>.cdx.json` | A CycloneDX 1.5 software bill of materials of the release dependency graph (the WebAssembly target, no `test-support`) |
| `SHA256SUMS` | The SHA-256 of the three files above |
| `<file>.sigstore.json` | A [cosign](https://docs.sigstore.dev/) bundle (signature, certificate and transparency log entry) for each of the four files above |

The archives are reproducible: building the same commit with the same pinned tools
gives the same bytes. The release build never contains the `test-support` feature;
the build checks the module's exports (`scripts/check-no-test-support.sh`) and the
package test `release_artifact_has_no_test_support_and_matches_sha256`
(`tests/node/release.test.mjs`) checks the archives themselves.

### Checking a release

Download the files of the release into one folder, then:

```sh
sha256sum -c SHA256SUMS

cosign verify-blob \
  --bundle ferret-core-wasm-web-X.Y.Z.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Ferdinand99/Faithful-Ferret/\.github/workflows/(release|release-please)\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ferret-core-wasm-web-X.Y.Z.tar.gz
```

The signature is made with the identity of the GitHub Actions workflow (keyless), so
there is no long-lived signing key to lose. Verify `SHA256SUMS` the same way, then
check the other files against it.

## The Public Suffix List snapshot

Passkey origin checks use an embedded snapshot of the Public Suffix List
(`crates/ferret-core/src/passkey/public_suffix_list.dat`). The workflow `PSL age` runs
`scripts/check-psl-age.sh` every week. The check prints a warning (a yellow annotation)
once the snapshot is more than 75 days old and fails when it is more than 90 days old.
The same check must pass for a release: it runs on the release pull request and again
at the start of the `Release` workflow.

To refresh the snapshot, run `scripts/update-psl.sh` and then:

1. Put the new commit and the SHA-256 of the test file, which the script prints, into
   `vectors/external/SOURCE.md`.
2. The test `psl_upstream_test_file` in `crates/ferret-core/tests/origin.rs` counts the
   `checkPublicSuffix` cases in the upstream test file. There are 78 today. If the script
   reports another number, change the number in the test and in `SOURCE.md`.
3. Look at the diff of the snapshot (the number of rules, and that no top-level domain of the
   ICANN section disappeared), run the test suite, and regenerate the vector manifest with
   `cargo run -p ferret-vectorgen --bin vectorgen -- generate`.

The script downloads both files into a temporary folder and moves them into place only
when both downloads worked.

### Why the release pull request needs a workaround

GitHub does not start `pull_request` workflows for a pull request that was opened with
the default `GITHUB_TOKEN`. Release-please opens the release pull request with that
token, so `PSL age` and the other workflows do not run on it by themselves. Two
measures cover this:

- `Release Please` runs the age check itself after it has opened or updated the pull
  request, and posts the result as a commit status named "Public Suffix List snapshot
  age" on the pull request. If branch protection requires that status, the pull request
  cannot be merged with a stale snapshot.
- To make every other workflow run on the release pull request as well, create a
  fine-grained personal access token (or a GitHub App) that can write contents and pull
  requests in this repository only, and store it as the repository secret
  `RELEASE_PLEASE_TOKEN`. The workflow uses it in place of `GITHUB_TOKEN` when it exists.
  Without the secret, close and reopen the release pull request, or push an empty commit to
  its branch from a normal account, to start the checks.

## Things that are bumped by hand

Dependabot (`.github/dependabot.yml`) opens pull requests for crates, npm packages, GitHub
Actions and the base image of the builder. These are not tracked by it:

- **The Rust toolchain** (`rust-toolchain.toml`, the minimum version in `Cargo.toml`, the
  builder image and the workflows). Change them together.
- **The nightly toolchain** used for fuzzing and branch coverage. `fuzz/NIGHTLY` and the
  `NIGHTLY_TOOLCHAIN` argument in `docker/builder.Dockerfile` must name the same dated
  nightly; the CI job "Fuzz nightly matches the builder image" fails if they differ. Move
  both together, then run the fuzz targets and the coverage check once.
- **Tools installed from release archives or with `cargo install`** in the builder image and
  the workflows (wasm-pack, wasm-bindgen-cli, wasm-tools, binaryen, Node, cargo-deny,
  cargo-vet, cargo-fuzz, cargo-llvm-cov, cargo-cyclonedx). Each is pinned by version, and the
  downloaded ones also by SHA-256. The same version appears in more than one place
  (`docker/builder.Dockerfile`, `.github/workflows/wasm.yml`, `.github/workflows/release.yml`,
  `.github/workflows/audit.yml`); change all of them.
- **The base images of the builder** are pinned by digest. To move to a new one, look up the
  digest of the new tag with `docker buildx imagetools inspect <image>:<tag>` and change the tag
  and the digest together.

## Supply-chain checks

- `cargo deny` (`deny.toml`) checks advisories, licenses, sources and duplicate versions. A
  duplicate version needs an entry with a reason. An advisory is not ignored without a written
  reason and an owner decision.
- `cargo vet` (`supply-chain/`) trusts the audits of Mozilla, Google and the Bytecode Alliance.
  Every other dependency version is an exemption with a date. `cargo vet suggest` shows which
  audits would remove exemptions.
- The workflows pin every third-party action by commit SHA, give each job the least permissions it
  needs, and never use `pull_request_target`.
