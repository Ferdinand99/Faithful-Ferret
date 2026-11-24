# Firefox test harness

Short probes of the extension's test build in real Firefox, through geckodriver,
in the runner image `docker/ext-runner.Dockerfile`.

```
scripts/lanbox-ext.sh firefox [--channel release|esr] [--manifest mv3|mv2] [--grep <name>] [--headed]
scripts/lanbox-ext.sh e2e     [--channel ...] [--manifest ...] [--grep <name>] [--no-up]
scripts/lanbox-ext.sh gate    [--channel ...] [--manifest ...]
```

Both run on the build host. The Firefox step has no network (`e2e`: only the
end-to-end stack's network). The WASM package is fetched and checked in a step of
its own. A skipped spec, or a run in which no test passed, fails the run.

`e2e` starts an end-to-end stack of its own for every run (compose project, network,
host names and volumes named `ferret-x<8 hex>`), so two runs never remove each
other's stack, and removes it when the run ends. It also starts the stack's Chromium
browser server (`lanbox-ferret-test.sh e2e-chromium`), which the end-to-end spec
drives with Playwright for the web vault's part. `gate` runs the `firefox` step and
then the `e2e` step (MV2 by default) and unpacks the screenshots the e2e specs take
into `test-results/out/gate-shots/<channel>/`.

At most two `e2e` runs at a time, counted inside the limit of two Firefox runs on the
build host (each also builds the server image, with at most four cargo jobs, and
runs a Chromium). The stack with the default names (`ferret-e2e`: `--no-up`, the web
vault's `lanbox-ferret-test.sh e2e-run`) stays for one user at a time. A run that is
killed hard (no exit trap) leaves its `ferret-x<8 hex>` stack; the next `e2e` run
removes any such stack older than six hours, and one can be removed at once with
`FERRET_E2E_SUFFIX=x<8 hex> scripts/lanbox-ferret-test.sh e2e-down` (find them with
`docker ps -a --format '{{.Label "owner"}}' | grep '^ferret-x'`).

The adversarial specs (`70-phishing`, `71-clickjacking`) and the end-to-end spec
(`80-end-to-end`) share `adversary.mjs`: a signed-in Firefox with the test sites'
entries, the real popup about a page's tab, a UI port that stays open across steps,
and a walk through every frame of a page to see where a password went.

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
another top-level domain, three kinds of homograph), the same host over http
and on another port, insecure ancestors and the loopback exception, same-site,
cross-site and foreign frames, frames without a usable origin (about:blank,
srcdoc, sandboxes, data:, blob:, javascript:, nested), a
private suffix (`a.github.io`, `b.github.io`), overlays, hidden and off-screen
fields, CSS on a parent (opacity, filter, transform, clip-path, mask,
mix-blend-mode, visibility, also through a shadow root), popover and modal
dialog covers, tiny and below-the-fold fields, pages that turn hostile on blur,
a page of forged events, a frame that moves to a foreign
origin on request, and a page that imitates Ferret's title and icon. `pages.mjs`
lists each site with its expected outcome; `origins.mjs` names the origins.

The example family is under `example.net` and `example.org`, which the core's
Public Suffix List knows (a name under `.test` has no registrable domain, so
same-site and `domain` matches would never hold there).

The fixture server serves them on three listeners (https on 443, a second https
port 8443 and http on 80 in the runner; the container allows unprivileged
processes to bind them), so `https://login.example.net/` is an ordinary origin
without a port. `server.siteUrl(id)` and `server.origin(name)` give the
addresses of a run. Every host is in `test/fixtures/hosts.json`, so the runner
maps it to the server and the release check refuses it in a release. Nothing
under `test/` is ever packaged.

A password field whose verdict does not depend on the page carries
`data-fixture-expect="fill"` (a clear control field) or `"reject"` (a hidden,
covered or off-screen one that must never be filled).

## The detection matrix

`scripts/lanbox-ext.sh matrix [--channel release|esr] [--manifest mv3|mv2] [--part fill|capture|all] [--set corpus|holdout|parity] [--grep <case id>]`
runs `95-matrix.e2e.spec.mjs` on the end-to-end stack: the extension signed in to it, a vault with a few
entries, and every case of the corpus in `test/fixtures/forms/` (see its README). The fill phase opens each
page with the real shortcut, asks the extension for the page's entries, fills them and reads every input of
every document; the capture phase types what a person types and reads the extension's offers through the test
bridge's `offers_peek` (the offers' kind, origin, user name, what the write path makes of them and the SHA-256 of
each password, never a password). A build without the `save` feature has no offers, `offers_peek` says so and the
capture phase counts every case as not run. The first test of the spec proves that WebDriver's key events are trusted
(`isTrusted`) in both channels; the extension counts only trusted input, so the matrix means nothing without it.

`matrixReport.mjs` turns the results into the numbers: the fill and capture rates over the positive cases,
the rate per category (no positive category below 80 %), the unsafe fills and unsafe offers (any one fails the
gate), the offers on harmless pages, and the cases that did not run (they count as failed). The reports
`<channel>-<manifest>.json` and `matrix.md` are unpacked into `test-results/out/u2-matrix/`. The plain `e2e`
run leaves the matrix out. `--set parity` runs the own-written autofill-parity suite of
`test/fixtures/forms-parity/` (see its README) with the same rules and writes its reports, apart from the corpus
ones, to `test-results/out/u2-matrix-parity/`. The parity set is part of the gate too: at least 90 % fill, capture and
generator, no unsafe fill or offer, no case that did not run and no false offer on a harmless page, in both channels.

The capture phase also reads the vault's item list (ids and revisions, from the test build's measure port) before and
after each case: the runner never clicks a save control there, so any change is counted as a write without a click,
whatever the extension reports about itself. A generator pass fills the new-password fields of the cases that expect it
and is reported as a line of its own, not in the capture rate. A frame the driver cannot enter makes its case not run.
A case starts with no offers and no kept user names in its tab, cleared before its `prepare` steps (the user name typed in a first step
belongs to the case). The shortcut that gives the page its permission (`activeTab`) is pressed on the page the case opens; a case whose
`prepare` steps lead to another page presses it again there, as a person who has gone on would.
A run of one part (`--part`) or of some cases (`--grep`) has no gate: `matrix.md` says "partial run" and whether the
part it measured is met.

### The hold-out set

`test/fixtures/forms-holdout/` is a second set of cases (`--set holdout`), written without sight of the detection code or of the corpus
(see its README for the cases, the numbers of record, the target and the closed list of explained misses). Fill and capture are held to
90 % per channel over the cases the stated rules allow, with no unsafe fill or offer; the raw rate is always printed beside the adjusted
one (`holdout_detection_is_at_least_90_percent`). Its cases keep the names their author gave them (`ho-...`). The runner maps what the
schema leaves open (category names, frame and field kinds, split-code indexes, absent keys, hosts; `HOLDOUT_LANGUAGES`, and the `ho-`
id prefix), and never an expectation. Six sign-in pages were edited, one `action` each, to post to the landing page instead of back
to themselves (listed in the set's README, in a commit of their own).

Run each channel on a stack of its own: a second channel on the same stack finds the first one's entries, so a page matches two items
and gets a choice where one item was expected. The gate script does so.

### The adversarial capture and the end-to-end specs

`72-capture-adversarial.e2e.spec.mjs` drives pages that try to cheat the capture (a page that plants a password and submits,
or submits on a timer with no click; a script that rewrites the typed password; a burst of submits; a look-alike host; a
tab that goes to another site; an offer nobody answers; a lock between the submit and the click) in the real popup and the web
vault. The pages that are not in the corpus (frozen) or the hold-out set are in `test/fixtures/forms-capture/`, with the
corpus' `case.json`; `matrix.mjs` loads them with `captureCasesOf` and the fixture server serves them next to the others.

`81-u2-end-to-end.e2e.spec.mjs` is the whole of saving and updating passwords in one browser: generate, save in a folder, see it in
the web vault, change, update (folders unchanged, "Previous passwords"), sign in with the new password, "Not now" and "Never",
and a save made while the server cannot be reached that goes out after the unlock. It also takes the access to https pages
back and checks that the vault still syncs.

`scripts/lanbox-ext.sh gate` runs the firefox step, the e2e step (these two specs included) and then the matrix of the corpus,
of the hold-out set and of the parity set, one channel at a time, each on a stack of its own.
`docs/TESTING-U2.md` says how to run the sets, what the gate asks, the explained misses and where the reports are saved.

### Timing bounds

The footprint specs (`58-capture`) have bounds for a quiet machine. `FERRET_TIMING_SLACK` loosens them for a shared runner:
a number from 1 to 2, nothing else (a larger factor would switch the bounds off). The build host and the gate keep 1.
