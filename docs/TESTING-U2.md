# Testing saving and the generator in the Firefox extension

This milestone added three things to the Firefox extension: a generator for passwords and passphrases, offers to save and
update a password after a form is submitted, and a better detection of what a form is for. This file lists how the detection
is measured (three sets of test forms, run in real Firefox), what the gate asks of the numbers, which misses are explained,
and how to run and keep the reports. `docs/TESTING-U1.md` describes the rest of the extension's test suites and the checks by
hand; `extension/test/firefox/README.md` describes the runner and the fixture server.

All data is throwaway test data. The forms are written for this repository: no real site, no copied markup, no brand names.

## What is measured

The detection matrix (`extension/test/firefox/95-matrix.e2e.spec.mjs`) runs in Firefox Release and Firefox ESR, each channel
on an end-to-end stack of its own with the extension signed in to it. Every case of a set is a small static page with a
`case.json` that states what must happen. Each case goes through up to three parts:

- **fill**: the page is opened, the real keyboard shortcut gives the extension access to the tab, the extension is asked for the
  page's logins, fills them, and every input of every document of the page is read back;
- **capture**: the runner types what a person types, submits, and reads the offer the extension made (its kind, origin, user
  name, and a hash of the password, never the password) through the test bridge. The runner never clicks a save control; the
  vault's item list is compared before and after, so any change counts as a write without a click;
- **generator**: the generator fills the new-password fields of the page, which must then hold a value that is not the vault's
  and that respects the password rules the page states.

A build without saving has no offers, so the capture part counts every case as not run.

## The three sets

| Set | Where | What it is | Run with |
| --- | --- | --- | --- |
| Corpus | `extension/test/fixtures/forms/` (and `forms-capture/` for the pages of the adversarial capture spec) | 130 forms, fixed before the detection was tuned on it, and frozen: a change needs a reviewer's yes and a line in the report | `scripts/lanbox-ext.sh matrix` |
| Hold-out | `extension/test/fixtures/forms-holdout/` | 39 forms written by someone who had not seen the detection code or the corpus | `scripts/lanbox-ext.sh matrix --set holdout` |
| Parity | `extension/test/fixtures/forms-parity/` | 68 forms that cover the patterns of a public autofill test catalogue, written from scratch (nothing copied) | `scripts/lanbox-ext.sh matrix --set parity` |

Each set has a README that explains its cases and the numbers of record. The unit tests (`scripts/lanbox-ext.sh unit`) check
the sets without a browser (the schema, the minimum number of cases per category, the closed lists below).

### Running a set

```
scripts/lanbox-ext.sh matrix [--channel release|esr] [--manifest mv3|mv2] [--part fill|capture|all] [--set corpus|holdout|parity] [--grep <case id>]
```

All of it runs on the build host. The manifest is MV2 unless named, as that is the build Firefox gets. Without `--channel`
the two channels run one after the other, each on a stack of its own, because every channel makes entries in the stack's one
account and a second channel on the same account would find twice as many (a page then matches two items and the extension
offers a choice where one item was expected). `--grep` keeps the cases whose id contains the text. A run of one part or of some
cases has no gate: `matrix.md` says "partial run" and whether the part it measured is met.

For a run that does not collide with another one on the build host, give the stack a name and a network of its own:

```
FERRET_E2E_SUFFIX=<name> FERRET_E2E_SUBNET=172.30.<n> scripts/lanbox-ext.sh matrix --set parity
```

At most two Firefox runs at a time on the build host, counting the matrix, `e2e` and `gate`.

## What the gate asks

The gate is the set of tests at the end of the matrix spec. They pass or fail per channel:

| Test | Rule |
| --- | --- |
| `matrix_detection_is_at_least_95_percent_for_fill_and_capture_in_release_and_esr` | Corpus: fill, capture and the generator pass at 95 % or more of the positive cases |
| `no_positive_category_is_below_80_percent` | Corpus: no positive category below 80 % |
| `holdout_detection_is_at_least_90_percent` | Hold-out: fill and capture at 90 % or more of the cases the stated rules allow (the explained misses below are taken out of the rate; the raw rate is always printed beside it) |
| `parity_detection_is_at_least_90_percent_for_fill_capture_and_generator` | Parity: fill, capture and generator at 90 % or more, and no case that did not run |
| `matrix_has_zero_unsafe_fills_and_zero_unsafe_offers` | Every set: no value in a field that must stay empty, no fill under a rule that does not match, no offer for a form that is not a sign-in, and no case that did not run |
| `false_offers_on_benign_negatives_are_reported` | The report states the offers made on harmless pages (the corpus and the parity set have none) |
| `matrix_fill_rate_is_at_least_the_baseline` | Corpus: the fill rate does not fall below the one of record |
| `webdriver_key_actions_are_trusted_in_both_channels` | The runner's key events are trusted (`isTrusted`), which the extension requires: without it the matrix means nothing |

A test that is about another set says so and passes without checking: a hold-out run does not check the corpus rules. So every
set has to be run, and the gate script runs all three.

### The explained misses

A miss is explained when a stated product rule forbids what the case wrote down. Explained misses are closed lists, kept in the
code and in the sets' READMEs, and they change only by a logged ruling. Each must miss exactly the rule's way and make nothing
unsafe; a case on a list that starts to pass fails the test, so a list cannot go stale.

- **Corpus.** Three cases are refused on purpose: `login-en-modal` and `spa-modal-nl` (fill) and `change-modal-de`
  (generator). Their form sits in a modal window that the page moves with a CSS transform, and the extension refuses a field
  under a transformed ancestor because such an ancestor can hide the field from the person. They are counted as misses
  (fill 53 of 55, generator 25 of 26) and the corpus still meets the 95 % rule.
- **Hold-out.** The rule is that a login is offered only after the page moved on or the form went away and no password form is
  shown again, because a failed sign-in looks exactly like a form that stays. Five cases send a request and leave the form on
  screen, or have a submit that nothing follows: `ho-controlled-react-en`, `ho-login-noform-nb-fetch`,
  `ho-login-noform-es-roleform`, `ho-shadow-custom-slot-de`, `ho-identifier-first-samepage-en`. A sixth,
  `ho-cross-action-de`, posts to another site, where the script cannot run; it is not in the positive rates. The raw
  numbers (fill 14 of 14, capture 15 of 20) are always printed beside the adjusted ones (10 of 10, 15 of 15).
- **Parity.** None.

## The gate script

```
scripts/lanbox-ext.sh gate [--channel release|esr] [--manifest mv3|mv2]
```

It runs, in this order, and fails if any step fails:

1. the Firefox step (the XF specs, no network);
2. the end-to-end step (the XE specs, against one stack; the screenshots of the specs are kept);
3. the matrix of the corpus, of the hold-out set and of the parity set, one channel at a time, each on a stack of its own
   that is removed afterwards.

The step 3 matrix takes the longest. The two channels of a step run one after the other inside one container, on one account:
a spec that looks for an item it made has to search for it by name (the popup's "All" list shows only the first 40 items by
name, and the account already holds the items of the channel that ran first).

### Saving the reports

What a container writes comes out of it as a tar archive on its standard output, also after a failure, and the script unpacks
it into `test-results/out/` (or `$FERRET_EXT_OUT_DIR/`, for a run that should keep its output somewhere else):

```
test-results/out/gate-shots/<channel>/                              the screenshots of the e2e specs
test-results/out/gate-matrix/<set>/<channel>/u2-matrix/             corpus and hold-out: <channel>-<manifest>.json and matrix.md
test-results/out/gate-matrix/parity/<channel>/u2-matrix-parity/     the same for the parity set
```

The gate puts every set and channel in a folder of its own, because the corpus and the hold-out set write to the same folder
name (`u2-matrix`) and a second run would overwrite the first one's reports. A plain `matrix` run writes to
`test-results/out/u2-matrix/` (parity: `u2-matrix-parity/`), so copy the reports away before running another set.

The script reads and writes the archives through the shell, never as `tar -f <path>`, and turns a temporary folder that comes
in Windows form (`C:\Users\...`) into the POSIX form first: GNU tar reads `C:` as the name of a remote host and refuses the
path. Run the script from Git Bash, WSL or Linux, not from a shell that has no `tar`.

The folder `test-results/` is ignored by git. To keep the numbers of a gate run, keep the folder or copy `matrix.md` and the
`.json` files of each set and channel.

### Reading `matrix.md`

`matrix.md` and the JSON hold, per channel: the fill, capture and generator rates over the positive cases; the rate per
category; the unsafe fills and unsafe offers (any one fails the gate); the offers made on harmless pages; the cases that did
not run (they count as failed); and each miss with its part and reason. The JSON never holds a password, only the verdicts and
hashes.

## Other things to know

- The release build and the test build differ: every matrix run uses the test build, which has a bridge for reading the offers.
  The release package is checked by `scripts/lanbox-ext.sh lint` (no test file, no test page, no fixed id, only the allowed
  permissions, and the saving feature on).
- The matrix says what the detection does on forms that cover the patterns we know. It says nothing about a site that does
  something new. A blind measure needs a new set, written the same way as the hold-out set.
- Timing bounds of the capture footprint specs are for a quiet machine. `FERRET_TIMING_SLACK` (a number from 1 to 2) loosens
  them on a shared one; the gate keeps 1.
