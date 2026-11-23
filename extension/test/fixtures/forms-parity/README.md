# The autofill-parity suite

One test page for each form of the public autofill test catalogue at autofill.me (about sixty pages: sign-in
variants, dialogs and frames, multi-step and single-page sign-up, password rules, payment, identity, search,
passkey and device-trust pages and a few more). The catalogue was used as a list of patterns to cover; the pages
here are our own work. **No markup, style or script of the catalogue is copied**: every page was written from
scratch for this suite, with its own ids, wording and structure, and carries no brand name and no remote resource.
(The catalogue states no licence, which is why nothing is taken from it.)

The suite is separate from the frozen detection corpus (`../forms/`) and from the hold-out set. It is not frozen:
a page may be corrected when it turns out to be a mistake in the fixture. It is served by the same fixture server
(`/<id>/` from any listed host), uses the same `case.json` schema and the same categories, and every id starts with
`ap-` followed by the category (`ap-login-...`, `ap-frame-...`, `ap-harmless-...`).

## Running it

    scripts/lanbox-ext.sh matrix --set parity [--channel release|esr] [--part fill|capture|all] [--grep <case id>]

The runner, the scoring and the safety rules are those of the corpus (see `../forms/README.md` and
`test/firefox/matrixReport.mjs`): fill and capture rates over the positive cases, the rate per category, unsafe
fills, unsafe offers, offers on harmless pages and cases that did not run. The report goes to
`test-results/out/u2-matrix-parity/` (`<channel>-<manifest>.json` and `matrix.md`), apart from the corpus reports.
The unit test `test/unit/corpusParity.test.mjs` checks the suite without a browser.

One addition to the schema belongs to this suite: `expect.generated.rules` (`minlength`, `maxlength`, `require`
and `forbid` with the classes `lower`, `upper`, `digit`, `symbol`) says which password rules the page states,
and the generator pass counts a generated password that breaks them as a miss. The runner checks the value
where it can see it; a report holds only the verdict.

## What each page stands for

| Page of the catalogue | Our case(s) |
|---|---|
| login-simple | `ap-login-simple` |
| login-multi-step, -hidden | `ap-identifier-multi-step`, `ap-identifier-multi-step-hidden` (the user name is carried to the second page in a read-only field, or in a hidden one) |
| login-multi-step-totp, -hidden-totp | `ap-identifier-multi-step-totp`, `ap-identifier-multi-step-hidden-totp` (user name, password, then a code) and `ap-otp-multi-step-totp`, `ap-otp-multi-step-hidden-totp` (the same flows measured at the code step) |
| login-duplicate-username | `ap-identifier-duplicate-username` |
| login-totp | `ap-login-totp-inline` |
| login-reveal-display-none, -zero-size, -added-hidden, -scroll | `ap-login-reveal-display-none`, `-zero-size`, `-added-hidden`, `-scroll` |
| login-broken | `ap-harmless-broken-login` (search-like fields with an invalid input type, no password) |
| login-dialogs, login-positioned-dialog | `ap-login-dialog-modal`, `ap-login-dialog-positioned` |
| login-iframe, -frameset, -nested-iframe | `ap-frame-iframe`, `ap-frame-frameset`, `ap-frame-nested-iframe` |
| login-dialogs-iframe, -nested-dialogs-iframe, -iframe-positioned-dialog | `ap-frame-dialog-iframe`, `ap-frame-nested-dialogs-iframe`, `ap-frame-iframe-positioned-dialog` |
| login-shadow | `ap-shadow-added-open` |
| sign-in-with | `ap-harmless-sign-in-with` |
| protected | `ap-harmless-protected` |
| the three performance pages | `ap-login-heavy-nodes` (thousands of elements), `ap-login-heavy-mutations` (the page changes every few milliseconds), `ap-login-heavy-buttons` (hundreds of provider buttons) |
| registration-email, -username, -simple | `ap-signup-email`, `ap-signup-username`, `ap-signup-email-and-username` |
| registration-multi-step, -hidden | `ap-signup-multi-step`, `ap-signup-multi-step-hidden` |
| registration-multi-step-spa, -spa-hidden | `ap-spa-registration-steps`, `ap-spa-registration-steps-hidden` |
| registration-2fa | `ap-harmless-totp-setup` (a page that shows an authenticator address and has nothing to fill) |
| totp-registration | `ap-signup-totp-registration` |
| ssh-key-generator | `ap-harmless-ssh-key` |
| change-password | `ap-change-password` |
| registration-password-rules | `ap-signup-rules-length`, `ap-signup-rules-mixed`, `ap-signup-rules-no-symbols` |
| credit-card-simple, -mm-yy | `ap-card-simple`, `ap-card-mm-yy` |
| identity-simple, -aria-expanded, -datalist | `ap-harmless-identity-simple`, `-aria-expanded`, `-datalist` |
| search | `ap-harmless-search` |
| data-1p-ignore-body, -elements | `ap-login-data-1p-ignore-body`, `ap-login-data-1p-ignore-elements` |
| the five passkey pages | `ap-harmless-passkeys-index`, `-register`, `-explicit`, `-code` (negative) and `ap-identifier-passkeys-implicit` (a user name field with `username webauthn` and no password: the user name is filled) |
| other-inputs | `ap-harmless-other-inputs` |
| single-page and multi-page multi-step form | `ap-harmless-steps-single-page`, `ap-harmless-steps-multi-page` |
| device-trust, device-trust-notifications | `ap-harmless-device-trust`, `ap-harmless-device-trust-notifications` |
| the three save pages | `ap-harmless-save-login`, `-save-card`, `-save-identity` |
| clue | `ap-identifier-player-id` |
| recipe | `ap-login-recipe-search-type` |

Passkey, SSH-key, device-trust, save-item, TOTP-setup and similar pages are negative cases: no offer is made
(`expect.no_offer`) and nothing is filled, except that a user name in the e-mail box of a bare `webauthn` page is
allowed (`expect.allow`: a fill or no fill both pass). The payment pages are in the `card` category, where an offer is always unsafe.

## Choices that are ours

- The pages post to the fixture server's blank page (`/static/login-done.html`); nothing leaves the machine.
- Where the catalogue's page is ambiguous, the case says what a password manager should do and the README of
  the run says what happened: `ap-identifier-player-id` (a form with a single identifier and no autocomplete
  hint) expects the user name to be filled; the `data-1p-ignore` pages expect a normal fill and offer, because
  the attribute is another product's hint and the person asked for the fill; identity forms must receive no
  user name or password, also in their e-mail box; a sign-up with both an e-mail and a user name expects the
  user name in the offer.
- A closed shadow root cannot be reached by the runner (WebDriver finds it only through script access that closed
  roots refuse), so only the open variant is a case.
- `ap-login-reveal-scroll` has a form four screens below the fold. The fill engine fills only a field the person can see (it checks that the
  field lies in the window), so the case is the person's: they scroll to the form and click in the first box, and then ask for the fill
  (`prepare`). Scrolling the page for the person is not done: a form the person cannot see would then be filled too.
- Multi-step flows use `prepare` to reach the step that is measured; the capture steps then continue from there.
