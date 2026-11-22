# The detection corpus

Static look-alike pages of the forms a password manager meets: sign-in, sign-up, change and reset
forms (positive), pages that look like them and must not be filled or offered (negative), and a few
special cases. Every page is written for this corpus: synthetic markup modelled on common patterns,
no copied page code, no brand names, no remote resources.

A case is a folder `<id>/` with `index.html`, `case.json` and, when the case needs them, other pages
(`page2.html`, `inner.html`, `failed.html`). The fixture server serves `/<id>/` and `/<id>/<file>`
from any listed host (`test/fixtures/hosts.json`), over https and over http. `{{origin:<name>}}` in
a page is the origin of a named origin of `test/fixtures/sites/origins.mjs`, with the run's ports.
A folder whose name starts with an underscore is not a case (`_selftest` is the page of the trusted
input self-test).

The corpus is **frozen** once it is merged: a change needs the reviewer's yes and a line in the report with the reason.

## case.json

```json
{ "id": "signup-confirm-nb", "class": "positive", "category": "signup", "lang": "nb",
  "host": "forms.example.net", "path": "/signup-confirm-nb/", "frame": null,
  "steps": [ { "type": "#epost", "text": "anna@example.net" }, { "click": "#go" } ],
  "expect": { "fill": null, "allow": ["#epost"], "generated": { "new": "#pw", "confirm": "#pw2" },
              "capture": { "offer": "save", "username": "anna@example.net", "password_from": "#pw",
                           "origin": "https://forms.example.net" } },
  "must_stay_empty": ["#pw", "#pw2"], "fields": { "#pw": "new_password" }, "source": "own" }
```

- `class`: `positive`, `negative` or `special`. `category` is one of the table in `matrixReport.mjs`
  (a test holds the minimum number of cases for each); the id starts with its category.
- `host`, `scheme` (default `https`), `path`: where the case is opened. `frame` describes the one
  frame of interest (`id`, `host`, `path`, `kind`) or is `null`.
- `prepare`: steps before the fill of the fill phase (a click that shows the next step, a wait for a
  late render). They also run before `steps`.
- `steps`: what a person does for the capture phase: `{ "type": "#id", "text": "...", "repeat": n }`
  (real key events), `{ "click": "#id" }`, `{ "key": "Enter" }`, `{ "wait": ms }`, `{ "generate_fill": true }`
  (the generator fills the new-password fields) and `{ "ferret_fill": true }` (the extension fills the
  page first). `{{password:<entry>}}` in a text is the stored password of a vault entry of the matrix.
- Fields are named by `id` (unique in the document, also inside shadow roots and frames).
- `expect.fill`: `{ entry, fields }`, which vault entry fills which field with `username`, `password`,
  `totp` (a whole code) or `totp:<n>` (digit n of a split code). `null` where the case does not test
  the fill. `expect.allow`: fields in which a fill is acceptable although the case does not test it
  (a real field next to a trap). Any other fill of a vault value is an unsafe fill.
- `expect.capture`: the offer the submission must lead to (`save`, `update` with its `target` entry, or
  `choose`), its user name (`null` when the form has none), the field the password came from and the
  origin. `reuse` and `info` name the warning or info line the offer must carry.
- `expect.generated`: the new-password fields the generator must fill. It is a measure of its own (a generator pass:
  the generator fills the page's new-password fields, which must then hold one value that is not the vault's); it is
  not part of the capture check, which is about the offer. A step `{ "generate_fill": true }` takes the place of
  typing the new-password fields (a few sign-up and change cases use it); the runner then hashes what the fields hold,
  so the offer's password can be matched to its field.
- Negative cases set `no_offer` (or `max_offers`); an offer in a category with no login a person could
  mean (hidden fields, card and PIN forms, a one-time code in a password field, planted values, frames
  that are not the page's own, plain http) is an unsafe offer.
- `must_stay_empty`: fields that must never receive a vault value. `fields`: the kind of the fields
  the case marks (`card_cvc`, `pin`, `otp`, `otp_digit`, `search`, `new_password`, ...); a value from
  such a field in an offer is an unsafe offer.

The vault of the matrix has the entries `forms` (`https://forms.example.net/`, host), `login`
(`https://login.example.net/`, host), `domain` (`https://app.forms.example.org/`, domain) and two
host entries of `https://www.forms.example.net/` (`wwwA`, `wwwB`, for the cases where a form has to
choose). Every entry has the user name `ola` and a password the run makes up.

The case `foreign-frame-blank-fr` tests the `document.open()` variant of a blank frame: the page writes the frame's
document itself, which gives the frame the page's address. A frame built with the DOM only (it keeps `about:blank`)
is the other variant.
