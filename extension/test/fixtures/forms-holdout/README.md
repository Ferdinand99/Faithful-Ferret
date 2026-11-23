# The hold-out set

39 cases of the corpus' schema (see ../forms/README.md), written without sight of the detection code or of the corpus, from the list of
categories and the `case.json` schema only. They measure how well the detection does on pages it was not shaped by. The set is no longer
blind: it is public, it has been run against, and one unit test replays the pattern of `ho-spa-hash-signup-nb`. A later blind measure
needs a new set, written the same way.

Each id is `ho-<the author's category>-...`. All cases use the host `forms.example.net` over https unless the table says otherwise.
"Save" means that a new user name is typed; "update" means the user name `ola` with a different password (target entry `forms`).

## The target

Fill and capture must each reach 90 % per channel, counted over the positive cases whose written outcome the stated product rules allow,
with no unsafe fill and no unsafe offer. A case whose written outcome a stated rule forbids is an explained miss: it is named in a closed
list with its rule (`EXPLAINED_HOLDOUT` in `test/firefox/95-matrix.e2e.spec.mjs`), it stays in the raw rate that is always reported beside
the adjusted one, and it must miss exactly the rule's way (no offer, nothing unsafe); one that starts to pass fails the test, so the list
cannot go stale. The list changes only by a logged ruling. The rules:

- A login is offered only after the page navigated or the form went away and no password form is shown again (a failed sign-in looks
  exactly like a form that stays). Five pages send a request and leave the form on screen, or have a submit that nothing follows:
  `ho-controlled-react-en`, `ho-login-noform-nb-fetch`, `ho-login-noform-es-roleform`, `ho-shadow-custom-slot-de`,
  `ho-identifier-first-samepage-en`.
- A post that lands on another site is a landing page the script cannot run in; it counts as unknown and gives no login offer:
  `ho-cross-action-de` (a special case, not in the positive rates, listed all the same).

## Numbers

The numbers of record are those of the first run (the raw copy with the schema mapping below, before any change to the detection, fill
or capture code), Release 159.0.1 and ESR 153.6.0, MV2, identical: fill 13/14 (92.9 %), capture 10/20 (50.0 %), generator 8/8, unsafe
offers 0, unsafe fills 6 (all precision, `unexpected_field`: the stored sign-in filled into the log-in fields of three negative sign-in
pages that carried no `allow` list; none is a security finding), false offers 0, not run 0. **The hold-out target was not met on the
first run (capture).**

On the final head of the matrix change (both channels, identical): raw fill 14/14 (100 %), capture 15/20 (75.0 %); adjusted (the five
explained positive cases out of the denominator) fill 14/14, capture 15/15; unsafe fills 0, unsafe offers 0.

## What was mapped, and what was edited

Schema mapping in `case.json` (no expectation changed): the author's category names are the corpus' (`identifier-first` is
`identifier`, `noise` is `harmless`, `card-pin` is `card`, `otp-as-password` is `otp-masked`, `planted` is `tamper`, `http` is
`insecure`, `reauth-failed` is `reauth`, `domain-subhost` is `domain-entry`, `cross-action` is `cross-post`); missing keys are the
schema's "none"; a frame's `kind` is a known kind and its `id` an `#id`; a field kind outside the list is `other`; `reuse` is `true`; the
info line of the domain-entry case is the runner's `domain_hit` and the look-alike case's invented `lookalike` info was dropped; a
negative case's `fill` is an `allow`; Spanish is allowed in this set; the hosts `forms.xn--exmple-4nf.net` and `shop.forms.example.org`
and the `foreign` origin are known to the fixture server. After the first run, and logged: a split code's digits are counted from 0 (as
in the corpus), and the log-in fields of three negative sign-in pages (`ho-flood-submits-en`, `ho-planted-swap-showpw-nl`,
`ho-reauth-failed-login-nb`) are `allow`ed, as the corpus' negatives do.

Six pages were edited (one `action` attribute each) as an environment change, in a commit of their own after the first run: a form that
posts back to its own address (`action="#..."`) gets the same page back from the fixture server, which looks like a failed sign-in, so
these now post to the server's landing page `/static/login-done.html`, as the corpus' forms do: `ho-login-de-placeholder`,
`ho-login-en-labelfor`, `ho-login-nl-aria`, `ho-frame-sameorigin-es` (`inner.html`), `ho-lookalike-nb`, `ho-domain-subhost-en`. Reverting
that commit restores the first-run behaviour of those six cases (no offer).

This file is the author's index of the cases, with its table kept.

| id | category | description | expected outcome |
|---|---|---|---|
| ho-login-en-labelfor | login | en, `<label for>`, header search + footer newsletter decoys | fill both; update `forms`; search/newsletter stay empty |
| ho-login-de-placeholder | login | de, placeholder-only fields, no labels, Enter submits | fill both; save kari.nordmann@example.net |
| ho-login-nl-aria | login | nl, visually hidden labels + `aria-label`, utility-class markup | fill both; save femke.de.vries@example.net |
| ho-login-noform-nb-fetch | login-noform | nb, `div`s + `type=button`, `fetch` on click and Enter | fill both; save anna.berg@example.net |
| ho-login-noform-es-roleform | login-noform | es, `role=form` div, div `role=button`, XHR | fill both; update `forms` |
| ho-identifier-first-samepage-en | identifier-first | en, email step then password step on the same page (toggle `hidden`) | save/update with username from step 1 (`ola`, update `forms`) |
| ho-identifier-first-twopages-de | identifier-first | de, step 1 page GET to `page2.html`, hidden username on page 2 | save with username kari.nordmann@example.net |
| ho-signup-confirm-nl | signup | nl, name/email/postcode + password + confirm, newsletter/terms boxes | generator fills both; save sanne.jansen@example.net |
| ho-signup-emailonly-en | signup | en, email + single `new-password`, placeholder + aria-label | generator fills `#pw`; save nora.hale@example.net |
| ho-signup-names-fr | signup | fr, given/family name, email, birthday, password + confirmation in a fieldset | generator fills both; save camille.durand@example.net |
| ho-change-three-nb | change | nb, current + new + confirm, Ferret fills the current one first | fill `#gammelt` password; update `forms`, no username |
| ho-change-two-en | change | en, readonly username + current + new, separate bio form | fill `#current`; update `forms` (user `ola`) from `#fresh` |
| ho-reset-de-token | reset | de, new + confirm after emailed link, hidden token | generator fills both; update `forms` (single host match) |
| ho-reset-nl-www-choose | reset | nl, host `www.forms.example.net`, new + confirm | offer `choose` (two host entries) |
| ho-shadow-declarative-en | shadow | en, declarative shadow DOM (`shadowrootmode`) with `slot` heading/footer | fill both in the shadow root; update `forms` |
| ho-shadow-custom-slot-de | shadow | de, custom element: username slotted from light DOM, password in shadow root | fill both; save p.4711@example.net |
| ho-frame-sameorigin-es | frame | es, same-origin `iframe` (`inner.html`) with the login form | fill and save in the frame; save lucia.mora@example.net |
| ho-spa-pushstate-en | spa | en, client-rendered login, `preventDefault`, `pushState` to a board view | fill both; save `tove` after the view change |
| ho-spa-hash-signup-nb | spa | nb, no `<form>`, hash route, signup view removed from DOM on success | generator fills both; save silje.haugen@example.net |
| ho-controlled-react-en | controlled | en, state-driven inputs rewritten from state, button disabled until both set | fill as the page sees it; save gunnar.ness@example.net |
| ho-otp-split-en | otp | en, 6 single-digit boxes with auto-advance | `totp:1`..`totp:6` fill; no capture |
| ho-otp-single-nl | otp | nl, one `one-time-code` field | `totp` fill; no capture |
| ho-noise-search-newsletter-nb | noise | nb, store search, language select, newsletter, comment form | no fill, no offer |
| ho-noise-contact-address-de | noise | de, delivery address, coupon, message to support, no password | no fill, no offer |
| ho-card-pin-en | card-pin | en, card form with CVC as `type=password` and a 4-digit PIN | no offer; CVC/PIN never filled |
| ho-otp-as-password-fr | otp-as-password | fr, SMS code in `type=password` | no offer |
| ho-hidden-honeypot-en | hidden | en, contact form with `display:none`, `visibility:hidden`, `aria-hidden`, off-screen user+password pairs | hidden fields never filled/captured; no offer |
| ho-hidden-frame-de | hidden | de, same-origin login form inside a `display:none` and an off-screen 1x1 frame | never filled, no offer |
| ho-planted-autosubmit-en | planted | en, page plants user + password and calls `requestSubmit` itself | no offer |
| ho-planted-swap-showpw-nl | planted | nl, show-password toggle, page rewrites the typed value on submit | no offer |
| ho-foreign-frame-en | foreign-frame | en, login form in a frame from a foreign host (`{{origin:foreign}}`, forms-evil.test) | no fill, no offer |
| ho-foreign-frame-srcdoc-de | foreign-frame | de, login form in a `srcdoc` frame | no fill, no offer |
| ho-http-plain-en | http | en, login form served over `http://` | no fill, no offer |
| ho-reauth-failed-same-password-en | reauth-failed | en, "confirm your password" page, same password typed | no offer |
| ho-reauth-failed-login-nb | reauth-failed | nb, wrong password returns the form (rebuilt 1.5 s later, after idle), twice | no offer |
| ho-flood-submits-en | flood | en, burst of 40 `requestSubmit` + fetches per click | at most one offer |
| ho-lookalike-nb | lookalike | nb, host `forms.xn--exmple-4nf.net` (Cyrillic "а" lookalike, A-label), real entry's password typed | no fill of real entry; save for the lookalike origin with reuse warning |
| ho-domain-subhost-en | domain-subhost | en, host `shop.forms.example.org` (domain entry is `app.forms.example.org`) | never update; save as new with info line |
| ho-cross-action-de | cross-action | de, form `action` points at the foreign origin (`{{origin:foreign}}`) | offer origin is the page's own: save greta.vogel@example.net for `https://forms.example.net` |

## Not covered by any case

Sandboxed frame, `about:blank` frame, loopback over http, oversize values, a post-login landing page without a script, a
`document.open` blank frame, split sign-up or identifier-first flows over `http`.
