# Hold-out set: index

39 cases, written blind from the category list (plan 6.1) and the forms README only. Category names are my own short names (the README says they come from `matrixReport.mjs`, which I did not see); each id is `ho-<category>-...`. All cases use host `forms.example.net` over https unless the table says otherwise. Capture "save" means a new user name is typed; "update" means user `ola` with a different password (target entry `forms`).

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

## Count per category vs plan minimum

Plan total 130 (80 positive, 45 negative, 5 special); hold-out target 25+, written 39 (22 positive, 14 negative, 3 special).

| category (plan row) | plan minimum | hold-out |
|---|---|---|
| login (form, en/nb/de/fr/nl) | 15 | 3 |
| login-noform | 8 | 2 |
| identifier-first | 6 | 2 |
| signup | 14 | 3 |
| change | 8 | 2 |
| reset | 4 | 2 |
| shadow | 6 | 2 |
| frame (same area) | 3 | 1 |
| spa | 6 | 2 |
| controlled | 5 | 1 |
| otp (split + single) | 5 | 2 |
| noise (search, newsletter, contact, comment, address, coupon, language) | 10 | 2 |
| card-pin | 4 | 1 |
| otp-as-password | 3 | 1 |
| hidden | 7 | 2 |
| planted (planted value, swap, show-password) | 5 | 2 |
| foreign-frame | 5 | 2 |
| http | 3 | 1 |
| reauth-failed | 5 | 2 |
| flood (flood, oversize, landing without script) | 3 | 1 |
| lookalike | 3 | 1 |
| domain-subhost | 1 | 1 |
| cross-action | 1 | 1 |

Not covered by any case: sandboxed frame, `about:blank` frame, loopback over http, oversize values, post-login landing page without script, a "document.open" blank frame, split sign-up/identifier-first over `http`.
