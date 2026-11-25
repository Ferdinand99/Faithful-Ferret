# Pages of the passkey bridge specs

The pages of `test/firefox/77-passkey-bridge.spec.mjs` and `78-passkey-response.spec.mjs`, served by the fixture server of the `firefox` step from any listed
host (`/<page id>/` is the folder's `index.html`, `/<page id>/<file>` another file of it), as the form corpus is.

- `pk-first`: its first inline script, in `<head>`, records whether `create` and `get` are still the browser's own; so does
  the same-origin frame it holds.
- `pk-adversary`: a page that, before the first request, listens in the capture phase for the handshake and every message,
  replaces `postMessage`, `MessagePort` methods, `Function.prototype.call`/`apply`, `EventTarget` methods and defines
  `Object.prototype.then`; it then forges handshakes of its own, and runs a registration and a sign-in on a click.
- `pk-calls`: calls that are not Ferret's to take (`password`, `federated`) and a registration and a sign-in, on a click, in
  the top page and in a frame of another origin (`frame.html`).
- `pk-response`: the answer objects of the passkey script against the browser's own. The spec puts the objects' builder on
  `window.__credentialFrom` (see `test/firefox/passkeyAnswer.mjs`); on a click the page makes a registration and a sign-in with
  the browser's own WebAuthn, builds the same answer from the same bytes, and writes every difference a script of the page can
  see (shape, members, prototypes, `toJSON()`, `JSON.stringify`) and what can not be the same into `data-result`.

Every page writes what it saw into `data-*` attributes of its root element.
