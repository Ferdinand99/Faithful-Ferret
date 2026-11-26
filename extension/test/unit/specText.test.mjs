// The design document states the rules that saving and updating passwords from
// the extension must keep (section 10.9, and the sentences of sections 7.2, 10.1,
// 10.3.4 and 10.5 that it changes), so the code that follows can be held to them.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { repoRoot } from "./buildHelpers.mjs";

/** The design document, with its line ends and runs of spaces made plain. */
const spec = readFileSync(join(repoRoot, "docs", "design", "phase-1-security-design.md"), "utf8").replace(/\r\n/g, "\n");

/**
 * The text of a numbered item of section 10 (up to the next item of that list).
 * @param {number} n
 */
function section10Item(n) {
  const start = spec.indexOf("## 10. Browser extension");
  const end = spec.indexOf("\n## 11.", start);
  assert.ok(start >= 0 && end > start, "section 10 is there");
  const body = spec.slice(start, end);
  const from = body.search(new RegExp(String.raw`\n${n}\. \*\*`));
  assert.ok(from >= 0, `item ${n} of section 10 is there`);
  const rest = body.slice(from + 1);
  const next = rest.search(new RegExp(String.raw`\n${n + 1}\. \*\*`));
  return next < 0 ? rest : rest.slice(0, next);
}

/** The text of section 7.2. */
function section72() {
  const start = spec.indexOf("### 7.2 Browser extension");
  const end = spec.indexOf("\n### 7.3", start);
  assert.ok(start >= 0 && end > start, "section 7.2 is there");
  return spec.slice(start, end);
}

test("the_capture_and_write_rules_are_in_the_spec", () => {
  const detection = section10Item(9);
  // Where capture runs, and what it never does to the page.
  for (const rule of [
    '**Detection of new and changed passwords.** When the user turns on "Offer to save passwords" and grants access to `https` pages (asked in an extension tab), a small capture script runs in every `https` page and frame.',
    "It changes nothing in the page, leaves no marker and sends nothing until the page has a password field, except the user name a person typed into a step that asks for the user name only, which it reports when that step is submitted and which never leads to an offer by itself.",
    // Trusted input only, shown fields only.
    "it reads the form group's password fields only when their last change came from the user's own input (a trusted `input` event) and the page has not changed them since, and only fields that are shown; a user name may also come from the page and is then shown as editable.",
    "When a sign-up, change or reset form is submitted and the new password is in its field but did not come from the user's own input (Ferret filled it), the script reports the form without any password, so that the extension can join it to the password Ferret generated for that form; no value the page could have set is ever sent.",
    // Origin and frames.
    "It never runs on `http://` pages; a capture from a frame whose ancestors are not all same-site with the top, secure and not opaque, or whose frame the page hides, is dropped; the origin is taken from the browser, never from the page.",
    // Where the captured value is held, and for how long.
    "Ferret keeps the captured values only in the memory of the background page and drops them after at most five minutes, on every lock of the vault, and when the tab closes; they are never written to extension storage or a log and never sent to a content script; the popup gets the password of one offer only when the user asks to see it (below).",
    "Copies made by the browser's JavaScript engine are freed but cannot be wiped; the copy inside the core is wiped, except that for a value with characters outside ASCII the start of it that the glue copies first may remain in freed WebAssembly memory.",
    // When an offer comes.
    "A login form leads to an offer only after the page navigated or the form went away and no password form is shown afterwards; a sign-up, change or reset form leads to an offer three seconds after the last input.",
    // Where it is shown.
    "The offer is shown only in Ferret's UI (the popup and a badge on the toolbar button), never in the page. The card shows the password hidden, and shows it only after the user clicks \"Show\" on that card: the request must come from a top-level page of the extension, in the popup session that was told of the offer, with the vault open, and a click counts only after the card's buttons have been on screen for 400 milliseconds. Only the answer to that request carries the password. The popup keeps it only in the card's field while it is shown, empties the field when the user hides it, when the card is answered or rebuilt, when the vault locks and when the popup closes, and asks again for each \"Show\".",
    // Save or update, and the target.
    'Whether it is "save" or "update" is decided in the core, which compares passwords without revealing them; "update" is offered only for items that match the exact host (or the exact address), and an offer names other items that use the same password.',
    // The write.
    "Nothing is stored without the user's click on the offer, and an offer can be used once.",
    "A new item stores the frame's origin (no path) with host matching; an update changes only the password, keeps every other field, the addresses and the folders, and moves the old password into the item's history (at most five).",
  ]) {
    assert.ok(detection.includes(rule), rule);
  }
  // The short version this replaces is gone.
  assert.equal(spec.includes("form submissions and navigation are captured in the content script"), false);

  // Section 10.1: the one message from a content script that carries a secret.
  const messages = section10Item(1);
  assert.ok(
    messages.includes(
      "validated strictly: schema, size and sender (`sender.id`, `sender.tab`, `frameId`). The one message from a content script that carries a secret is the capture of a submitted form (§ 10.9): what the user typed into it. It is size- and rate-limited, its origin is taken from `sender`, and nothing is sent back.",
    ),
    "10.1",
  );

  // Section 10.3.4: a new-password field takes only a value Ferret generated, on the user's click.
  assert.ok(
    section10Item(3).includes(
      'It never fills a field that sets a new password (`autocomplete="new-password"`), except a value Ferret generated, on the user\'s click, into the new and confirm fields of a sign-up, change or reset group, and never a field outside that form.',
    ),
    "10.3.4",
  );

  // Section 10.5: with the optional permission for https pages, a frame below another origin's frame is checked.
  const frames = section10Item(5);
  assert.ok(
    frames.includes(
      "a frame below a frame of another origin can only be checked with that origin's host permission, and is refused without it; with the optional permission for `https` pages it is checked like any other frame;",
    ),
    "10.5",
  );
  assert.equal(frames.includes("(always, in this release)"), false);

  // Section 7.2: captured and generated values are not vault data, and where they live.
  assert.ok(
    section72().includes(
      "  - **Captured form values and generated passwords** (§ 10.9) are not vault data. Ferret keeps them only in the memory of the background page, and a captured password also in the popup's card while the user has chosen to show it (§ 10.9): captured values for at most five minutes, a generated password for at most fifteen minutes. Every lock of the vault drops both, as do sign-out, forgetting the server, closing the tab and a restart.",
    ),
    "7.2",
  );
});

/** The text of one section of the design document, from its heading to the next heading of the same or a higher level. @param {string} heading */
function section(heading) {
  const start = spec.indexOf(heading);
  assert.ok(start >= 0, `${heading} is there`);
  const level = /^#+/.exec(heading)?.[0].length ?? 2;
  const rest = spec.slice(start + heading.length);
  const next = rest.search(new RegExp(String.raw`\n#{1,${level}} `));
  return next < 0 ? rest : rest.slice(0, next);
}

test("the_pin_and_prf_rules_are_in_the_spec", () => {
  const ext = section72();
  // The PIN: setting, format, key and wrap, where it lives, the warning, the cost, the counter, deletion, honesty.
  for (const rule of [
    "- **PIN** (optional) is **a convenience, and in the extension it is not a hard boundary**:",
    "Only with the vault open, a network, and the master password typed again in the same dialog",
    "Every set or change makes a **new `device_salt` and a new local `method_id`**.",
    "Only the extension's own top-level pages can send the messages that set, use or turn off a PIN",
    "It is NFKD like MP (Unicode 16.0), control characters and unassigned characters are refused, the minimum length counts Unicode scalar values of the composed form (NFC of the NFKD form, so a letter with a combining accent, or a Hangul syllable written as separate jamo, counts as one), and a PIN has at most 64 scalar values of the NFKD form and 256 bytes of it.",
    "The minimum length comes from the server's rule (4 to 64, default 6), and the client never accepts less than 4",
    "**The record holds neither the length nor whether the PIN is digits or text:**",
    "KEK_pin = Argon2id(NFKD(PIN), device_salt, PIN profile 1: m = 256 MiB, t = 3, p = 1, L = 32)",
    "device_salt, kdf]) ‖ commit",
    "**By default on disk,** in a database of the extension's own",
    "It is never in `storage.local` (a content script's process can write it) and never in the shared vault database",
    '**In memory only** (`storage.session`, gone after a restart) when the user turns on "Require master password after restart" (**off** by default), or when the admin forbids a PIN after restart (§ 11).',
    "Moving a PIN from memory to disk needs the master password; the other way does not.",
    'Before a PIN is saved **on disk** the user must tick "I understand"; the box is never ticked beforehand.',
    "can try PINs on their own computer, where the limit of five attempts does not apply.",
    "One Argon2id with 256 MiB per guess, and about 100 guesses per second on one powerful machine (a server with 64 cores and memory for 64 parallel guesses;",
    "which is 64 x 2.03 x 0.72 = 93.5 for the reference machine, rounded up to 100",
    "ct/results/pin-guess-rate.md",
    "| 6 digits | 1 000 000 | under 3 hours | under 2 minutes |",
    "(measured on a reference container with 2 CPUs and 4 GiB, in Firefox Release 159 and ESR 153, and on one Mac with 10 cores in Firefox 160, where profile 1 took 0.37 seconds at the median and 0.44 seconds at the 95th percentile; **to be confirmed on real machines**, and Windows is still to be measured)",
    "Setting a PIN therefore derives `KEK_pin` in a separate worker",
    "the counter is raised and written **before** Argon2id runs",
    "An interrupted attempt counts, and attempts run one at a time.",
    "The wait before attempt 1 to 5 is 0, 0, 5, 15 and 30 seconds, counted from the last failure in the record.",
    "An unlock with the master password resets the counter.",
    "A copy of the profile is attacked on another computer and never meets it; anyone who can write to the profile can reset the counter or put back an older copy of the blob",
    "sign-out (also without a network, because it is local)",
    "a blob whose VK does not give the pinned record's `pk_a` (a swapped blob)",
    "the admin turns PINs off, or turns off PIN after restart (for the blob on disk)",
    "Firefox does not use `secure_delete` for it (measured: a deleted blob stays in the file's free pages after a clean shutdown, and overwriting it first is not reliable)",
  ]) {
    assert.ok(ext.includes(rule), rule);
  }
  assert.equal(ext.includes("lives **only in `storage.session`**"), false, "the old memory-only rule is gone");
  assert.equal(ext.includes("Exponential backoff"), false);

  // The passkey (PRF) method.
  for (const rule of [
    "is a hardware or platform authenticator, device-bound or synced",
    "`rp.id` is **the exact host of the vault's origin, never a parent domain**",
    "`userVerification` is `required` and the UV flag of the authenticator data is checked",
    "`results.first` must be exactly 32 bytes",
    "**A passkey method opens VK without MP and without SK** for whoever has the wrap and the authenticator.",
    "A **synced passkey is as safe as the cloud account** (iCloud, Google) it lives in",
    'The list of methods says "Synced passkey" or "This device only" from `BE`',
    "**The PRF output is never stored,**",
    "from a window or tab of the extension's own, never from the toolbar popup (it closes when the platform's dialog takes focus), with one WebAuthn call per click, only with live tokens and online",
    "**Another provider can take the call.**",
    "a separate `get`, with its own click, is needed",
    "an older backup still holds the wrap, so only a full rekey (§ 4.7) makes a leaked output useless",
    "the core refuses to derive `KEK_pin` from a PIN below 4 whatever the rule says",
  ]) {
    assert.ok(ext.includes(rule), rule);
  }

  // The principle (7.1), the web vault (7.3), mobile (7.4) and revocation (7.6).
  assert.ok(section("### 7.1 Common rules").includes("a PIN kept on disk, which is the default there, can be guessed offline from a copy of the browser profile"));
  assert.ok(section("### 7.3 Web vault").includes("**while the vault session lives**; when the session has ended, MP is required. There is no PIN in the web vault."));
  assert.ok(section("### 7.4 iOS").includes("The mobile PIN keeps the 64 MiB sign-in profile and the hardware limit, and it has the same AAD as the extension's PIN"));
  assert.ok(section("### 7.4 iOS").includes("The WebAssembly build makes and opens only PIN profile 1"));
  const devices = section("### 7.6 Devices and revocation");
  for (const rule of [
    "**A PIN can unlock without the server, for at most seven days**",
    "**Contact** is a successful renewal of the device's token",
    "**also while the vault is locked**",
    "The answers `device_revoked`, `token_reused` and `token_expired` to that renewal delete the PIN blob",
    "guards only against a clock set back",
    "**Revocation deletes the PIN at the first contact.** A revoked device that is kept offline can still be unlocked with its PIN for at most seven days after its last contact with the server",
    "The clock can be forged by someone who controls the machine before the extension has seen a later time, and whoever can set the system clock can keep an offline PIN usable for as long as they hold the clock still inside the window's logic",
    "The window uses the device's own time, never the server's",
    "A contact sets the highest time seen to the device's own time **on purpose**",
    "**After every PIN unlock,** the blob's VK is checked against the pinned record's `pk_a`, offline too",
    "The renewal while locked runs on the same schedule whether or not a PIN is set",
    "within five attempts in the extension",
  ]) {
    assert.ok(devices.includes(rule), rule);
  }

  // The threat model: the offline guess, the revoked device, the passkey that goes around SK.
  const threats = section("### 2.2 Attackers and what they must not achieve");
  for (const rule of [
    "**except when a PIN is kept on disk** (the extension's default, § 7.2)",
    "one Argon2id (256 MiB, t = 3) per guess, with no limit on attempts",
    "a revoked device that is kept offline can still be unlocked with its PIN for at most seven days after its last contact with the server",
    "Seven days as the device's own clock counts them: whoever controls that clock can stretch the window for as long as they hold the clock still",
    "a passkey method opens VK **without MP and without SK**",
  ]) {
    assert.ok(threats.includes(rule), rule);
  }
  assert.ok(section("### 2.3 Outside the threat model (documented limitations)").includes("**L9 Deleted data on disk.**"));

  // The manifest, the wraps, the routes, the policy, the build and the decisions.
  const wraps = section("### 4.3 Vault key and wraps");
  assert.ok(wraps.includes("`pin` (local method, never on the server): adds `device_salt` and `kdf`"));
  assert.ok(wraps.includes('The list of methods says "Synced passkey" or "This device only" from `BE`.'));
  assert.ok(wraps.includes("Ferret's own AAGUID is refused as an extra guard (§ 9.4)"));
  assert.ok(section("### 4.6 Sensitive operations and signed proofs (F-15, F-05, F-07)").includes("A local PIN is **no unlock method on the server**"));
  assert.ok(section("### 9.4 Choice between Ferret and the browser (F-13)").includes('an all-zero AAGUID is accepted and shown as "unknown"'));
  // The handover is the one-time pass on both channels, with the reason and what would reopen it.
  const handover = section("### 9.4 Choice between Ferret and the browser (F-13)");
  for (const rule of [
    "**The one-time pass is the handover on both channels, Release and ESR; the original is not called at the moment the window closes.**",
    "the probe of 2026-11-25 ran headless with a virtual authenticator",
    "ESR 153 under the same harness already made it a race",
    "the hand tests on real hardware (§ 15)",
    '"Never on this site" has no pass',
  ]) assert.ok(handover.includes(rule), rule);
  const server = section("## 11. Server and vole-kit – limits");
  for (const rule of [
    "**Allow PIN** (on; an emergency switch), **Allow PIN after restart** (on;",
    "**minimum length** (4 to 64, default 6;",
    "**`GET /api/vault/policy`**",
    'An older server without the route (404) means "no PIN"',
    "**Build feature `quick-unlock`.**",
    "`GET /api/vault/policy` is mounted in both builds; with the feature off it answers `pin.allowed: false` and `prf.enabled: false`.",
  ]) {
    assert.ok(server.includes(rule), rule);
  }
  assert.ok(section("## 12. Releases and update chain (L2)").includes("it must equal the entry in that release's cosign-signed `SHA256SUMS`"));
  const appendixB = section("## Appendix B – Schema: body, manifest, export");
  assert.ok(appendixB.includes('"n": text? name (passkey only, the folder-name rule above'));
  assert.ok(appendixB.includes('"be": bool?'));
  assert.ok(appendixB.includes('"bs": bool?'));
  const decisions = section("## 16. Decisions the maintainer must make");
  assert.ok(decisions.includes('| E3 ✅ | "PIN after browser restart" | **Reopened and decided 2026-11-24:**'));
  assert.ok(decisions.includes("| E16 ✅ | PIN without a network |"));
  assert.ok(decisions.includes("**Provisional outcome on the Mac (2026-11-24):** the extension can use PRF from its own window or tab, never from the toolbar popup"));
  assert.ok(section("## 15. What phase 0A has not proven yet (affects choices)").includes("It does not work in the toolbar popup, which closes when the system dialog takes focus."));
  assert.ok(decisions.includes("| E17 ✅ | Synced passkeys as an unlock method |"));
});

test("the_passkey_rules_are_in_the_spec", () => {
  // 9.2: when Ferret acts, the origin and the frames, the binding, the user activation and the limits.
  const origin = section("### 9.2 Origin and RP ID (F-12)");
  for (const rule of [
    'Only when all of these hold. Otherwise the call goes to the browser **untouched**:',
    '(a) "Use Ferret for passkeys" is on (**off** by default;',
    "(c) the origin is `https` and **not `localhost`**: a release build never acts on `localhost`, with any scheme, and leaves the call to the browser",
    "(d) the calling frame and **every ancestor up to the top** have the origin of the top",
    '(e) the origin is not a signed-in Ferret server and is not on the "Never on this site" list',
    "(f) where `document.featurePolicy` exists, it says that `publickey-credentials-create` and `publickey-credentials-get` are allowed (Firefox 159 and ESR 153 do not have it",
    "Never from the page: the messages from a page have no field for origin, top or frame.",
    '**Cross-origin is not supported in v1,** and neither are "related origins"',
    "The background goes up the `parentFrameId` chain with `webNavigation.getAllFrames`, the same rule as for filling (§ 10.5)",
    "Anything else goes **untouched to the browser**, which then answers: a cross-origin frame, a frame inside a foreign frame, a frame with an opaque origin, `about:blank`, `srcdoc` and `data:`.",
    "Ferret never writes `crossOrigin: false` into `clientDataJSON` where the browser would have said something else.",
    "A new document in the frame (`webNavigation.onCommitted`, or a new `documentId`) cancels it. A change of address with `pushState` (`onHistoryStateUpdated`) **does not** cancel it",
    "the origin is checked again before the answer is sent, and the answer goes only to the same `documentId`.",
    "The bridge in the page passes on an answer or an error only for a request id that it issued itself, and drops everything else.",
    // The relaxation of "create requires user activation".
    "Ferret opens its window only for a request that came with transient user activation in the page (`navigator.userActivation.isActive`, read in the isolated world and never in the MAIN world). That goes for `get` and for `create`.",
    "A request without it is not refused and opens no window: it is shown as a badge on the toolbar button and a card in the popup, and the click on the card opens the window. That click is the user action, in Ferret's own UI.",
    "*Relaxed 2026-11-25:* earlier text said that `create` requires transient activation in the page.",
    // Limits (the bounds, the one window, the calm period).
    "challenge at most 1 KiB, `allowCredentials` and `excludeCredentials` at most 200, a credential id at most 1 023 bytes, texts at most 1 KiB, a message at most 64 KiB",
    "One pending **modal** request per tab",
    "a request from another tab while the window is busy gets a badge and waits, and never replaces the open one.",
    "`timeout` is clamped to 30 seconds to 10 minutes (default 5 minutes); a conditional request has none.",
    "The page's `timeout` is read first as the browser reads it, a WebIDL `unsigned long`, so a number of 2^32 or more wraps.",
    "A call of a document while 64 of its calls already wait ends at once with `AbortError`, like a second modal call of a tab, and never goes to the browser.",
    // The core still canonicalizes an RP ID with a trailing dot or upper case; the extension refuses those first.
    "The extension therefore refuses such an RP ID itself, with a `SecurityError` and before any window, for `create` and for `get`, so a page call never reaches that path of the core: the RP ID must be lower-case ASCII labels",
    "and the page's host or a dot-delimited suffix of it. That the suffix is not a public suffix is still checked by the core only, in the window.",
    "**Calm period:** three cancelled requests within one minute from the same tab give five minutes in which new requests from that tab only get the badge and the card in the popup, with no window.",
    "the stored `rp_id` must be **exactly equal** to the requested `rpId`.",
  ]) {
    assert.ok(origin.includes(rule), rule);
  }
  assert.equal(origin.includes("Cross-origin is denied in v1."), false, "the old cross-origin rule is gone");
  assert.equal(origin.includes("Requires transient user activation for `create`."), false, "the old activation rule is gone");
  assert.equal(origin.includes("On `webNavigation.onCommitted` or `onHistoryStateUpdated` for the frame, it is cancelled."), false, "pushState no longer cancels");

  // 9.3: UP, UV in practice, the answer fields, the errors, imported passkeys and the privacy rule.
  const flags = section("### 9.3 Flags and responses (F-29)");
  for (const rule of [
    "**`UP`** is set only after a click with `isTrusted` in **Ferret's own UI**: the chooser window or the popup, never DOM in the page.",
    "only 400 ms after the window got focus or its content last changed",
    "There is no setting that answers without a click.",
    "**Recent unlock (on by default; the user can turn it off in the settings):** the vault was unlocked with MP, PIN or a passkey (PRF) at most **5 minutes** ago, and the user clicks in Ferret's window or popup.",
    "A verification in the chooser counts as a new unlock.",
    "is measured on a monotonic clock and on the wall clock",
    "and is erased at every lock.",
    "`prf_output` in `prf_unlock` and `passkey_verify`",
    "A restored session, a renewal of tokens and an unlock that verified nobody do not.",
    "**A passkey for unlock (PRF):** Windows Hello, Touch ID or a phone, as a real WebAuthn call against the vault's host **in Ferret's window, never in the popup** (§ 7.2).",
    "**PIN:** the same check and the same limit of five attempts as at unlock (§ 7.2). Without a network only within seven days after the last contact with the server (§ 7.6).",
    "**MP:** the same job as at unlock, with the same `pk_a`: **a full OPAQUE sign-in to the server**, which the window says.",
    "Unlocking a locked vault in the same window counts as verification.",
    "**`required` and `preferred`** ask for verification; **`discouraged`** gives the click only (`UV = 0`).",
    "`preferred` answers with `UV = 0` after the click, like an authenticator without verification; `required` says why and offers the browser, and the page gets `NotAllowedError` only if the user cancels.",
    "**The result is a one-time token** in the background's memory, bound to the request id, used at signing and then deleted.",
    "**PRF exists only for a passkey whose `create` asked for `prf`** (as CTAP `hmac-secret`)",
    "`authenticatorAttachment: \"platform\"` and `getTransports()` = `[\"hybrid\", \"internal\"]`",
    "`credProps: { rk: true }`",
    "`NotAllowedError` for cancelled, no match, timeout, verification impossible and a wrong RP at signing (the same type, and a cancellation is answered no sooner than a normal answer would be",
    "`InvalidStateError` only for `excludeCredentials`, **after** the user's click; `SecurityError` for an RP ID the page cannot use; `NotSupportedError` for a `prf` `evalByCredential` at `create`, or at `get` with an empty `allowCredentials`, before any window; `AbortError` with the page's `signal.reason`; `TypeError` for malformed options",
    "**Imported passkeys** (§ 9.6) get counter 0 like every Ferret passkey.",
    "so a passkey that had a counter above zero must be registered again at the site.",
    // The privacy rule.
    "cannot be told apart by the page, neither by error type nor by timing, **because the chooser is always shown**: also when Ferret has no passkey for the site, the window opens",
    "with \"No Ferret passkey for this site\" and the choice \"Use the browser or a security key\".",
    "**Automatic handover** to the browser without a window is decided only by properties of the request, never by what the vault holds (§ 9.4).",
  ]) {
    assert.ok(flags.includes(rule), rule);
  }
  assert.equal(flags.includes("That option is off by default"), false, "recent unlock is no longer off by default");

  // 9.4: the chooser, the wording about the browser's dialog, the handover, "Never", the servers and another extension.
  const choice = section("### 9.4 Choice between Ferret and the browser (F-13)");
  for (const rule of [
    "**a window of its own** from the extension (`windows.create` with `type: \"popup\"`), at the top level, with `frame-ancestors 'none'`, never in `web_accessible_resources`.",
    "The page cannot see, imitate or click the window. **Ferret comes first:**",
    "**\"Use the browser instead\"**",
    "**\"Never on this site\"** and **Cancel**",
    "no default button, no initial focus on an action, and Enter does nothing; a click counts only with `isTrusted` and 400 ms after the window got focus or its content changed.",
    "**The browser's own dialog is given only when the user chooses it, or when Ferret cannot or must not answer.**",
    "`pubKeyCredParams` that is not empty and has no ES256 (an **empty** list means ES256 and RS256, and Ferret answers it); `extensions.appid` or `appidExclude`; `attestation: \"enterprise\"`",
    "and a call without `publicKey` (`password`, `federated`, `identity`, `otp`).",
    "The script calls the saved original with the page's **own options**, which Ferret never changes.",
    "the **next** call of the same kind (`create` or `get`) from the same tab, frame, `documentId` and origin within 60 seconds goes untouched to the browser, once.",
    "is kept per host of the RP ID in `storage.local` (only in memory in private windows), can be edited in the settings, and holds at most 500 hosts.",
    "The background refuses such requests itself as well, because the registration of the script excludes a server by address and lags behind a change of server",
    "**Another extension** may already have replaced `navigator.credentials` before the script runs",
    "\"Another password manager also handles passkeys on this page. Turn the passkey feature off in it, or use it.\"",
  ]) {
    assert.ok(choice.includes(rule), rule);
  }
  assert.equal(choice.includes("The browser's own dialog** is given only if the user chooses it."), false, "the old wording is gone");

  // 9.5 and 9.6: conditional UI as a part of the popup and a badge, PRF from Ferret, the import.
  const conditional = section("### 9.5 Conditional UI and PRF via Ferret");
  for (const rule of [
    "**as a part of the popup and a badge, not a list in the page.**",
    "(a) a new **modal** request from the same document **replaces** a waiting conditional one",
    "(b) a conditional request has **no timeout**",
    "(c) **at the same time** the script gives a conditional call to the browser's original with its own `AbortController`",
    "**only a successful answer** from the original wins",
    "(d) if a probe shows that the browser runs one WebAuthn transaction at a time",
    "**PRF delivered by Ferret** (E10: yes)",
  ]) {
    assert.ok(conditional.includes(rule), rule);
  }
  const imports = section("### 9.6 Export, import and passkeys");
  for (const rule of [
    "Unencrypted JSON has them only after an explicit choice; CSV never.",
    "reads **Bitwarden's unencrypted JSON** (`login.fido2Credentials`) and **AliasVault's `.avux`** (`items[].passkeys`)",
    "The key goes from the file straight to the core's `passkey_import`",
    "JavaScript holds only the file, as with passwords in an import (L6).",
    "**A passkey that is not discoverable**",
    "AliasVault's `prfKey` uses the same PRF formula as Ferret (§ 9.5) and is **one secret**, so **both seeds are set to it**",
    "An encrypted Bitwarden export and `.avex` are not read.",
  ]) {
    assert.ok(imports.includes(rule), rule);
  }

  // 9.8: the known limits.
  const limits = section("### 9.8 Known limits of the passkey provider in the extension");
  for (const rule of [
    "**A recent unlock counts as verification for 5 minutes** (§ 9.3).",
    "**There is no official provider API in Firefox.**",
    "a page that loads in that very moment can miss the script and then uses the browser's own WebAuthn, which is safe.",
    "**The browser's event page can be suspended**",
  ]) {
    assert.ok(limits.includes(rule), rule);
  }

  // 10.8: the bridge between the MAIN world and the content script.
  const bridge = section10Item(8);
  for (const rule of [
    "no `window.postMessage` at all, not even for the handshake",
    "`scripting.registerContentScripts` (`world: \"MAIN\"` and the isolated world, `runAt: \"document_start\"`, `allFrames: true`, `matches: [\"https://*/*\"]`, `persistAcrossSessions: true`",
    "The background registers them at every start of its page, and an install or an update starts it, so the registrations an update clears are made again at once.",
    "**The handshake is synchronous.** One script makes a `MessageChannel` and calls `document.dispatchEvent` with a cancelable `MessageEvent`",
    "**It does not depend on which script runs first:** both listen and both send",
    "**The MAIN script keeps every built-in it uses** when it is installed",
    "It **fails closed:** on anything unexpected the call goes to the browser's original, never a malformed request.",
    "**Answers are boxed.** What comes from the port is put in an object with a null prototype before any promise resolves it",
    "**The MAIN script is untrusted and dumb:** no secrets, no keys, no decisions, no network, no change to the DOM, no dependencies, at most 30 KiB.",
    "never from the MAIN script, and the messages have no field for them.",
    "The bridge pings the background every 20 seconds, only while a request waits",
    "the request fails closed with `NotAllowedError`.",
  ]) {
    assert.ok(bridge.includes(rule), rule);
  }
  assert.equal(bridge.includes("a private `MessageChannel` or `CustomEvent` handshake"), false, "the old wording is gone");

  // 8.3 and 8.5: the write of a new passkey.
  const idempotency = section("### 8.3 Idempotency");
  for (const rule of [
    "**A new passkey is written online only** (§ 9.3, § 9.4). The write of an item that `create` just made never goes into the offline outbox and never to the conflict view.",
    "It is sent at once with an `idem` of its own, and the answer to the page waits for the outcome.",
    "**An unknown outcome** (timeout, broken connection): the same request with the same `idem` is sent again until a sure answer, for at most 30 seconds",
    "**Accepted too late:** if the server accepts the item after the page has gone, has navigated or has cancelled, or the user cancelled, the item is deleted at once with an ordinary tombstone",
  ]) {
    assert.ok(idempotency.includes(rule), rule);
  }
  assert.ok(section("### 8.5 Conflicts (maintainer's decision: the user chooses)").includes("**A new passkey never makes a conflict** (§ 8.3)"));

  // 2.2: the person at the unlocked machine (the cost of the recent-unlock rule).
  const threats = section("### 2.2 Attackers and what they must not achieve");
  for (const rule of [
    "| A10 | Someone at the unlocked machine |",
    "an unlock within the last 5 minutes counts as user verification for a passkey, so one click in Ferret's window gives `UV = 1`.",
    "Every lock erases the time, auto-lock and screen lock apply (§ 7.2), and the user can turn the rule off.",
  ]) {
    assert.ok(threats.includes(rule), rule);
  }
  // The row has as many cells as the table's header, or the renderer drops the rest.
  const cells = (/** @type {string} */ prefix) => (threats.split("\n").find((line) => line.startsWith(prefix)) ?? "").split("|").length;
  assert.equal(cells("| A10 |"), cells("| # |"), "the A10 row has the cells of the header");
  assert.equal(cells("| A9 |"), cells("| # |"), "the A9 row has the cells of the header");

  // 11: the server's build feature and the policy answer.
  const server = section("## 11. Server and vole-kit – limits");
  for (const rule of [
    '"passkeys": { "import" } }`. `passkeys.import` says whether the build of this server has the cargo feature `passkey-import`',
    "**Build feature `passkey-import`**",
    "answers `passkeys: { import: false }` in `GET /api/vault/policy`",
  ]) {
    assert.ok(server.includes(rule), rule);
  }

  // 15 and 16: the probe, and the decisions E7 (on, 5 minutes) and E10 (yes).
  assert.ok(section("## 15. What phase 0A has not proven yet (affects choices)").includes("*Probed on 2026-11-25 with a virtual authenticator (Firefox Release 159.0.1 and ESR 153.6.0, Manifest V2 and V3):*"));
  const decisions = section("## 16. Decisions the maintainer must make");
  assert.ok(decisions.includes('| E7 ✅ | "Trust recent unlock" for passkey UV | **Decided 2026-11-25: on by default, 5 minutes,**'));
  assert.equal(decisions.includes('| E7 | "Trust recent unlock" for passkey UV | Off by default |'), false);
  assert.ok(decisions.includes("| E10 ✅ | PRF delivered by Ferret (§ 9.5) in v1? | **Decided 2026-11-25: yes,**"));

  // Appendix B: the two texts of the site, and the change log.
  const appendixB = section("## Appendix B – Schema: body, manifest, export");
  assert.ok(appendixB.includes('"rp_name": text?, "user_display_name": text?,'));
  assert.ok(appendixB.includes("`rp_name` and `user_display_name` are optional, at most 1 KiB each"));
  assert.ok(spec.includes("**Changes for the passkey provider in the extension (2026-11-25).**"));
});
