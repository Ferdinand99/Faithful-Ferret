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
    "It is NFKD like MP (Unicode 16.0), control characters and unassigned characters are refused, the length counts Unicode scalar values, and a PIN has at most 64 scalar values and 256 bytes.",
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
    "One Argon2id with 256 MiB per guess, and about 100 guesses per second on one powerful machine",
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
