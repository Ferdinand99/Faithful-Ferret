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
    "It changes nothing in the page, leaves no marker and sends nothing until the page has a password field.",
    // Trusted input only, shown fields only.
    "it reads the form group's password fields only when their last change came from the user's own input (a trusted `input` event) and the page has not changed them since, and only fields that are shown; a user name may also come from the page and is then shown as editable.",
    // Origin and frames.
    "It never runs on `http://` pages; a capture from a frame whose ancestors are not all same-site with the top, secure and not opaque, or whose frame the page hides, is dropped; the origin is taken from the browser, never from the page.",
    // Where the captured value is held, and for how long.
    "Ferret keeps the captured values only in the memory of the background page and drops them after at most five minutes, on every lock of the vault, and when the tab closes; they are never written to extension storage or a log and never sent to the popup or a content script.",
    "Copies made by the browser's JavaScript engine are freed but cannot be wiped; the copy inside the core is wiped, except that for a value with characters outside ASCII the start of it that the glue copies first may remain in freed WebAssembly memory.",
    // When an offer comes.
    "A login form leads to an offer only after the page navigated or the form went away and no password form is shown afterwards; a sign-up, change or reset form leads to an offer three seconds after the last input.",
    // Where it is shown.
    "The offer is shown only in Ferret's UI (the popup and a badge on the toolbar button), never in the page, and it never shows the password.",
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
      "  - **Captured form values and generated passwords** (§ 10.9) are not vault data. Ferret keeps them only in the memory of the background page: captured values for at most five minutes, a generated password for at most fifteen minutes. Every lock of the vault drops both, as do sign-out, forgetting the server, closing the tab and a restart.",
    ),
    "7.2",
  );
});
