// A generated password through the whole path in real Firefox on the end-to-end stack: the extension is signed in to a
// real server with its vault open, "Offer to save passwords" is on (the settings tab's real click asks for access to
// https pages), and the sign-up fixture of the form corpus is open in a tab.
//
// - generate_fill_and_submit_on_the_sign_up_fixture_gives_one_save_offer: the popup's own messages `generate` and
//   `fill_generated` put one generated password into the new and the confirm field of the page (the page holds the same
//   value in both), the e-mail is typed with real key events, the form is submitted by a real click, and the store of
//   offers then holds exactly one offer for the tab: a new item (save), marked as generated, for the fixture's origin,
//   with the typed user name joined to it, and whose password is the one that went into the page (its SHA-256, never
//   the value). The later capture of the submitted form joined the generated offer; it is not a second one. Nothing is
//   written to the vault, because nobody clicked a save control. The offers are read through the test bridge's
//   `offers_peek` (the offer UI's own list is a later step); it never carries a password.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { world } from "./adversary.mjs";
import { EXTENSION_ORIGIN, channels, fixtures, stopFixtures } from "./harness.mjs";
import { ENTRIES, captureCase, caseUrl, casesOf } from "./matrix.mjs";

after(() => stopFixtures());

const CASE = "signup-confirm-en";

test("generate_fill_and_submit_on_the_sign_up_fixture_gives_one_save_offer", async () => {
  const [c] = casesOf("corpus", CASE);
  assert.equal(c?.id, CASE);
  assert.deepEqual(c.steps.map((/** @type {Record<string, unknown>} */ s) => Object.keys(s)[0]), ["type", "generate_fill", "click"], "the case generates, then submits");
  for (const channel of channels()) {
    const server = await fixtures();
    const w = await world(channel, { grant: [], entries: ENTRIES });
    try {
      // The vault stays open for the run.
      await w.ui.open();
      try {
        await w.ui.body("settings", { lock_seconds: 86_400 });
      } finally {
        await w.ui.close();
      }
      // "Offer to save passwords" on, with a real click in the settings tab.
      await w.session.navigate(`${EXTENSION_ORIGIN}/pages/settings.html`);
      await w.session.waitFor(() => w.session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
      const [toggle] = await w.session.findAll('[data-role="capture-switch"]');
      assert.ok(toggle, `${channel}: the settings page has the switch`);
      await w.session.click(toggle);
      await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "true"), 15_000, "capture on");
      await w.session.switchTo(w.pageTab);

      const vault = await w.vaultState();
      assert.equal(vault.running, true, `${channel}: the sync engine runs`);

      const result = await captureCase(w, c);
      assert.equal(result.error, undefined, `${channel}: ${result.error}`);
      assert.equal(result.ran.capture, true, channel);
      const offers = result.observed?.offers ?? [];
      assert.equal(offers.length, 1, `${channel}: exactly one offer (${JSON.stringify(offers)})`);
      const [offer] = offers;
      assert.equal(offer.type, "save", `${channel}: a new item`);
      assert.equal(offer.origin, new URL(caseUrl(c, server)).origin, `${channel}: the fixture's origin`);
      assert.equal(offer.generated, true, `${channel}: marked as generated`);
      assert.equal(offer.username, "anna@example.net", `${channel}: the typed user name joined the generated offer`);
      assert.equal(offer.password_field, "#pw", `${channel}: the offer's password is the one that went into the new-password field`);
      assert.equal(result.observed?.vault_changed, false, `${channel}: nothing was written without a click`);
      assert.deepEqual(await w.vaultState(), vault, `${channel}: the item list stands still`);
    } finally {
      await w.quit();
    }
  }
});
