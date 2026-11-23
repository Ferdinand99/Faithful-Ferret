// The whole of "save and update passwords", end to end on the end-to-end stack, in one Firefox per channel: the extension is signed in
// to a real server, the web vault is open beside it in the same browser, and "Offer to save passwords" is on.
//
// - full_u2_flow_end_to_end, in the order a person meets it:
//    1. a folder made in the web vault; a sign-up page; the generator puts a password into it and the form is submitted;
//    2. the popup's save card (a generated password, named and put in the folder) is answered with "Save";
//    3. the web vault shows the item: its name, the page's address, the folder, the user name and the generated password;
//    4. a change-password page: the password in use is typed, a new one chosen, the form submitted;
//    5. the popup's update card names the item; "Update" writes the new password and nothing else;
//    6. the web vault shows the same folders, address and user name, the new password, and "Previous passwords" with the old one;
//    7. a sign-in page is filled by the extension with the item's new password, and signing in with it makes no new offer;
//    8. "Not now" ends one offer and blocks nothing; "Never" ends one and stops the offers of that site (the settings list shows
//       the host and removes it);
//    9. a save made while the server cannot be reached says it waits, survives a lock, and goes out after the unlock.
// - the_vault_still_syncs_after_the_https_access_is_taken_back: turning "Offer to save passwords" off takes the access to https
//   pages back; an item made in the web vault afterwards still reaches the extension and the popup asks for no new access.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { SLOW, pace } from "./e2e.mjs";
import { EXTENSION_ORIGIN, channels, fixtures, stopFixtures } from "./harness.mjs";
import { caseUrl, casesOf, captureCase, leave, locate, offersPeek, readValue } from "./matrix.mjs";
import { allText, newestTab, popupWithCard, readyWorld, sleep, uniqueSignup, vaultItemHref } from "./offerWorld.mjs";

after(() => stopFixtures());

const ORIGIN = "https://forms.example.net";

/**
 * Switches the malicious server of the stack to a mode (web/test/e2e-stack/evil/modes.mjs).
 * @param {string} mode @param {Record<string, unknown>} [params]
 */
async function evil(mode, params = {}) {
  const base = process.env.FERRET_E2E_EVIL_URL ?? "";
  assert.ok(base, "FERRET_E2E_EVIL_URL is not set (run the specs in the e2e mode of the Firefox runner)");
  const response = await fetch(`${base}/mode`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...params, mode }) });
  assert.equal(response.ok, true, `the malicious server answered ${response.status} for ${mode}: ${await response.text()}`);
}

/**
 * Whether the server's feed has the item at `rev` or above, read in the web vault's tab with its session.
 * @param {import("./driver.mjs").Session} session @param {string} id @param {number} rev
 */
function serverHas(session, id, rev) {
  return session.content(async (/** @type {string} */ wanted, /** @type {number} */ atLeast) => {
    let since = 0;
    for (let page = 0; page < 50; page += 1) {
      const response = await fetch(`/api/sync/changes?since=${since}&limit=500`, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
      if (!response.ok) return false;
      const feed = await response.json();
      if (feed.changes.some((/** @type {any} */ c) => c.id === wanted && c.rev >= atLeast)) return true;
      if (!feed.has_more || feed.changes.length === 0) return false;
      since = feed.changes[feed.changes.length - 1].seq;
    }
    return false;
  }, id, rev);
}

/** Clears the name field of the card and types `name` with real keys. @param {Awaited<ReturnType<typeof readyWorld>>} w @param {string} name */
async function nameTheCard(w, name) {
  const [nameField] = await w.session.findAll('[data-role="offer-name"]');
  await w.session.content(() => {
    const input = /** @type {HTMLInputElement} */ (document.querySelector('[data-role="offer-name"]'));
    input.value = "";
    input.focus();
  });
  await w.session.type(nameField, name);
}

/**
 * The item page in the web vault, once it shows the item's revision with the wanted password (the page is read again until it does).
 * @param {Awaited<ReturnType<typeof readyWorld>>} w @param {string} href @param {string} password
 */
async function itemShowsPassword(w, href, password) {
  const base = (await w.session.currentUrl()).split("#")[0];
  await w.session.waitFor(async () => {
    await w.session.navigate(`${base}#/items`);
    await w.page.waitVisible('[data-role="list"]', SLOW);
    await w.session.navigate(`${base}${href}`);
    await w.page.waitVisible('[data-role="reveal"][data-key="f1"]', SLOW);
    const hidden = await w.page.text('[data-role="value"][data-key="f1"]');
    await w.page.click('[data-role="reveal"][data-key="f1"]');
    const shown = await w.session.waitFor(async () => {
      const text = await w.page.text('[data-role="value"][data-key="f1"]');
      return text !== hidden ? text : null;
    }, 10_000, "the shown password");
    return shown === password;
  }, 90_000, "the web vault shows the item with the wanted password");
}

test("full_u2_flow_end_to_end", async () => {
  for (const channel of channels()) {
    const w = await readyWorld(channel);
    try {
      const server = await fixtures();
      const tag = randomBytes(3).toString("hex");
      const folder = `E2E-flow ${tag}`;
      const name = `E2E-flow-${tag}`;

      // 1. A folder, made in the web vault with an item of another site (so it matches no page of this test).
      await w.session.switchTo(w.vaultTab);
      await w.page.click('[data-role="nav-items"]');
      await w.page.waitVisible('[data-role="new-item"]');
      await w.page.click('[data-role="new-item"]');
      await w.page.waitVisible('[data-role="edit-form"]');
      await w.page.type('[data-role="name"]', `Folder-maker-${tag}`);
      await w.page.type('[data-role="username"]', `maker-${tag}`);
      await w.page.type('[data-role="password"]', `Pw-${randomBytes(6).toString("hex")}`);
      await w.page.type('[data-role="url"]', "https://folder-maker.example.org/");
      await w.page.type('[data-role="folder-input"]', folder);
      await w.page.click('[data-role="folder-add"]');
      await w.page.click('[data-role="save"]');
      await w.session.waitFor(async () => (await w.page.text('[data-role="item"] h1')).includes(`Folder-maker-${tag}`), 30_000, "the item that makes the folder");
      await w.session.switchTo(w.pageTab);
      // The extension has the folder once its sync has brought the item.
      await w.ui.open();
      try {
        await w.session.waitFor(async () => (await w.ui.body("folder_names", {})).folders.includes(folder), 60_000, "the folder in the extension");
      } finally {
        await w.ui.close();
      }

      // The sign-up page: the generator fills the new and confirm fields and the form is submitted with a real click.
      const { c: signup, user } = uniqueSignup("signup-confirm-en", tag);
      assert.deepEqual(signup.steps.map((/** @type {Record<string, unknown>} */ s) => Object.keys(s)[0]), ["type", "generate_fill", "click"], "the case types a user name, generates, and submits");
      const made = await captureCase(w, signup);
      assert.equal(made.error, undefined, `${channel}: ${made.error}`);
      assert.equal(made.observed?.offers.length, 1, `${channel}: one offer (${JSON.stringify(made.observed?.offers)})`);
      assert.equal(made.observed?.offers[0].generated, true, `${channel}: marked as made by Ferret`);
      assert.equal(made.observed?.vault_changed, false, `${channel}: nothing is written before the click`);
      const tabId = await newestTab(w);
      // The generated password, as the card's "Show" gives it (the popup session that was told of the offer).
      await w.ui.open();
      /** @type {string} */
      let generated;
      try {
        const listed = await w.ui.body("offer_list", { tab_id: tabId });
        assert.equal(listed.offers.length, 1, `${channel}: the popup is told of one offer`);
        generated = (await w.ui.body("offer_reveal", { offer_id: listed.offers[0].offer_id })).value;
      } finally {
        await w.ui.close();
      }
      assert.ok(generated.length >= 8, `${channel}: a generated password`);

      // 2. The save card: named, put in the folder, saved.
      const beforeSave = JSON.stringify(await w.vaultState());
      const saveHandle = await popupWithCard(w, tabId, "save");
      assert.equal(await w.page.text('[data-role="offer-title"]'), "Save in Ferret?", channel);
      assert.equal(await w.page.visible('[data-role="offer-generated"]'), true, `${channel}: the card says the password was made by Ferret`);
      await nameTheCard(w, name);
      await w.session.content((/** @type {string} */ wanted) => {
        const select = /** @type {HTMLSelectElement} */ (document.querySelector('[data-role="offer-folder"]'));
        select.value = wanted;
        select.dispatchEvent(new Event("change", { bubbles: true }));
      }, folder);
      assert.equal(await w.session.content(() => /** @type {HTMLSelectElement} */ (document.querySelector('[data-role="offer-folder"]')).value), folder, `${channel}: the folder is chosen`);
      await w.page.click('[data-role="offer-save"]');
      await w.page.waitVisible('[data-role="offer-result"]', SLOW);
      assert.ok(["Saved.", "Saved. Waiting for sync."].includes(await w.page.text('[data-role="offer-result"]')), channel);
      await w.session.closeTab().catch(() => {});
      void saveHandle;
      await w.session.switchTo(w.pageTab);
      assert.deepEqual((await offersPeek(w, tabId)).offers, [], `${channel}: the offer is used up`);
      // The positive control of the matrix's vault check: when the person does click "Save", the item list changes.
      await w.session.waitFor(async () => JSON.stringify(await w.vaultState()) !== beforeSave, 30_000, "the item list changes after the click");

      // 3. The web vault shows the item: name, the page's address, the folder, the user name and the generated password.
      const href = await vaultItemHref(w, name);
      await w.session.navigate(`${(await w.session.currentUrl()).split("#")[0]}${href}`);
      await w.page.waitVisible('[data-role="item"] h1', SLOW);
      assert.ok((await w.page.text('[data-role="item"] h1')).includes(name), channel);
      assert.deepEqual(await allText(w, '[data-role="url"]'), [ORIGIN], `${channel}: the address is the page's origin`);
      assert.deepEqual(await allText(w, '[data-role="folder-chip"]'), [folder], `${channel}: the folder`);
      assert.ok((await allText(w, '[data-role="value"]')).includes(user), `${channel}: the user name`);
      await itemShowsPassword(w, href, generated);

      // 4. A change-password page: the password in use is the item's (typed by the person), the new one is chosen, the form is sent.
      const next = `Zq7!chg-${tag}-Vm4$`;
      const [changeBase] = casesOf("corpus", "change-two-fr");
      assert.equal(changeBase?.id, "change-two-fr");
      const change = structuredClone(changeBase);
      change.steps = change.steps.map((/** @type {any} */ s) => (s.type === "#cur" ? { ...s, text: generated } : s.type === "#new" ? { ...s, text: next } : s));
      const changed = await captureCase(w, change);
      assert.equal(changed.error, undefined, `${channel}: ${changed.error}`);
      assert.equal(changed.observed?.offers.length, 1, `${channel}: one offer for the change (${JSON.stringify(changed.observed?.offers)})`);
      assert.equal(changed.observed?.offers[0].type, "update", `${channel}: the core says update (the password in use is this item's)`);
      assert.equal(changed.observed?.vault_changed, false, `${channel}: nothing is written before the click`);

      // 5. The update card names the item; "Update" writes.
      const changeTab = await newestTab(w);
      const updateHandle = await popupWithCard(w, changeTab, "update");
      assert.equal(await w.page.text('[data-role="offer-title"]'), "Update the password?", channel);
      assert.equal(await w.page.text('[data-role="offer-target-name"]'), name, `${channel}: the card names the item`);
      assert.equal((await w.session.content(() => document.body.textContent ?? "")).includes(next), false, `${channel}: no password in the popup`);
      await w.page.click('[data-role="offer-update"]');
      await w.page.waitVisible('[data-role="offer-result"]', SLOW);
      assert.ok(["Updated.", "Updated. Waiting for sync."].includes(await w.page.text('[data-role="offer-result"]')), channel);
      await w.session.closeTab().catch(() => {});
      void updateHandle;
      await w.session.switchTo(w.pageTab);

      // 6. The web vault: the same folder, address and user name; the new password; the old one under "Previous passwords".
      await w.session.switchTo(w.vaultTab);
      await itemShowsPassword(w, href, next);
      assert.deepEqual(await allText(w, '[data-role="folder-chip"]'), [folder], `${channel}: the folder stays`);
      assert.deepEqual(await allText(w, '[data-role="url"]'), [ORIGIN], `${channel}: the address stays`);
      assert.ok((await allText(w, '[data-role="value"]')).includes(user), `${channel}: the user name stays`);
      await w.session.waitFor(() => w.page.visible('[data-card="history"]'), 60_000, "the previous passwords card");
      const [reveal] = await w.session.findAll('[data-card="history"] [data-role="reveal"]');
      assert.ok(reveal, `${channel}: the earlier password can be shown`);
      await w.session.click(reveal);
      const shownOld = await w.session.waitFor(async () => {
        const text = await w.session.content(() => document.querySelector('[data-card="history"] [data-role="value"]')?.textContent?.trim() ?? "");
        return text !== "" && !/^[•*]+$/.test(text) ? text : null;
      }, 20_000, "the shown earlier password");
      assert.equal(shownOld, generated, `${channel}: the generated password is the one under Previous passwords`);
      await w.session.switchTo(w.pageTab);

      // 7. A sign-in page: the extension fills the item's new password, and signing in with it is no new offer.
      const [login] = casesOf("corpus", "login-basic-en");
      assert.equal(login?.id, "login-basic-en");
      const loginTab = await w.visit(caseUrl(login, server));
      await w.ui.open();
      try {
        const candidates = await w.ui.body("candidates", { tab_id: loginTab });
        const row = candidates.handles.find((/** @type {{ name: string }} */ h) => h.name === name);
        assert.ok(row, `${channel}: the sign-in page offers the new item (${JSON.stringify(candidates.handles.map((/** @type {{ name: string }} */ h) => h.name))})`);
        const filled = await w.ui.ask("fill", { ref: row.ref, tab_id: loginTab });
        assert.equal(filled.type, "fill", channel);
        assert.equal(filled.body?.ok, true, `${channel}: ${JSON.stringify(filled.body)}`);
      } finally {
        await w.ui.close();
      }
      await sleep(700);
      assert.equal(await readValue(w.session, "#u"), user, `${channel}: the user name went into the page`);
      assert.equal(await readValue(w.session, "#p"), next, `${channel}: the new password went into the page, not the old one`);
      await leave(w.session);
      const go = await locate(w.session, "#go");
      assert.ok(go, `${channel}: the sign-in button`);
      await w.session.click(go);
      await leave(w.session);
      await sleep(9000);
      assert.deepEqual((await offersPeek(w, loginTab)).offers, [], `${channel}: signing in with the saved password makes no offer`);

      // 8. "Not now" ends one offer and blocks nothing; "Never" ends one and stops the offers of the site.
      const vaultBefore = await w.vaultState();
      const notNow = uniqueSignup("signup-confirm-fr");
      assert.equal((await captureCase(w, notNow.c)).observed?.offers.length, 1, `${channel}: an offer to say "Not now" to`);
      const notNowTab = await newestTab(w);
      const notNowHandle = await popupWithCard(w, notNowTab, "save");
      await w.page.click('[data-role="offer-not-now"]');
      await w.page.waitVisible('[data-role="offer-result"]', SLOW);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="offer-result"]')?.getAttribute("data-outcome") ?? ""), "dismissed", channel);
      await w.session.closeTab().catch(() => {});
      void notNowHandle;
      await w.session.switchTo(w.pageTab);
      assert.deepEqual((await offersPeek(w, notNowTab)).offers, [], `${channel}: "Not now" ended the offer`);
      assert.deepEqual(await w.vaultState(), vaultBefore, `${channel}: "Not now" wrote nothing`);

      const never = uniqueSignup("signup-confirm-fr");
      assert.equal((await captureCase(w, never.c)).observed?.offers.length, 1, `${channel}: "Not now" blocked nothing: the next form gets an offer`);
      const neverTab = await newestTab(w);
      const neverHandle = await popupWithCard(w, neverTab, "save");
      await w.page.click('[data-role="offer-never"]');
      await w.page.waitVisible('[data-role="offer-result"]', SLOW);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="offer-result"]')?.getAttribute("data-outcome") ?? ""), "never", channel);
      await w.session.closeTab().catch(() => {});
      void neverHandle;
      await w.session.switchTo(w.pageTab);
      assert.deepEqual((await offersPeek(w, neverTab)).offers, [], `${channel}: "Never" ended the offer`);
      const blocked = await captureCase(w, uniqueSignup("signup-confirm-fr").c);
      assert.equal(blocked.error, undefined, `${channel}: ${blocked.error}`);
      assert.deepEqual(blocked.observed?.offers, [], `${channel}: "Never" stops the offers of the site`);
      assert.deepEqual(await w.vaultState(), vaultBefore, `${channel}: "Not now" and "Never" wrote nothing`);
      // The settings page lists the host, and takes it off again.
      await w.session.navigate(`${EXTENSION_ORIGIN}/pages/settings.html`);
      await w.session.waitFor(() => w.session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
      await w.page.waitVisible('[data-role="never-list"] [data-role="never-host"]');
      assert.ok((await allText(w, '[data-role="never-host"]')).some((t) => t.includes("forms.example.net")), `${channel}: the settings list has the host`);
      await w.page.click('[data-role="never-remove"][data-host="forms.example.net"]');
      await w.session.waitFor(() => w.page.visible('[data-role="never-empty"]'), 15_000, "the list is empty");
      await w.session.switchTo(w.pageTab);

      // 9. A save made while the server cannot be reached says that it waits, survives a lock, and goes out after the unlock.
      const offline = uniqueSignup("signup-confirm-nl");
      const before = await w.vaultState();
      await w.ui.open();
      try {
        assert.equal((await w.ui.ask("lock", {})).type, "lock", `${channel}: lock`);
        await evil("seq_lie", { latest_seq: 1 });
        await pace();
      const unlocked = await w.ui.ask("unlock", { mp: w.account.password });
        assert.equal(unlocked.body?.ok, true, `${channel}: ${JSON.stringify(unlocked.body)}`);
      } finally {
        await w.ui.close();
      }
      /** @type {string | undefined} */
      let newId;
      try {
        await w.session.waitFor(async () => (await w.vaultState()).running === true, 60_000, "the engine runs");
        const offered = await captureCase(w, offline.c);
        assert.equal(offered.error, undefined, `${channel}: ${offered.error}`);
        assert.equal(offered.observed?.offers.length, 1, `${channel}: an offer while the server cannot be reached`);
        const offlineTab = await newestTab(w);
        const handle = await popupWithCard(w, offlineTab, "save");
        const offlineName = `E2E-offline-${tag}`;
        await nameTheCard(w, offlineName);
        await w.page.click('[data-role="offer-save"]');
        await w.page.waitVisible('[data-role="offer-result"]', SLOW);
        assert.equal(await w.page.text('[data-role="offer-result"]'), "Saved. Waiting for sync.", `${channel}: the card says the save waits`);
        await w.session.closeTab().catch(() => {});
        void handle;
        await w.session.switchTo(w.pageTab);
        const now = await w.vaultState();
        const fresh = now.rows.filter((/** @type {string} */ r) => !before.rows.includes(r));
        assert.equal(fresh.length, 1, `${channel}: the item is in the local list, once (${JSON.stringify(fresh)})`);
        newId = fresh[0].split(":")[0];
        await w.session.switchTo(w.vaultTab);
        assert.equal(await serverHas(w.session, newId, 1), false, `${channel}: the server does not have it while it cannot be reached`);
        await w.session.switchTo(w.pageTab);
        // A lock does not lose it.
        await w.ui.open();
        try {
          assert.equal((await w.ui.ask("lock", {})).type, "lock", `${channel}: lock`);
        } finally {
          await w.ui.close();
        }
      } finally {
        await evil("honest");
      }
      await w.ui.open();
      try {
        await pace();
      const unlocked = await w.ui.ask("unlock", { mp: w.account.password });
        assert.equal(unlocked.body?.ok, true, `${channel}: ${JSON.stringify(unlocked.body)}`);
      } finally {
        await w.ui.close();
      }
      assert.ok(newId, "the new item has an id");
      await w.session.switchTo(w.vaultTab);
      await w.session.waitFor(() => serverHas(w.session, /** @type {string} */ (newId), 1), 90_000, `${channel}: the server took the save after the unlock`);
      assert.ok(await vaultItemHref(w, `E2E-offline-${tag}`), `${channel}: the web vault lists the save that waited`);
    } finally {
      await w.quit();
    }
  }
});

test("the_vault_still_syncs_after_the_https_access_is_taken_back", async () => {
  for (const channel of channels()) {
    const w = await readyWorld(channel);
    try {
      const granted = await w.fromBridge(() => w.bridge.invoke("permissions.getAll"));
      assert.equal((granted.origins ?? []).includes("https://*/*"), true, `${channel}: the click asked for the access and got it`);
      // The person turns the setting off in the settings tab: the access goes with it.
      await w.session.navigate(`${EXTENSION_ORIGIN}/pages/settings.html`);
      await w.session.waitFor(() => w.session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
      const [toggle] = await w.session.findAll('[data-role="capture-switch"]');
      await w.session.click(toggle);
      await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "false"), 15_000, "the switch off");
      await w.session.waitFor(async () => !((await w.fromBridge(() => w.bridge.invoke("permissions.getAll"))).origins ?? []).includes("https://*/*"), 15_000, "the access removed");
      await w.session.switchTo(w.pageTab);

      // The vault still syncs: an item made in the web vault reaches the extension, and the popup asks for no new access.
      const before = await w.vaultState();
      assert.equal(before.running, true, `${channel}: the sync engine runs`);
      const name = `After-access-${randomBytes(3).toString("hex")}`;
      await w.session.switchTo(w.vaultTab);
      await w.page.click('[data-role="nav-items"]');
      await w.page.waitVisible('[data-role="new-item"]');
      await w.page.click('[data-role="new-item"]');
      await w.page.waitVisible('[data-role="edit-form"]');
      await w.page.type('[data-role="name"]', name);
      await w.page.type('[data-role="username"]', `after-${randomBytes(3).toString("hex")}`);
      await w.page.type('[data-role="password"]', `Pw-${randomBytes(6).toString("hex")}`);
      await w.page.type('[data-role="url"]', "https://after-access.example.org/");
      await w.page.click('[data-role="save"]');
      await w.session.waitFor(async () => (await w.page.text('[data-role="item"] h1')).includes(name), 30_000, "the saved item");
      await w.session.switchTo(w.pageTab);
      await w.session.waitFor(async () => (await w.vaultState()).rows.length > before.rows.length, 60_000, `${channel}: the extension took the item the web vault made`);
      const handle = await w.session.newWindow();
      await w.session.switchTo(handle);
      await w.session.navigate(`${EXTENSION_ORIGIN}/pages/popup.html`);
      await w.page.ready();
      await w.page.waitVisible('[data-role="sync"][data-state="idle"]', SLOW);
      assert.equal(await w.page.visible('[data-role="grant"]'), false, `${channel}: the popup asks for no access to the server again`);
      await w.session.closeTab().catch(() => {});
      await w.session.switchTo(w.pageTab);
    } finally {
      await w.quit();
    }
  }
});
