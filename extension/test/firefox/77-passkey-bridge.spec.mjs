// The passkey scripts of the test build in real Firefox (Release and ESR, Manifest V3 and V2): the registration, the
// script in the page's own world before the page's first script, the synchronous handshake against a hostile page, and the
// calls that go to the browser untouched (design document § 9.2 and § 10.8). Until the request broker decides, the
// background hands every request back to the browser, so each ceremony here is answered by the browser's own WebAuthn (a
// WebDriver virtual authenticator) after a full trip through the bridge: page -> its script -> port -> bridge -> background
// -> push -> bridge -> port -> the browser's own function, with the page's own options.
//
//   the_main_script_installs_before_the_first_page_script
//   the_bridge_port_cannot_be_observed_or_forged_by_a_page_script   (also: no window.postMessage, tampered built-ins)
//   calls_that_are_not_ours_go_to_the_original_untouched
//   registration_follows_permission_setting_and_sign_in
//   the_override_is_off_on_ferret_servers_and_extension_pages
//
// The extension's own pages hear what a content script sends (runtime.sendMessage reaches every page of the extension), so
// the test bridge tab records the bridge's messages: that is how a spec sees that a request went through the bridge, and
// what it carried.
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import { ABOUT_URL, channels, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID } from "./harness.mjs";

after(() => stopFixtures());

const MANIFESTS = /** @type {const} */ (["mv3", "mv2"]);
/** The soft token answers (the virtual authenticator), the USB token does not. */
const PREFS = Object.freeze({ "security.webauth.webauthn_enable_softtoken": true, "security.webauth.webauthn_enable_usbtoken": false });
/** The server the extension is signed in to, for the specs: a fixture host, so its pages can be opened. */
const SERVER = "https://login.example.net";
const IDS = ["ferret-passkey-bridge", "ferret-passkey-main"];

/**
 * Firefox with the test build, a bridge tab that records the bridge's messages, and a page tab.
 * @param {"release" | "esr"} channel @param {"mv3" | "mv2"} manifest
 */
async function setup(channel, manifest) {
  const session = await launch({ channel, manifest, prefs: PREFS });
  const server = await fixtures();
  await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
  await session.addVirtualAuthenticator();
  const bridgeTab = await session.windowHandle();
  const bridge = await openBridge(session);
  await listen(session);
  const pageTab = await session.newTab();
  await session.switchTo(pageTab);

  /** Runs `body` in the bridge tab and goes back to the page tab. @template T @param {() => Promise<T>} body */
  const inBridge = async (body) => {
    await session.switchTo(bridgeTab);
    try {
      return await body();
    } finally {
      await session.switchTo(pageTab);
    }
  };
  return {
    session,
    server,
    bridge,
    inBridge,
    pageTab,
    /** The scripts the browser holds under the feature's ids. @returns {Promise<string[]>} */
    registered: () => inBridge(() => session.content(async (/** @type {string[]} */ ids) => (await browser.scripting.getRegisteredContentScripts({ ids })).map((s) => s.id).sort(), IDS)),
    /** The bridge's messages since the last clear. @returns {Promise<Array<{ type: string, body: any, frameId: number }>>} */
    messages: () => inBridge(() => session.content(() => /** @type {any} */ (window).passkeyMessages ?? [])),
    clear: () => inBridge(() => session.content(() => { /** @type {any} */ (window).passkeyMessages = []; })),
    /** @param {Record<string, unknown>} items */
    store: (items) => inBridge(() => bridge.invoke("storage.local.set", items)),
    grant: () => inBridge(() => grant(session)),
    revoke: () => inBridge(() => session.content(() => browser.permissions.remove({ origins: ["https://*/*"] }))),
  };
}

/** Records every message of the passkey bridge that reaches the extension's pages. @param {import("./driver.mjs").Session} session */
async function listen(session) {
  await session.content(() => {
    const w = /** @type {any} */ (window);
    w.passkeyMessages = [];
    browser.runtime.onMessage.addListener((/** @type {unknown} */ raw, /** @type {any} */ sender) => {
      try {
        const message = JSON.parse(String(raw));
        if (typeof message.type === "string" && message.type.startsWith("passkey_")) w.passkeyMessages.push({ type: message.type, body: message.body, frameId: sender.frameId, url: sender.url });
      } catch {
        // Not ours.
      }
      return undefined;
    });
    return true;
  });
}

/** The optional permission for https pages, asked in the extension's own page with a real click. @param {import("./driver.mjs").Session} session */
async function grant(session) {
  await session.content(() => {
    if (document.getElementById("pk-grant")) return;
    const button = document.createElement("button");
    button.id = "pk-grant";
    button.textContent = "grant";
    button.addEventListener("click", () => {
      browser.permissions.request({ origins: ["https://*/*"] }).then(
        (ok) => { document.documentElement.dataset.pkGranted = String(ok); },
        (error) => { document.documentElement.dataset.pkGranted = `error ${error}`; },
      );
    });
    document.body.append(button);
  });
  const [button] = await session.findAll("#pk-grant");
  await session.click(button);
  const answer = await session.waitFor(() => session.content(() => document.documentElement.dataset.pkGranted), 15_000, "the answer to the permission request");
  assert.equal(answer, "true", "the permission for https pages was granted");
}

/**
 * Turns the feature on the way the settings will (permission, setting, a signed-in server) and waits for both scripts.
 * @param {Awaited<ReturnType<typeof setup>>} s
 */
async function turnOn(s) {
  await s.grant();
  await s.store({ use_passkeys: true, server: SERVER });
  await s.session.waitFor(async () => (await s.registered()).length === 2, 15_000, "both passkey scripts registered");
}

/** Opens a page and reads the JSON its scripts wrote into `data-<name>` of the root. @param {any} session @param {string} url @param {string} name */
async function openAndRead(session, url, name) {
  await session.navigate(url);
  const raw = await session.waitFor(() => session.content((/** @type {string} */ n) => document.documentElement.dataset[n], name), 15_000, `${name} of ${url}`);
  return JSON.parse(raw);
}

/** Clicks a button of the page (a real click: transient user activation) and waits for `data-<name>`. @param {any} session @param {string} id @param {string} name */
async function press(session, id, name) {
  const [button] = await session.findAll(`#${id}`);
  assert.ok(button, `#${id}`);
  await session.content((/** @type {string} */ n) => { delete document.documentElement.dataset[n]; }, name);
  await session.click(button);
  const raw = await session.waitFor(() => session.content((/** @type {string} */ n) => document.documentElement.dataset[n], name), 30_000, `${name} after #${id}`);
  return JSON.parse(raw);
}

/** Runs `body` inside the page's frame of another origin. @template T @param {any} session @param {() => Promise<T>} body */
async function inCrossFrame(session, body) {
  const [cross] = await session.findAll("#cross");
  await session.switchToFrame(cross);
  try {
    await session.waitFor(() => session.content(() => document.readyState === "complete" && document.getElementById("go") !== null), 15_000, "the frame");
    return await body();
  } finally {
    await session.switchToTopFrame();
  }
}

/** A ceremony the browser answered: both calls gave the browser's own PublicKeyCredential. */
const ANSWERED = { create: { type: "public-key", native: true }, get: { type: "public-key", native: true } };

// One suite, so `--grep passkey` (and `--grep passkey_bridge`) picks every test of the file.
describe("passkey_bridge", () => {
  test("the_main_script_installs_before_the_first_page_script", async () => {
    for (const channel of channels()) {
      for (const manifest of MANIFESTS) {
        const label = `${channel}/${manifest}`;
        const s = await setup(channel, manifest);
        try {
          const url = s.server.url("fixture.test", "/pk-first/");
          // Before the feature is on, the page has the browser's own functions.
          assert.deepEqual(await openAndRead(s.session, url, "first"), { createNative: true, getNative: true, readyState: "loading", scripts: 1 }, `${label}: off`);
          await turnOn(s);
          const first = await openAndRead(s.session, url, "first");
          assert.deepEqual(first, { createNative: false, getNative: false, readyState: "loading", scripts: 1 }, `${label}: the first inline script already sees Ferret's functions`);
          // In a frame of the same origin too.
          const [frame] = await s.session.findAll("#same");
          await s.session.switchToFrame(frame);
          const inFrame = JSON.parse(await s.session.waitFor(() => s.session.content(() => document.documentElement.dataset.first), 15_000, "the frame"));
          await s.session.switchToTopFrame();
          assert.equal(inFrame.createNative, false, `${label}: frame`);
          // The first page after a restart of the browser (the registration is kept across sessions).
          await s.session.restart();
          await s.session.navigate(url);
          const afterRestart = JSON.parse(await s.session.waitFor(() => s.session.content(() => document.documentElement.dataset.first), 15_000, "the first page after a restart"));
          assert.equal(afterRestart.createNative, false, `${label}: the first page after a restart`);
          assert.equal(afterRestart.readyState, "loading");
        } finally {
          await s.session.quit();
        }
      }
    }
  });

  test("the_bridge_port_cannot_be_observed_or_forged_by_a_page_script", async () => {
    for (const channel of channels()) {
      for (const manifest of MANIFESTS) {
        const label = `${channel}/${manifest}`;
        const s = await setup(channel, manifest);
        try {
          await turnOn(s);
          await s.clear();
          const url = s.server.url("fixture.test", "/pk-adversary/");
          await s.session.navigate(url);
          await s.session.waitFor(() => s.session.content(() => document.documentElement.dataset.adv), 15_000, "the hostile page");
          const result = await press(s.session, "go", "result");
          // The ceremony worked, through the bridge, although the page had replaced the built-ins (tampered built-ins fail
          // closed: here they changed nothing at all).
          assert.deepEqual(result, ANSWERED, `${label}: both calls answered`);
          const messages = await s.messages();
          const requests = messages.filter((m) => m.type === "passkey_request");
          assert.deepEqual(requests.map((m) => m.body.kind), ["create", "get"], `${label}: both went through the bridge`);
          assert.equal(requests[0].body.activation, true, `${label}: the click's user activation, read in the isolated world`);
          assert.equal(requests[0].body.policy, null, `${label}: Firefox has no document.featurePolicy`);
          for (const r of requests) assert.deepEqual(Object.keys(r.body).sort(), ["activation", r.body.kind, "kind", "mediation", "policy", "request_id"].sort(), `${label}: no origin, frame or address`);
          // The forged request the page sent on its own ports never reached the background.
          assert.equal(requests.length, 2, `${label}: no forged request`);
          const adv = JSON.parse(await s.session.content(() => document.documentElement.dataset.adv));
          // The page's listeners heard its own two forged handshakes (on the document and on the window) and nothing else.
          assert.ok(adv.handshakeEvents >= 2 && adv.handshakeEvents <= 4, `${label}: ${adv.handshakeEvents} handshake events`);
          delete adv.handshakeEvents;
          assert.deepEqual(adv, {
            portsSeen: 0,
            windowMessages: 0,
            windowPostMessage: 0,
            foreignPortUse: 0,
            stolenMessages: 0,
            forgedTaken: 0,
            repliesToForged: 0,
          }, `${label}: the page saw no port and no message, and nothing took its forged handshakes`);
        } finally {
          await s.session.quit();
        }
      }
    }
  });

  test("calls_that_are_not_ours_go_to_the_original_untouched", async () => {
    for (const channel of channels()) {
      for (const manifest of MANIFESTS) {
        const label = `${channel}/${manifest}`;
        const s = await setup(channel, manifest);
        try {
          const url = s.server.url("fixture.test", "/pk-calls/");
          // What the browser alone answers (Ferret off: nothing registered), in the top page and in the frame of another origin.
          await s.session.navigate(url);
          const browserOther = await press(s.session, "other", "other");
          assert.deepEqual(await press(s.session, "go", "result"), ANSWERED, `${label}: the browser alone`);
          const frameAlone = await inCrossFrame(s.session, () => press(s.session, "go", "result"));

          await turnOn(s);
          await s.clear();
          await s.session.navigate(url);
          // password, federated, no options, silent: the same answer as without Ferret, and nothing reaches the bridge.
          assert.deepEqual(await press(s.session, "other", "other"), browserOther, `${label}: the calls that are not Ferret's`);
          assert.deepEqual((await s.messages()).filter((m) => m.type === "passkey_request"), [], `${label}: none of them went to the background`);
          // A ceremony Ferret looks at and hands back: the browser's own credential objects.
          assert.deepEqual(await press(s.session, "go", "result"), ANSWERED, `${label}: handed to the browser`);
          assert.equal((await s.messages()).filter((m) => m.type === "passkey_request").length, 2);

          // A frame of another origin: the browser answers there too (the background decides; until then it hands back).
          await s.clear();
          assert.deepEqual(await inCrossFrame(s.session, () => press(s.session, "go", "result")), frameAlone, `${label}: a frame of another origin`);
          const fromFrame = (await s.messages()).filter((m) => m.type === "passkey_request");
          assert.equal(fromFrame.length, 2);
          assert.ok(fromFrame.every((m) => m.frameId !== 0), `${label}: the requests came from the frame`);

          // Ferret off again: nothing is registered, and the page has the browser's own functions.
          await s.store({ use_passkeys: false });
          await s.session.waitFor(async () => (await s.registered()).length === 0, 15_000, "the scripts gone (setting off)");
          assert.equal((await openAndRead(s.session, s.server.url("fixture.test", "/pk-first/"), "first")).createNative, true, `${label}: off`);
          // Signed out: the same.
          await s.store({ use_passkeys: true });
          await s.session.waitFor(async () => (await s.registered()).length === 2, 15_000, "registered again");
          await s.inBridge(() => s.session.content(() => browser.storage.local.remove("server")));
          await s.session.waitFor(async () => (await s.registered()).length === 0, 15_000, "the scripts gone (signed out)");
          assert.equal((await openAndRead(s.session, s.server.url("fixture.test", "/pk-first/"), "first")).createNative, true, `${label}: signed out`);
        } finally {
          await s.session.quit();
        }
      }
    }
  });

  test("registration_follows_permission_setting_and_sign_in", async () => {
    for (const channel of channels()) {
      for (const manifest of MANIFESTS) {
        const label = `${channel}/${manifest}`;
        const s = await setup(channel, manifest);
        try {
          // The setting and a server without the permission: nothing is registered, and the setting cannot stay on.
          await s.store({ use_passkeys: true, server: SERVER });
          await s.session.waitFor(async () => (await s.inBridge(() => s.bridge.invoke("storage.local.get", "use_passkeys"))).use_passkeys === false, 15_000, "the setting off without the permission");
          assert.deepEqual(await s.registered(), [], `${label}: no permission`);
          // The permission alone turns nothing on; then the setting: both registered.
          await s.grant();
          assert.deepEqual(await s.registered(), [], `${label}: the permission alone turns nothing on`);
          await s.store({ use_passkeys: true });
          await s.session.waitFor(async () => (await s.registered()).length === 2, 15_000, "registered");
          const scripts = await s.inBridge(() => s.session.content(async (/** @type {string[]} */ ids) => browser.scripting.getRegisteredContentScripts({ ids }), IDS));
          for (const script of scripts) {
            assert.deepEqual(script.matches, ["https://*/*"], `${label}: ${script.id}`);
            assert.deepEqual(script.excludeMatches, ["https://login.example.net/*"], `${label}: ${script.id}`);
            assert.equal(script.runAt, "document_start");
            assert.equal(script.allFrames, true);
            assert.equal(script.persistAcrossSessions, true);
          }
          assert.equal(scripts.find((/** @type {any} */ x) => x.id === "ferret-passkey-main")?.world, "MAIN", `${label}: the page's own world`);
          assert.notEqual(scripts.find((/** @type {any} */ x) => x.id === "ferret-passkey-bridge")?.world, "MAIN", `${label}: the bridge is isolated`);
          // The permission taken back: the scripts and the setting go.
          await s.revoke();
          await s.session.waitFor(async () => (await s.registered()).length === 0, 15_000, "the scripts gone (permission removed)");
          const stored = await s.inBridge(() => s.bridge.invoke("storage.local.get", "use_passkeys"));
          assert.equal(stored.use_passkeys, false, `${label}: the setting went with the permission`);
        } finally {
          await s.session.quit();
        }
      }
    }
  });

  test("the_override_is_off_on_ferret_servers_and_extension_pages", async () => {
    for (const channel of channels()) {
      for (const manifest of MANIFESTS) {
        const label = `${channel}/${manifest}`;
        const s = await setup(channel, manifest);
        try {
          await turnOn(s);
          // The signed-in server's own pages keep the browser's functions.
          const onServer = await openAndRead(s.session, s.server.url("login.example.net", "/pk-first/"), "first");
          assert.equal(onServer.createNative, true, `${label}: the server's origin`);
          // And another page does not (the control).
          assert.equal((await openAndRead(s.session, s.server.url("www.example.net", "/pk-first/"), "first")).createNative, false, `${label}: another origin`);
          // An extension page has the browser's own functions.
          await s.session.navigate(ABOUT_URL);
          const native = await s.session.content(() => /\[native code\]/.test(Function.prototype.toString.call(CredentialsContainer.prototype.create)));
          assert.equal(native, true, `${label}: an extension page`);
        } finally {
          await s.session.quit();
        }
      }
    }
  });
});
