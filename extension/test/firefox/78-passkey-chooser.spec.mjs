// The chooser window for passkey requests in real Firefox (Release and ESR; the `passkeys` feature, design § 9.4 and § 10.3.3). What the
// unit tests cannot see: the style sheet (nothing is drawn wider than the window, the website's texts are isolated and the host is read
// left to right, in the light and the dark theme), a real click against the 400 ms guard, a real Enter, a page of the extension that no
// web page and no extension page can frame, and the window that closes when it has no request of its own.
//
// The window runs here on the test build's canned page (pages/test-only/passkeyChooserPage.html), which answers the window's messages
// itself and shows what the window sent in `data-calls` on the body. The window's own page (pages/passkey.html) is opened only for what
// does not need a request. The screenshots (dark and light: a new passkey, a get with two passkeys, a get with none, and more) go to
// FERRET_SHOTS_DIR when it is set (scripts/lanbox-ext.sh firefox with FERRET_SHOTS_OUT), else to a folder of the container's own.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, fixtures, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const ENTER = String.fromCharCode(0xe007);
const PAGE = `${EXTENSION_ORIGIN}/pages/test-only/passkeyChooserPage.html`;
const WINDOW = `${EXTENSION_ORIGIN}/pages/passkey.html`;

/** @param {import("./driver.mjs").Session} session @param {string} scenario @param {"dark" | "light"} [theme] */
async function open(session, scenario, theme = "dark") {
  await session.navigate(`${PAGE}?s=${scenario}&theme=${theme}`);
  await session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 20_000, `the chooser page (${scenario})`);
}

/** What the window sent so far, and whether it closed. @param {import("./driver.mjs").Session} session */
const sent = (session) =>
  session.content(() => ({ calls: JSON.parse(document.body.dataset.calls ?? "[]"), closed: document.body.dataset.closed === "1" }));

/** @param {import("./driver.mjs").Session} session @param {string} css */
async function one(session, css) {
  const [element] = await session.findAll(css);
  assert.ok(element, css);
  return element;
}

/** Where the screenshots of a channel go. @param {string} channel */
function shotsDir(channel) {
  const dir = join(process.env.FERRET_SHOTS_DIR ?? join(tmpdir(), "ferret-shots"), channel);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** What the page draws: the window's width against what it holds, and the isolation of the texts. @param {import("./driver.mjs").Session} session */
const layout = (session) =>
  session.content(() => {
    const root = document.documentElement;
    const isolated = [...document.querySelectorAll("[data-site-text]")].map((n) => getComputedStyle(n).unicodeBidi);
    const hosts = [...document.querySelectorAll(".ff-host")].map((n) => ({ dir: getComputedStyle(n).direction, bidi: getComputedStyle(n).unicodeBidi }));
    const cards = [...document.querySelectorAll(".ff-chooser, .ff-pk-ferret, .ff-pk-site, .ff-pk-claims, .ff-pk-row, .ff-pk-others")].map((n) => Math.round(n.getBoundingClientRect().right));
    return {
      overflow: root.scrollWidth > root.clientWidth,
      width: root.clientWidth,
      isolated,
      hosts,
      widest: Math.max(0, ...cards),
      text: document.body.textContent ?? "",
    };
  });

test("the_chooser_window_flow_in_release_and_esr", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.setWindowSize(520, 760).catch(() => {});

      // A get with two passkeys: the site first, Ferret's choices, then the browser, "Never" and Cancel.
      await open(session, "get2");
      const shape = await session.content(() => {
        const nodes = [...document.querySelectorAll("[data-role]")].map((n) => n.getAttribute("data-role"));
        return {
          order: ["passkey-site", "passkey-site-texts", "passkey-ferret", "passkey-others"].map((r) => nodes.indexOf(r)),
          host: document.querySelector('[data-role="passkey-host"]')?.textContent,
          rpId: document.querySelector('[data-role="passkey-rp-id"]')?.textContent,
          forms: document.querySelectorAll("form").length,
          focused: document.activeElement?.getAttribute("data-role"),
          rows: [...document.querySelectorAll('[data-role="passkey-candidate"]')].map((n) => n.getAttribute("data-item")),
        };
      });
      assert.deepEqual(shape.order, [...shape.order].sort((a, b) => a - b), `${channel}: the order of the parts`);
      assert.ok(shape.order.every((i) => i >= 0), `${channel}: every part is there`);
      assert.equal(shape.host, "www.example.com", channel);
      assert.equal(shape.rpId, "example.com", channel);
      assert.equal(shape.forms, 0, `${channel}: no form, no default button`);
      assert.equal(shape.focused, "passkey-title", `${channel}: the focus starts on the heading`);
      assert.equal(shape.rows.length, 2, channel);
      const drawn = await layout(session);
      assert.equal(drawn.overflow, false, `${channel}: nothing is drawn wider than the window`);
      assert.ok(drawn.widest <= drawn.width, `${channel}: nothing sticks out (${drawn.widest} of ${drawn.width})`);
      for (const host of drawn.hosts) assert.deepEqual(host, { dir: "ltr", bidi: "isolate" }, `${channel}: the host is read left to right in isolation`);
      for (const bidi of drawn.isolated) assert.equal(bidi, "isolate", `${channel}: a text of the website is isolated`);

      // Enter does nothing: not on the heading, which has the focus.
      await session.type(await one(session, '[data-role="passkey-title"]'), ENTER);
      assert.deepEqual((await sent(session)).calls, [], `${channel}: Enter sent nothing`);

      // A click that a script made does not count, whenever it comes.
      await new Promise((resolve) => setTimeout(resolve, 800));
      await session.content(() => /** @type {HTMLElement} */ (document.querySelector('[data-role="passkey-candidate"]')).click());
      await new Promise((resolve) => setTimeout(resolve, 200));
      assert.deepEqual((await sent(session)).calls, [], `${channel}: an untrusted click does not count`);

      // A real click within 400 ms of the focus does not count; one after does. The focus is given again (as a window gets it),
      // and the click comes as soon as the driver can make it; a slow driver gets another try.
      let guarded = false;
      for (let attempt = 0; attempt < 6 && !guarded; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 700));
        const row = await one(session, '[data-role="passkey-candidate"]');
        await session.content(() => {
          document.body.dataset.at = "";
          window.dispatchEvent(new Event("focus"));
          const focusedAt = performance.now();
          document.addEventListener("click", (event) => {
            document.body.dataset.at = String(performance.now() - focusedAt);
            document.body.dataset.trusted = String(event.isTrusted);
          }, { capture: true, once: true });
        });
        await session.click(row);
        const at = Number(await session.content(() => document.body.dataset.at));
        const trusted = await session.content(() => document.body.dataset.trusted);
        assert.equal(trusted, "true", `${channel}: the driver's click is the person's`);
        if (at < 350) {
          guarded = true;
          assert.deepEqual((await sent(session)).calls, [], `${channel}: a click ${Math.round(at)} ms after the focus does not count`);
        } else if ((await sent(session)).calls.length > 0) {
          // The driver was too slow for this try; the choice went through, and the page is started again.
          await open(session, "get2");
        }
      }
      assert.ok(guarded, `${channel}: a click within the guard was tried`);
      await new Promise((resolve) => setTimeout(resolve, 700));
      const second = await one(session, '[data-role="passkey-candidate"]');
      await session.click(second);
      await session.waitFor(async () => (await sent(session)).calls.length === 1, 10_000, "the choice");
      const choice = (await sent(session)).calls[0];
      assert.equal(choice.call, "choose", channel);
      assert.deepEqual(Object.keys(choice.arg).sort(), ["itemId", "kind"], `${channel}: only the item and the kind go`);
      await session.waitFor(async () => (await sent(session)).closed, 10_000, "the window closes after an answer");

      // A new passkey: the name starts as the host without www, Enter in the field does nothing, one click makes the passkey.
      await open(session, "create");
      const name = await one(session, '[data-role="passkey-name"]');
      assert.equal(await session.content(() => /** @type {HTMLInputElement} */ (document.querySelector('[data-role="passkey-name"]')).value), "example.com", channel);
      await session.type(name, `${ENTER}`);
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.deepEqual((await sent(session)).calls, [], `${channel}: Enter in the field sent nothing`);
      await new Promise((resolve) => setTimeout(resolve, 600));
      await session.click(await one(session, '[data-role="passkey-create-new"]'));
      await session.waitFor(async () => (await sent(session)).calls.length === 1, 10_000, "the new passkey");
      assert.deepEqual((await sent(session)).calls[0].arg, { kind: "create", mode: "new", name: "example.com", folderId: null }, channel);
      assert.equal(await session.content(() => /** @type {HTMLInputElement | null} */ (document.querySelector('[data-role="passkey-name"]'))?.value ?? ""), "", `${channel}: the field is emptied`);

      // No Ferret passkey: the window is there, with the browser as the clear way on.
      await open(session, "none");
      assert.match((await layout(session)).text, /No Ferret passkey for this website/, channel);
      assert.match(await session.content(() => document.querySelector('[data-role="passkey-browser"]')?.className ?? ""), /ff-primary/, channel);

      // A locked vault unlocks in the window, and the window then shows the passkeys.
      await open(session, "locked");
      assert.equal(await session.content(() => document.querySelector('[data-role="passkey-ferret"]') === null), true, `${channel}: nothing of the vault while locked`);
      await session.type(await one(session, '[data-role="passkey-password"]'), "a-password");
      await session.click(await one(session, '[data-role="passkey-unlock"]'));
      await session.waitFor(() => session.content(() => document.querySelectorAll('[data-role="passkey-candidate"]').length === 2), 10_000, "the passkeys after the unlock");
      assert.equal(await session.content(() => /** @type {HTMLInputElement | null} */ (document.querySelector('[data-role="passkey-password"]'))?.value ?? ""), "", `${channel}: no password left in the page`);

      // Texts of a website that try to look like something else: isolated, no direction character left, nothing wider than the window.
      await open(session, "hostile");
      const hostile = await layout(session);
      assert.equal(hostile.overflow, false, `${channel}: long and hostile texts do not widen the window`);
      assert.ok(hostile.widest <= hostile.width, `${channel}: nothing sticks out (${hostile.widest} of ${hostile.width})`);
      assert.equal([...hostile.text].some((ch) => { const cp = /** @type {number} */ (ch.codePointAt(0)); return (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069); }), false, `${channel}: no direction character is in the window`);
      assert.ok(hostile.isolated.length >= 3 && hostile.isolated.every((b) => b === "isolate"), channel);

      // The screenshots: a new passkey, a get with two passkeys, a get with none; each dark and light (and a few more in dark).
      const dir = shotsDir(channel);
      for (const theme of /** @type {const} */ (["dark", "light"])) {
        for (const scenario of ["create", "get2", "none", "create_attach", "locked", "offline", "foreign", "hostile"]) {
          if (theme === "light" && !["create", "get2", "none"].includes(scenario)) continue;
          await open(session, scenario, theme);
          await new Promise((resolve) => setTimeout(resolve, 700));
          await session.fullScreenshot(join(dir, `u4-6-${scenario}-${theme}.png`));
        }
      }
    } finally {
      await session.quit();
    }
  }
});

/**
 * What an iframe of the selected tab holds: the URI of its document, and whether it built the chooser page.
 * @param {import("./driver.mjs").Session} session @param {string} css
 */
async function frameDocument(session, css) {
  const [frame] = await session.findAll(css);
  assert.ok(frame, css);
  await session.switchToFrame(frame);
  try {
    return await session.content(() => ({ uri: document.documentURI, built: document.querySelector('[data-role="passkey-chooser"]') !== null || document.body?.dataset.ready === "1" }));
  } finally {
    await session.switchToTopFrame();
  }
}

test("the_chooser_page_cannot_be_framed_and_closes_without_a_request_of_its_own", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const home = await session.windowHandle();
      // A web page frames it (with a request id in the address, as the background would open it).
      await session.navigate(server.url(server.hosts[0], "/static/blank.html"));
      await session.content((/** @type {string} */ src) => {
        const frame = document.createElement("iframe");
        frame.id = "framed-chooser";
        frame.src = src;
        document.body.append(frame);
      }, `${WINDOW}?r=${"ab".repeat(16)}`);
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      const web = await frameDocument(session, "#framed-chooser");
      assert.equal(web.uri.startsWith("moz-extension:"), false, `${channel}: a web page framed the window (${web.uri})`);
      assert.equal(web.built, false, `${channel}: the window built itself in a web page's frame`);

      // An extension page frames it: frame-ancestors 'none' applies to every ancestor.
      await session.navigate(`${EXTENSION_ORIGIN}/pages/about.html`);
      await session.content((/** @type {string} */ src) => {
        const frame = document.createElement("iframe");
        frame.id = "framed-chooser";
        frame.src = src;
        document.body.append(frame);
      }, `${WINDOW}?r=${"ab".repeat(16)}`);
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      const own = await frameDocument(session, "#framed-chooser");
      assert.equal(own.built, false, `${channel}: an extension page framed the window (${own.uri})`);

      // Opened without a request of its own (an address typed by hand), it says so and closes by itself.
      const before = await session.windowHandles();
      const tab = await session.newTab();
      await session.switchTo(tab);
      await session.navigate(WINDOW);
      await session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 20_000, "the window page");
      assert.match(await session.content(() => document.querySelector('[data-role="passkey-title"]')?.textContent ?? ""), /This request has ended/, channel);
      await session.waitFor(async () => (await session.windowHandles()).length === before.length, 15_000, "the window closed itself");
      await session.switchTo(home);
    } finally {
      await session.quit();
    }
  }
});
