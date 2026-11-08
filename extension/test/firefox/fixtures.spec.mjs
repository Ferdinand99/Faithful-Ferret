// The adversarial test sites (test/fixtures/sites) in real Firefox: every site is
// served on the host, scheme and port it is meant for, the frames that should
// load do, and each hostile field really is hostile for the reason its page
// names (and each control field really is clear), judged by the browser's own
// computed styles and hit testing. The fill engine's rules are tested against
// these sites later; this spec only proves the sites are what they claim to be.
//
// Run by the Firefox runner (`scripts/lanbox-ext.sh firefox`).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  CONFUSABLE_A_LABEL_HOST, CONFUSABLE_UNICODE_HOST, DIGIT_A_LABEL_HOST, DIGIT_UNICODE_HOST,
  HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST, ORIGINS, SITES,
} from "../fixtures/sites/index.mjs";
import { channels, fixtures, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/**
 * @template T
 * @param {Parameters<typeof launch>[0]} options
 * @param {(session: import("./driver.mjs").Session) => Promise<T>} body
 * @returns {Promise<T>}
 */
async function withFirefox(options, body) {
  const session = await launch(options);
  try {
    return await body(session);
  } finally {
    await session.quit();
  }
}

/** What a page says about itself. Runs in the browser. */
function readPage() {
  const root = document.documentElement;
  return {
    site: root.dataset.fixtureSite ?? null,
    href: location.href,
    origin: location.origin,
    protocol: location.protocol,
    hostname: location.hostname,
    port: location.port,
    secure: window.isSecureContext,
  };
}

/**
 * The fields that match `selector` (default: every field marked
 * data-fixture-expect, also inside shadow roots), with the reasons the
 * browser's own state gives for not filling each. Runs in the browser: a field
 * is clear when it has none. The ancestors are walked through shadow roots, and
 * `visibility`, `opacity`, `filter`, `transform`, `clip-path`, `mask` and
 * `mix-blend-mode` are read on every one of them.
 * @param {string} [selector]
 */
function auditFields(selector = "[data-fixture-expect]") {
  /** @type {Element[]} */
  const fields = [];
  /** @param {ParentNode} root */
  const collect = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.matches(selector)) fields.push(el);
      if (el.shadowRoot) collect(el.shadowRoot);
    }
  };
  collect(document);
  /** @param {Element} el @returns {Element | null} */
  const parentOf = (el) => el.parentElement ?? /** @type {any} */ (el.getRootNode()).host ?? null;
  /** @type {Record<string, { expect: string | null, reason: string | null, reasons: string[] }>} */
  const out = {};
  for (const el of fields) {
    /** @type {Set<string>} */
    const reasons = new Set();
    const input = /** @type {HTMLInputElement} */ (el);
    if (input.disabled) reasons.add("disabled");
    if (input.readOnly) reasons.add("readonly");
    if (input.hidden) reasons.add("hidden");
    if (el.getAttribute("aria-hidden") === "true") reasons.add("aria-hidden");
    if (getComputedStyle(el).display === "none") reasons.add("display");
    for (let node = /** @type {Element | null} */ (el); node; node = parentOf(node)) {
      const style = getComputedStyle(node);
      if (style.visibility !== "visible") reasons.add("visibility");
      if (Number.parseFloat(style.opacity) < 1) reasons.add("opacity");
      if (style.filter !== "none") reasons.add("filter");
      if (style.transform !== "none") reasons.add("transform");
      if (style.clipPath !== "none") reasons.add("clip-path");
      if (style.maskImage !== "none") reasons.add("mask");
      if (style.mixBlendMode !== "normal") reasons.add("mix-blend-mode");
    }
    const rect = el.getBoundingClientRect();
    if (rect.width < 5 || rect.height < 5) reasons.add("size");
    else if (rect.right <= 0 || rect.bottom <= 0 || rect.left >= window.innerWidth || rect.top >= window.innerHeight) reasons.add("offscreen");
    else {
      const root = /** @type {any} */ (el.getRootNode());
      const top = (root.elementFromPoint ? root : document).elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      if (top !== el) reasons.add("covered");
    }
    out[el.id || `#${Object.keys(out).length}`] = {
      expect: el.getAttribute("data-fixture-expect"),
      reason: el.getAttribute("data-fixture-reason"),
      reasons: [...reasons],
    };
  }
  return out;
}

/** Reads what a frame lets its parent see. Runs in the browser. @param {string} id */
function probeFrame(id) {
  const frame = /** @type {HTMLIFrameElement | null} */ (document.getElementById(id));
  if (!frame) return null;
  let doc = null;
  try {
    doc = frame.contentDocument;
  } catch {
    doc = null;
  }
  return {
    readable: doc !== null,
    href: doc ? doc.location.href : null,
    password: doc ? doc.querySelectorAll('input[type="password"]').length : null,
    sandbox: frame.getAttribute("sandbox"),
  };
}

/** @param {import("./fixtures-server.mjs").Fixtures} server @param {string} host @param {string} path @param {string} listener */
const saw = (server, host, path, listener) => server.requests.some((r) => r.host === host && r.path === path && r.listener === listener);

/**
 * Loads a site and waits until it says it is that site.
 * @param {import("./driver.mjs").Session} session
 * @param {string} url
 * @param {string} id
 * @param {string} where
 */
async function load(session, url, id, where) {
  await session.navigate(url);
  return session.waitFor(async () => {
    const seen = await session.content(readPage);
    return seen.site === id ? seen : false;
  }, 15_000, `${where} to load (${url})`);
}

test("every_fixture_answers_on_its_host_and_scheme", async () => {
  const server = await fixtures();
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      for (const site of SITES) {
        const origin = ORIGINS[site.origin];
        const where = `${channel}: ${site.id}`;
        const url = server.siteUrl(site.id);
        server.requests.length = 0;
        const page = await load(session, url, site.id, where);

        // The right scheme, host and port: the origin the page says it has is the one the site table names.
        assert.equal(page.origin, server.origin(site.origin), `${where}: origin`);
        assert.equal(page.protocol, `${origin.scheme}:`, `${where}: scheme`);
        assert.equal(page.hostname, origin.host, `${where}: host`);
        assert.equal(page.href, url, `${where}: address`);
        assert.equal(page.port, new URL(url).port, `${where}: port`);
        assert.equal(page.secure, origin.scheme === "https" || origin.ip === true, `${where}: secure context on https and on loopback only`);
        // The server saw the request on the listener meant for it.
        assert.ok(saw(server, origin.host, site.path, origin.listener), `${where}: served by the ${origin.listener} listener`);

        if (site.expect.outcome === "fields") {
          const entries = Object.entries(await session.content(auditFields));
          assert.ok(entries.some(([, f]) => f.expect === "reject"), `${where}: has a field that must be rejected`);
          for (const [id, field] of entries) {
            if (field.expect === "fill") {
              assert.deepEqual(field.reasons, [], `${where}: ${id} is a clear control field`);
              continue;
            }
            // Hostile for the reason the page names, and (where the page says so) for no other.
            assert.ok(field.reason, `${where}: ${id} names its reason`);
            assert.ok(field.reasons.includes(String(field.reason)), `${where}: ${id} is hostile for ${field.reason} (the browser says ${field.reasons})`);
            if (site.expect.exact === true) assert.deepEqual(field.reasons, [field.reason], `${where}: ${id} has no reason but ${field.reason}`);
          }
        }
      }
    });
  }
});

test("the_framing_pages_load_their_frames_and_the_opaque_frames_are_opaque", async () => {
  const server = await fixtures();
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      /** @param {string} id @param {string} host @param {string} path @param {string} listener */
      const framed = async (id, host, path, listener) => {
        server.requests.length = 0;
        await session.navigate(server.siteUrl(id));
        await session.waitFor(() => saw(server, host, path, listener), 15_000, `${channel}: ${id} loads its frame`);
      };
      // A frame from the same site, a cross-site page that frames the entry's page,
      // a foreign frame, nesting, and the insecure ancestors: all are fetched.
      await framed("framed-same-site", ORIGINS.login.host, "/", "https");
      await framed("framed-cross-site", ORIGINS.login.host, "/", "https");
      await framed("framed-foreign", ORIGINS.evil.host, "/login", "https");
      await framed("framed-nested", ORIGINS.login.host, "/t/nested-login.html", "https");
      await framed("http-framed-same-site", ORIGINS.loginHttp.host, "/", "http");
      await framed("http-top-https-frame", ORIGINS.login.host, "/", "https");
      await framed("loopback-framed", ORIGINS.loopback.host, "/", "http");

      // Frames without a usable origin: about:blank and srcdoc are readable from the
      // page and hold a password field; the sandboxes are opaque (no access).
      server.requests.length = 0;
      await session.navigate(server.siteUrl("frames-opaque"));
      await session.waitFor(() => saw(server, ORIGINS.login.host, "/t/sandboxed-login.html", "https"), 15_000, `${channel}: the sandbox frame's request`);
      /** @param {string} id */
      const probe = (id) => session.content(probeFrame, id);
      assert.deepEqual(await probe("frame-blank"), { readable: true, href: "about:blank", password: 1, sandbox: null }, `${channel}: about:blank frame`);
      assert.deepEqual(await probe("frame-srcdoc"), { readable: true, href: "about:srcdoc", password: 1, sandbox: null }, `${channel}: srcdoc frame`);
      assert.equal((await probe("frame-sandbox-srcdoc")).readable, false, `${channel}: sandbox srcdoc frame is opaque`);
      const sandboxed = await probe("frame-sandbox-https");
      assert.equal(sandboxed.readable, false, `${channel}: sandbox https frame is opaque although its address is https`);
      assert.equal(sandboxed.sandbox, "allow-scripts allow-forms", `${channel}: no allow-same-origin`);

      // Frames by address kind: data: is opaque; blob: and javascript: keep the page's origin.
      await session.navigate(server.siteUrl("frames-special"));
      assert.equal((await session.waitFor(() => probe("frame-data"), 10_000, "the data frame")).readable, false, `${channel}: data frame is opaque`);
      const blob = await session.waitFor(async () => {
        const seen = await probe("frame-blob");
        return seen?.readable && seen.password === 1 ? seen : false;
      }, 10_000, `${channel}: the blob frame`);
      assert.ok(String(blob.href).startsWith("blob:"), `${channel}: the blob frame's address is a blob: address (${blob.href})`);
      await session.waitFor(async () => (await probe("frame-javascript"))?.password === 1, 10_000, `${channel}: the javascript frame holds its form`);

      // A frame inside the entry's page, about:blank.
      await session.navigate(server.siteUrl("nested-login"));
      assert.deepEqual(await session.waitFor(() => probe("nested-blank"), 10_000, "the nested frame"), { readable: true, href: "about:blank", password: 1, sandbox: null }, `${channel}: nested about:blank frame`);

      // The page that moves its frame does so on request, and not before: to a foreign
      // origin, to a data: page (opaque) and to about:blank.
      for (const kind of ["foreign", "data", "blank"]) {
        server.requests.length = 0;
        await session.navigate(server.siteUrl("navigate-frame"));
        await session.waitFor(() => saw(server, ORIGINS.login.host, "/", "https"), 15_000, `${channel}: the frame's first page`);
        assert.equal(saw(server, ORIGINS.evil.host, "/login", "https"), false, `${channel}: nothing moves by itself`);
        await session.content((/** @type {string} */ k) => /** @type {any} */ (window).navigateFrame(k), kind);
        if (kind === "foreign") await session.waitFor(() => saw(server, ORIGINS.evil.host, "/login", "https"), 15_000, `${channel}: the frame moved to the foreign origin`);
        else if (kind === "data") assert.equal((await session.waitFor(async () => {
          const seen = await probe("frame");
          return seen && seen.readable === false ? seen : false;
        }, 10_000, `${channel}: the frame became a data: page`)).readable, false);
        else assert.equal((await session.waitFor(async () => {
          const seen = await probe("frame");
          return seen?.readable && seen.href === "about:blank" ? seen : false;
        }, 10_000, `${channel}: the frame became about:blank`)).href, "about:blank");
      }
    });
  }
});

test("pages_that_change_after_the_choice_turn_hostile_on_request", async () => {
  const server = await fixtures();
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      for (const id of ["blur-opacity", "blur-overlay", "blur-swap"]) {
        const where = `${channel}: ${id}`;
        await load(session, server.siteUrl(id), id, where);
        const before = await session.content(auditFields, "#login-pass");
        assert.deepEqual(before["login-pass"].reasons, [], `${where}: clear before`);
        await session.content(() => /** @type {any} */ (window).turnHostile());
        const after = await session.content(auditFields, "#login-pass");
        const reason = /** @type {string} */ (/** @type {any} */ (SITES.find((s) => s.id === id)).expect.reason);
        assert.ok(after["login-pass"].reasons.includes(reason), `${where}: hostile for ${reason} afterwards (${after["login-pass"].reasons})`);
      }
      // The page that leaves for a foreign origin.
      await load(session, server.siteUrl("blur-navigate"), "blur-navigate", `${channel}: blur-navigate`);
      await session.content(() => { setTimeout(() => /** @type {any} */ (window).turnHostile(), 0); });
      await session.waitFor(async () => (await session.content(() => location.hostname)) === ORIGINS.evil.host, 15_000, `${channel}: the page left for the foreign origin`);
    });
  }
});

test("a_page_full_of_forged_events_changes_nothing_by_itself", async () => {
  const server = await fixtures();
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      await load(session, server.siteUrl("forged-events"), "forged-events", `${channel}: forged-events`);
      const state = await session.waitFor(async () => {
        const seen = await session.content(() => /** @type {any} */ (window).fixtureState());
        return seen.sent >= 3 ? seen : false;
      }, 10_000, `${channel}: the page sends its noise`);
      assert.equal(state.userValue, "", `${channel}: nothing typed into the user name`);
      assert.equal(state.passwordValue, "", `${channel}: nothing typed into the password`);
      assert.ok(state.received >= 1, `${channel}: the page received its own forged messages`);
    });
  }
});

test("the_homograph_hosts_are_served_as_their_a_labels", async () => {
  // A host name typed with a Cyrillic o, with an all-Cyrillic label or with a
  // Devanagari digit goes over the wire as its A-label. This checks the sites and
  // the browser's own parser; the popup's display rules are the core's
  // display_host (see expect.display of the sites), which a later test of the
  // extension compares against.
  const server = await fixtures();
  const cases = [
    ["lookalike-homograph", "homograph", HOMOGRAPH_UNICODE_HOST, HOMOGRAPH_A_LABEL_HOST],
    ["lookalike-confusable", "confusable", CONFUSABLE_UNICODE_HOST, CONFUSABLE_A_LABEL_HOST],
    ["lookalike-digit", "digit", DIGIT_UNICODE_HOST, DIGIT_A_LABEL_HOST],
  ];
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      for (const [id, originName, unicode, aLabel] of cases) {
        const where = `${channel}: ${id}`;
        server.requests.length = 0;
        const unicodeUrl = `${server.origin(originName).replace(aLabel, unicode)}/`;
        const page = await load(session, unicodeUrl, id, where);
        assert.equal(page.hostname, aLabel, `${where}: the browser connects to the A-label`);
        assert.equal(page.origin, server.origin(originName), `${where}: the origin is the A-label origin`);
        const shown = await session.content((/** @type {string} */ typed) => ({
          note: document.getElementById("host-note")?.textContent ?? null,
          parsed: new URL(`https://${typed}/`).hostname,
        }), unicode);
        assert.equal(shown.note, unicode, `${where}: the page shows the typed form`);
        assert.equal(shown.parsed, aLabel, `${where}: the browser's own parser gives the A-label`);
        assert.ok(saw(server, aLabel, "/", "https"), `${where}: the server was asked for the A-label host`);
      }
    });
  }
});
