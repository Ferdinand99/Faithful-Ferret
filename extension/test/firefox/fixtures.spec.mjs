// The adversarial test sites (test/fixtures/sites) in real Firefox: every site is
// served on the host, scheme and port it is meant for, the frames that should
// load do, and each hostile field really is hostile (and each control field
// really is clear), judged by the browser's own computed styles and hit
// testing. The fill engine's rules are tested against these sites later; this
// spec only proves the sites are what they claim to be.
//
// Run by the Firefox runner (`scripts/lanbox-ext.sh firefox`).
import assert from "node:assert/strict";
import { domainToASCII } from "node:url";
import { after, test } from "node:test";
import { HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST, ORIGINS, SITES } from "../fixtures/sites/index.mjs";
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
 * Every field marked data-fixture-expect (also inside shadow roots), with the
 * reasons the browser's own state gives for not filling it. Runs in the browser:
 * a field is clear when it has none.
 */
function auditFields() {
  /** @type {Element[]} */
  const fields = [];
  /** @param {ParentNode} root */
  const collect = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.hasAttribute("data-fixture-expect")) fields.push(el);
      if (el.shadowRoot) collect(el.shadowRoot);
    }
  };
  collect(document);
  /** @param {Element} el @returns {Element | null} */
  const parentOf = (el) => el.parentElement ?? /** @type {any} */ (el.getRootNode()).host ?? null;
  /** @type {Record<string, { expect: string | null, reasons: string[] }>} */
  const out = {};
  for (const el of fields) {
    /** @type {Set<string>} */
    const reasons = new Set();
    const input = /** @type {HTMLInputElement} */ (el);
    if (input.disabled) reasons.add("disabled");
    if (input.readOnly) reasons.add("readonly");
    if (input.hidden) reasons.add("hidden");
    if (el.getAttribute("aria-hidden") === "true") reasons.add("aria-hidden");
    const own = getComputedStyle(el);
    if (own.display === "none") reasons.add("display");
    if (own.visibility !== "visible") reasons.add("visibility");
    for (let node = /** @type {Element | null} */ (el); node; node = parentOf(node)) {
      const style = getComputedStyle(node);
      if (Number.parseFloat(style.opacity) < 1) reasons.add("opacity");
      if (style.filter !== "none") reasons.add("filter");
      if (style.transform !== "none") reasons.add("transform");
      if (style.clipPath !== "none") reasons.add("clip-path");
      if (style.maskImage !== "none") reasons.add("mask");
      if (style.mixBlendMode !== "normal") reasons.add("mix-blend-mode");
    }
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) reasons.add("size");
    else if (rect.right <= 0 || rect.bottom <= 0 || rect.left >= window.innerWidth || rect.top >= window.innerHeight) reasons.add("offscreen");
    else {
      const root = /** @type {any} */ (el.getRootNode());
      const top = (root.elementFromPoint ? root : document).elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      if (top !== el) reasons.add("covered");
    }
    out[el.id || `#${Object.keys(out).length}`] = { expect: el.getAttribute("data-fixture-expect"), reasons: [...reasons] };
  }
  return out;
}

/** @param {import("./fixtures-server.mjs").Fixtures} server @param {string} host @param {string} path @param {string} listener */
const saw = (server, host, path, listener) => server.requests.some((r) => r.host === host && r.path === path && r.listener === listener);

test("every_fixture_answers_on_its_host_and_scheme", async () => {
  const server = await fixtures();
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      for (const site of SITES) {
        const origin = ORIGINS[site.origin];
        const where = `${channel}: ${site.id}`;
        const url = server.siteUrl(site.id);
        server.requests.length = 0;
        await session.navigate(url);
        const page = await session.waitFor(async () => {
          const seen = await session.content(readPage);
          return seen.site === site.id ? seen : false;
        }, 15_000, `${where} to load (${url})`);

        // The right scheme, host and port: the origin the page says it has is the one the site table names.
        assert.equal(page.origin, server.origin(site.origin), `${where}: origin`);
        assert.equal(page.protocol, `${origin.scheme}:`, `${where}: scheme`);
        assert.equal(page.hostname, origin.host, `${where}: host`);
        assert.equal(page.href, url, `${where}: address`);
        assert.equal(page.port, new URL(url).port, `${where}: port`);
        assert.equal(page.secure, origin.scheme === "https", `${where}: secure context only on https`);
        // The server saw the request on the listener meant for it.
        assert.ok(saw(server, origin.host, site.path, origin.listener), `${where}: served by the ${origin.listener} listener`);

        if (site.expect.outcome === "fields") {
          const fields = await session.content(auditFields);
          const entries = Object.entries(fields);
          assert.ok(entries.some(([, f]) => f.expect === "reject"), `${where}: has a field that must be rejected`);
          for (const [id, field] of entries) {
            if (field.expect === "fill") assert.deepEqual(field.reasons, [], `${where}: ${id} is a clear control field`);
            else assert.ok(field.reasons.length > 0, `${where}: ${id} is hostile (the browser gives a reason not to fill it)`);
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
      // A frame from the same site and one from a foreign site: both are fetched.
      server.requests.length = 0;
      await session.navigate(server.siteUrl("framed-same-site"));
      await session.waitFor(() => saw(server, ORIGINS.login.host, "/", "https"), 15_000, `${channel}: the same-site frame`);
      server.requests.length = 0;
      await session.navigate(server.siteUrl("framed-foreign"));
      await session.waitFor(() => saw(server, ORIGINS.evil.host, "/login", "https"), 15_000, `${channel}: the foreign frame`);

      // Frames without a usable origin: about:blank and srcdoc are readable from the
      // page and hold a password field; the sandboxes are opaque (no access).
      server.requests.length = 0;
      await session.navigate(server.siteUrl("frames-opaque"));
      await session.waitFor(() => saw(server, ORIGINS.login.host, "/t/sandboxed-login.html", "https"), 15_000, `${channel}: the sandbox frame's request`);
      const frames = await session.content(() => {
        /** @param {string} id */
        const probe = (id) => {
          const frame = /** @type {HTMLIFrameElement} */ (document.getElementById(id));
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
        };
        return Object.fromEntries(["frame-blank", "frame-srcdoc", "frame-sandbox-srcdoc", "frame-sandbox-https"].map((id) => [id, probe(id)]));
      });
      assert.deepEqual(frames["frame-blank"], { readable: true, href: "about:blank", password: 1, sandbox: null }, `${channel}: about:blank frame`);
      assert.deepEqual(frames["frame-srcdoc"], { readable: true, href: "about:srcdoc", password: 1, sandbox: null }, `${channel}: srcdoc frame`);
      assert.equal(frames["frame-sandbox-srcdoc"].readable, false, `${channel}: sandbox srcdoc frame is opaque`);
      assert.equal(frames["frame-sandbox-https"].readable, false, `${channel}: sandbox https frame is opaque although its address is https`);
      assert.equal(frames["frame-sandbox-https"].sandbox, "allow-scripts allow-forms", `${channel}: no allow-same-origin`);

      // The page that moves its frame to a foreign origin does so on request, and not before.
      server.requests.length = 0;
      await session.navigate(server.siteUrl("navigate-frame"));
      await session.waitFor(() => saw(server, ORIGINS.login.host, "/", "https"), 15_000, `${channel}: the frame's first page`);
      assert.equal(saw(server, ORIGINS.evil.host, "/login", "https"), false, `${channel}: nothing moves by itself`);
      await session.content(() => /** @type {any} */ (window).navigateFrame());
      await session.waitFor(() => saw(server, ORIGINS.evil.host, "/login", "https"), 15_000, `${channel}: the frame moved to the foreign origin`);
    });
  }
});

test("the_homograph_host_is_served_and_its_a_label_comes_from_the_core", async () => {
  // The host name has a Cyrillic o. Whatever sends or shows it must use the
  // A-label for the connection and may show the Unicode form next to it. The
  // A-label here is the browser's own and the standard's (WHATWG, through Node's
  // idna), which is what the core's display function must return for this host.
  assert.notEqual(HOMOGRAPH_UNICODE_HOST, HOMOGRAPH_A_LABEL_HOST);
  assert.match(HOMOGRAPH_UNICODE_HOST, /[^\x00-\x7f]/, "the Unicode form is not ASCII");
  assert.equal(domainToASCII(HOMOGRAPH_UNICODE_HOST), HOMOGRAPH_A_LABEL_HOST);
  assert.match(HOMOGRAPH_A_LABEL_HOST, /^xn--[a-z0-9-]+\.example\.test$/);

  const server = await fixtures();
  const unicodeUrl = `${server.origin("homograph").replace(HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST)}/`;
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      server.requests.length = 0;
      await session.navigate(unicodeUrl);
      const page = await session.waitFor(async () => {
        const seen = await session.content(readPage);
        return seen.site === "lookalike-homograph" ? seen : false;
      }, 15_000, `${channel}: the homograph page`);
      assert.equal(page.hostname, HOMOGRAPH_A_LABEL_HOST, `${channel}: the browser connects to the A-label`);
      assert.equal(page.origin, server.origin("homograph"), `${channel}: the origin is the A-label origin`);
      const shown = await session.content((/** @type {string} */ unicode) => ({
        note: document.getElementById("host-note")?.textContent ?? null,
        parsed: new URL(`https://${unicode}/`).hostname,
      }), HOMOGRAPH_UNICODE_HOST);
      assert.equal(shown.note, HOMOGRAPH_UNICODE_HOST, `${channel}: the page shows the Unicode form`);
      assert.equal(shown.parsed, HOMOGRAPH_A_LABEL_HOST, `${channel}: the browser's own parser gives the A-label`);
      assert.ok(saw(server, HOMOGRAPH_A_LABEL_HOST, "/", "https"), `${channel}: the server was asked for the A-label host`);
    });
  }
});
