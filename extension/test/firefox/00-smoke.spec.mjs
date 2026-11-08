// Short probes of the harness itself: the pinned Firefox builds start, the test
// build is installed permanently under its fixed UUID, a real shortcut and a real
// menu click reach it, and a web page cannot reach it. Run in the runner image
// with `scripts/lanbox-ext.sh firefox`.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { after, test } from "node:test";
import {
  ABOUT_URL, channels, fixtures, FIXED_UUID, launch, openBridge, pinnedVersions, stopFixtures,
  TEST_ADDON_ID, TEST_COMMAND, TEST_SHORTCUT,
} from "./harness.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";

after(() => stopFixtures());

/**
 * Starts Firefox, runs `body`, and always ends the session.
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

test("firefox_release_and_esr_start_and_report_their_pinned_versions", async () => {
  const pins = pinnedVersions();
  assert.equal(process.versions.node, pins.node, "Node");
  assert.match(execFileSync("geckodriver", ["--version"], { encoding: "utf8" }), new RegExp(`^geckodriver ${pins.geckodriver.replaceAll(".", "\\.")} `));
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      assert.equal(session.browserVersion, pins[channel], `${channel}: version reported to WebDriver`);
      const info = await session.chrome(() => {
        const { AppConstants } = ChromeUtils.importESModule("resource://gre/modules/AppConstants.sys.mjs");
        return {
          version: Services.appinfo.version,
          requireSigning: AppConstants.MOZ_REQUIRE_SIGNING,
          signaturesRequired: Services.prefs.getBoolPref("xpinstall.signatures.required"),
        };
      });
      assert.equal(info.version, pins[channel], `${channel}: version in the browser`);
      // The build allows unsigned add-ons, and the profile says so.
      assert.equal(info.requireSigning, false, `${channel}: build that does not force signatures`);
      assert.equal(info.signaturesRequired, false, `${channel}: signatures not required`);
    });
  }
});

test("the_test_build_is_installed_permanently_and_its_uuid_is_the_fixed_one", async () => {
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      const addon = await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on in the add-on manager");
      assert.equal(addon.id, TEST_ADDON_ID);
      assert.equal(addon.name, "Faithful Ferret (test)");
      assert.equal(addon.active, true, "enabled");
      assert.equal(addon.temporary, false, "not a temporary add-on");
      assert.equal(addon.uuid, FIXED_UUID, "the fixed UUID");
      await session.navigate(ABOUT_URL);
      assert.equal(await session.content(() => document.location.origin), `moz-extension://${FIXED_UUID}`);
      await session.waitFor(() => session.content(() => document.querySelector("h1")?.textContent), 10_000, "the about page");
    });
  }
});

test("the_add_on_survives_a_restart_of_the_profile", async () => {
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      let bridge = await openBridge(session);
      await bridge.invoke("storage.local.set", { marker: `kept-${channel}` });

      await session.restart();

      const addon = await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on after the restart");
      assert.equal(addon.active, true);
      assert.equal(addon.temporary, false);
      assert.equal(addon.uuid, FIXED_UUID);
      bridge = await openBridge(session);
      assert.deepEqual(await bridge.invoke("storage.local.get", "marker"), { marker: `kept-${channel}` });
    });
  }
});

test("the_about_page_loads_and_an_injected_inline_script_is_blocked_by_csp", async () => {
  /** Tries to run an inline script and an inline handler in the current page. */
  const injectInline = () => new Promise((resolve) => {
    const violations = /** @type {string[]} */ ([]);
    document.addEventListener("securitypolicyviolation", (event) => violations.push(event.violatedDirective));
    const script = document.createElement("script");
    script.textContent = "window.__inlineScriptRan = true;";
    document.head.append(script);
    const button = document.createElement("button");
    button.setAttribute("onclick", "window.__inlineHandlerRan = true;");
    document.body.append(button);
    button.click();
    window.setTimeout(() => resolve({
      scriptRan: window.__inlineScriptRan === true,
      handlerRan: window.__inlineHandlerRan === true,
      violations,
    }), 500);
  });

  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      const server = await fixtures();
      // Control: the same injection runs on a page without a CSP, so the probe can fail.
      await session.navigate(server.url(server.hosts[0], "/static/blank.html"));
      const control = await session.content(injectInline);
      assert.equal(control.scriptRan, true, `${channel}: control script ran`);
      assert.equal(control.handlerRan, true, `${channel}: control handler ran`);

      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.navigate(ABOUT_URL);
      await session.waitFor(() => session.content(() => document.querySelector("h1")?.textContent), 10_000, "the about page");
      assert.equal(await session.content(() => document.querySelector("h1")?.textContent), "Faithful Ferret");
      const result = await session.content(injectInline);
      assert.equal(result.scriptRan, false, `${channel}: inline script blocked`);
      assert.equal(result.handlerRan, false, `${channel}: inline handler blocked`);
      assert.ok(result.violations.some((/** @type {string} */ d) => d.startsWith("script-src")), `${channel}: a script-src violation was reported: ${result.violations}`);
    });
  }
});

test("a_page_on_the_fixture_server_cannot_load_any_extension_url", async () => {
  const targets = ["pages/about.html", "manifest.json", "background/compat.mjs", "assets/app.css", "test/bridge.html", "test/bridge.mjs", "locales.en.json"];
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.navigate(server.url(server.hosts[0], "/static/login.html"));
      assert.equal(await session.content(() => document.title), "Fixture sign-in", "the fixture page loaded over trusted https");
      const results = await session.content(async (/** @type {string} */ origin, /** @type {string[]} */ paths) => {
        /** @type {Record<string, Record<string, string>>} */
        const out = {};
        for (const path of paths) {
          const url = `${origin}/${path}`;
          const row = /** @type {Record<string, string>} */ ({});
          const viaElement = (/** @type {HTMLElement} */ element) => new Promise((resolve) => {
            element.addEventListener("load", () => resolve("loaded"));
            element.addEventListener("error", () => resolve("blocked"));
            document.head.append(element);
            window.setTimeout(() => resolve("timeout"), 5000);
          });
          const script = document.createElement("script");
          script.src = url;
          row.script = await viaElement(script);
          const link = document.createElement("link");
          link.rel = "stylesheet";
          link.href = url;
          row.stylesheet = await viaElement(link);
          row.fetch = await window.fetch(url).then(() => "loaded", () => "blocked");
          row.xhr = await new Promise((resolve) => {
            const request = new window.XMLHttpRequest();
            request.addEventListener("load", () => resolve("loaded"));
            request.addEventListener("error", () => resolve("blocked"));
            try {
              request.open("GET", url);
              request.send();
            } catch {
              resolve("blocked");
            }
          });
          out[path] = row;
        }
        const page = window;
        out.apis = { browser: typeof page.browser, chrome: typeof page.chrome, bridge: typeof page.ferretBridge };
        return out;
      }, `moz-extension://${FIXED_UUID}`, targets);
      for (const path of targets) {
        for (const [how, outcome] of Object.entries(results[path])) {
          assert.equal(outcome, "blocked", `${channel}: ${path} via ${how}`);
        }
      }
      assert.deepEqual(results.apis, { browser: "undefined", chrome: "undefined", bridge: "undefined" }, `${channel}: no extension API in the page`);
    });
  }
});

test("chrome_context_can_press_a_shortcut_and_click_a_context_menu_item", async () => {
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const bridgeTab = await session.windowHandle();
      const bridge = await openBridge(session);
      const pageUrl = server.url(server.hosts[0], "/static/login.html");
      const pageTab = await session.newTab();
      await session.switchTo(pageTab);
      await session.navigate(pageUrl);
      await session.waitFor(() => session.findAll("#username").then((found) => found.length === 1), 10_000, "the sign-in form");

      /** Reads what the test variant recorded, from the bridge tab, and goes back to the page. */
      const recorded = async () => {
        await session.switchTo(bridgeTab);
        try {
          return await bridge.events();
        } finally {
          await session.switchTo(pageTab);
        }
      };

      // Control: before the shortcut, the extension cannot see the page's address (it has no tabs permission and no activeTab yet).
      await session.switchTo(bridgeTab);
      const before = await bridge.invoke("tabs.query", {});
      await session.switchTo(pageTab);
      assert.equal(before.length, 2);
      assert.deepEqual(before.filter((/** @type {{ url?: string }} */ tab) => tab.url === undefined).length, 1, `${channel}: one tab without an address`);
      assert.equal(before.some((/** @type {{ url?: string }} */ tab) => tab.url === pageUrl), false, `${channel}: the page's address is hidden`);

      // A real shortcut. The test command saw the page's address, which an extension without the tabs permission sees only under activeTab.
      await session.pressShortcut(TEST_SHORTCUT);
      const commandEvent = await session.waitFor(async () => (await recorded()).find((e) => e.kind === "command"), 10_000, "the command event");
      assert.equal(commandEvent.name, TEST_COMMAND);
      assert.equal(commandEvent.tabUrl, pageUrl, `${channel}: the command was called with activeTab`);

      // A real context menu click on the form field.
      const title = await session.waitFor(async () => {
        await session.switchTo(bridgeTab);
        try {
          return await session.content(() => window.ferretBridge.menuTitle);
        } finally {
          await session.switchTo(pageTab);
        }
      }, 10_000, "the menu title");
      await session.clickContextMenuItem(title, "#username");
      const menuEvent = await session.waitFor(async () => (await recorded()).find((e) => e.kind === "menu"), 10_000, "the menu event");
      assert.equal(menuEvent.menuItemId, "ferret-test-menu-item");
      assert.equal(menuEvent.tabUrl, pageUrl, `${channel}: the menu click came with activeTab`);
    });
  }
});

test("the_mv2_build_installs_too", async () => {
  for (const channel of channels()) {
    await withFirefox({ channel, manifest: "mv2" }, async (session) => {
      const addon = await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      assert.equal(addon.active, true);
      assert.equal(addon.temporary, false);
      assert.equal(addon.uuid, FIXED_UUID);
      const bridge = await openBridge(session);
      const manifest = await bridge.invoke("runtime.getManifest");
      assert.equal(manifest.manifest_version, 2);
      assert.equal(manifest.browser_specific_settings.gecko.id, TEST_ADDON_ID);
      await session.navigate(ABOUT_URL);
      await session.waitFor(() => session.content(() => document.querySelector("h1")?.textContent), 10_000, "the about page");
    });
  }
});

test("the_fixture_server_is_trusted_and_streams_events", async () => {
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      const server = await fixtures();
      for (const host of server.hosts) {
        await session.navigate(server.url(host, "/healthz"));
        assert.equal(await session.content(() => document.body.textContent?.trim()), "ok", `${channel}: ${host}`);
      }
      await session.navigate(server.url(server.hosts[0], "/static/blank.html"));
      const text = await session.content(async (/** @type {string} */ url) => {
        const response = await window.fetch(url);
        const reader = response.body.getReader();
        let text = "";
        while (!text.includes("event: tick")) {
          const { value, done } = await reader.read();
          if (done) break;
          text += new TextDecoder().decode(value);
        }
        await reader.cancel();
        return text;
      }, "/sse");
      assert.match(text, /event: tick\ndata: 1\n/);
    });
  }
});

test("terminate_background_ends_the_background_page", async () => {
  for (const channel of channels()) {
    await withFirefox({ channel }, async (session) => {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const state = await session.terminateBackground(TEST_ADDON_ID);
      assert.notEqual(state, "running", `${channel}: the background is not running right after Terminate`);
    });
  }
});
