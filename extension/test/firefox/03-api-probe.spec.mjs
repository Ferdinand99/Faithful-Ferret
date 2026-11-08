// What the Firefox extension plan relies on: does each API exist, does it work,
// and in which Firefox? One probe per row of docs/EXTENSION-FIREFOX.md, run in the
// unbranded Release and in ESR, for both manifest versions. The probes are short
// (about a minute and a half for each channel and manifest version) and run with
// every Firefox probe run and in CI.
//
// The test reports every row (one `probe-row {json}` line each on stderr, and a
// JSON file when FERRET_PROBE_OUT is set) and fails when a row is missing or when
// a probe itself broke. A row that says "absent" or "fails" is a result, not a
// failure of the test: that is what the probe is for, and the document says what
// the plan does when an API is missing.
//
// Statuses: works, partial (works with a limit the detail names), absent (the API
// is not there), fails (it is there and does not do what the plan needs),
// not_applicable (the row is about the other manifest version), error (the probe
// broke; the test fails).
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { packZip, readZip } from "../../scripts/lib/archive.mjs";
import {
  channels, EXTENSION_ORIGIN, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID, TEST_SHORTCUT, xpiPath,
} from "./harness.mjs";
import { MEASURE_URL, portCommand } from "./measure.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";

after(() => stopFixtures());

/** Every row of the document's tables. A run that lacks one fails. */
export const ROWS = Object.freeze([
  "firefox.version",
  "install.permanent",
  "manifest.data_collection_permissions",
  "storage.session",
  "storage.session.setAccessLevel",
  "runtime.sender.origin",
  "webNavigation.getAllFrames.documentId",
  "tabs.sendMessage.documentId",
  "optional_host_permissions",
  "permissions.request.from_tab",
  "permissions.auto_grant_pref",
  "menus.getTargetElement",
  "action.openPopup.from_command",
  "idle.onStateChanged.locked",
  "wasm.module_workers_under_csp",
  "wasm.instantiate_under_csp",
  "trusted_types",
  "navigator.locks",
  "clipboard.writeText.background",
  "scripting.executeScript.opaque_frames",
  "options_ui.open_in_tab_true",
  "options_ui.embedded_in_about_addons",
  "chrome_context.shortcut",
  "chrome_context.context_menu",
  "chrome_context.terminate_background",
]);

const MANIFESTS = /** @type {const} */ (["mv3", "mv2"]);
const OUT = process.env.FERRET_PROBE_OUT;

/** The message of an error, short and on one line. @param {unknown} error */
const brief = (error) => String(/** @type {Error} */ (error)?.message ?? error).replace(/\s+/g, " ").slice(0, 300);

/**
 * Runs one row's probe. A throw is an "error" row (the probe broke), not a result.
 * @param {any[]} rows
 * @param {{ channel: string, manifest: string, firefox: () => string }} ctx
 * @param {string} name
 * @param {() => Promise<{ status: string, detail?: unknown }>} body
 */
async function row(rows, ctx, name, body) {
  /** @type {{ status: string, detail?: unknown }} */
  let result;
  try {
    result = await body();
  } catch (error) {
    result = { status: "error", detail: brief(error) };
  }
  const entry = { row: name, channel: ctx.channel, manifest: ctx.manifest, firefox: ctx.firefox(), ...result };
  rows.push(entry);
  console.error(`probe-row ${JSON.stringify(entry)}`);
}

/** @param {import("./driver.mjs").Session} session @param {string} id */
const waitForAddOn = (session, id = TEST_ADDON_ID) => session.waitFor(async () => (await session.addonInfo(id))?.active, 30_000, "the add-on");

/** The rows that open the options page: inside about:addons (the manifest's value) and in a tab (the same build with open_in_tab true). */
async function optionsRows(rows, ctx, /** @type {"release" | "esr"} */ channel, /** @type {"mv3" | "mv2"} */ manifest) {
  /**
   * @param {string | undefined} addon
   * @param {boolean} expectTab
   */
  const probe = async (addon, expectTab) => {
    const session = await launch({ channel, manifest, addon });
    try {
      await waitForAddOn(session);
      const bridgeTab = await session.windowHandle();
      const bridge = await openBridge(session);
      await session.execute(() => browser.storage.local.remove("probe_whoami_options"));
      const opened = await session.execute(async () => {
        const options = browser.runtime.getManifest().options_ui;
        await browser.runtime.openOptionsPage();
        return { options_ui: options ?? null };
      });
      const stored = await session.waitFor(async () => (await bridge.invoke("storage.local.get", "probe_whoami_options")).probe_whoami_options, 30_000, "the options page's answer");
      const handles = await session.windowHandles();
      const other = handles.find((h) => h !== bridgeTab);
      let tabUrl = null;
      if (other) {
        await session.switchTo(other);
        tabUrl = await session.currentUrl();
        await session.switchTo(bridgeTab);
      }
      const inTab = typeof tabUrl === "string" && tabUrl.startsWith(`${EXTENSION_ORIGIN}/`);
      const detail = { options_ui: opened.options_ui, tabUrl, inTab, isUiPort: stored.isUiPort, isTopLevel: stored.isTopLevel, sender: stored.sender };
      if (inTab !== expectTab) return { status: "fails", detail };
      // The router takes the page (a top-level extension page) or turns it away: either way it is a fact the plan needs.
      return { status: stored.isUiPort === true ? "works" : "fails", detail };
    } finally {
      await session.quit();
    }
  };
  await row(rows, ctx, "options_ui.embedded_in_about_addons", () => probe(undefined, false));
  await row(rows, ctx, "options_ui.open_in_tab_true", async () => {
    const files = readZip(readFileSync(xpiPath(manifest)));
    const parsed = JSON.parse(/** @type {Buffer} */ (files.get("manifest.json")).toString("utf8"));
    parsed.options_ui.open_in_tab = true;
    files.set("manifest.json", Buffer.from(`${JSON.stringify(parsed, null, 2)}\n`));
    const dir = mkdtempSync(join(tmpdir(), "ferret-optionstab-"));
    const file = join(dir, `options-tab-${manifest}.xpi`);
    writeFileSync(file, packZip(files));
    return probe(file, true);
  });
}

/**
 * Every row for one channel and manifest version.
 * @param {"release" | "esr"} channel
 * @param {"mv3" | "mv2"} manifest
 * @returns {Promise<any[]>}
 */
async function probeAll(channel, manifest) {
  /** @type {any[]} */
  const rows = [];
  let version = "";
  const ctx = { channel, manifest, firefox: () => version };
  const server = await fixtures();
  const session = await launch({ channel, manifest });
  try {
    version = session.browserVersion;
    await waitForAddOn(session);
    const bridgeTab = await session.windowHandle();
    const bridge = await openBridge(session);

    /** Runs `body` in the bridge tab and goes back to the tab that was selected. @template T @param {string} back @param {() => Promise<T>} body */
    const fromBridge = async (back, body) => {
      await session.switchTo(bridgeTab);
      try {
        return await body();
      } finally {
        await session.switchTo(back);
      }
    };

    await row(rows, ctx, "firefox.version", async () => {
      const info = await session.chrome(() => ({
        version: Services.appinfo.version,
        name: Services.appinfo.name,
        build: Services.appinfo.appBuildID,
        channel: Services.prefs.getCharPref("app.update.channel", ""),
      }));
      return { status: info.version === version ? "works" : "fails", detail: info };
    });

    // ------------------------------------------------------------ storage.session
    await row(rows, ctx, "storage.session", async () => {
      const out = await session.execute(async () => {
        const area = browser.storage.session;
        if (!area) return { present: false };
        await area.set({ probe: 1 });
        const got = await area.get("probe");
        await area.remove("probe");
        return { present: true, roundTrip: got.probe === 1, quotaBytes: area.QUOTA_BYTES ?? null };
      });
      return { status: out.present ? (out.roundTrip ? "works" : "fails") : "absent", detail: out };
    });
    await row(rows, ctx, "storage.session.setAccessLevel", async () => {
      const out = await session.execute(async () => {
        const area = browser.storage.session;
        if (!area || typeof area.setAccessLevel !== "function") return { present: false };
        await area.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
        return { present: true };
      });
      return { status: out.present ? "works" : "absent", detail: { ...out, note: "without setAccessLevel the area is for trusted contexts only (the content-script access is in runtime.sender.origin)" } };
    });

    // ------------------------------------------------- WebAssembly, workers, Trusted Types, locks
    // The driver runs its scripts in a sandbox, not in the page's own realm, so the page's CSP does
    // not apply to what they run directly (a control showed eval working there). What the plan's code
    // really does (WebAssembly and module workers) happens in the background page, which has the
    // CSP, and is proven by the core operations below. The page-level checks here are for APIs that
    // belong to the window itself.
    const page = await session.execute(async () => {
      /** @param {() => unknown} fn */
      const attempt = async (fn) => {
        try {
          return { ok: true, value: await fn() };
        } catch (error) {
          return { ok: false, error: `${error && error.name}: ${String(error && error.message).slice(0, 120)}` };
        }
      };
      const out = /** @type {Record<string, any>} */ ({});
      out.trustedTypes = await attempt(() => {
        if (typeof trustedTypes === "undefined") return { present: false };
        trustedTypes.createPolicy(`probe-${Math.random().toString(36).slice(2)}`, {});
        return { present: true, createPolicy: true };
      });
      out.locks = await attempt(async () => {
        if (!navigator.locks) return { present: false };
        return { present: true, value: await navigator.locks.request("ferret-probe", async () => "held") };
      });
      return out;
    });
    const background = await portCommand(session, { cmd: "probe" });
    const core = await portCommandCall(session, "ping", undefined);
    const bench = await portCommandCall(session, "argon2_bench", { m_kib: 65_536, t: 3, p: 1 });

    await row(rows, ctx, "wasm.instantiate_under_csp", async () => {
      // The CSP is in force in the background page (eval throws there), and the core's WASM still starts there.
      const cspInForce = typeof background.evalBlocked === "string";
      return {
        status: cspInForce && core.ok === true && bench.ok === true ? "works" : "fails",
        detail: { background_eval_is_blocked_by: background.evalBlocked, background_core_ping: core },
      };
    });
    await row(rows, ctx, "wasm.module_workers_under_csp", async () => ({
      status: core.ok === true && bench.ok === true ? "works" : "fails",
      detail: {
        vault_module_worker_started_by_background_ping: core.ok === true,
        job_module_worker_started_by_background_argon2: bench.ok ? { ms: bench.value.ms } : bench,
        manifest_csp: (await bridgeCall(session, bridgeTab, bridge, "runtime.getManifest")).content_security_policy,
      },
    }));
    await row(rows, ctx, "trusted_types", async () => ({
      status: background.trustedTypes === "object" && page.trustedTypes.ok && page.trustedTypes.value?.present ? "works" : background.trustedTypes === "object" ? "partial" : "absent",
      detail: { background: background.trustedTypes, extension_page: page.trustedTypes },
    }));
    await row(rows, ctx, "navigator.locks", async () => {
      const held = await portCommand(session, { cmd: "locks" });
      return { status: page.locks.ok && page.locks.value?.value === "held" && held?.ok === true ? "works" : "fails", detail: { extension_page: page.locks, background_request: held } };
    });

    // ------------------------------------------------------ the background page's own view
    await row(rows, ctx, "clipboard.writeText.background", async () => {
      const text = `ferret-probe-${Math.random().toString(36).slice(2, 10)}`;
      if (background.clipboardWriteText !== "function") return { status: "absent", detail: background };
      const written = await portCommand(session, { cmd: "clipboard", text });
      if (!written.ok) return { status: "fails", detail: { write: written.error } };
      const read = await session.chrome((/** @type {string} */ want) => {
        try {
          const trans = Cc["@mozilla.org/widget/transferable;1"].createInstance(Ci.nsITransferable);
          trans.init(null);
          trans.addDataFlavor("text/plain");
          try {
            Services.clipboard.getData(trans, Ci.nsIClipboard.kGlobalClipboard, null);
          } catch {
            Services.clipboard.getData(trans, Ci.nsIClipboard.kGlobalClipboard);
          }
          const data = {};
          trans.getTransferData("text/plain", data);
          const got = data.value.QueryInterface(Ci.nsISupportsString).data;
          return { got, same: got === want };
        } catch (error) {
          return { error: String(error).slice(0, 200) };
        }
      }, text);
      return { status: read.same ? "works" : "partial", detail: { write: written, read } };
    });

    await row(rows, ctx, "idle.onStateChanged.locked", async () => {
      const api = await session.execute(async () => ({
        onStateChanged: typeof browser.idle?.onStateChanged?.addListener,
        queryState: typeof browser.idle?.queryState,
        state: await browser.idle.queryState(60),
      }));
      const source = await session.chrome(async () => {
        const win = Services.wm.getMostRecentWindow("navigator:browser");
        for (const url of ["chrome://extensions/content/parent/ext-idle.js", "resource://gre/modules/ExtensionIdle.sys.mjs"]) {
          try {
            const text = await (await win.fetch(url)).text();
            return {
              url,
              mentionsLocked: /locked/i.test(text),
              lines: text.split("\n").filter((l) => /locked/i.test(l)).slice(0, 6).map((l) => l.trim().slice(0, 160)),
            };
          } catch {
            // try the next place
          }
        }
        return { url: null, mentionsLocked: false, lines: [] };
      });
      // The locked state cannot be made to happen in a headless test; the source of the API says whether Firefox reports it.
      const status = api.onStateChanged !== "function" ? "absent" : source.mentionsLocked ? "partial" : "absent";
      return { status, detail: { api, source, note: "event delivery for the locked state is not reproducible headless; verified by the source of the API and by the user's own Firefox" } };
    });

    // ---------------------------------------- activeTab from a real shortcut and a real menu click
    /** Listeners in the bridge page: the popup call from the command, and what the menu click carried. */
    await session.execute(() => {
      browser.commands.onCommand.addListener((_name, tab) => {
        const api = browser.action ?? browser.browserAction;
        const rec = /** @type {Record<string, unknown>} */ ({ tabId: tab?.id ?? null, api: browser.action ? "action" : "browserAction" });
        let pending;
        try {
          pending = api.openPopup();
        } catch (error) {
          rec.error = String(error && error.message).slice(0, 200);
        }
        Promise.resolve(pending).then(
          () => { rec.ok = true; },
          (error) => { rec.error = String(error && error.message).slice(0, 200); },
        ).finally(() => browser.storage.local.set({ probe_openpopup: rec }));
      });
      browser.menus.onClicked.addListener((info) => {
        browser.storage.local.set({ probe_menu: { targetElementId: info.targetElementId ?? null, frameId: info.frameId ?? null, menuItemId: info.menuItemId } });
      });
    });
    await bridge.clearEvents();
    await session.execute(() => browser.storage.local.remove(["probe_openpopup", "probe_menu"]));

    const framesTab = await session.newTab();
    await session.switchTo(framesTab);
    await session.navigate(server.url(server.hosts[0], "/static/frames.html"));
    await session.waitFor(() => session.findAll("#top").then((found) => found.length === 1), 15_000, "the frames page");

    // A real shortcut: the command runs with activeTab on this tab.
    let command;
    await row(rows, ctx, "chrome_context.shortcut", async () => {
      await session.pressShortcut(TEST_SHORTCUT);
      command = await session.waitFor(async () => (await fromBridge(framesTab, () => bridge.events())).find((e) => e.kind === "command"), 15_000, "the command event");
      return { status: command.tabUrl === server.url(server.hosts[0], "/static/frames.html") ? "works" : "fails", detail: { tabId: command.tabId, sawTheTabAddress: command.tabUrl !== null } };
    });
    const tabId = /** @type {number} */ (command?.tabId);

    await row(rows, ctx, "action.openPopup.from_command", async () => {
      const rec = await session.waitFor(async () => (await fromBridge(framesTab, () => bridge.invoke("storage.local.get", "probe_openpopup"))).probe_openpopup, 15_000, "the openPopup result");
      return { status: rec.ok ? "works" : rec.error ? "fails" : "partial", detail: rec };
    });

    /** What the extension can do on the tab it has activeTab for. */
    const flow = await fromBridge(framesTab, () => session.execute(async (/** @type {number} */ id) => {
      const out = /** @type {Record<string, any>} */ ({});
      const brief = (/** @type {any} */ error) => String(error && error.message).replace(/\s+/g, " ").slice(0, 160);
      const frames = await browser.webNavigation.getAllFrames({ tabId: id });
      out.frames = frames.map((f) => ({ frameId: f.frameId, parentFrameId: f.parentFrameId, url: f.url, documentId: f.documentId ?? null, documentLifecycle: f.documentLifecycle ?? null }));
      out.inject = [];
      for (const f of frames) {
        try {
          const result = await browser.scripting.executeScript({
            target: { tabId: id, frameIds: [f.frameId] },
            func: () => ({ origin: self.origin, href: location.href, top: window === window.top }),
          });
          out.inject.push({ frameId: f.frameId, url: f.url, ok: true, result: result[0]?.result ?? null, documentId: result[0]?.documentId ?? null });
        } catch (error) {
          out.inject.push({ frameId: f.frameId, url: f.url, ok: false, error: brief(error) });
        }
      }
      try {
        const area = await browser.scripting.executeScript({ target: { tabId: id, frameIds: [0] }, func: () => ({ storage_session: typeof browser.storage?.session, storage_local: typeof browser.storage?.local }) });
        out.contentStorage = area[0]?.result ?? null;
      } catch (error) {
        out.contentStorage = { error: brief(error) };
      }
      try {
        const sent = await browser.scripting.executeScript({ target: { tabId: id, frameIds: [0] }, func: () => browser.runtime.sendMessage({ ferretProbe: "sender" }) });
        out.contentSender = sent[0]?.result ?? null;
      } catch (error) {
        out.contentSender = { error: brief(error) };
      }
      try {
        await browser.scripting.executeScript({
          target: { tabId: id, frameIds: [0] },
          func: () => {
            browser.runtime.onMessage.addListener((m) => (m && m.ferretPing ? Promise.resolve({ pong: m.ferretPing, href: location.href }) : undefined));
            return true;
          },
        });
      } catch (error) {
        out.listener = { error: brief(error) };
      }
      // Each call on its own: an option that a Firefox does not know throws at once, and that must not hide the other result.
      try {
        out.sendByFrameId = await browser.tabs.sendMessage(id, { ferretPing: "frame" }, { frameId: 0 });
      } catch (error) {
        out.sendByFrameId = { error: brief(error) };
      }
      const top = frames.find((f) => f.frameId === 0);
      try {
        out.sendByDocumentId = top?.documentId
          ? await browser.tabs.sendMessage(id, { ferretPing: "doc" }, { documentId: top.documentId })
          : { error: "the frame has no documentId" };
      } catch (error) {
        out.sendByDocumentId = { error: brief(error) };
      }
      return out;
    }, tabId));

    await row(rows, ctx, "runtime.sender.origin", async () => {
      const answer = await fromBridge(framesTab, () => session.execute(() => new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-test-whoami" });
        const timer = setTimeout(() => reject(new Error("no answer")), 10_000);
        port.onMessage.addListener((a) => { clearTimeout(timer); port.disconnect(); resolve(a); });
      })));
      const page = answer.sender.origin;
      const content = flow.contentSender?.sender?.origin;
      const ok = page === EXTENSION_ORIGIN && content === new URL(server.url(server.hosts[0], "/")).origin;
      return { status: ok ? "works" : page || content ? "partial" : "absent", detail: { extensionPage: page, contentScript: content ?? flow.contentSender, contentSender: flow.contentSender?.contentSender, contentScriptSees: flow.contentStorage } };
    });
    await row(rows, ctx, "webNavigation.getAllFrames.documentId", async () => {
      const ids = flow.frames.map((/** @type {any} */ f) => f.documentId);
      const all = ids.every((/** @type {unknown} */ id) => typeof id === "string" && id !== "");
      return { status: all ? "works" : ids.some((/** @type {unknown} */ id) => typeof id === "string") ? "partial" : "absent", detail: { frames: flow.frames } };
    });
    await row(rows, ctx, "tabs.sendMessage.documentId", async () => {
      const byDoc = flow.sendByDocumentId;
      const works = byDoc?.pong === "doc";
      return { status: works ? "works" : "fails", detail: { byFrameId: flow.sendByFrameId, byDocumentId: byDoc } };
    });
    await row(rows, ctx, "scripting.executeScript.opaque_frames", async () => {
      /** @param {string} url */
      const kind = (url) => (url === "about:srcdoc" ? "srcdoc" : url === "about:blank" ? "about_blank" : url.endsWith("/static/blank.html") ? "sandboxed_no_same_origin" : url.endsWith("/static/login.html") ? "same_origin" : url.endsWith("/static/frames.html") ? "top" : "other");
      const frames = flow.inject.map((/** @type {any} */ f) => ({ kind: kind(f.url), url: f.url, injected: f.ok, origin: f.result?.origin ?? null, error: f.error ?? null }));
      const opaque = frames.filter((/** @type {{ kind: string }} */ f) => ["srcdoc", "about_blank", "sandboxed_no_same_origin"].includes(f.kind));
      const sandboxed = frames.find((/** @type {{ kind: string }} */ f) => f.kind === "sandboxed_no_same_origin");
      // works: Firefox refuses the frame with the opaque origin itself; partial: it injects, and the page's self.origin is "null"
      // (the plan refuses it by that, and by the frame URL for the about: frames, which inherit the parent's origin).
      return {
        status: opaque.length === 3 ? (sandboxed?.injected ? "partial" : "works") : "error",
        detail: { frames, note: "srcdoc and about:blank frames are injected and report the parent's origin; the sandboxed frame is refused (works) or injected with origin 'null' (partial)" },
      };
    });

    // A real context menu click on the top frame's input.
    await row(rows, ctx, "chrome_context.context_menu", async () => {
      const title = await fromBridge(framesTab, () => session.content(() => window.ferretBridge.menuTitle));
      await session.clickContextMenuItem(title, "#top");
      const menu = await session.waitFor(async () => (await fromBridge(framesTab, () => bridge.invoke("storage.local.get", "probe_menu"))).probe_menu, 15_000, "the menu click");
      return { status: menu.menuItemId === "ferret-test-menu-item" ? "works" : "fails", detail: menu };
    });
    await row(rows, ctx, "menus.getTargetElement", async () => {
      const menu = (await fromBridge(framesTab, () => bridge.invoke("storage.local.get", "probe_menu"))).probe_menu;
      if (!menu) return { status: "error", detail: "no menu click was recorded" };
      const out = await fromBridge(framesTab, () => session.execute(async (/** @type {number} */ id, /** @type {string | number | null} */ target, /** @type {number} */ frameId) => {
        try {
          const result = await browser.scripting.executeScript({
            target: { tabId: id, frameIds: [frameId] },
            func: (/** @type {string | number | null} */ targetId) => {
              if (typeof browser.menus?.getTargetElement !== "function") return { present: false };
              const element = browser.menus.getTargetElement(/** @type {any} */ (targetId));
              return { present: true, found: element !== null && element !== undefined, tag: element ? element.tagName : null, id: element ? element.id : null };
            },
            args: [target],
          });
          return result[0]?.result ?? null;
        } catch (error) {
          return { error: String(error && error.message).slice(0, 200) };
        }
      }, tabId, menu.targetElementId, menu.frameId ?? 0));
      const status = out?.error ? "fails" : out?.present === false ? "absent" : out?.found && out.id === "top" ? "works" : "fails";
      return { status, detail: { click: menu, element: out } };
    });

    // ------------------------------------ optional host permissions, asked from a tab with a click
    await row(rows, ctx, "permissions.request.from_tab", async () => {
      const tab = await session.newTab();
      await session.switchTo(tab);
      await session.navigate(MEASURE_URL);
      await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 30_000, "the measure page");
      const origin = new URL(server.url(server.hosts[0], "/")).origin;
      const before = await session.execute(async (/** @type {string} */ o) => browser.permissions.contains({ origins: [`${o}/*`] }), origin);
      await session.execute((/** @type {string} */ value) => { /** @type {HTMLInputElement} */ (document.getElementById("url")).value = value; }, server.url(server.hosts[0], "/sse"));
      const [grant] = await session.findAll("#grant");
      await session.click(grant);
      const outcome = await session.waitFor(() => session.content(() => document.documentElement.dataset.granted), 20_000, "the answer to permissions.request").catch(() => "timeout");
      const pageStatus = await session.content(() => document.documentElement.dataset.status ?? null);
      const after = await session.execute(async (/** @type {string} */ o) => ({
        contains: await browser.permissions.contains({ origins: [`${o}/*`] }),
        all: await browser.permissions.getAll(),
      }), origin);
      await session.closeTab();
      await session.switchTo(framesTab);
      probeState.granted = outcome === "1";
      probeState.before = before;
      probeState.after = after;
      return {
        status: outcome === "1" && after.contains ? "works" : outcome === "timeout" ? "fails" : "fails",
        detail: { origin, containedBefore: before, answer: outcome, pageStatus, containedAfter: after.contains, allowedOrigins: after.all.origins },
      };
    });
    await row(rows, ctx, "permissions.auto_grant_pref", async () => {
      const pref = await session.chrome(() => ({
        name: "extensions.webextOptionalPermissionPrompts",
        type: Services.prefs.getPrefType("extensions.webextOptionalPermissionPrompts"),
        value: Services.prefs.getBoolPref("extensions.webextOptionalPermissionPrompts", true),
        userSet: Services.prefs.prefHasUserValue("extensions.webextOptionalPermissionPrompts"),
      }));
      // The pref is the right one when the request was answered without a prompt while it is false.
      return { status: probeState.granted && pref.value === false ? "works" : "fails", detail: { pref, requestGranted: probeState.granted } };
    });
    await row(rows, ctx, "optional_host_permissions", async () => {
      if (manifest === "mv2") return { status: "not_applicable", detail: "MV2 lists origins in optional_permissions (the build folds them)" };
      const manifestJson = await bridgeCall(session, bridgeTab, bridge, "runtime.getManifest");
      const listed = manifestJson.optional_host_permissions ?? null;
      const ok = Array.isArray(listed) && listed.includes("https://*/*") && probeState.before === false && probeState.after?.contains === true;
      return { status: ok ? "works" : "fails", detail: { optional_host_permissions: listed, granted_after_request: probeState.after?.contains ?? null } };
    });
    await row(rows, ctx, "manifest.data_collection_permissions", async () => {
      const manifestJson = await bridgeCall(session, bridgeTab, bridge, "runtime.getManifest");
      const wanted = manifestJson.browser_specific_settings?.gecko?.data_collection_permissions;
      const all = await bridgeCall(session, bridgeTab, bridge, "permissions.getAll");
      return {
        status: wanted ? "works" : "fails",
        detail: { declared: wanted ?? null, strict_min_version: manifestJson.browser_specific_settings?.gecko?.strict_min_version ?? null, permissions_getAll_keys: Object.keys(all) },
      };
    });

    // ---------------------------------------------------------------- terminate, then a restart
    await row(rows, ctx, "chrome_context.terminate_background", async () => {
      const before = await session.backgroundState(TEST_ADDON_ID);
      const after = await session.terminateBackground(TEST_ADDON_ID);
      return { status: before === "running" && after !== "running" ? "works" : "fails", detail: { before, after } };
    });
    await row(rows, ctx, "install.permanent", async () => {
      const first = await session.addonInfo(TEST_ADDON_ID);
      await session.restart();
      const again = await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active && (await session.addonInfo(TEST_ADDON_ID)), 30_000, "the add-on after a restart");
      const ok = first.temporary === false && again.temporary === false && again.uuid === first.uuid;
      return { status: ok ? "works" : "fails", detail: { temporary: first.temporary, afterRestart: { active: again.active, temporary: again.temporary, sameUuid: again.uuid === first.uuid }, signedState: first.signedState } };
    });
  } finally {
    await session.quit();
  }

  await optionsRows(rows, ctx, channel, manifest);
  return rows;
}

/** What the permission rows tell each other. */
const probeState = /** @type {{ granted: boolean, before: unknown, after: any }} */ ({ granted: false, before: null, after: null });

/**
 * Calls the bridge page's API from whatever tab is selected: goes to the bridge tab and back.
 * @param {import("./driver.mjs").Session} session
 * @param {string} bridgeTab
 * @param {{ invoke: (api: string, ...args: unknown[]) => Promise<any> }} bridge
 * @param {string} api
 */
async function bridgeCall(session, bridgeTab, bridge, api) {
  const back = await session.windowHandle();
  await session.switchTo(bridgeTab);
  try {
    return await bridge.invoke(api);
  } finally {
    await session.switchTo(back);
  }
}

/**
 * One operation on the core port, from the bridge page.
 * @param {import("./driver.mjs").Session} session
 * @param {string} op
 * @param {unknown} args
 * @returns {Promise<{ ok: boolean, value?: any, code?: string }>}
 */
async function portCommandCall(session, op, args) {
  return session.execute(
    (/** @type {string} */ name, /** @type {unknown} */ params) => new Promise((resolve, reject) => {
      const port = browser.runtime.connect({ name: "ferret-test-core" });
      const timer = setTimeout(() => reject(new Error("no answer")), 60_000);
      port.onMessage.addListener((reply) => { clearTimeout(timer); port.disconnect(); resolve(reply); });
      port.postMessage({ id: "1", op: name, args: params });
    }),
    op,
    args,
  );
}

test("api_probe_reports_every_row", async () => {
  /** @type {any[]} */
  const all = [];
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      probeState.granted = false;
      probeState.before = null;
      probeState.after = null;
      const rows = await probeAll(channel, manifest);
      all.push(...rows);
      const names = rows.map((r) => r.row);
      for (const name of ROWS) assert.ok(names.includes(name), `${channel} ${manifest}: the row ${name} is missing`);
      assert.equal(new Set(names).size, names.length, `${channel} ${manifest}: a row is reported twice`);
      const broken = rows.filter((r) => r.status === "error");
      assert.deepEqual(broken.map((r) => `${r.row}: ${JSON.stringify(r.detail)}`), [], `${channel} ${manifest}: probes that broke`);
      // What the whole extension stands on: WebAssembly and module workers under the extension's CSP.
      for (const name of ["wasm.instantiate_under_csp", "wasm.module_workers_under_csp"]) {
        assert.equal(rows.find((r) => r.row === name)?.status, "works", `${channel} ${manifest}: ${name}: ${JSON.stringify(rows.find((r) => r.row === name)?.detail)}`);
      }
    }
  }
  if (OUT) {
    mkdirSync(OUT, { recursive: true });
    writeFileSync(join(OUT, "api-probe.json"), `${JSON.stringify({ madeAt: new Date().toISOString(), rows: all }, null, 2)}\n`);
  }
  assert.equal(all.length, channels().length * MANIFESTS.length * ROWS.length);
});
