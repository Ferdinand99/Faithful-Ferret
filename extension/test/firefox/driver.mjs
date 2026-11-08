// A thin WebDriver client over geckodriver (HTTP, no dependencies), with the few
// things the extension tests need that WebDriver itself does not give:
//
//  * geckodriver starts Firefox with -remote-allow-system-access (its --allow-system-access), so the session can switch to
//    the chrome context (POST /session/{id}/moz/context) and run scripts in the
//    browser window itself. That is how a test presses a real keyboard shortcut
//    and clicks a real context menu item (so Firefox grants activeTab, which a
//    page of the extension cannot make happen) and terminates the background the
//    way about:debugging does.
//  * The test build is installed permanently in the profile before Firefox
//    starts (profile.mjs), so a restart of the same profile finds it again.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createProfile, FIREFOX_DIRS, profilePrefs, writePolicies } from "./profile.mjs";

/** The key of a web element in the WebDriver wire format. */
export const ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf";

/** @typedef {{ [ELEMENT_KEY]: string }} Element */

/** @param {number} ms */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** @returns {Promise<number>} a free TCP port on the loopback address */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
      server.close(() => resolve(port));
    });
  });
}

/**
 * @param {string} method
 * @param {string} url
 * @param {unknown} [body]
 * @returns {Promise<any>} the `value` of the answer
 */
async function wire(method, url, body) {
  const response = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(180_000),
  });
  const text = await response.text();
  /** @type {any} */
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`webdriver: ${method} ${url}: not JSON (${response.status}): ${text.slice(0, 200)}`);
  }
  const value = json.value;
  if (!response.ok || (value && typeof value === "object" && typeof value.error === "string")) {
    throw new Error(`webdriver: ${method} ${url.replace(/^.*\/session\/[^/]+/, "")}: ${value?.error}: ${value?.message}`);
  }
  return value;
}

/**
 * Serializes a function into an asynchronous script. The function runs in the
 * browser (not here), gets the arguments, may return a promise and may throw.
 * @param {(...args: any[]) => any} fn
 * @returns {string}
 */
function asyncScript(fn) {
  return `const fn = (${fn.toString()});
const done = arguments[arguments.length - 1];
const args = Array.prototype.slice.call(arguments, 0, -1);
Promise.resolve().then(() => fn.apply(null, args)).then(
  (value) => done(value === undefined ? null : value),
  (error) => done({ __ferretError: error && error.message ? error.name + ": " + error.message + " | " + error.stack : String(error) }),
);`;
}

/**
 * The options of startFirefox.
 * @typedef {{
 *   channel: "release" | "esr",
 *   prefs?: Record<string, string | number | boolean>,
 *   headless?: boolean,
 *   addon: string,
 *   hosts?: string[],
 *   certificateFiles?: string[],
 *   profileDir?: string,
 *   firefoxDir?: string,
 *   env?: Record<string, string>,
 * }} StartOptions
 */

/**
 * Starts Firefox under geckodriver with a fresh test profile.
 * @param {StartOptions} options
 * @returns {Promise<Session>}
 */
export async function startFirefox(options) {
  const session = new Session(options);
  await session.launch();
  return session;
}

export class Session {
  /** @param {StartOptions} options */
  constructor(options) {
    if (options.channel !== "release" && options.channel !== "esr") throw new Error(`driver: channel ${options.channel} is not release or esr`);
    if (typeof options.addon !== "string" || options.addon === "") throw new Error("driver: addon (the .xpi to install) is required");
    this.options = options;
    this.channel = options.channel;
    this.profileDir = options.profileDir ?? mkdtempSync(join(tmpdir(), "ferret-profile-"));
    /** @type {string} */
    this.browserVersion = "";
    /** @type {string} */
    this.sessionId = "";
    /** @type {string} */
    this.base = "";
    /** @type {import("node:child_process").ChildProcess | undefined} */
    this.geckodriver = undefined;
    this.log = "";
    this.context = "content";
  }

  /** Writes the profile and policies, starts geckodriver and opens a session. */
  async launch() {
    const { options } = this;
    const firefoxDir = options.firefoxDir ?? FIREFOX_DIRS[this.channel];
    // The profile folder keeps its content over a restart; the add-on is placed only when it is not there yet.
    createProfile({ dir: this.profileDir, xpi: options.addon, prefs: profilePrefs({ hosts: options.hosts, extra: options.prefs }) });
    // Read when Firefox starts, from the files that exist now.
    writePolicies(firefoxDir, options.certificateFiles ?? []);

    const port = await freePort();
    this.log = "";
    const child = spawn("geckodriver", ["--host", "127.0.0.1", "--port", String(port), "--log", "warn", "--allow-system-access"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...options.env },
    });
    this.geckodriver = child;
    /** @param {Buffer} chunk */
    const collect = (chunk) => { this.log = `${this.log}${chunk}`.slice(-200_000); };
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);
    this.base = `http://127.0.0.1:${port}`;
    for (let i = 0; ; i++) {
      try {
        await wire("GET", `${this.base}/status`);
        break;
      } catch (error) {
        if (child.exitCode !== null || i > 100) throw new Error(`driver: geckodriver did not start: ${error}\n${this.log}`);
        await sleep(100);
      }
    }

    const args = ["-profile", this.profileDir, "-no-remote"];
    if (options.headless !== false) args.push("-headless");
    try {
      const value = await wire("POST", `${this.base}/session`, {
        capabilities: {
          alwaysMatch: {
            browserName: "firefox",
            "moz:firefoxOptions": { binary: join(firefoxDir, "firefox"), args, env: options.env ?? {} },
          },
        },
      });
      this.sessionId = value.sessionId;
      this.browserVersion = String(value.capabilities?.browserVersion ?? "");
    } catch (error) {
      await this.#killDriver();
      throw new Error(`${error}\n${this.log.slice(-4000)}`);
    }
    this.context = "content";
    await wire("POST", `${this.#s()}/timeouts`, { script: 120_000, pageLoad: 60_000, implicit: 0 });
  }

  #s() {
    return `${this.base}/session/${this.sessionId}`;
  }

  async #killDriver() {
    const child = this.geckodriver;
    this.geckodriver = undefined;
    if (!child || child.exitCode !== null) return;
    const exited = new Promise((resolve) => child.once("exit", resolve));
    child.kill("SIGTERM");
    await Promise.race([exited, sleep(10_000).then(() => child.kill("SIGKILL"))]);
  }

  /** @param {"content" | "chrome"} context */
  async setContext(context) {
    await wire("POST", `${this.#s()}/moz/context`, { context });
    this.context = context;
  }

  /** @param {string} url */
  async navigate(url) {
    await wire("POST", `${this.#s()}/url`, { url });
  }

  /** @returns {Promise<string>} the handle of the selected tab */
  async windowHandle() {
    return wire("GET", `${this.#s()}/window`);
  }

  /** Opens a tab (in the background) and returns its handle. @returns {Promise<string>} */
  async newTab() {
    const value = await wire("POST", `${this.#s()}/window/new`, { type: "tab" });
    return value.handle;
  }

  /** Makes a tab the selected one, so a shortcut and a click reach it. @param {string} handle */
  async switchTo(handle) {
    await wire("POST", `${this.#s()}/window`, { handle, focus: true });
  }

  async currentUrl() {
    return /** @type {string} */ (await wire("GET", `${this.#s()}/url`));
  }

  /**
   * Runs `fn(...args)` in the browser, in the current context, and returns its
   * value (a promise is awaited; a throw becomes a rejection here).
   * @param {(...args: any[]) => any} fn
   * @param {...any} args
   * @returns {Promise<any>}
   */
  async execute(fn, ...args) {
    const value = await wire("POST", `${this.#s()}/execute/async`, { script: asyncScript(fn), args });
    if (value && typeof value === "object" && "__ferretError" in value) throw new Error(`script: ${value.__ferretError}`);
    return value;
  }

  /**
   * Runs `fn` in the other context and goes back.
   * @param {"content" | "chrome"} context
   * @param {(...args: any[]) => any} fn
   * @param {...any} args
   */
  async #in(context, fn, ...args) {
    const before = this.context;
    if (before !== context) await this.setContext(context);
    try {
      return await this.execute(fn, ...args);
    } finally {
      if (before !== context) await this.setContext(before);
    }
  }

  /** Runs `fn` in the chrome context (the browser window). @param {(...args: any[]) => any} fn @param {...any} args */
  chrome(fn, ...args) {
    return this.#in("chrome", fn, ...args);
  }

  /** Runs `fn` in the content context (the selected tab). @param {(...args: any[]) => any} fn @param {...any} args */
  content(fn, ...args) {
    return this.#in("content", fn, ...args);
  }

  /** @param {string} file path of a PNG */
  async screenshot(file) {
    const before = this.context;
    if (before !== "content") await this.setContext("content");
    try {
      const png = await wire("GET", `${this.#s()}/screenshot`);
      writeFileSync(file, Buffer.from(png, "base64"));
    } finally {
      if (before !== "content") await this.setContext(before);
    }
  }

  /** @param {string} css @returns {Promise<Element[]>} */
  async findAll(css) {
    return wire("POST", `${this.#s()}/elements`, { using: "css selector", value: css });
  }

  /** @param {Element} el */
  async click(el) {
    await wire("POST", `${this.#s()}/element/${el[ELEMENT_KEY]}/click`, {});
  }

  /** @param {Element} el @param {string} text */
  async type(el, text) {
    await wire("POST", `${this.#s()}/element/${el[ELEMENT_KEY]}/value`, { text });
  }

  /**
   * Polls `fn` (here, not in the browser) until it returns something truthy.
   * @template T
   * @param {() => T | Promise<T>} fn
   * @param {number} [timeoutMs]
   * @param {string} [what] named in the error
   * @returns {Promise<Awaited<T>>}
   */
  async waitFor(fn, timeoutMs = 10_000, what = "condition") {
    const deadline = Date.now() + timeoutMs;
    /** @type {unknown} */
    let last;
    for (;;) {
      try {
        const value = await fn();
        if (value) return value;
        last = undefined;
      } catch (error) {
        last = error;
      }
      if (Date.now() > deadline) throw new Error(`waitFor: ${what} did not hold within ${timeoutMs} ms${last ? `: ${last}` : ""}`);
      await sleep(100);
    }
  }

  /**
   * Presses a keyboard shortcut in the browser window, as a keyboard would
   * (chrome context): "Alt+Shift+F9", "Ctrl+Shift+Y".
   * @param {string} keys modifiers and one key, joined by +
   */
  async pressShortcut(keys) {
    await this.chrome((/** @type {string} */ spec) => {
      const win = Services.wm.getMostRecentWindow("navigator:browser");
      const parts = spec.split("+");
      const name = parts.pop() ?? "";
      /** @type {Record<string, { key: string, code: string, keyCode: number, flag: string }>} */
      const modifierKeys = {
        alt: { key: "Alt", code: "AltLeft", keyCode: 18, flag: "altKey" },
        ctrl: { key: "Control", code: "ControlLeft", keyCode: 17, flag: "ctrlKey" },
        control: { key: "Control", code: "ControlLeft", keyCode: 17, flag: "ctrlKey" },
        shift: { key: "Shift", code: "ShiftLeft", keyCode: 16, flag: "shiftKey" },
        meta: { key: "Meta", code: "MetaLeft", keyCode: 91, flag: "metaKey" },
      };
      const modifiers = parts.map((part) => {
        const found = modifierKeys[part.toLowerCase()];
        if (!found) throw new Error(`unknown modifier ${part}`);
        return found;
      });
      const upper = name.toUpperCase();
      const keyCode = win.KeyboardEvent[`DOM_VK_${upper}`];
      if (typeof keyCode !== "number") throw new Error(`unknown key ${name}`);
      const printable = upper.length === 1;
      const flags = Object.fromEntries(modifiers.map((m) => [m.flag, true]));
      const tip = Cc["@mozilla.org/text-input-processor;1"].createInstance(Ci.nsITextInputProcessor);
      tip.beginInputTransactionForTests(win);
      win.focus();
      const down = [];
      for (const m of modifiers) {
        down.push(m);
        tip.keydown(new win.KeyboardEvent("", { key: m.key, code: m.code, keyCode: m.keyCode, ...Object.fromEntries(down.map((d) => [d.flag, true])) }));
      }
      const event = new win.KeyboardEvent("", {
        key: printable ? (flags.shiftKey ? upper : upper.toLowerCase()) : upper,
        code: printable ? (/[0-9]/.test(upper) ? `Digit${upper}` : `Key${upper}`) : upper,
        keyCode,
        ...flags,
      });
      const keyFlags = printable ? 0 : tip.KEY_NON_PRINTABLE_KEY;
      tip.keydown(event, keyFlags);
      tip.keyup(event, keyFlags);
      for (const m of modifiers.reverse()) {
        down.pop();
        tip.keyup(new win.KeyboardEvent("", { key: m.key, code: m.code, keyCode: m.keyCode, ...Object.fromEntries(down.map((d) => [d.flag, true])) }));
      }
    }, keys);
  }

  /**
   * Opens the context menu on the element that `target` (a CSS selector) names, in
   * the selected tab, and clicks the item with `label` (chrome context).
   * @param {string} label
   * @param {string} target
   */
  async clickContextMenuItem(label, target) {
    const before = this.context;
    if (before !== "content") await this.setContext("content");
    try {
      await this.execute((/** @type {string} */ css) => document.querySelector(css)?.scrollIntoView({ block: "center" }), target);
      const [element] = await this.findAll(target);
      if (!element) throw new Error(`no element for ${target}`);
      // A right click through the WebDriver actions: Firefox makes the same trusted contextmenu event as for a person.
      await wire("POST", `${this.#s()}/actions`, {
        actions: [{
          type: "pointer",
          id: "mouse",
          parameters: { pointerType: "mouse" },
          actions: [
            { type: "pointerMove", origin: element, x: 0, y: 0 },
            { type: "pointerDown", button: 2 },
            { type: "pointerUp", button: 2 },
          ],
        }],
      });
      await wire("DELETE", `${this.#s()}/actions`);
    } finally {
      if (before !== "content") await this.setContext(before);
    }
    await this.chrome(async (/** @type {string} */ wanted) => {
      const win = Services.wm.getMostRecentWindow("navigator:browser");
      const popup = win.document.getElementById("contentAreaContextMenu");
      for (let i = 0; popup.state !== "open"; i++) {
        if (i > 100) throw new Error("the context menu did not open");
        await new Promise((resolve) => win.setTimeout(resolve, 100));
      }
      const items = [...popup.querySelectorAll("menuitem")];
      const item = items.find((i) => i.getAttribute("label") === wanted);
      if (!item) {
        popup.hidePopup();
        throw new Error(`no menu item ${wanted}; there are: ${items.map((i) => i.getAttribute("label")).join(" | ")}`);
      }
      popup.activateItem(item);
    }, label);
  }

  /**
   * What the add-on manager says about an add-on and where its pages live.
   * @param {string} id
   */
  async addonInfo(id) {
    return this.chrome(async (/** @type {string} */ addonId) => {
      const { AddonManager } = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
      const addon = await AddonManager.getAddonByID(addonId);
      if (!addon) return null;
      const policy = WebExtensionPolicy.getByID(addonId);
      return {
        id: addon.id,
        name: addon.name,
        version: addon.version,
        active: addon.isActive,
        temporary: Boolean(addon.temporarilyInstalled),
        signedState: addon.signedState,
        uuid: policy ? policy.mozExtensionHostname : null,
        backgroundState: policy?.extension ? policy.extension.backgroundState ?? null : null,
      };
    }, id);
  }

  /**
   * Ends the background of an add-on the way the Terminate button of
   * about:debugging does (chrome context). Returns the state afterwards.
   * @param {string} addonId
   */
  async terminateBackground(addonId) {
    return this.chrome(async (/** @type {string} */ id) => {
      const policy = WebExtensionPolicy.getByID(id);
      const extension = policy?.extension;
      if (!extension) throw new Error(`no extension ${id}`);
      await extension.terminateBackground({ ignoreDevToolsAttached: true });
      return extension.backgroundState ?? null;
    }, addonId);
  }

  /** Ends Firefox and starts it again on the same profile. */
  async restart() {
    await this.quit({ keepProfile: true });
    await this.launch();
  }

  /** Ends the session and Firefox, and removes the profile unless told to keep it. @param {{ keepProfile?: boolean }} [options] */
  async quit({ keepProfile = false } = {}) {
    if (this.sessionId) {
      try {
        await wire("DELETE", this.#s());
      } catch {
        // geckodriver is killed below
      }
      this.sessionId = "";
    }
    await this.#killDriver();
    if (!keepProfile && !this.options.profileDir) rmSync(this.profileDir, { recursive: true, force: true });
  }
}
