// The demo smoke of the passkey matrix (U4-13, the set "demo"): a sign-up and a sign-in with a Ferret passkey at the public demo
// sites, as a person does them, in each channel (plan § 11.3: a failure there gives an issue, not a stop, when the fixtures pass and
// the failure is understood). Not a spec (run.sh picks up *.spec.mjs only); passkeyMatrix.mjs runs it with the Ferret provider.
//
// What a site needs is kept here per site: the field for the user name, the buttons, and the texts that say the sign-up and the
// sign-in worked. A site whose sign-up needs something no test can give (an e-mail code) is reported as not run, with the reason.
// The run never uses a real account: a made-up user name of the run's own (Global Constraint 69).
import { pressInChooser } from "./passkeyMatrix.mjs";

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * @typedef {{
 *   user?: string, register: string, registered: RegExp, login: string, loggedIn: RegExp, failed?: RegExp, before?: string,
 *   unsupported?: string,
 * }} DemoSite
 *   `user` (a CSS selector) gets the user name; `register` and `login` are a CSS selector or `text:<label>` (a button with that
 *   text); `registered`, `loggedIn` and `failed` are read from the page's text; `before` is pressed first when the site has it
 *   (a cookie notice).
 */

/** @type {Readonly<Record<string, DemoSite>>} */
export const DEMO_SITES = Object.freeze({
  "webauthn.io": {
    user: "#input-email",
    register: "#register-button",
    registered: /success!?\s*now try to authenticate/i,
    login: "#login-button",
    loggedIn: /you'?re logged in/i,
    failed: /registration failed|authentication failed|something went wrong/i,
  },
  "webauthn.me": {
    register: "text:Register",
    registered: /registration (?:successful|complete)|credential created|"type":\s*"public-key"/i,
    login: "text:Authenticate",
    loggedIn: /authentication (?:successful|complete)|"authenticatorData"/i,
    failed: /NotAllowedError|SecurityError|failed/i,
  },
  "www.passkeys.io": {
    register: "text:Sign up",
    registered: /never/,
    login: "text:Sign in",
    loggedIn: /never/,
    unsupported: "the sign-up sends a code to an e-mail address, which an automated run cannot read; the sign-in with a passkey needs an account made that way",
  },
});

/**
 * Clicks a control of the page: a CSS selector, or `text:<label>` for the first visible button or link with that text.
 * @param {import("./driver.mjs").Session} session @param {string} what
 */
async function press(session, what) {
  if (what.startsWith("text:")) {
    const label = what.slice(5).toLowerCase();
    const marked = await session.content((/** @type {string} */ text) => {
      // A button before a link of the same text (a page's tab is often a link), and the last one on the page (the form's own).
      const nodes = [...document.querySelectorAll("button, input[type=submit], input[type=button], [role=button], a")].filter((node) => {
        const shown = node.getClientRects().length > 0 && node.closest("[hidden]") === null;
        const name = (node.textContent || /** @type {HTMLInputElement} */ (node).value || "").trim().toLowerCase();
        return shown && name === text;
      });
      const pick = [...nodes].reverse().find((n) => n.tagName !== "A") ?? nodes.at(-1);
      if (!pick) return false;
      pick.scrollIntoView({ block: "center" });
      pick.setAttribute("data-ferret-demo", "go");
      return true;
    }, label);
    if (!marked) throw new Error(`no button "${what.slice(5)}" on the page`);
    const [el] = await session.findAll('[data-ferret-demo="go"]');
    await session.click(el);
    await session.content(() => document.querySelector('[data-ferret-demo="go"]')?.removeAttribute("data-ferret-demo"));
    return;
  }
  const [el] = await session.findAll(what);
  if (!el) throw new Error(`no ${what} on the page`);
  await session.click(el);
}

/** The page's text. @param {import("./driver.mjs").Session} session */
const pageText = (session) => session.content(() => document.body?.innerText ?? "").catch(() => "");

/**
 * One step at the site: press, let Ferret's window be answered as a person would, and wait until the page says it worked or failed.
 * @param {import("./driver.mjs").Session} session @param {string} control @param {RegExp} worked @param {RegExp | undefined} failed
 * @returns {Promise<{ ok: boolean, windows: number, presses: Array<{ kind: string, role: string }>, text: string }>}
 */
async function step(session, control, worked, failed) {
  const main = await session.windowHandle();
  const baseline = new Set(await session.windowHandles());
  /** @type {Set<string>} */
  const pressed = new Set();
  /** @type {Array<{ kind: string, role: string }>} */
  const presses = [];
  let windows = 0;
  await press(session, control);
  const until = Date.now() + 60_000;
  let text = "";
  while (Date.now() < until) {
    await sleep(500);
    const handles = await session.windowHandles().catch(() => /** @type {string[]} */ ([]));
    windows = Math.max(windows, handles.filter((h) => !baseline.has(h)).length);
    if (handles.some((h) => !baseline.has(h) && !pressed.has(h))) presses.push(...(await pressInChooser(session, baseline, pressed, main)));
    text = await pageText(session);
    if (worked.test(text)) return { ok: true, windows, presses, text: "" };
    if (failed?.test(text) && presses.length > 0) break;
  }
  return { ok: false, windows, presses, text: text.slice(0, 400) };
}

/**
 * Runs one demo case: sign up with a made-up user name, then sign in, both with Ferret's window.
 * @param {import("./passkeyDrive.mjs").DriveContext} ctx @param {any} c
 * @returns {Promise<import("./passkeyCases.mjs").CaseResult>}
 */
export async function runDemoCase(ctx, c) {
  const url = new URL(c.page.url);
  const site = DEMO_SITES[url.hostname];
  if (!site) return { status: "not-run", reason: `the demo driver knows no site ${url.hostname}` };
  if (site.unsupported) return { status: "not-run", reason: `${url.hostname}: ${site.unsupported}` };
  const session = ctx.a.session;
  if (ctx.a.pageTab !== null) await session.switchTo(ctx.a.pageTab);
  const user = `ferret-smoke-${Math.random().toString(16).slice(2, 10)}`;
  try {
    await session.navigate(url.href);
    await session.waitFor(() => session.content(() => document.readyState === "complete"), 30_000, url.hostname);
    await sleep(1500);
    if (site.user) {
      const [field] = await session.findAll(site.user);
      if (!field) return { status: "not-run", reason: `${url.hostname}: no field ${site.user} (the site changed)` };
      await session.type(field, user);
    }
    const made = await step(session, site.register, site.registered, site.failed);
    /** @type {any[]} */
    const reports = [{ kind: "started" }];
    reports.push({ kind: "step", step: "create", ok: made.ok, ...(made.ok ? {} : { error: { name: "ServerRefused", message: `the site did not say the sign-up worked: ${made.text}` } }) });
    let windows = made.windows;
    let last = made;
    if (made.ok) {
      const signed = await step(session, site.login, site.loggedIn, site.failed);
      reports.push({ kind: "step", step: "get", ok: signed.ok, ...(signed.ok ? {} : { error: { name: "ServerRefused", message: `the site did not say the sign-in worked: ${signed.text}` } }) });
      windows = Math.max(windows, signed.windows);
      last = signed;
    }
    reports.push({ kind: "done", ok: reports.filter((r) => r.kind === "step").every((r) => r.ok) });
    const steps = reports.filter((r) => r.kind === "step");
    const failed = steps.find((s) => !s.ok);
    /** @type {NonNullable<import("./passkeyCases.mjs").CaseResult["observed"]>} */
    const observed = {
      ceremony: failed ? "server-refused" : "ok",
      ...(failed ? { failStep: failed.step } : {}),
      route: last.windows > 0 ? "ferret" : "browser",
      windowShown: last.windows > 0,
      windowsOpened: windows,
      reports,
      problems: [],
    };
    return { status: "ran", observed, unsafe: [], provider: "ferret" };
  } catch (e) {
    return { status: "not-run", reason: `${url.hostname}: the run threw: ${e instanceof Error ? e.message : String(e)}` };
  }
}
