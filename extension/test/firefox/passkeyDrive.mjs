// The driver steps of the passkey matrix (U4-13): what a case's `actions` say, done the way a person, the page or the browser
// would, while Ferret answers (the provider "ferret" of passkeyMatrix.mjs). Not a spec (run.sh picks up *.spec.mjs only).
//
// A case runs in phases. A phase is one click on the ceremony page's #go with a list of steps (`create`, `get`, `conditional`),
// in the same document, under a report id of its own (`<run>-p<n>`) and the case's relying-party session (`sid`, the run's id),
// so the relying party keeps what an earlier phase registered. What the case is judged on is the judged phases: their step reports
// in order, the route of the last one (a Ferret window in it, or the browser's own answer) and the most Ferret windows seen at once.
// A phase that only sets the scene (the passkey a later step needs, the first half of a hand-over) is not judged.
//
// The verbs (case.json `actions`):
//   start-create, start-get              a phase with that one step; the next verb says what happens in the window
//   start-waiting-create, -get           the same, and waits until Ferret's window is ready (nothing is pressed)
//   choose-in-window                     presses what a person would in the window (Save in Ferret, the newest passkey), verifies
//                                        when asked (with the case's way: the master password unless a verify-* verb names another)
//   choose-browser                       "Use the browser": the page's call ends (hand-over H2), and the page's button is clicked once
//                                        more, so the next call of that kind goes to the browser with its own click (one-time pass)
//   choose-never                         "Never on this site": the call ends, the page's button is clicked again, and every call goes to
//                                        the browser without a window; the list is emptied after the case
//   lock, unlock-in-window               the vault locks (the popup's lock, over the UI port); the window shows the unlock and the
//                                        runner unlocks there with the master password
//   unlock                               a real unlock now (lock, then unlock with the master password): the recent unlock counts
//   age-unlock {minutes}                 no unlock in the last five minutes: the setting "count a recent unlock" is off for the case,
//                                        which is what the window sees after five minutes (the clock itself is not moved)
//   go-offline                           the server is gone: requests to it go to a proxy that nothing listens on; the fixture pages
//                                        stay reachable (they are not the server)
//   age-offline {days}                   the last contact with the server is `days` ago (the disk PIN record's contact time, as the U3
//                                        specs move it); more than seven days also means no recent unlock
//   create-online                        the passkey the case signs in with, made in Ferret's window while the server is there
//   verify-pin, -master-password, -prf   the way the window verifies (a PIN is set first; PRF is the account's passkey on the
//                                        virtual authenticator); the steps of the case run with it
//   navigate {url}, pushState {path}     the page goes to a new document, or changes its address in the same document
//   close-tab                            the page's tab is closed
//   terminate-background                 the background page is ended the way about:debugging's Terminate does
//   wait-for-saving                      the server's answer to the passkey's write is dropped once (the stack's malicious proxy),
//                                        so Ferret sends the same write again under the same key and the server's earlier yes stands
//   expect-notice {text}, expect-no-candidate
//                                        what the window must show; nothing is pressed
//   profile {name}, sync                 profile "b" is a second Firefox signed in to the same account; `sync` asks the extension to
//                                        sync and waits until the case's item is there (or gone, after a delete)
//   delete-passkey                       the case's passkey item is deleted in this profile (the sync engine's delete)
//
// After the verbs, the steps of the case that no judged phase ran yet run as one more phase (as a person would go on), unless the
// last judged phase ended without an outcome.
//
// The runner sets nothing up that a person could not: the settings are the extension's own (storage), the lock is the popup's,
// the network is taken away outside the browser. Nothing here reads a key.
import { TEST_ADDON_ID } from "./harness.mjs";
import { pace } from "./e2e.mjs";
import { ask, editDiskRecord, setPin } from "./unlock.mjs";
import { TEST_HOSTS, caseAddress, observe, specOf } from "./passkeyCases.mjs";
import { CHOOSER_PAGE, MATRIX_PIN, chooserSnapshot, ferretWindows, browserPrompts, detectUnsafe, fetchReports, launchMatrixBrowser, pressInChooser, turnOnFerret, withServer } from "./passkeyMatrix.mjs";

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The verbs a case's `actions` may use (the switch of runActionCase; the unit tests check every fixture against this list). */
export const DRIVER_VERBS = Object.freeze([
  "start-create", "start-get", "start-waiting-create", "start-waiting-get", "choose-in-window", "choose-browser", "choose-never",
  "lock", "unlock-in-window", "unlock", "age-unlock", "go-offline", "age-offline", "create-online", "verify-pin", "verify-master-password",
  "verify-prf", "navigate", "pushState", "close-tab", "terminate-background", "wait-for-saving", "expect-notice", "expect-no-candidate",
  "profile", "sync", "delete-passkey",
]);


/** The test hosts of the fixture: they stay reachable while the server is "gone" (go-offline). */
const FIXTURE_HOSTS = [...Object.values(TEST_HOSTS), "127.0.0.1"];

/**
 * Takes Ferret's server away from the browser (or gives it back): requests go to a proxy that nothing listens on, except the
 * fixture's own hosts. The extension's pages and workers still load.
 * @param {import("./driver.mjs").Session} session @param {boolean} offline
 */
export async function serverOffline(session, offline) {
  await session.chrome((/** @type {boolean} */ value, /** @type {string} */ keep) => {
    const prefs = /** @type {any} */ (globalThis).Services.prefs;
    if (value) {
      prefs.setStringPref("network.proxy.http", "127.0.0.1");
      prefs.setIntPref("network.proxy.http_port", 9);
      prefs.setStringPref("network.proxy.ssl", "127.0.0.1");
      prefs.setIntPref("network.proxy.ssl_port", 9);
      prefs.setStringPref("network.proxy.no_proxies_on", keep);
      prefs.setIntPref("network.proxy.type", 1);
    } else {
      prefs.setIntPref("network.proxy.type", 0);
    }
    // The open connections (the sync's event stream among them) would go on past the proxy: going off line they are ended, so the
    // next request takes the new way.
    if (value) {
      const obs = /** @type {any} */ (globalThis).Services.obs;
      obs.notifyObservers(null, "net:cancel-all-connections");
      obs.notifyObservers(null, "net:prune-all-connections");
    }
  }, offline, FIXTURE_HOSTS.join(", "));
}

/** What the sync says when it cannot reach the server (background/main.mjs: the passkey verification counts these as no network). */
const OFFLINE_STATUSES = ["offline", "retrying", "failed", "unauthorized"];

/**
 * The server there (`reachable`) or gone for the profile's browser, and the extension's sync agreeing: a sync is asked for until its
 * state says so (the extension learns that the server is gone from a request that fails, not from the proxy setting).
 * @param {Profile} p @param {boolean} reachable
 */
async function setServer(p, reachable) {
  await serverOffline(p.session, !reachable);
  // The sync waits a little longer after each failed request; back on line it can take it a minute or two to try again.
  const until = Date.now() + 150_000;
  let last = null;
  while (Date.now() < until) {
    await inExt(p, () => ask(p.session, "sync_retry", {})).catch(() => null);
    last = /** @type {any} */ (await inExt(p, () => ask(p.session, "sync_state", {})).catch(() => null));
    const online = last?.running === true && !OFFLINE_STATUSES.includes(last?.status);
    if (online === reachable) return;
    await sleep(4000);
  }
  throw new Error(`profile ${p.name}: the sync did not see the server ${reachable ? "back" : "gone"} (${JSON.stringify(last)})`);
}

/**
 * Switches the end-to-end stack's malicious proxy to a mode (web/test/e2e-stack/evil/modes.mjs).
 * @param {string} mode @param {Record<string, unknown>} [params]
 */
export async function evil(mode, params = {}) {
  const base = process.env.FERRET_E2E_EVIL_URL ?? "";
  if (!base) throw new Error("FERRET_E2E_EVIL_URL is not set (the Ferret provider runs on the end-to-end stack)");
  const response = await fetch(`${base}/mode`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...params, mode }) });
  const body = await response.json();
  if (!response.ok) throw new Error(`the malicious proxy answered ${response.status} for ${mode}: ${JSON.stringify(body)}`);
  return body;
}

/** The malicious proxy's mode now. */
async function evilMode() {
  const base = process.env.FERRET_E2E_EVIL_URL ?? "";
  return /** @type {any} */ (await (await fetch(`${base}/mode`)).json());
}

/**
 * One core operation of the test build over its core port, from the extension's tab.
 * @param {import("./driver.mjs").Session} session @param {string} op @param {unknown} [args]
 */
export async function coreOp(session, op, args = {}) {
  return /** @type {any} */ (await session.content(
    (/** @type {string} */ name, /** @type {string} */ json) =>
      new Promise((resolve) => {
        const port = browser.runtime.connect({ name: "ferret-test-core" });
        const timer = setTimeout(() => resolve({ ok: false, code: "no_answer" }), 45_000);
        port.onMessage.addListener((/** @type {any} */ message) => {
          clearTimeout(timer);
          port.disconnect();
          resolve(message);
        });
        port.postMessage({ id: "c1", op: name, args: JSON.parse(json) });
      }),
    op,
    JSON.stringify(args),
  ));
}

/**
 * A profile of the case: a Firefox signed in to the run's account, its extension tab (the bridge page) and the tab of the case.
 * @typedef {{ name: string, session: import("./driver.mjs").Session, extTab: string, pageTab: string | null }} Profile
 */

/**
 * What a case is run with.
 * @typedef {{
 *   channel: "release" | "esr",
 *   manifest: "mv3" | "mv2",
 *   account: { email: string, password: string, secretKey: string, qrText: string },
 *   a: Profile,
 *   b: () => Promise<Profile>,
 *   prf: () => Promise<boolean>,
 *   pinSet: { value: boolean },
 * }} DriveContext
 */

/** In the profile's extension tab, then back. @template T @param {Profile} p @param {() => Promise<T>} fn @returns {Promise<T>} */
async function inExt(p, fn) {
  const back = await p.session.windowHandle().catch(() => null);
  await p.session.switchTo(p.extTab);
  try {
    return await fn();
  } finally {
    if (back !== null && back !== p.extTab) await p.session.switchTo(back).catch(() => {});
  }
}

/** The vault's state as the extension says it ("unlocked", "locked" or "signed_out"). @param {Profile} p */
async function vaultState(p) {
  return inExt(p, async () => /** @type {any} */ (await ask(p.session, "state", {}))?.state ?? "unknown");
}

/** A real unlock with the master password, over the UI port (as the popup does). @param {Profile} p @param {string} password */
async function unlockNow(p, password) {
  return inExt(p, async () => {
    await pace();
    const reply = /** @type {any} */ (await ask(p.session, "unlock", { mp: password }));
    if (reply?.ok !== true && reply?.state !== "unlocked") throw new Error(`the unlock failed: ${JSON.stringify(reply)}`);
  });
}

/**
 * A real unlock now (the popup's lock, then the master password): the unlock in the last five minutes counts, as it does for a person
 * who just opened the vault, so a click in Ferret's window needs no verification step. Without it a request's verification (the
 * master password signs in to the server, and waits for its sign-in limit) can take longer than Firefox's user activation lasts,
 * and the page's next call then waits without a window. passkeyMatrix.mjs runs it before the first case and every four minutes.
 * @param {Profile} p @param {string} password
 */
export async function freshUnlock(p, password) {
  await lockNow(p);
  await unlockNow(p, password);
}

/** The popup's lock, over the UI port. @param {Profile} p */
async function lockNow(p) {
  return inExt(p, () => ask(p.session, "lock", {}));
}

/** @param {Profile} p @param {Record<string, unknown>} items */
async function storageSet(p, items) {
  return inExt(p, () => p.session.content((/** @type {string} */ json) => browser.storage.local.set(JSON.parse(json)), JSON.stringify(items)));
}

/** @param {Profile} p @param {string[]} keys */
async function storageRemove(p, keys) {
  return inExt(p, () => p.session.content((/** @type {string[]} */ list) => browser.storage.local.remove(list), keys));
}

/**
 * The ceremony page of a case in the profile's case tab (opened when the profile has none), ready for a click.
 * @param {Profile} p @param {any} c @param {string} sid
 */
async function openPage(p, c, sid) {
  const s = p.session;
  if (p.pageTab === null || !(await s.windowHandles()).includes(p.pageTab)) {
    p.pageTab = await s.newTab();
  }
  await s.switchTo(p.pageTab);
  const address = caseAddress(c, { spec: { ...specOf(c, sid), sid }, auto: false });
  await s.navigate(address.url);
  await enter(s, address.frames);
  return address;
}

/** Enters the frames of the case's chain and waits for the ceremony page. @param {import("./driver.mjs").Session} s @param {{ id: string }[]} frames */
async function enter(s, frames) {
  await s.switchToTopFrame();
  for (const frame of frames) {
    const el = await s.waitFor(async () => (await s.findAll(`#${frame.id}`))[0], 15_000, `the frame #${frame.id}`);
    await s.switchToFrame(el);
  }
  await s.waitFor(() => s.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the ceremony page");
}

/**
 * @typedef {{
 *   profile: Profile, run: string, steps: string[], baseline: Set<string>, known: Map<string, boolean>, pressed: Set<string>,
 *   presses: Array<{ kind: string, role: string }>, windowsOpened: number, judged: boolean, ended: boolean, reports: any[],
 *   promptsBefore: number, browserPrompted: boolean, windowsAtEnd?: any[],
 * }} Phase
 */

/**
 * A phase of the case: sets the page's spec for these steps (a script element, so the page's own code reads it) and clicks #go.
 * @param {Profile} p @param {any} c @param {{ sid: string, n: number, steps: string[], frames: { id: string }[] }} o
 * @returns {Promise<Phase>}
 */
async function startPhase(p, c, { sid, n, steps, frames }) {
  const s = p.session;
  const run = `${sid}-p${n}`.slice(0, 90);
  const spec = { ...specOf(c, run), sid, steps };
  await s.switchTo(/** @type {string} */ (p.pageTab));
  await enter(s, frames);
  await s.content((/** @type {string} */ json) => {
    const script = document.createElement("script");
    script.textContent = `window.__spec = ${json};`;
    document.head.append(script);
  }, JSON.stringify(spec));
  const baseline = new Set(await s.windowHandles());
  const promptsBefore = (await browserPrompts(s)).length;
  await s.switchTo(/** @type {string} */ (p.pageTab));
  await enter(s, frames);
  const [go] = await s.findAll("#go");
  if (!go) throw new Error("the page has no #go button");
  await s.click(go);
  return { profile: p, run, steps, baseline, known: new Map(), pressed: new Set(), presses: [], windowsOpened: 0, judged: true, ended: false, reports: [], promptsBefore, browserPrompted: false };
}

/** The chooser windows of Ferret that the phase opened. @param {Phase} ph */
async function chooserWindows(ph) {
  const s = ph.profile.session;
  /** @type {string[]} */
  const out = [];
  for (const h of await s.windowHandles()) {
    if (ph.baseline.has(h)) continue;
    await s.switchTo(h);
    if ((await s.currentUrl().catch(() => "")).startsWith(CHOOSER_PAGE)) out.push(h);
  }
  await s.switchTo(/** @type {string} */ (ph.profile.pageTab)).catch(() => {});
  return out;
}

/** Counts Ferret's windows of the phase now (a page's own popups are not counted). @param {Phase} ph */
async function countWindows(ph) {
  const handles = await ph.profile.session.windowHandles().catch(() => /** @type {string[]} */ ([]));
  const fresh = handles.filter((h) => !ph.baseline.has(h));
  ph.windowsOpened = Math.max(ph.windowsOpened, await ferretWindows(ph.profile.session, fresh, ph.known, /** @type {string} */ (ph.profile.pageTab)));
  return handles;
}

/**
 * Waits until a Ferret window of the phase is ready and in the state `state` ("ready", "locked"); returns its handle and what it
 * shows. The session is left in the page's tab.
 * @param {Phase} ph @param {{ state?: string, ms?: number }} [o]
 */
async function waitWindow(ph, { state = "ready", ms = 30_000 } = {}) {
  const s = ph.profile.session;
  const until = Date.now() + ms;
  while (Date.now() < until) {
    await countWindows(ph);
    for (const h of await chooserWindows(ph)) {
      await s.switchTo(h);
      const shown = await s
        .content(() => {
          const root = document.querySelector('[data-role="passkey-chooser"]');
          return {
            ready: document.body?.dataset.ready === "1",
            kind: root?.getAttribute("data-kind") ?? "",
            state: root?.getAttribute("data-state") ?? "",
            busy: root?.getAttribute("aria-busy") === "true",
            count: Number(document.querySelector('[data-role="passkey-ferret"]')?.getAttribute("data-count") ?? "-1"),
            candidates: document.querySelectorAll('[data-role="passkey-candidate"]').length,
            offline: document.querySelector('[data-role="passkey-offline"]')?.textContent ?? null,
            none: document.querySelector('[data-role="passkey-none"]') !== null,
          };
        })
        .catch(() => null);
      await s.switchTo(/** @type {string} */ (ph.profile.pageTab)).catch(() => {});
      if (shown?.ready && !shown.busy && shown.state === state) return { handle: h, shown };
    }
    await sleep(250);
  }
  throw new Error(`no Ferret window in the state ${state} within ${ms} ms`);
}

/**
 * Lets the phase run to its end: presses in its windows per `press` and waits for the page's "done" (or `ms`).
 * @param {Phase} ph
 * @param {{ press: "auto" | "none" | "browser" | "never", method: string, name: string | null, password: string, ms: number, browserWhenEmpty?: boolean }} o
 */
async function finishPhase(ph, o) {
  const s = ph.profile.session;
  // The time counts from the last thing the runner did in a window (an unlock or a verification takes seconds).
  let until = Date.now() + o.ms;
  for (;;) {
    await sleep(250);
    const handles = await countWindows(ph);
    if (o.press !== "none" && handles.some((h) => !ph.baseline.has(h) && !ph.pressed.has(h))) {
      const main = /** @type {string} */ (ph.profile.pageTab);
      const did = await pressInChooser(s, ph.baseline, ph.pressed, main, {
        browserWhenEmpty: o.browserWhenEmpty ?? true,
        choose: o.press === "browser" ? "browser" : o.press === "never" ? "never" : "auto",
        method: o.method,
        name: o.name,
        password: o.password,
      });
      ph.presses.push(...did);
      if (did.length > 0) until = Math.max(until, Date.now() + o.ms);
    }
    ph.reports = await fetchReports(ph.run);
    if (ph.reports.some((r) => r.kind === "done") || Date.now() > until) break;
  }
  ph.browserPrompted = (await browserPrompts(s)).length > ph.promptsBefore;
  if (!ph.reports.some((r) => r.kind === "done")) ph.windowsAtEnd = await windowSnapshot(ph);
  ph.ended = true;
  return ph;
}

/** What the phase's Ferret windows show (for the log of a case that did not end). @param {Phase} ph */
const windowSnapshot = (ph) => chooserSnapshot(ph.profile.session, ph.baseline, /** @type {string} */ (ph.profile.pageTab));

/** The step reports of a phase. @param {Phase} ph */
const stepsOf = (ph) => ph.reports.filter((r) => r.kind === "step");

/**
 * Runs one case that has driver steps (or needs Ferret to answer without any: `needs: "provider"`).
 * @param {DriveContext} ctx @param {any} c
 * @returns {Promise<import("./passkeyCases.mjs").CaseResult>}
 */
export async function runActionCase(ctx, c) {
  const sid = `${Math.random().toString(16).slice(2, 10)}-${c.id}`.slice(0, 60);
  const actions = /** @type {Array<Record<string, any>>} */ (c.actions ?? []);
  const verbs = actions.map((a) => String(a.do));
  const specSteps = /** @type {string[]} */ (c.spec.steps ?? ["create", "get"]);
  const expectNone = c.expected.ceremony === "none";
  /** The way the window verifies when it asks: the master password unless a verify-* verb names another. */
  let method = verbs.includes("verify-pin") ? "pin" : verbs.includes("verify-prf") ? "prf" : "password";
  // "An unlock within five minutes counts as verification": the window must not have to ask, so it is not answered if it does.
  if (c.category === "verification" && verbs[0] === "unlock") method = "none";
  // The name of the case's passkey item (a name of the test's own, so a profile can find, wait for and delete it).
  const itemName = `pk-${sid}`.slice(0, 80);
  /** @type {string[]} */
  const problems = [];
  /** @type {Phase[]} */
  const phases = [];
  /** @type {Phase | null} */
  let current = null;
  let profile = ctx.a;
  let n = 0;
  /** How many of the case's steps the judged phases have run, in order. */
  let covered = 0;
  /** What to undo after the case. */
  const undo = { online: false, recent: false, never: false, evil: false };
  /** The case's page per profile (loaded once in each). @type {Map<string, { url: string, frames: { id: string }[] }>} */
  const loaded = new Map();
  /** A sync waits for the case's item to be there (true), or gone after a delete (false). */
  let itemExpected = true;

  const press = { method, name: itemName, password: ctx.account.password };
  const wait = c.waitMs ?? 20_000;
  /** @returns {Phase} */
  const now = () => /** @type {Phase} */ (current);
  const running = () => current !== null && !current.ended;

  /** A new phase with `steps`, in the profile's page (loaded first when the profile has not shown it yet). @param {string[]} steps */
  const start = async (steps) => {
    if (running()) await finish("auto");
    let address = loaded.get(profile.name);
    if (!address) {
      address = await openPage(profile, c, sid);
      loaded.set(profile.name, address);
    }
    current = await startPhase(profile, c, { sid, n: ++n, steps, frames: address.frames });
    phases.push(current);
    return current;
  };
  /** Runs the current phase to its end with the press policy `how`. @param {"auto" | "none" | "browser" | "never"} how @param {number} [ms] */
  const finish = async (how, ms = wait) => {
    if (!running()) return;
    await finishPhase(now(), { press: how, ...press, ms, browserWhenEmpty: !expectNone });
    if (now().judged) cover(now());
  };
  /** The case's steps a judged phase ran: the position after its last step in the case's list. @param {Phase} ph */
  const cover = (ph) => {
    let at = covered;
    for (const step of ph.steps) {
      const i = specSteps.indexOf(step, at);
      if (i >= 0) at = i + 1;
    }
    covered = at;
  };
  /** The steps of the case still to run. */
  const rest = () => specSteps.slice(covered);
  /** The phase did not count (a hand-over's first half, or the scene for a later step): the steps it ran are not covered. @param {Phase} ph */
  const unjudge = (ph) => {
    ph.judged = false;
    covered = 0;
    for (const done of phases) if (done.judged && done.ended) cover(done);
  };
  /**
   * Hand-over (H2): the runner chose the browser in Ferret's window and the page's call ended. The page's button is clicked once more
   * for the same steps, and the browser answers that call with its own click (the one-time pass). Only for a case whose call must
   * end at the browser.
   */
  const handOverIfBrowser = async () => {
    if (current === null || c.expected.route !== "browser") return;
    const ph = current;
    if (!ph.presses.some((x) => x.role === "passkey-browser")) return;
    const failed = stepsOf(ph).find((x) => !x.ok);
    if (failed?.error?.name !== "NotAllowedError") return;
    unjudge(ph);
    await start(ph.steps.slice(ph.steps.indexOf(failed.step)));
    await finish("auto");
  };

  try {
    // The setting-up the verbs need before anything runs.
    if (verbs.some((v) => ["age-offline", "verify-pin"].includes(v)) && !ctx.pinSet.value) {
      await inExt(ctx.a, () => setPin(ctx.a.session, ctx.account, MATRIX_PIN, "disk"));
      ctx.pinSet.value = true;
    }
    if (verbs.includes("verify-prf") && !(await ctx.prf())) throw new Error("the account has no passkey to verify with (PRF)");
    // A verification case verifies with its own way: no recent unlock may stand in for it.
    if (verbs.some((v) => v.startsWith("verify-"))) {
      await storageSet(profile, { passkey_recent_unlock: false });
      undo.recent = true;
    }
    if (verbs.includes("wait-for-saving")) {
      await evil("drop_put_answer", { count: 1 });
      undo.evil = true;
    }

    const body = async () => {
      for (const a of actions) {
        switch (a.do) {
          case "start-create":
          case "start-get":
          case "start-waiting-create":
          case "start-waiting-get": {
            const step = a.do.endsWith("create") ? "create" : "get";
            // A get needs the passkey the case's create makes: when no phase made it yet, it is made first (a judged step of the case).
            if (step === "get" && covered === 0 && specSteps[0] === "create" && !phases.some((ph) => ph.steps.includes("create"))) {
              await start(["create"]);
              await finish("auto");
            }
            await start([step]);
            if (a.do.startsWith("start-waiting")) await waitWindow(now());
            break;
          }
          case "choose-in-window":
            if (!running()) await start(rest());
            await finish("auto");
            break;
          case "choose-browser":
            if (!running()) await start(rest());
            await waitWindow(now());
            await finish("browser", 15_000);
            // The page's call ended; its button is clicked once more and the browser answers (the one-time pass).
            unjudge(now());
            await start(now().steps);
            await finish("auto");
            await handOverIfBrowser();
            break;
          case "choose-never":
            if (!running()) await start(rest());
            await waitWindow(now());
            await finish("never", 15_000);
            unjudge(now());
            undo.never = true;
            break;
          case "lock":
            // A lock ends a request that waits (plan section 6, UK112 b): its window closes and the page's call ends. A request that
            // starts while the vault is locked is unlocked in the window instead (unlock-in-window).
            if (running()) await waitWindow(now());
            await lockNow(profile);
            if (running()) {
              await windowsGone(now(), problems, "the vault locked");
              await finish("none", 5000);
            }
            break;
          case "unlock-in-window":
            if (!running()) await start(rest());
            // The window shows the unlock; pressInChooser unlocks there with the master password, then presses as usual.
            await waitWindow(now(), { state: "locked" });
            break;
          case "unlock":
            await lockNow(profile);
            await unlockNow(profile, ctx.account.password);
            break;
          case "age-unlock":
            await storageSet(profile, { passkey_recent_unlock: false });
            undo.recent = true;
            break;
          case "go-offline":
            if (running()) await finish("auto");
            undo.online = true;
            await setServer(profile, false);
            break;
          case "age-offline":
            // More than seven days without the server: no unlock in the last five minutes either.
            await storageSet(profile, { passkey_recent_unlock: false });
            undo.recent = true;
            await inExt(profile, () => editDiskRecord(profile.session, { kind: "contact_days_ago", days: Number(a.days) }));
            break;
          case "create-online":
            await start(["create"]);
            await finish("auto");
            break;
          case "verify-pin":
          case "verify-master-password":
          case "verify-prf":
            if (!running()) await start(rest());
            await finish("auto");
            break;
          case "navigate":
            if (running()) await waitWindow(now());
            await profile.session.switchTo(/** @type {string} */ (profile.pageTab));
            await profile.session.switchToTopFrame();
            await profile.session.navigate(String(a.url));
            if (current !== null) await windowsGone(now(), problems, "the page went to a new document");
            await finish("none", 3000);
            break;
          case "pushState":
            if (running()) await waitWindow(now());
            await profile.session.switchTo(/** @type {string} */ (profile.pageTab));
            await profile.session.switchToTopFrame();
            await profile.session.content((/** @type {string} */ path) => history.pushState({}, "", path), String(a.path));
            break;
          case "close-tab": {
            if (running()) await waitWindow(now());
            const before = await vaultRows(profile);
            const s = profile.session;
            const fresh = await s.newTab();
            await s.switchTo(/** @type {string} */ (profile.pageTab));
            await s.closeTab();
            await s.switchTo(fresh);
            profile.pageTab = fresh;
            if (current !== null) {
              await windowsGone(now(), problems, "the page's tab was closed");
              now().reports = await fetchReports(now().run);
              now().ended = true;
            }
            await sleep(3000);
            const after = await vaultRows(profile);
            const added = after.filter((r) => !before.includes(r));
            if (added.length > 0) problems.push(`UNSAFE: passkey-not-delivered: the vault has new items after the tab closed: ${added.join(", ")}`);
            break;
          }
          case "terminate-background":
            if (running()) await waitWindow(now());
            await profile.session.terminateBackground(TEST_ADDON_ID);
            await finish("none");
            break;
          case "wait-for-saving": {
            await finish("auto");
            const mode = await evilMode();
            if (mode?.params?.count !== 0) problems.push(`the server's answer to the passkey's write was not dropped (the proxy's mode: ${JSON.stringify(mode)})`);
            break;
          }
          case "expect-notice": {
            if (!running()) await start(rest());
            const { shown } = await waitWindow(now());
            const text = String(shown.offline ?? "");
            if (!text.toLowerCase().includes(String(a.text).toLowerCase())) problems.push(`the window did not say ${JSON.stringify(a.text)} (it said ${JSON.stringify(text)})`);
            await finish("none", 3000);
            break;
          }
          case "expect-no-candidate": {
            if (!running()) await start(rest());
            const { shown } = await waitWindow(now());
            if (shown.candidates !== 0 || shown.count !== 0) problems.push(`the window offered ${shown.candidates} passkeys, none expected`);
            await finish("none", 3000);
            break;
          }
          case "profile":
            if (running()) await finish("auto");
            profile = a.name === "b" ? await ctx.b() : ctx.a;
            break;
          case "sync":
            if (running()) await finish("auto");
            await syncUntil(profile, itemName, itemExpected);
            break;
          case "delete-passkey": {
            // The passkey to delete is the case's own: made here first, and seen in the other profile before it goes.
            if (!phases.some((ph) => ph.steps.includes("create"))) {
              await start(["create"]);
              await finish("auto");
              const made = now();
              const b = await ctx.b();
              await syncUntil(profile, itemName, true);
              await syncUntil(b, itemName, true);
              unjudge(made);
            }
            const gone = await inExt(profile, () => coreOp(profile.session, "item_delete_probe", { name: itemName }));
            if (gone?.ok !== true) throw new Error(`item_delete_probe: ${JSON.stringify(gone)}`);
            itemExpected = false;
            // The other profile's get asks for the passkey the relying party knows for this session (allow "all").
            covered = Math.max(covered, specSteps.indexOf("get"));
            break;
          }
          default:
            throw new Error(`the runner has no driver step for "${a.do}" (DRIVER_VERBS: ${DRIVER_VERBS.includes(String(a.do)) ? "listed" : "not listed"})`);
        }
      }
      // What the verbs left running ends; then the case's steps that are left run as a person would go on, unless the last judged
      // phase ended without an outcome (that is what the case is about).
      if (running()) await finish(expectNone ? "none" : "auto");
      await handOverIfBrowser();
      const last = [...phases].reverse().find((ph) => ph.judged) ?? null;
      const goOn = actions.length === 0 || (last !== null && stepsOf(last).length > 0 && stepsOf(last).every((x) => x.ok));
      if (goOn && rest().length > 0) {
        await start(rest());
        await finish(expectNone ? "none" : "auto");
        await handOverIfBrowser();
      }
    };
    // A page on the vault's origin: the fixture's vault host is the signed-in server for this case (and only for it).
    if ((c.page?.chain ?? []).includes("vault-fixture.test")) await withServer(ctx.a, "https://vault-fixture.test", body);
    else await body();
  } catch (e) {
    return { status: "not-run", reason: `the run threw: ${e instanceof Error ? e.message : String(e)}` };
  } finally {
    await cleanUp(ctx, profile, phases, undo);
  }

  const judged = phases.filter((ph) => ph.judged);
  if (judged.length === 0) return { status: "not-run", reason: "no phase of the case ran" };
  // A phase that ended is judged on what the page had reported by then (the clean-up closes windows, which the page may report).
  for (const ph of phases) if (!ph.ended) ph.reports = await fetchReports(ph.run);
  // The page reports "started" under the case's own id when it loads (in each profile).
  if (!(await fetchReports(sid)).some((r) => r.kind === "started")) return { status: "not-run", reason: "the page never started (no report from it at all)" };
  const last = judged[judged.length - 1];
  const reports = [...judged.flatMap((ph) => ph.reports.filter((r) => r.kind !== "done")), ...last.reports.filter((r) => r.kind === "done")];
  const observed = observe(reports, { windowShown: last.windowsOpened > 0, windowsOpened: Math.max(...phases.map((ph) => ph.windowsOpened)) });
  // The route of the last call: a Ferret window, or the browser's own answer (its prompt counts: a call the browser holds has no step).
  if (observed.route === "none" && last.windowsOpened === 0 && last.browserPrompted) observed.route = "browser";
  observed.problems = problems.filter((x) => !x.startsWith("UNSAFE: "));
  /** @type {any} */ (observed).windowsAtEnd = phases.flatMap((ph) => ph.windowsAtEnd ?? []);
  const unsafe = [...detectUnsafe(c, observed, "ferret"), ...problems.filter((x) => x.startsWith("UNSAFE: ")).map((x) => x.slice(8).split(":")[0])];
  return { status: "ran", observed, unsafe, provider: "ferret" };
}

/** Waits until the phase's Ferret windows are gone; a window that stays is a problem of the case. @param {Phase} ph @param {string[]} problems @param {string} why */
async function windowsGone(ph, problems, why) {
  if (!ph) return;
  const until = Date.now() + 10_000;
  while (Date.now() < until) {
    // Ferret's windows only (the runner's own new tab is not one).
    if ((await chooserWindows(ph).catch(() => [])).length === 0) return;
    await sleep(250);
  }
  problems.push(`Ferret's window stayed open after ${why}`);
}

/** The items of the open vault (ids and revisions), from the test hooks' measure port. @param {Profile} p @returns {Promise<string[]>} */
export async function vaultRows(p) {
  return inExt(p, async () => {
    const reply = /** @type {any} */ (await p.session.content(() => new Promise((resolve) => {
      const port = browser.runtime.connect({ name: "ferret-test-measure" });
      const timer = setTimeout(() => resolve({ ok: false }), 15_000);
      port.onMessage.addListener((/** @type {any} */ m) => {
        clearTimeout(timer);
        port.disconnect();
        resolve(m);
      });
      port.postMessage({ id: "v1", cmd: "vault" });
    })));
    return /** @type {string[]} */ ((reply?.value?.rows ?? []).map((/** @type {string} */ r) => r.split(":")[0]));
  });
}

/**
 * Asks the profile's extension to sync, until the case's item is there (`present`) or gone.
 * @param {Profile} p @param {string} name @param {boolean} present
 */
async function syncUntil(p, name, present) {
  const until = Date.now() + 60_000;
  let last = null;
  while (Date.now() < until) {
    await inExt(p, () => ask(p.session, "sync_retry", {})).catch(() => null);
    last = await inExt(p, () => coreOp(p.session, "item_find_probe", { name }));
    if (last?.ok === true && last.value && "item" in last.value && (last.value.item !== null) === present) return;
    await sleep(1500);
  }
  throw new Error(`profile ${p.name}: the item ${name} is ${present ? "not there" : "still there"} after the sync (${JSON.stringify(last)})`);
}

/**
 * Puts back what the case changed: the server, the settings, the "never" list, the proxy's mode, and the vault unlocked.
 * @param {DriveContext} ctx @param {Profile} profile @param {Phase[]} phases @param {{ online: boolean, recent: boolean, never: boolean, evil: boolean }} undo
 */
async function cleanUp(ctx, profile, phases, undo) {
  for (const p of [ctx.a, profile]) {
    const s = p.session;
    // Ferret windows the case left open, and the page.
    try {
      for (const ph of phases) {
        if (ph.profile !== p) continue;
        for (const h of await s.windowHandles()) if (!ph.baseline.has(h) && h !== p.pageTab && h !== p.extTab) {
          await s.switchTo(h);
          await s.closeTab();
        }
      }
    } catch {
      // Gone already.
    }
    if (undo.online) await setServer(p, true).catch(() => {});
  }
  try {
    if (undo.recent) await storageRemove(ctx.a, ["passkey_recent_unlock"]);
    // The settings page's own "remove all" (the background keeps the list in memory as well as in storage).
    if (undo.never) await inExt(ctx.a, () => ask(ctx.a.session, "passkey_settings", { never_clear: true }));
    if (undo.evil) await evil("honest");
    // A case that locked the vault (or ended the background, which comes back locked) leaves it unlocked for the next one.
    const state = await vaultState(ctx.a).catch(() => "unknown");
    if (state === "locked") await unlockNow(ctx.a, ctx.account.password);
    if (profile !== ctx.a && (await vaultState(profile).catch(() => "unknown")) === "locked") await unlockNow(profile, ctx.account.password);
  } catch {
    // The next case finds out.
  }
  // The matrix goes on in profile A's tab of the case (a new one when the case closed it).
  const a = ctx.a.session;
  const handles = await a.windowHandles().catch(() => /** @type {string[]} */ ([]));
  if (ctx.a.pageTab === null || !handles.includes(ctx.a.pageTab)) ctx.a.pageTab = await a.newTab().catch(() => null);
  if (ctx.a.pageTab !== null) await a.switchTo(ctx.a.pageTab).catch(() => {});
}

/**
 * The second profile of the sync cases: a Firefox of its own, signed in to the same account, with passkeys on.
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2" }} o
 * @returns {Promise<Profile>}
 */
export async function secondProfile({ channel, manifest }) {
  const session = await launchMatrixBrowser({ channel, manifest });
  const { tab, account } = await turnOnFerret(session, channel, { revoke: false });
  const b = { name: "b", session, extTab: tab, pageTab: null };
  await freshUnlock(b, account.password);
  return b;
}

export { launchMatrixBrowser };
