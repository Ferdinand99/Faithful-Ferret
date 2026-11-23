// The store of offers (offers.mjs): what the background holds of the forms the
// user submitted. Nothing here is believed before the browser's own facts
// (the frames of the tab, the origin from the core) agree; a login is offered only
// after it worked; everything is held in memory with a wall-clock end and is
// cleared by every lock. The browser and the core are fakes with the rules of the
// real ones for the addresses these tests use.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  FRAME_GAP_MS,
  GENERATED_TTL_MS,
  MAX_MESSAGE,
  MAX_OFFERS,
  MAX_OFFERS_PER_TAB,
  OFFER_TTL_MS,
  TAB_MAX,
  createOffers,
} from "../../src/background/offers.mjs";
import { createNeverList } from "../../src/background/captureRegistry.mjs";
import { createClock, createFakeTimers } from "./backgroundHelpers.mjs";

const TAB = 5;
const PAGE = "https://login.example.net/signin?next=%2Fhome";
const ORIGIN = "https://login.example.net";
const PASSWORD = "Typed-PASSWORD-for-the-form-1";

/** The registrable domain as far as these tests need it. @param {string} host */
const site = (host) => host.split(".").slice(-2).join(".");

/**
 * A store of offers over a fake browser: the frames of each tab are set by the test, the core answers by the rules of
 * its functions (an opaque address has no origin), the clock is the test's.
 * @param {{ never?: string[], classify?: (capture: any) => Promise<{ action: string } | null>, badges?: Array<[number, number]> }} [options]
 */
function world({ never: hosts = [], classify, badges } = {}) {
  const clock = createClock();
  const timers = createFakeTimers(clock);
  /** @type {Map<string, any>} */
  const frameTable = new Map();
  /** @type {Set<number>} */
  const privateTabs = new Set();
  /** Frames that the parent-side check refuses. @type {Set<string>} */
  const hidden = new Set();
  /** @type {Set<string>} */
  const never = new Set(hosts);
  /** @type {Array<[string, any]>} */
  const neverAdded = [];
  let counter = 0;

  /** @param {string} url */
  const originOf = (url) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.origin : null;
  };

  /** @type {import("../../src/background/offers.mjs").Frames} */
  const frames = {
    origin: async (url) => originOf(url),
    sameSite: async (a, b) => site(new URL(a).hostname) === site(new URL(b).hostname),
    host: async (url) => ({ a_label: new URL(url).hostname, unicode: new URL(url).hostname }),
    frame: async (tabId, frameId) => frameTable.get(`${tabId}:${frameId}`) ?? null,
    shown: async (tabId, frame) => !hidden.has(`${tabId}:${frame.frameId}`),
    incognito: async (tabId) => privateTabs.has(tabId),
  };
  /** @type {import("../../src/background/offers.mjs").Never} */
  const neverList = {
    has: async (host) => never.has(host),
    add: async (host, options) => {
      neverAdded.push([host, options]);
      never.add(host);
    },
  };
  const offers = createOffers({
    now: clock.now,
    frames,
    random: (bytes) => {
      counter += 1;
      bytes.fill(0);
      bytes[15] = counter;
      bytes[0] = 0xab;
      return bytes;
    },
    never: neverList,
    timers,
    ...(classify ? { writer: { classify } } : {}),
    ...(badges ? { badge: { set: (tabId, count) => void badges.push([tabId, count]) } } : {}),
  });

  /** A top frame in a tab. @param {number} tabId @param {string} url @param {Record<string, any>} [extra] */
  const openFrame = (tabId, url, extra = {}, frameId = 0) => {
    const origin = /** @type {string} */ (originOf(url));
    frameTable.set(`${tabId}:${frameId}`, { frameId, url, origin, ancestors: frameId === 0 ? [] : [{ frameId: 0 }], chainSecure: origin.startsWith("https://"), documentId: `doc-${tabId}-${frameId}`, ...extra });
  };
  openFrame(TAB, PAGE);

  /** @param {Record<string, any>} [over] @param {Record<string, any>} [senderOver] */
  const send = async (over = {}, senderOver = {}) => {
    await offers.onCapture(
      { tabId: TAB, frameId: 0, documentId: `doc-${TAB}-0`, url: PAGE, ...senderOver },
      { capture_id: "cap1", self_origin: ORIGIN, kind: "login", username: "me@example.net", username_from: "typed", password: PASSWORD, ...over },
    );
  };
  /** The sign-up kind: ready three seconds after the last capture. */
  const signup = (over = {}, senderOver = {}) => send({ kind: "signup", ...over }, senderOver);
  /** The signals of a login that left its page for a new document. @param {string} [to] */
  const landOn = async (to = "https://login.example.net/home", documentId = "doc-new") => {
    await offers.onSignal(TAB, { type: "committed", frameId: 0, url: to, documentId });
    await offers.onSignal(TAB, { type: "completed", frameId: 0, url: to, documentId });
  };
  return { clock, timers, offers, frames, frameTable, privateTabs, hidden, never, neverAdded, openFrame, send, signup, landOn };
}

test("capture_from_http_opaque_or_cross_site_frames_is_dropped", async () => {
  const w = world();
  // http, a loopback address included: the capture is https only.
  for (const url of ["http://login.example.net/signin", "http://localhost:3000/login", "http://127.0.0.1/login"]) {
    w.openFrame(TAB, url);
    await w.signup({}, { url });
    w.clock.advance(FRAME_GAP_MS + 1);
  }
  assert.equal(w.offers.size(), 0, "no http capture is held");
  w.openFrame(TAB, PAGE);

  // A sandboxed or opaque address has no origin; the script's own origin "null" and a different one narrow to nothing.
  await w.signup({}, { url: "about:blank" });
  w.clock.advance(FRAME_GAP_MS + 1);
  await w.signup({ self_origin: "null" });
  w.clock.advance(FRAME_GAP_MS + 1);
  await w.signup({ self_origin: "https://other.example.org" });
  w.clock.advance(FRAME_GAP_MS + 1);
  assert.equal(w.offers.size(), 0);

  // A frame whose ancestors are not all https and of the top's site is not a frame the browser lists as fillable.
  w.openFrame(TAB, "https://ads.other.org/frame", {}, 3);
  w.frameTable.delete(`${TAB}:3`);
  await w.signup({ self_origin: "https://ads.other.org" }, { frameId: 3, url: "https://ads.other.org/frame" });
  w.clock.advance(FRAME_GAP_MS + 1);
  assert.equal(w.offers.size(), 0, "a frame that is not listed is dropped");
  // A same-site frame below an http top (the chain is not whole https).
  w.openFrame(TAB, "http://login.example.net/", {});
  w.openFrame(TAB, "https://login.example.net/inner", { ancestors: [{ frameId: 0 }], chainSecure: false }, 4);
  await w.signup({}, { frameId: 4, url: "https://login.example.net/inner" });
  w.clock.advance(FRAME_GAP_MS + 1);
  assert.equal(w.offers.size(), 0);

  // The control: the same capture from an https top frame is held.
  w.openFrame(TAB, PAGE);
  await w.signup();
  assert.equal(w.offers.size(), 1);
});

test("a_capture_handled_after_the_frame_navigated_keeps_the_sender_origin_or_is_dropped", async () => {
  // The frame now shows another origin than the sender: nothing is re-attributed to it.
  const moved = world();
  moved.openFrame(TAB, "https://evil.example.org/phish");
  await moved.signup();
  assert.equal(moved.offers.size(), 0);

  // The frame moved on inside the same origin (another document): the capture keeps the sender's origin and address.
  const same = world();
  same.openFrame(TAB, "https://login.example.net/other-page", { documentId: "doc-later" });
  await same.signup();
  same.clock.advance(3000);
  const [offer] = same.offers.forTab(TAB, "a".repeat(32));
  assert.ok(offer);
  assert.equal(offer.host.a_label, "login.example.net");
  const capture = same.offers.peek(offer.offer_id, "a".repeat(32));
  assert.equal(capture?.origin, ORIGIN);
  assert.equal(capture?.frameUrl, PAGE, "the sender's address, not the frame's present one");
});

test("a_hidden_same_site_frame_cannot_capture", async () => {
  const w = world();
  w.openFrame(TAB, "https://login.example.net/embedded", {}, 2);
  w.hidden.add(`${TAB}:2`);
  await w.signup({}, { frameId: 2, url: "https://login.example.net/embedded" });
  assert.equal(w.offers.size(), 0, "hidden or covered: no capture");
  // A frame that is shown is captured from; the top frame has nothing above it to check.
  w.hidden.clear();
  w.clock.advance(FRAME_GAP_MS + 1);
  await w.signup({}, { frameId: 2, url: "https://login.example.net/embedded" });
  assert.equal(w.offers.size(), 1);
});

test("a_login_offer_needs_an_outcome_signal_and_no_password_form_after_it", async () => {
  const w = world();
  await w.send();
  assert.deepEqual(w.offers.forTab(TAB), [], "a submit alone is nothing yet");
  // A new document, finished loading, then two quiet seconds.
  w.clock.advance(1000);
  await w.landOn();
  w.clock.advance(1999);
  assert.deepEqual(w.offers.forTab(TAB), []);
  w.clock.advance(1);
  const offers = w.offers.forTab(TAB);
  assert.equal(offers.length, 1);
  assert.deepEqual(Object.keys(offers[0]).sort(), ["generated", "host", "kind", "offer_id", "username"]);
  assert.equal(offers[0].kind, "login");

  // The history changed (a single-page app): two seconds after it.
  const spa = world();
  await spa.send();
  spa.clock.advance(500);
  await spa.offers.onSignal(TAB, { type: "history", frameId: 0, url: "https://login.example.net/app/home" });
  spa.clock.advance(1999);
  assert.deepEqual(spa.offers.forTab(TAB), []);
  spa.clock.advance(1);
  assert.equal(spa.offers.forTab(TAB).length, 1);

  // The form is gone within five seconds: the same.
  const gone = world();
  await gone.send();
  gone.clock.advance(4000);
  await gone.offers.onSignal(TAB, { type: "form_gone", frameId: 0, captureId: "cap1" });
  gone.clock.advance(2000);
  assert.equal(gone.offers.forTab(TAB).length, 1);
  // The script's last look is at 4.9 s: a message that is a little late still counts (the window is six seconds).
  const tolerant = world();
  await tolerant.send();
  tolerant.clock.advance(5600);
  await tolerant.offers.onSignal(TAB, { type: "form_gone", frameId: 0, captureId: "cap1" });
  tolerant.clock.advance(2000);
  assert.equal(tolerant.offers.forTab(TAB).length, 1);
  // Gone after seven seconds, or reported for another capture: no outcome.
  const late = world();
  await late.send();
  late.clock.advance(7000);
  await late.offers.onSignal(TAB, { type: "form_gone", frameId: 0, captureId: "cap1" });
  late.clock.advance(5000);
  assert.deepEqual(late.offers.forTab(TAB), []);
  assert.equal(late.offers.size(), 0, "no outcome in ten seconds drops it");
  const other = world();
  await other.send();
  await other.offers.onSignal(TAB, { type: "form_gone", frameId: 0, captureId: "someone-else" });
  other.clock.advance(5000);
  assert.deepEqual(other.offers.forTab(TAB), []);

  // Without an outcome nothing comes, however long it waits.
  const quiet = world();
  await quiet.send();
  quiet.clock.advance(60_000);
  assert.deepEqual(quiet.offers.forTab(TAB), []);

  // A navigation that comes before the page finished loading is not enough: the new document must complete.
  const slow = world();
  await slow.send();
  await slow.offers.onSignal(TAB, { type: "committed", frameId: 0, url: "https://login.example.net/home", documentId: "doc-new" });
  slow.clock.advance(20_000);
  assert.deepEqual(slow.offers.forTab(TAB), []);
});

test("a_failed_login_whose_form_reappears_after_document_idle_gives_no_offer", async () => {
  const w = world();
  await w.send();
  w.clock.advance(500);
  // The page reloads with its error and shows the form again: its script says so at document idle.
  await w.landOn("https://login.example.net/signin?error=1");
  w.clock.advance(800);
  await w.offers.onSignal(TAB, { type: "page_ready", frameId: 0, url: "https://login.example.net/signin?error=1", documentId: "doc-new" });
  w.clock.advance(5000);
  assert.deepEqual(w.offers.forTab(TAB), []);
  assert.equal(w.offers.size(), 0);

  // A form of another site on the landing page does not count against the login.
  const foreign = world();
  await foreign.send();
  await foreign.landOn();
  foreign.clock.advance(500);
  await foreign.offers.onSignal(TAB, { type: "page_ready", frameId: 1, url: "https://ads.other.org/widget", documentId: "doc-ad" });
  foreign.clock.advance(2000);
  assert.equal(foreign.offers.forTab(TAB).length, 1);

  // The page the user left reporting late does not count: it is not the new document.
  const old = world();
  await old.send();
  await old.landOn();
  old.clock.advance(500);
  await old.offers.onSignal(TAB, { type: "page_ready", frameId: 0, url: PAGE, documentId: `doc-${TAB}-0` });
  old.clock.advance(2000);
  assert.equal(old.offers.forTab(TAB).length, 1);
});

test("a_login_that_lands_on_a_page_without_the_script_gives_no_update_offer", async () => {
  for (const landing of ["http://login.example.net/home", "https://accounts.other.org/home", "about:blank"]) {
    const w = world();
    await w.send();
    w.clock.advance(300);
    await w.landOn(landing);
    w.clock.advance(5000);
    assert.deepEqual(w.offers.forTab(TAB), [], landing);
    assert.equal(w.offers.size(), 0, landing);
  }
  // A login that went through another site and came back to its own is judged by where it ended.
  const back = world();
  await back.send();
  await back.offers.onSignal(TAB, { type: "committed", frameId: 0, url: "https://sso.other.org/step", documentId: "d1" });
  await back.landOn("https://login.example.net/home", "d2");
  back.clock.advance(2000);
  assert.equal(back.offers.forTab(TAB).length, 1);
});

test("signup_change_and_reset_offers_come_3_seconds_after_the_last_input_without_focus", async () => {
  for (const kind of ["signup", "change", "reset"]) {
    const w = world();
    await w.send({ kind, ...(kind === "change" ? { current_password: "Old-password-1" } : {}) });
    w.clock.advance(2999);
    assert.deepEqual(w.offers.forTab(TAB), [], kind);
    // A later capture of the same group (the user typed on) moves the end: three seconds after the last.
    w.clock.advance(FRAME_GAP_MS);
    await w.send({ kind, password: `${PASSWORD}-longer`, ...(kind === "change" ? { current_password: "Old-password-1" } : {}) });
    w.clock.advance(2999);
    assert.deepEqual(w.offers.forTab(TAB), [], `${kind}: the second capture restarted the wait`);
    w.clock.advance(1);
    const [offer] = w.offers.forTab(TAB, "b".repeat(32));
    assert.equal(offer.kind, kind);
    assert.equal(w.offers.size(), 1, `${kind}: one offer`);
    assert.equal(w.offers.peek(offer.offer_id, "b".repeat(32))?.password, `${PASSWORD}-longer`);
  }
  // An unknown landing page does not block them: the user left for another site at once.
  const away = world();
  await away.signup();
  await away.landOn("https://accounts.other.org/welcome");
  away.clock.advance(3000);
  assert.equal(away.offers.forTab(TAB).length, 1);
});

test("an_identifier_step_is_joined_with_the_password_step_on_the_same_site_within_five_minutes", async () => {
  const w = world();
  // The first step names the user and has no password.
  await w.send({ kind: "identifier", username: "step@example.net", password: undefined });
  assert.equal(w.offers.size(), 0, "an identifier step is no offer");
  w.clock.advance(60_000);
  // The second step is a page of the same site (another host) and has a password only.
  w.openFrame(TAB, "https://secure.example.net/password");
  await w.send({ kind: "signup", username: undefined, username_from: undefined, self_origin: "https://secure.example.net" }, { url: "https://secure.example.net/password" });
  w.clock.advance(3000);
  const [offer] = w.offers.forTab(TAB, "c".repeat(32));
  const capture = w.offers.peek(offer.offer_id, "c".repeat(32));
  assert.equal(capture?.username, "step@example.net");
  assert.equal(capture?.usernameFrom, "identifier");

  // After five minutes it is forgotten; another tab or another site never gets it.
  const late = world();
  await late.send({ kind: "identifier", username: "step@example.net", password: undefined });
  late.clock.advance(300_001);
  await late.signup({ username: undefined, username_from: undefined });
  late.clock.advance(3000);
  assert.equal(late.offers.forTab(TAB)[0].username, null);
  const elsewhere = world();
  await elsewhere.send({ kind: "identifier", username: "step@example.net", password: undefined });
  elsewhere.clock.advance(FRAME_GAP_MS + 1);
  elsewhere.openFrame(TAB, "https://shop.other.org/pw");
  await elsewhere.signup({ username: undefined, username_from: undefined, self_origin: "https://shop.other.org" }, { url: "https://shop.other.org/pw" });
  elsewhere.clock.advance(3000);
  assert.equal(elsewhere.offers.forTab(TAB)[0].username, null);
  // A user name that the second step has itself is its own.
  const own = world();
  await own.send({ kind: "identifier", username: "step@example.net", password: undefined });
  own.clock.advance(FRAME_GAP_MS + 1);
  await own.signup({ username: "typed@example.net" });
  own.clock.advance(3000);
  assert.equal(own.offers.forTab(TAB)[0].username, "typed@example.net");
  // A lock drops the user name too.
  const locked = world();
  await locked.send({ kind: "identifier", username: "step@example.net", password: undefined });
  locked.offers.clear("lock");
  await locked.signup({ username: undefined, username_from: undefined });
  locked.clock.advance(3000);
  assert.equal(locked.offers.forTab(TAB)[0].username, null);
});

test("a_second_capture_replaces_the_first_offer", async () => {
  const w = world();
  await w.signup();
  w.clock.advance(FRAME_GAP_MS + 1);
  await w.signup({ password: "Second-PASSWORD-typed-2" });
  w.clock.advance(3000);
  const listed = w.offers.forTab(TAB, "d".repeat(32));
  assert.equal(listed.length, 1);
  assert.equal(w.offers.peek(listed[0].offer_id, "d".repeat(32))?.password, "Second-PASSWORD-typed-2");
  // Another kind is another offer.
  w.clock.advance(FRAME_GAP_MS + 1);
  await w.send({ kind: "change", current_password: "Old-password-1" });
  w.clock.advance(3000);
  assert.equal(w.offers.forTab(TAB).length, 2);
});

test("a_capture_with_the_generated_value_joins_the_generated_offer", async () => {
  const w = world();
  const id = await w.offers.onGenerated({ tabId: TAB, frameId: 0, documentId: `doc-${TAB}-0`, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
  assert.match(String(id), /^[0-9a-f]{32}$/);
  const [shown] = w.offers.forTab(TAB, "e".repeat(32));
  assert.equal(shown.generated, true, "the save card is there at once");
  assert.equal(shown.username, null);
  // The user submits the form: the same password, now with the user name they typed. It joins, it is not a second offer.
  w.clock.advance(1000);
  await w.signup({ password: "Generated-by-Ferret-9", username: "new-user" });
  w.clock.advance(5000);
  const listed = w.offers.forTab(TAB, "e".repeat(32));
  assert.equal(listed.length, 1);
  assert.equal(listed[0].offer_id, shown.offer_id);
  assert.equal(listed[0].username, "new-user");
  assert.equal(w.offers.peek(shown.offer_id, "e".repeat(32))?.generated, true);
  assert.equal(w.offers.size(), 1);
  // Another password for the same form is a capture of its own.
  w.clock.advance(FRAME_GAP_MS + 1);
  await w.signup({ password: "Typed-something-else-3" });
  w.clock.advance(3000);
  assert.equal(w.offers.forTab(TAB).length, 2);
});

test("an_offer_is_gone_after_five_minutes_of_wall_clock_even_if_timers_slept", async () => {
  const w = world();
  await w.signup();
  w.clock.advance(3000);
  const session = "f".repeat(32);
  const [offer] = w.offers.forTab(TAB, session);
  assert.ok(offer);
  // The machine sleeps: the clock jumps, no timer runs. Every access reads the clock.
  w.clock.jump(OFFER_TTL_MS - 3000 - 1);
  assert.equal(w.offers.forTab(TAB).length, 1, "one millisecond before the end");
  w.clock.advance(1);
  assert.equal(w.timers.pending.size > 0, true, "a timer is still waiting; it did not decide anything");
  assert.equal(w.offers.peek(offer.offer_id, session), null);
  assert.deepEqual(w.offers.forTab(TAB), []);
  assert.equal(w.offers.take(offer.offer_id, session), null);
  assert.equal(w.offers.size(), 0);
  // A generated password lives fifteen minutes.
  const gen = world();
  await gen.offers.onGenerated({ tabId: TAB, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
  gen.clock.jump(GENERATED_TTL_MS - 1);
  assert.equal(gen.offers.forTab(TAB).length, 1);
  gen.clock.jump(1);
  assert.deepEqual(gen.offers.forTab(TAB), []);
  // A clock that went back drops what it cannot place.
  const back = world();
  await back.signup();
  back.clock.advance(3000);
  back.clock.set(back.clock.now() - 10_000_000);
  assert.deepEqual(back.offers.forTab(TAB), []);
});

test("offers_are_cleared_on_sign_out_forget_tab_close_restart_capture_off_and_permission_removed", async () => {
  for (const reason of ["lock", "sign_out", "forget", "restart", "capture_off", "permission_removed"]) {
    const w = world();
    await w.signup();
    await w.offers.onGenerated({ tabId: 6, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
    w.openFrame(7, PAGE);
    await w.send({ kind: "identifier", username: "step@example.net", password: undefined }, { tabId: 7 });
    w.clock.advance(3000);
    assert.equal(w.offers.size(), 2, reason);
    w.offers.clear(reason);
    assert.equal(w.offers.size(), 0, reason);
    assert.deepEqual(w.offers.forTab(TAB), [], reason);
    assert.deepEqual(w.offers.forTab(6), [], reason);
  }
  // A closed tab takes only its own offers.
  const w = world();
  await w.signup();
  await w.offers.onGenerated({ tabId: 6, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
  w.offers.clear("tab_closed", { tabId: TAB });
  assert.equal(w.offers.size(), 1);
  assert.equal(w.offers.forTab(6).length, 1);
  assert.throws(() => w.offers.clear("because"), RangeError);

  // A capture that is being judged when a lock comes is not kept.
  const racing = world();
  const pending = racing.signup();
  racing.offers.clear("lock");
  await pending;
  assert.equal(racing.offers.size(), 0);
});

test("never_clears_the_offers_of_that_host", async () => {
  const w = world();
  await w.signup();
  w.openFrame(8, "https://shop.example.org/login");
  await w.signup({ self_origin: "https://shop.example.org" }, { tabId: 8, url: "https://shop.example.org/login" });
  w.clock.advance(3000);
  const session = "1".repeat(32);
  const [mine] = w.offers.forTab(TAB, session);
  const [theirs] = w.offers.forTab(8, session);
  // Another offer for the same host in another tab goes with it.
  w.openFrame(9, PAGE);
  await w.signup({}, { tabId: 9 });
  w.clock.advance(3000);
  assert.equal(w.offers.size(), 3);
  w.offers.dismiss(mine.offer_id, { never: true });
  assert.equal(w.offers.forTab(TAB).length, 0);
  assert.equal(w.offers.forTab(9).length, 0, "every offer of that host");
  assert.equal(w.offers.forTab(8).length, 1, "another host is left alone");
  assert.deepEqual(w.neverAdded, [["login.example.net", { incognito: false }]]);
  assert.equal(w.offers.take(theirs.offer_id, session)?.origin, "https://shop.example.org");
  // "Not now" drops only that offer and never touches the list.
  const again = world();
  await again.signup();
  again.clock.advance(3000);
  const [one] = again.offers.forTab(TAB, session);
  again.offers.dismiss(one.offer_id);
  assert.equal(again.offers.size(), 0);
  assert.deepEqual(again.neverAdded, []);
});

test("an_offer_can_be_written_once", async () => {
  const w = world();
  await w.signup();
  w.clock.advance(3000);
  const session = "2".repeat(32);
  const [offer] = w.offers.forTab(TAB, session);
  // A page session that was not told of the offer cannot read or take it, whatever it guesses.
  assert.equal(w.offers.peek(offer.offer_id, "3".repeat(32)), null);
  assert.equal(w.offers.take(offer.offer_id, "3".repeat(32)), null);
  assert.equal(w.offers.peek("nothing", session), null);
  assert.equal(w.offers.peek(offer.offer_id, ""), null);
  // `peek` leaves it; `take` gives it once.
  assert.equal(w.offers.peek(offer.offer_id, session)?.password, PASSWORD);
  assert.equal(w.offers.peek(offer.offer_id, session)?.password, PASSWORD);
  const taken = w.offers.take(offer.offer_id, session);
  assert.equal(taken?.password, PASSWORD);
  assert.equal(w.offers.take(offer.offer_id, session), null);
  assert.equal(w.offers.peek(offer.offer_id, session), null);
  assert.deepEqual(w.offers.forTab(TAB), []);
  // A page that has gone can no longer read what it was told of.
  const gone = world();
  await gone.signup();
  gone.clock.advance(3000);
  const [kept] = gone.offers.forTab(TAB, session);
  gone.offers.endSession(session);
  assert.equal(gone.offers.take(kept.offer_id, session), null);
});

test("take_after_dismiss_returns_null", async () => {
  const w = world();
  await w.signup();
  w.clock.advance(3000);
  const session = "4".repeat(32);
  const [offer] = w.offers.forTab(TAB, session);
  w.offers.dismiss(offer.offer_id);
  assert.equal(w.offers.take(offer.offer_id, session), null);
  assert.equal(w.offers.peek(offer.offer_id, session), null);
  w.offers.dismiss(offer.offer_id);
  w.offers.dismiss("not-an-id", { never: true });
});

test("floods_and_oversized_captures_are_dropped", async () => {
  const w = world();
  // One per frame in two seconds: the second, a moment later, is dropped (it does not replace the first).
  await w.signup();
  w.clock.advance(FRAME_GAP_MS - 1);
  await w.signup({ password: "Flood-PASSWORD-2" });
  w.clock.advance(3000);
  assert.equal(w.offers.peek(w.offers.forTab(TAB, "5".repeat(32))[0].offer_id, "5".repeat(32))?.password, PASSWORD);
  // Twenty per tab in a minute.
  const busy = world();
  for (let i = 0; i < TAB_MAX + 5; i += 1) {
    await busy.send({ kind: "identifier", username: `user${i}@example.net`, password: undefined });
    busy.clock.advance(FRAME_GAP_MS + 1);
  }
  busy.clock.advance(1);
  // The 21st capture within the minute was dropped; one minute later the tab may send again.
  busy.clock.advance(61_000);
  await busy.signup();
  assert.equal(busy.offers.size(), 1);
  // Oversized values and messages never get in.
  const big = world();
  await big.signup({ password: "p".repeat(1025) });
  big.clock.advance(FRAME_GAP_MS + 1);
  await big.signup({ username: "u".repeat(513) });
  big.clock.advance(FRAME_GAP_MS + 1);
  await big.signup({ username: "u".repeat(512), password: "p".repeat(1024), current_password: "c".repeat(1024), extra: "x".repeat(MAX_MESSAGE) });
  big.clock.advance(FRAME_GAP_MS + 1);
  await big.signup({ password: 12345 });
  big.clock.advance(FRAME_GAP_MS + 1);
  await big.signup({ kind: "totally_new" });
  big.clock.advance(FRAME_GAP_MS + 1);
  await big.signup({ password: "" });
  big.clock.advance(FRAME_GAP_MS + 1);
  await big.signup({ kind: "change", password: undefined, current_password: "Old-password-1" });
  big.clock.advance(FRAME_GAP_MS + 1);
  assert.equal(big.offers.size(), 0);
  // The largest the protocol allows (user name 512, two passwords of 1 024) is within the message limit and is held.
  const max = world();
  await max.signup({ username: "u".repeat(512), password: "p".repeat(1024), kind: "change", current_password: "c".repeat(1024) });
  assert.equal(max.offers.size(), 1);

  // At most four offers per tab and sixteen in all: the oldest go.
  const caps = world();
  for (let i = 0; i < MAX_OFFERS_PER_TAB + 2; i += 1) {
    await caps.offers.onGenerated({ tabId: TAB, frameId: 0, frameUrl: `https://login${i}.example.net/`, kind: "signup", password: `Generated-by-Ferret-${i}` });
    caps.clock.advance(10);
  }
  assert.equal(caps.offers.forTab(TAB).length, MAX_OFFERS_PER_TAB);
  assert.equal(caps.offers.forTab(TAB).some((o) => o.host.a_label === "login0.example.net"), false, "the oldest went");
  for (let tab = 100; tab < 100 + MAX_OFFERS; tab += 1) {
    for (let i = 0; i < MAX_OFFERS_PER_TAB; i += 1) {
      await caps.offers.onGenerated({ tabId: tab, frameId: 0, frameUrl: `https://tab${tab}-${i}.example.net/`, kind: "signup", password: `Generated-by-Ferret-${tab}-${i}` });
      caps.clock.advance(10);
    }
  }
  assert.equal(caps.offers.size(), MAX_OFFERS);
});

test("a_never_listed_host_gets_no_offer", async () => {
  const w = world({ never: ["login.example.net"] });
  await w.signup();
  await w.send({ kind: "login" });
  w.clock.advance(FRAME_GAP_MS + 1);
  assert.equal(w.offers.size(), 0);
  assert.equal(await w.offers.onGenerated({ tabId: TAB, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" }), null);
  assert.equal(w.offers.size(), 0);
  // Another host is not affected.
  w.openFrame(8, "https://shop.example.org/login");
  await w.signup({ self_origin: "https://shop.example.org" }, { tabId: 8, url: "https://shop.example.org/login" });
  assert.equal(w.offers.size(), 1);
});

test("never_from_a_private_window_is_kept_in_memory_only", async () => {
  // The offer knows whether its tab is private and tells the list; the list keeps a private choice in memory only.
  const w = world();
  w.privateTabs.add(TAB);
  await w.signup();
  w.clock.advance(3000);
  const [offer] = w.offers.forTab(TAB);
  w.offers.dismiss(offer.offer_id, { never: true });
  assert.deepEqual(w.neverAdded, [["login.example.net", { incognito: true }]]);

  /** @type {Array<Record<string, unknown>>} */
  const writes = [];
  const storage = { get: async () => ({}), set: async (/** @type {Record<string, unknown>} */ items) => void writes.push(items) };
  const list = createNeverList({ storageLocal: storage });
  await list.add("login.example.net", { incognito: true });
  assert.equal(await list.has("login.example.net"), true, "kept for this browser session");
  assert.deepEqual(writes, [], "never written to the disk");
  await list.add("shop.example.org", { incognito: false });
  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0], { capture_never: ["shop.example.org"] });
  assert.deepEqual(await list.list(), ["login.example.net", "shop.example.org"]);
  // A new list over the same storage (a browser restart) has only what was written.
  const restarted = createNeverList({ storageLocal: { get: async () => writes[0], set: async () => {} } });
  assert.equal(await restarted.has("login.example.net"), false);
  assert.equal(await restarted.has("shop.example.org"), true);
});

test("a_private_window_capture_works_like_a_normal_one", async () => {
  for (const isPrivate of [false, true]) {
    const w = world();
    if (isPrivate) w.privateTabs.add(TAB);
    await w.signup();
    w.clock.advance(3000);
    const session = "6".repeat(32);
    const [offer] = w.offers.forTab(TAB, session);
    assert.ok(offer, `private: ${isPrivate}`);
    assert.equal(w.offers.take(offer.offer_id, session)?.password, PASSWORD);
  }
});

test("the_badge_follows_the_ready_offers_of_a_tab_and_a_saved_login_is_not_offered", async () => {
  /** @type {Array<[number, number]>} */
  const badges = [];
  const w = world({ badges });
  await w.signup();
  assert.deepEqual(badges.filter(([tab]) => tab === TAB).at(-1) ?? [TAB, 0], [TAB, 0], "nothing is ready yet");
  w.clock.advance(3000);
  w.offers.forTab(TAB);
  assert.deepEqual(badges.at(-1), [TAB, 1]);
  w.offers.clear("lock");
  assert.deepEqual(badges.at(-1), [TAB, 0]);

  // The write path can say that the vault holds the login already: then nothing is offered.
  const saved = world({ classify: async () => ({ action: "none" }) });
  await saved.signup();
  saved.clock.advance(3000);
  saved.offers.forTab(TAB);
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.deepEqual(saved.offers.forTab(TAB), []);
  // An offer that is not known to be saved stays, and so does one whose classification failed.
  for (const classify of [async () => ({ action: "save" }), async () => Promise.reject(new Error("vault_locked")), async () => null]) {
    const kept = world({ classify });
    await kept.signup();
    kept.clock.advance(3000);
    kept.offers.forTab(TAB);
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(kept.offers.forTab(TAB).length, 1);
  }
});

test("an_identifier_capture_is_never_an_offer_by_itself", async () => {
  const w = world();
  await w.send({ kind: "identifier", username: "step@example.net", password: undefined });
  // Not a badge, not an offer, not a classification, however long it waits and whatever the tab does.
  await w.landOn();
  w.clock.advance(60_000);
  assert.equal(w.offers.size(), 0);
  assert.deepEqual(w.offers.forTab(TAB), []);
});

test("a_capture_of_an_inconsistent_shape_is_refused_and_never_filled_in", async () => {
  /** @type {Array<[string, Record<string, any>]>} */
  const refused = [
    ["an identifier with a password", { kind: "identifier", password: PASSWORD }],
    ["an identifier with a current password", { kind: "identifier", password: undefined, current_password: PASSWORD }],
    ["an identifier with no user name", { kind: "identifier", password: undefined, username: undefined, username_from: undefined }],
    ["an identifier whose name came from the page", { kind: "identifier", password: undefined, username_from: "page" }],
    ["a login with no password", { kind: "login", password: undefined }],
    ["a login with only a current password", { kind: "login", password: undefined, current_password: PASSWORD }],
    ["a login with a current password", { kind: "login", current_password: "Old-password-1" }],
    ["a sign-up with a current password", { kind: "signup", current_password: "Old-password-1" }],
    ["a reset with a current password", { kind: "reset", current_password: "Old-password-1" }],
    ["a change with only a current password", { kind: "change", password: undefined, current_password: "Old-password-1" }],
    ["a source with no user name", { kind: "signup", username: undefined, username_from: "typed" }],
    ["a source of another kind", { kind: "signup", username_from: "guess" }],
  ];
  for (const [name, over] of refused) {
    const w = world();
    await w.send(over);
    w.clock.advance(3000);
    assert.equal(w.offers.size(), 0, name);
    assert.deepEqual(w.offers.forTab(TAB), [], name);
  }
  // A user name with no source is the page's, never the person's.
  const page = world();
  await page.signup({ username_from: undefined });
  page.clock.advance(3000);
  const [offer] = page.offers.forTab(TAB, "7".repeat(32));
  assert.equal(page.offers.peek(offer.offer_id, "7".repeat(32))?.usernameFrom, "page");
  // And a login's password is the password field's, not a current password.
  const login = world();
  await login.send();
  assert.equal(login.offers.size(), 1);
});

test("a_join_request_gives_its_user_name_to_the_generated_offer_of_its_own_frame_and_document_and_is_never_an_offer", async () => {
  const w = world();
  const id = await w.offers.onGenerated({ tabId: TAB, frameId: 0, documentId: `doc-${TAB}-0`, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
  assert.ok(id);
  const session = "8".repeat(32);
  assert.equal(w.offers.forTab(TAB, session)[0].username, null);
  // The form was submitted with the generated password, which the script cannot send: no password at all, the user name
  // as usual. It joins by tab, frame and document.
  w.clock.advance(1000);
  await w.signup({ password: undefined, username: "ola@example.net" });
  const [joined] = w.offers.forTab(TAB, session);
  assert.equal(joined.offer_id, id);
  assert.equal(joined.username, "ola@example.net");
  assert.equal(w.offers.size(), 1, "no offer of its own");
  assert.equal(w.offers.peek(id, session)?.password, "Generated-by-Ferret-9", "the password stays the generator's");
  assert.equal(w.offers.peek(id, session)?.usernameFrom, "typed");
  w.clock.advance(5000);
  assert.equal(w.offers.size(), 1);

  // Not by value, and not by another document, frame or tab: such a request is dropped and changes nothing.
  for (const [name, senderOver, openAt] of /** @type {Array<[string, Record<string, any>, number | null]>} */ ([
    ["another document", { documentId: "doc-other" }, null],
    ["another frame", { frameId: 2, url: "https://login.example.net/embedded" }, 2],
    ["another tab", { tabId: 9 }, 9],
  ])) {
    const x = world();
    await x.offers.onGenerated({ tabId: TAB, frameId: 0, documentId: `doc-${TAB}-0`, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
    if (openAt === 9) x.openFrame(9, PAGE);
    if (openAt === 2) x.openFrame(TAB, "https://login.example.net/embedded", {}, 2);
    await x.signup({ password: undefined, username: "ola@example.net" }, senderOver);
    assert.equal(x.offers.forTab(TAB)[0].username, null, name);
    assert.equal(x.offers.size(), 1, name);
    assert.equal(x.offers.forTab(9).length, 0, name);
  }
  // With no generated offer at all the request is nothing; for a login or an identifier it is not a join request.
  const none = world();
  await none.signup({ password: undefined });
  await none.send({ kind: "login", password: undefined });
  none.clock.advance(5000);
  assert.equal(none.offers.size(), 0);
  // The same for a change and a reset form.
  for (const kind of ["change", "reset"]) {
    const k = world();
    await k.offers.onGenerated({ tabId: TAB, frameId: 0, documentId: `doc-${TAB}-0`, frameUrl: PAGE, kind: /** @type {any} */ (kind), password: "Generated-by-Ferret-9" });
    await k.send({ kind, password: undefined, username: "ola@example.net" });
    assert.equal(k.offers.forTab(TAB)[0].username, "ola@example.net", kind);
    assert.equal(k.offers.size(), 1, kind);
  }
});
