// The numbers of the matrix without a browser: what counts toward which rate, what is unsafe, and what
// the gate needs. The runner (test/firefox/matrix.mjs) produces the results these tests make up by hand.
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fillsIn, mergePhases, scanDocs, shortcutWentToAnExtensionPage, unreadableOf } from "../firefox/matrix.mjs";
import { computeMatrix, ruleMatches, unsafeFillsOf, unsafeOffersOf, writeReport } from "../firefox/matrixReport.mjs";
import { base32, recentCodes, totpAt } from "../firefox/totp.mjs";

const ENTRIES = {
  forms: { url: "https://forms.example.net/", matching: "host" },
  domain: { url: "https://app.forms.example.org/", matching: "domain", domain: "example.org" },
};
const ORIGIN = "https://forms.example.net";

/** A case with what every case has. @param {Record<string, any>} over */
function makeCase(over) {
  const { expect = {}, ...rest } = over;
  return {
    id: "x-1", class: "positive", category: "login", lang: "en", host: "forms.example.net", path: "/x-1/", frame: null, steps: [],
    must_stay_empty: [], fields: {}, source: "own", dir: "/nowhere",
    expect: { fill: null, generated: null, capture: null, ...expect },
    ...rest,
  };
}

/** A positive case that expects both fields to be filled. @param {string} id @param {string} [category] */
const filling = (id, category = "login") => makeCase({ id, category, expect: { fill: { entry: "forms", fields: { "#u": "username", "#p": "password" } } } });
/** A positive case that expects a save offer from #p. @param {string} id @param {string} [category] */
const capturing = (id, category = "login") => makeCase({ id, category, expect: { capture: { offer: "save", username: "anna@example.net", password_from: "#p", origin: ORIGIN } } });

const DOC = `${ORIGIN}/x-1/`;
/** The observation of a fill that worked. */
const filled = () => ({ fills: [{ entry: "forms", kind: "username", id: "#u", docUrl: DOC }, { entry: "forms", kind: "password", id: "#p", docUrl: DOC }], tried: [{ entry: "forms", ok: true }] });
/** The offer that matches `capturing`. @param {Record<string, any>} [over] */
const offer = (over = {}) => ({ type: "save", origin: ORIGIN, username: "anna@example.net", password_field: "#p", ...over });

/**
 * A result of a case that ran.
 * @param {Record<string, any>} c @param {Record<string, any>} [observed] @param {{ fill?: boolean, capture?: boolean }} [ran]
 */
const ran = (c, observed = {}, { fill = true, capture = true } = {}) => ({ case: c, ran: { fill, capture }, observed: { fills: [], tried: [], entries: ENTRIES, offers: [], generated: null, ...observed } });

test("matrix_rate_counts_only_positive_cases", () => {
  const results = [
    ran(filling("login-a"), filled()),
    ran(filling("login-b"), filled()),
    ran(filling("login-c"), filled()),
    ran(filling("login-d"), { tried: [{ entry: "forms", ok: true }] }),
    // A negative case that fails its own checks, and a special case that fails, do not touch the rates.
    ran(makeCase({ id: "harmless-a", class: "negative", category: "harmless", expect: { no_offer: true } }), { offers: [offer()] }),
    ran(makeCase({ id: "lookalike-a", class: "special", category: "lookalike", expect: { capture: { offer: "save", username: null, password_from: "#p", origin: ORIGIN } } })),
  ];
  const m = computeMatrix(results, { part: "fill" });
  assert.deepEqual([m.fill.passed, m.fill.total, m.fill.rate], [3, 4, 0.75]);
  assert.equal(m.capture.selected, false);
  const both = computeMatrix(results, { part: "all" });
  assert.deepEqual(both.falseOffers.cases, ["harmless-a"], "the harmless negative that got an offer is reported");
  assert.deepEqual([both.capture.passed, both.capture.total], [0, 0], "no positive case here expects a capture");
  assert.equal(both.perCategory.lookalike.total, 1, "a special category has its own line");
});

test("a_category_below_80_percent_fails_the_gate", () => {
  /** @param {number} good */
  const run = (good) => {
    const results = [];
    for (let i = 0; i < 100; i += 1) results.push(ran(filling(`login-${i}`), filled()));
    for (let i = 0; i < 5; i += 1) results.push(ran(filling(`change-${i}`, "change"), i < good ? filled() : { tried: [{ entry: "forms", ok: true }] }));
    return computeMatrix(results, { part: "fill" });
  };
  const weak = run(3);
  assert.ok(weak.fill.rate !== null && weak.fill.rate >= 0.95, `the overall rate is ${weak.fill.rate}`);
  assert.equal(weak.perCategory.change.rate, 0.6);
  assert.equal(weak.met, false, "one weak category fails the gate although the overall rate is high");
  assert.equal(run(4).met, true, "four of five is 80 %: the floor is met (positive control)");
  assert.equal(run(5).met, true);
});

test("one_unsafe_fill_or_unsafe_offer_fails_the_gate", () => {
  const good = () => [ran(filling("login-a"), filled()), ran(capturing("login-b"), { offers: [offer()] }), ran(makeCase({ id: "harmless-a", class: "negative", category: "harmless", expect: { no_offer: true } }))];
  assert.equal(computeMatrix(good()).gate, true, "positive control: nothing unsafe");
  const unsafeFill = good();
  unsafeFill.push(ran(makeCase({ id: "hidden-a", class: "negative", category: "hidden", must_stay_empty: ["#trap"], expect: { no_offer: true } }),
    { fills: [{ entry: "forms", kind: "password", id: "#trap", docUrl: DOC }] }));
  const a = computeMatrix(unsafeFill);
  assert.equal(a.unsafeFills.length, 1);
  assert.equal(a.unsafeFills[0].reason, "must_stay_empty");
  assert.equal(a.gate, false);
  const unsafeOffer = good();
  unsafeOffer.push(ran(makeCase({ id: "insecure-a", class: "negative", category: "insecure", expect: { no_offer: true } }), { offers: [offer({ origin: "http://forms.example.net" })] }));
  const b = computeMatrix(unsafeOffer);
  assert.ok(b.unsafeOffers.some((x) => x.reason === "offer_in_a_case_with_no_login"));
  assert.equal(b.gate, false);
});

test("a_cvc_value_in_an_offer_and_an_update_on_another_host_are_unsafe", () => {
  const card = makeCase({ id: "card-a", class: "negative", category: "card", fields: { "#cvc": "card_cvc" }, expect: { no_offer: true } });
  const fromCvc = unsafeOffersOf(ran(card, { offers: [offer({ password_field: "#cvc" })] }));
  assert.ok(fromCvc.some((x) => x.reason === "value_from_cvc_pin_or_code_field"), JSON.stringify(fromCvc));
  // The same holds in a case that is not a "never" case: the marked field is what decides.
  const login = makeCase({ id: "login-z", fields: { "#pin": "pin" }, expect: { capture: { offer: "save", username: null, password_from: "#p", origin: ORIGIN } } });
  assert.ok(unsafeOffersOf(ran(login, { offers: [offer({ password_field: "#pin" })] })).some((x) => x.reason === "value_from_cvc_pin_or_code_field"));
  assert.deepEqual(unsafeOffersOf(ran(login, { offers: [offer()] })), [], "an offer from the right field is fine (positive control)");

  const update = makeCase({ id: "login-u", expect: { capture: { offer: "update", username: "ola", password_from: "#p", origin: ORIGIN, target: "forms" } } });
  const own = offer({ type: "update", username: "ola", target_entry: "forms", target_host: "forms.example.net", target_match: "host" });
  assert.deepEqual(unsafeOffersOf(ran(update, { offers: [own] })), [], "an update of an entry on the capture's own host is fine (positive control)");
  assert.deepEqual(unsafeOffersOf(ran(update, { offers: [{ ...own, target_host: "login.example.net" }] })).map((x) => x.reason), ["update_on_another_host"]);
  assert.deepEqual(unsafeOffersOf(ran(update, { offers: [{ ...own, target_match: "domain" }] })).map((x) => x.reason), ["domain_update_without_an_explicit_pick"]);
  assert.deepEqual(unsafeOffersOf(ran(update, { offers: [{ ...own, target_match: "domain", picked: true }] })), [], "a domain hit the person picked from a list");
  assert.deepEqual(unsafeOffersOf(ran(update, { offers: [{ ...own, written_without_click: true }] })).map((x) => x.reason), ["write_without_a_click"]);
  assert.deepEqual(unsafeOffersOf(ran(update, { offers: [{ ...own, origin: "https://evil.example.org" }] })).map((x) => x.reason).sort(), ["update_on_another_host", "wrong_origin"].sort());

  const flood = makeCase({ id: "flood-a", class: "negative", category: "flood", expect: { no_offer: false, max_offers: 1 } });
  assert.deepEqual(unsafeOffersOf(ran(flood, { offers: [offer()] })), [], "one offer is the limit");
  assert.deepEqual(unsafeOffersOf(ran(flood, { offers: [offer(), offer()] })).map((x) => x.reason), ["more_offers_than_allowed"]);
});

test("a_fill_of_an_item_whose_rule_does_not_match_is_unsafe", () => {
  const c = filling("login-a");
  const elsewhere = (/** @type {string} */ docUrl) => ran(c, { ...filled(), fills: [{ entry: "forms", kind: "username", id: "#u", docUrl }, { entry: "forms", kind: "password", id: "#p", docUrl }] });
  assert.deepEqual(unsafeFillsOf(elsewhere(DOC)), [], "the entry's own host (positive control)");
  for (const docUrl of ["https://forms-evil.test/x/", "https://www.forms.example.net/x/", "http://forms.example.net/x/", "about:srcdoc", "about:blank", "not a url"]) {
    const found = unsafeFillsOf(elsewhere(docUrl));
    assert.deepEqual(found.map((x) => x.reason), ["rule_mismatch", "rule_mismatch"], docUrl);
    assert.equal(computeMatrix([elsewhere(docUrl)], { part: "fill" }).met, false, `${docUrl}: the gate`);
  }
  // The rules themselves.
  assert.equal(ruleMatches(ENTRIES.forms, "https://forms.example.net/a?b#c"), true);
  assert.equal(ruleMatches(ENTRIES.forms, "https://forms.example.net:8443/"), false, "another port is another host");
  assert.equal(ruleMatches(ENTRIES.domain, "https://www.forms.example.org/"), true);
  assert.equal(ruleMatches(ENTRIES.domain, "https://login.example.net/"), false);
  assert.equal(ruleMatches(ENTRIES.domain, "https://forms-example.org/"), false, "a dash is not a dot");
  assert.equal(ruleMatches({ url: "https://a.example.net/x", matching: "exact" }, "https://a.example.net/x#y"), true);
  assert.equal(ruleMatches({ url: "https://a.example.net/x", matching: "exact" }, "https://a.example.net/y"), false);
});

test("the_other_unsafe_fills_are_named", () => {
  const field = (/** @type {string} */ id, /** @type {"username" | "password" | "totp"} */ kind, extra = {}) => ({ entry: "forms", kind, id, docUrl: DOC, ...extra });
  const reasons = (/** @type {Record<string, any>} */ c, /** @type {any[]} */ fills) => unsafeFillsOf(ran(c, { fills })).map((x) => x.reason);
  const signup = makeCase({ id: "signup-a", category: "signup", fields: { "#pw": "new_password" }, expect: { allow: ["#email"], capture: { offer: "save", username: null, password_from: "#pw", origin: ORIGIN } } });
  assert.deepEqual(reasons(signup, [field("#pw", "password")]), ["stored_password_in_new_password"]);
  assert.deepEqual(reasons(signup, [field("#email", "username")]), [], "an allowed field");
  assert.deepEqual(reasons(signup, [field("#other", "username")]), ["unexpected_field"]);
  const card = makeCase({ id: "card-a", class: "negative", category: "card", fields: { "#cvc": "card_cvc" }, expect: { no_offer: true } });
  assert.deepEqual(reasons(card, [field("#cvc", "password")]), ["wrong_kind"]);
  const login = filling("login-a");
  assert.deepEqual(reasons(login, [field("#u", "password")]), ["wrong_kind"], "a password in the user name field");
  const otp = makeCase({ id: "otp-a", category: "otp", fields: { "#d1": "otp_digit" }, expect: { fill: { entry: "forms", fields: { "#d1": "totp:0" } } } });
  assert.deepEqual(reasons(otp, [field("#d1", "totp", { index: 0 })]), [], "a code in a code field is the point of the case");
  assert.deepEqual(reasons(otp, [field("#d1", "password")]), ["wrong_kind"]);
});

test("a_case_that_did_not_run_counts_as_failed", () => {
  const passing = [ran(filling("login-a"), filled()), ran(filling("login-b"), filled())];
  assert.equal(computeMatrix(passing, { part: "fill" }).met, true, "positive control");
  const notRun = { case: filling("login-c"), ran: { fill: false, capture: false }, error: "the page did not load" };
  const m = computeMatrix([...passing, notRun], { part: "fill" });
  assert.deepEqual(m.notRun, ["login-c"]);
  assert.deepEqual([m.fill.passed, m.fill.total], [2, 3], "the case is in the total and not in the passed");
  assert.equal(m.met, false);
  assert.ok(m.misses.some((x) => x.id === "login-c" && x.reason.includes("the page did not load")));
  // A negative case that did not run blocks the gate too, although it has no rate.
  const negative = { case: makeCase({ id: "harmless-a", class: "negative", category: "harmless", expect: { no_offer: true } }), ran: { fill: false, capture: false } };
  const n = computeMatrix([...passing, negative], { part: "fill" });
  assert.deepEqual(n.notRun, ["harmless-a"]);
  assert.equal(n.met, false);
  // A part that was not selected is not a failure.
  assert.equal(computeMatrix([...passing, { case: makeCase({ id: "harmless-b", class: "negative", category: "harmless", expect: { no_offer: true } }), ran: { fill: true, capture: false } }], { part: "fill" }).met, true);
});

test("the_capture_check_wants_one_offer_of_the_right_kind_from_the_right_field", () => {
  const c = capturing("login-a");
  /** @param {Record<string, any>} [over] @param {number} [n] */
  const run = (over = {}, n = 1) => computeMatrix([ran(c, { offers: Array.from({ length: n }, () => offer(over)) })], { part: "capture" });
  assert.equal(run().capture.rate, 1);
  for (const [name, m] of /** @type {Array<[string, ReturnType<typeof run>]>} */ ([
    ["the type", run({ type: "update", target_host: "forms.example.net", target_match: "host" })],
    ["the user name", run({ username: "other" })],
    ["the field", run({ password_field: "#q" })],
    ["no offer", run({}, 0)],
    ["two offers", run({}, 2)],
  ])) {
    assert.equal(m.capture.rate, 0, name);
    assert.equal(m.misses.length, 1, name);
  }
});

test("the_generator_is_a_measure_of_its_own_and_part_of_the_gate_but_not_of_the_capture_check", () => {
  const gen = makeCase({ id: "signup-a", category: "signup", expect: { generated: { new: "#pw", confirm: "#pw2" }, capture: { offer: "save", username: "anna@example.net", password_from: "#pw", origin: ORIGIN } } });
  // A correct offer passes the capture check without any generator observation.
  const captured = computeMatrix([ran(gen, { offers: [offer({ password_field: "#pw" })] })], { part: "capture" });
  assert.equal(captured.capture.rate, 1, "capture does not ask for the generator");
  assert.equal(captured.generated.total, 1);
  assert.deepEqual(captured.generated.notRun, ["signup-a"], "the generator did not run: reported, in its own line");
  assert.equal(captured.met, false, "a generator pass that did not run counts as failed in the gate");
  // The generator pass has its own result.
  /** @param {string[]} filled */
  const withGenerator = (filled) => computeMatrix([{ ...ran(gen, { offers: [offer({ password_field: "#pw" })], generated: { filled } }), ran: { fill: true, capture: true, generated: true } }], { part: "capture" });
  assert.deepEqual([withGenerator(["#pw", "#pw2"]).generated.passed, withGenerator(["#pw", "#pw2"]).generated.total], [1, 1]);
  const half = withGenerator(["#pw"]);
  assert.equal(half.generated.passed, 0);
  assert.ok(half.misses.some((x) => x.part === "generated" && x.reason.includes("#pw2")), "the miss names the field");
  assert.equal(half.capture.rate, 1, "a failed generator does not fail the capture");
  assert.equal(half.met, false, "but it fails the gate");
  assert.equal(withGenerator(["#pw", "#pw2"]).met, true, "positive control");
  // A field that is neither new nor confirm holding the value is a miss too.
  const stray = computeMatrix([{ ...ran(gen, { offers: [offer({ password_field: "#pw" })], generated: { filled: ["#pw", "#pw2"], stray: ["#cur"] } }), ran: { fill: true, capture: true, generated: true } }], { part: "capture" });
  assert.equal(stray.generated.passed, 0);
  assert.ok(stray.misses.some((x) => x.part === "generated" && x.reason.includes("#cur")), "the miss names the field");
  // The fill part does not run the generator.
  assert.equal(computeMatrix([ran(gen)], { part: "fill" }).generated.selected, false);
});

test("a_partial_run_has_no_gate_and_says_so", () => {
  const results = [ran(filling("login-a"), filled()), ran(capturing("login-b"), { offers: [offer()] })];
  assert.equal(computeMatrix(results, { part: "all" }).gate, true, "a complete run that meets everything");
  const fillOnly = computeMatrix(results, { part: "fill" });
  assert.equal(fillOnly.gate, false);
  assert.equal(fillOnly.met, true);
  const some = computeMatrix(results, { part: "all", grep: "login-a" });
  assert.equal(some.gate, false);
  const dir = mkdtempSync(join(tmpdir(), "ferret-matrix-"));
  try {
    writeReport(dir, "release", fillOnly);
    writeReport(dir, "esr", some);
    const text = readFileSync(join(dir, "matrix.md"), "utf8");
    assert.ok(text.includes("PARTIAL RUN (fill part): no gate; the part is met"), text);
    assert.ok(text.includes("PARTIAL RUN (some cases, cases matching login-a)"), text);
    assert.equal(text.includes("GATE MET"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a_change_of_the_vault_during_a_case_is_a_write_without_a_click", () => {
  const c = capturing("login-a");
  assert.deepEqual(unsafeOffersOf(ran(c, { offers: [offer()], vault_changed: false })), [], "an unchanged vault (positive control)");
  const reasons = unsafeOffersOf(ran(c, { offers: [offer()], vault_changed: true })).map((x) => x.reason);
  assert.deepEqual(reasons, ["write_without_a_click"], "whatever the extension says about itself");
  assert.equal(computeMatrix([ran(c, { offers: [offer()], vault_changed: true })], { part: "capture" }).gate, false);
});

test("a_frame_the_scan_cannot_read_is_reported_and_not_skipped", async () => {
  // A stand-in session: the top document has one frame, and the driver cannot enter it.
  let content = 0;
  const session = /** @type {any} */ ({
    switchToTopFrame: async () => {},
    switchToParentFrame: async () => {},
    findAll: async () => [{ id: "frame" }],
    switchToFrame: async () => {
      throw new Error("no such frame");
    },
    content: async () => {
      content += 1;
      return content === 1 ? { url: "https://forms.example.net/x/", inputs: [{ id: "u", type: "text", value: "" }] } : 1;
    },
  });
  const rows = await scanDocs(session);
  assert.equal(unreadableOf(rows).length, 1, JSON.stringify(rows));
  assert.deepEqual(rows.filter((r) => r.type !== "unreadable").map((r) => r.id), ["u"]);
  assert.equal(unreadableOf([{ type: "text" }]).length, 0, "a readable page has none (positive control)");
});

test("only_a_shortcut_that_went_to_an_extension_page_is_tried_again_and_retries_are_counted", () => {
  const message = (/** @type {string} */ tabUrl) => new Error(`release: the shortcut on https://forms.example.net/x/ gave no activeTab ({"kind":"command","tabId":2,"tabUrl":"${tabUrl}"})`);
  assert.equal(shortcutWentToAnExtensionPage(message("moz-extension://5c1d6b3e/test/bridge.html")), true, "the command went to the bridge tab");
  assert.equal(shortcutWentToAnExtensionPage(message("https://forms.example.net/x/")), false, "it reached the page: a failure of the extension");
  assert.equal(shortcutWentToAnExtensionPage(new Error('{"tabUrl":"moz-extension://x/"} but another error')), false, "another error");
  assert.equal(shortcutWentToAnExtensionPage(new Error("gave no activeTab ({\"kind\":\"command\",\"tabUrl\":null})")), false, "no address at all");
  // The count reaches the report.
  const c = filling("login-a");
  const retried = { ...ran(c, filled()), observed: { ...ran(c, filled()).observed, retries: 2 } };
  const m = computeMatrix([retried, ran(filling("login-b"), filled())], { part: "fill" });
  assert.deepEqual(m.retries, { total: 2, cases: [{ id: "login-a", retries: 2 }] });
  const dir = mkdtempSync(join(tmpdir(), "ferret-matrix-"));
  try {
    writeReport(dir, "release", m);
    assert.ok(readFileSync(join(dir, "matrix.md"), "utf8").includes("shortcut retries (the command went to the bridge tab) | | 2 | login-a x2"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the_phases_of_a_case_are_merged_into_one_result", () => {
  const c = filling("login-a");
  const merged = mergePhases(
    [{ case: c, ran: { fill: true, capture: false }, observed: { fills: [], tried: [{ entry: "forms", ok: true }] } }],
    [{ case: c, ran: { fill: false, capture: true }, observed: { offers: [offer()], vault_changed: false }, error: "late" }],
    [{ case: c, ran: { fill: false, capture: false, generated: true }, observed: { generated: { filled: ["#pw"] } } }],
  );
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].ran, { fill: true, capture: true, generated: true });
  assert.equal(merged[0].observed?.offers?.length, 1);
  assert.equal(merged[0].observed?.vault_changed, false);
  assert.deepEqual(merged[0].observed?.generated, { filled: ["#pw"] });
  assert.equal(merged[0].error, "late");
});

test("the_hold_out_set_has_no_category_floor_and_needs_90_percent", () => {
  const results = [];
  for (let i = 0; i < 9; i += 1) results.push(ran(filling(`login-${i}`), filled()));
  results.push(ran(filling("login-9"), { tried: [{ entry: "forms", ok: true }] }));
  assert.equal(computeMatrix(results, { set: "holdout", part: "fill" }).met, true, "nine of ten");
  assert.equal(computeMatrix(results, { set: "corpus", part: "fill" }).met, false, "the corpus needs 95 %");
  assert.equal(computeMatrix(results, { set: "holdout", part: "fill" }).meta.set, "holdout");
});

test("report_lists_every_miss_with_its_reason", () => {
  const dir = mkdtempSync(join(tmpdir(), "ferret-matrix-"));
  try {
    const results = [
      ran(filling("login-a"), filled()),
      ran(filling("login-b"), { tried: [{ entry: "forms", ok: false, reason: "no_fields" }] }),
      ran(filling("login-c"), { tried: [{ entry: "forms", ok: true }] }),
      { case: filling("login-d"), ran: { fill: false, capture: false }, error: "the page did not load" },
      ran(makeCase({ id: "hidden-a", class: "negative", category: "hidden", must_stay_empty: ["#trap"], expect: { no_offer: true } }), { fills: [{ entry: "forms", kind: "password", id: "#trap", docUrl: DOC }] }),
    ];
    const m = computeMatrix(results, { part: "fill", manifest: "mv2" });
    writeReport(dir, "release", m);
    writeReport(dir, "esr", computeMatrix(results.slice(0, 1), { part: "fill", manifest: "mv2" }));
    assert.deepEqual(readdirSync(dir).sort(), ["esr-mv2.json", "matrix.md", "release-mv2.json"]);
    const text = readFileSync(join(dir, "matrix.md"), "utf8");
    // Every miss is in the text with its reason.
    for (const miss of m.misses) assert.ok(text.includes(`${miss.id} (${miss.category}, ${miss.part}): ${miss.reason}`), `the report names ${miss.id}`);
    assert.ok(text.includes("login-b (login, fill): fill refused: no_fields"));
    assert.ok(text.includes("did not run: the page did not load"));
    assert.ok(text.includes("hidden-a (hidden): must_stay_empty in #trap"), "the unsafe fill with its field");
    assert.ok(text.includes("## release (mv2), set corpus, part fill: PARTIAL RUN (fill part): no gate; the part is not met") && text.includes("## esr (mv2), set corpus, part fill: PARTIAL RUN (fill part): no gate; the part is met"), "both channels are in the text");
    const json = JSON.parse(readFileSync(join(dir, "release-mv2.json"), "utf8"));
    assert.equal(json.channel, "release");
    assert.equal(json.misses.length, m.misses.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the_runner_computes_the_codes_of_rfc_6238_and_finds_a_split_code_by_its_digits", () => {
  // RFC 6238, appendix B (SHA-1): the secret "12345678901234567890" at 59 s gives 94287082; six digits: 287082.
  const secret = base32(new TextEncoder().encode("12345678901234567890"));
  assert.equal(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  assert.equal(totpAt(secret, 1), "287082");
  assert.equal(totpAt(secret, Math.floor(1111111109 / 30)), "081804");
  assert.deepEqual(recentCodes(secret, 59_000), [totpAt(secret, 0), "287082", totpAt(secret, 2)]);
  // A scan: the code whole in one field, its digits in a row of boxes, and the other vault values.
  const doc = "https://forms.example.net/x/";
  const rows = [
    { id: "u", type: "text", value: "ola", docUrl: doc },
    { id: "p", type: "password", value: "pw", docUrl: doc },
    { id: "code", type: "text", value: "287082", docUrl: doc },
    ...[..."287082"].map((d, i) => ({ id: `d${i + 1}`, type: "text", value: d, docUrl: doc })),
    { id: "lone", type: "text", value: "2", docUrl: doc },
  ];
  assert.deepEqual(fillsIn(rows, "forms", "pw", ["287082"]).map((f) => [f.id, f.kind, f.index]), [
    ["#u", "username", undefined], ["#p", "password", undefined], ["#code", "totp", undefined],
    ...[1, 2, 3, 4, 5, 6].map((n) => [`#d${n}`, "totp", n - 1]),
  ]);
  // Digits that are no piece of a code of the entry are no fill.
  assert.deepEqual(fillsIn(rows, "forms", "pw", ["999999"]).map((f) => f.id), ["#u", "#p"]);
  // A code spread over two documents is no whole code; a run of two or more digits in one document that is a piece
  // of a code is a fill of the code with no index (part of a code, or a code in the wrong boxes).
  const split = rows.map((r) => (r.id === "d4" ? { ...r, docUrl: "https://forms.example.net/frame/" } : r));
  assert.deepEqual(fillsIn(split, "forms", "pw", ["287082"]).map((f) => [f.id, f.kind, f.index]), [
    ["#u", "username", undefined], ["#p", "password", undefined], ["#code", "totp", undefined],
    ["#d1", "totp", undefined], ["#d2", "totp", undefined], ["#d3", "totp", undefined],
  ]);
  // The values of radio buttons, check boxes and buttons are the page's (a rating's "1" and "5"), never a fill, whatever the code.
  const rating = [
    { id: "", type: "radio", value: "2", docUrl: doc }, { id: "", type: "radio", value: "8", docUrl: doc },
    { id: "ok", type: "checkbox", value: "7", docUrl: doc }, { id: "go", type: "submit", value: "0", docUrl: doc },
    { id: "mail", type: "email", value: "", docUrl: doc },
  ];
  assert.deepEqual(fillsIn(rating, "forms", "pw", ["287082"]), [], "a pair of radio buttons that spells a piece of the code");
  assert.deepEqual(fillsIn([...rating, { id: "u", type: "text", value: "ola", docUrl: doc }], "forms", "pw", ["287082"]).map((f) => f.id), ["#u"], "a text field beside them is still read");
  // A whole secret is a fill wherever it sits: a radio button or a check box that holds the password, the user name or the code.
  const whole = [
    { id: "r", type: "radio", value: "pw", docUrl: doc }, { id: "c", type: "checkbox", value: "ola", docUrl: doc }, { id: "h", type: "hidden", value: "287082", docUrl: doc },
  ];
  assert.deepEqual(fillsIn(whole, "forms", "pw", ["287082"]).map((f) => [f.id, f.kind]), [["#r", "password"], ["#c", "username"], ["#h", "totp"]]);
  // Four boxes with the first four digits of a six-digit code.
  const four = [..."2870"].map((d, i) => ({ id: `b${i + 1}`, type: "text", value: d, docUrl: doc }));
  assert.deepEqual(fillsIn(four, "forms", "pw", ["287082"]).map((f) => [f.id, f.index]), [["#b1", undefined], ["#b2", undefined], ["#b3", undefined], ["#b4", undefined]]);
});

test("a_typed_new_password_from_the_expected_field_is_not_an_unsafe_offer_but_any_other_must_stay_empty_value_is", () => {
  const signup = makeCase({
    id: "signup-a", category: "signup", must_stay_empty: ["#pw", "#pw2"], fields: { "#pw": "new_password", "#pw2": "confirm_password", "#cvc": "card_cvc", "#cur": "current_password" },
    expect: { capture: { offer: "save", username: "anna@example.net", password_from: "#pw", origin: ORIGIN } },
  });
  // The offer comes from the field the case expects, which is also a field the fill must leave empty: fine (positive control).
  assert.deepEqual(unsafeOffersOf(ran(signup, { offers: [offer({ password_field: "#pw" })] })), []);
  // The same value from the confirm field, a CVC field or a current password is unsafe.
  assert.deepEqual(unsafeOffersOf(ran(signup, { offers: [offer({ password_field: "#pw2" })] })).map((x) => x.reason), ["value_from_a_field_that_must_stay_empty"]);
  assert.deepEqual(unsafeOffersOf(ran(signup, { offers: [offer({ password_field: "#cvc" })] })).map((x) => x.reason), ["value_from_cvc_pin_or_code_field"]);
  assert.deepEqual(unsafeOffersOf(ran(signup, { offers: [offer({ password_field: "#cur" })] })).map((x) => x.reason), ["current_password_offered_as_a_new_one"]);
  // In a negative case every such field stays unsafe, the case's expected source (it has none) included.
  const negative = makeCase({ id: "hidden-b", class: "negative", category: "hidden", must_stay_empty: ["#pw"], expect: { no_offer: true, max_offers: 1, capture: { offer: "save", username: null, password_from: "#pw", origin: ORIGIN } } });
  assert.ok(unsafeOffersOf(ran(negative, { offers: [offer({ password_field: "#pw" })] })).some((x) => x.reason === "value_from_a_field_that_must_stay_empty"));
  // And a login's own current password is the value of a login (positive control).
  const login = makeCase({ id: "login-z", category: "login", fields: { "#p": "current_password" }, expect: { capture: { offer: "save", username: "anna@example.net", password_from: "#p", origin: ORIGIN } } });
  assert.deepEqual(unsafeOffersOf(ran(login, { offers: [offer()] })), []);
});
