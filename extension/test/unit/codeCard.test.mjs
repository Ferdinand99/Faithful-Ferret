// The live one-time code card of the popup (pages/codeCard.mjs): the code is grouped for reading, the countdown follows
// the clock and asks for the next code when the period is over, a screen reader is told only when the code changes, a
// refusal clears the code, and the card ends its timer when it is stopped. It runs on a small stand-in for the DOM and a
// clock and timers the test moves.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { pkg } from "./sessionHelpers.mjs";

// The card imports the shared DOM helpers, which exist only in a build: it is loaded from the built package.
/** @type {typeof import("../../src/pages/codeCard.mjs")} */
const { CODE_PLACEHOLDER, createCodeCard, groupCode } = await (await pkg()).load("pages/codeCard.mjs");

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "..", "src");
/** @param {string} lang */
const catalog = (lang) => JSON.parse(readFileSync(join(src, "locales", lang, "popup.json"), "utf8"));

// ------------------------------------------------------------------ a small DOM

class FakeNode {
  /** @param {number} nodeType */
  constructor(nodeType) {
    this.nodeType = nodeType;
    /** @type {FakeNode | null} */
    this.parentNode = null;
    /** @type {FakeNode[]} */
    this.childNodes = [];
  }

  /** @param {FakeNode} child */
  appendChild(child) {
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }
}

class FakeText extends FakeNode {
  /** @param {string} data */
  constructor(data) {
    super(3);
    this.data = data;
  }

  get textContent() {
    return this.data;
  }
}

class FakeElement extends FakeNode {
  /** @param {string} tagName */
  constructor(tagName) {
    super(1);
    this.tagName = tagName.toUpperCase();
    /** @type {Map<string, string>} */
    this.attributes = new Map();
    /** @type {Array<[string, (event: any) => void]>} */
    this.listeners = [];
    /** How many times the text was written (a live region is read each time). */
    this.writes = 0;
  }

  /** @param {string} name @param {string} value */
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  /** @param {string} name */
  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  /** @param {string} type @param {(event: any) => void} fn */
  addEventListener(type, fn) {
    this.listeners.push([type, fn]);
  }

  get textContent() {
    return this.childNodes.map((c) => /** @type {any} */ (c).textContent).join("");
  }

  set textContent(text) {
    this.childNodes = [new FakeText(String(text))];
    this.writes += 1;
  }

  click() {
    for (const [type, fn] of this.listeners) if (type === "click") fn({ type });
  }

  /** @param {string} role @returns {FakeElement} */
  byRole(role) {
    /** @type {FakeElement[]} */
    const out = [];
    const walk = (/** @type {FakeNode} */ n) => {
      if (n instanceof FakeElement && n.getAttribute("data-role") === role) out.push(n);
      for (const c of n.childNodes) walk(c);
    };
    walk(this);
    return out[0];
  }
}

/** @type {any} */ (globalThis).document = {
  createElement: (/** @type {string} */ tag) => new FakeElement(tag),
  createTextNode: (/** @type {string} */ data) => new FakeText(data),
};

/** @param {string} lang */
const textsOf = (lang) => (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) =>
  (catalog(lang)[key] ?? `?${key}`).replace(/\{(\w+)\}/g, (/** @type {string} */ all, /** @type {string} */ name) => (name in vars ? String(vars[name]) : all));

/** A clock and timers that move only when the test moves them. */
function world() {
  let now = 1_000_000;
  /** @type {Map<number, { at: number, fn: () => void }>} */
  const waiting = new Map();
  let next = 1;
  return {
    now: () => now,
    timers: {
      setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
        const id = next++;
        waiting.set(id, { at: now + ms, fn });
        return id;
      },
      clearTimeout: (/** @type {number} */ id) => {
        waiting.delete(id);
      },
    },
    /** Moves the clock by one second at a time, running the timers that fall due, and lets the answers land. @param {number} seconds */
    async run(seconds) {
      for (let i = 0; i < seconds; i += 1) {
        now += 1000;
        for (const [id, timer] of [...waiting]) {
          if (timer.at <= now) {
            waiting.delete(id);
            timer.fn();
          }
        }
        await settle();
      }
    },
    pending: () => waiting.size,
  };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * A card whose background answers from `answers` (one per ask).
 * @param {Array<{ ok: boolean, reason?: string, code?: string, seconds_left?: number }>} answers
 * @param {{ fill?: boolean, quiet?: boolean }} [options]
 */
function cardOf(answers, { fill = true, quiet = false } = {}) {
  const w = world();
  /** @type {boolean[]} */
  const asked = [];
  /** @type {Array<string | undefined>} */
  const refused = [];
  const done = { copy: 0, fill: 0 };
  const card = createCodeCard({
    t: textsOf("en"),
    fetchCode: async (automatic) => {
      asked.push(automatic);
      const answer = answers.shift();
      if (!answer) throw Object.assign(new Error("vault_locked"), { code: "vault_locked" });
      return answer;
    },
    copy: () => {
      done.copy += 1;
    },
    fill: fill ? () => {
      done.fill += 1;
    } : null,
    onRefused: (reason) => refused.push(reason),
    now: w.now,
    timers: w.timers,
    quiet,
  });
  const root = /** @type {FakeElement} */ (/** @type {unknown} */ (card.root));
  return { w, card, root, asked, refused, done, code: root.byRole("totp-code"), left: root.byRole("totp-left") };
}

test("a_code_is_grouped_three_and_three_or_four_and_four", () => {
  assert.equal(groupCode("081804"), "081 804");
  assert.equal(groupCode("07081804"), "0708 1804");
  assert.equal(groupCode("123456789"), "123 456 789");
  assert.equal(groupCode("1234567"), "1234567");
  assert.equal(groupCode("12ab"), "12ab");
  assert.equal(CODE_PLACEHOLDER, "••• •••");
});

test("the_card_shows_the_code_and_counts_the_seconds_down_and_asks_again_when_the_period_is_over", async () => {
  const { w, code, left, asked } = cardOf([
    { ok: true, code: "081804", seconds_left: 3 },
    { ok: true, code: "287082", seconds_left: 30 },
  ]);
  assert.equal(code.textContent, CODE_PLACEHOLDER, "before the first answer nothing is shown");
  await settle();
  assert.equal(code.textContent, "081 804");
  assert.equal(left.textContent, "Changes in 3 s");
  await w.run(1);
  assert.equal(left.textContent, "Changes in 2 s");
  await w.run(1);
  assert.equal(left.textContent, "Changes in 1 s");
  assert.equal(code.textContent, "081 804");
  // The period ends: the card asks again by itself, and the new code shows.
  await w.run(1);
  assert.equal(code.textContent, "287 082");
  assert.equal(left.textContent, "Changes in 30 s");
  // The first ask is the user's, the next is the page's own.
  assert.deepEqual(asked, [false, true]);
});

test("a_screen_reader_hears_the_code_only_when_it_changes", async () => {
  const { w, code, left } = cardOf([
    { ok: true, code: "081804", seconds_left: 4 },
    { ok: true, code: "287082", seconds_left: 30 },
  ]);
  await settle();
  assert.equal(code.getAttribute("aria-live"), "polite");
  assert.equal(code.getAttribute("aria-atomic"), "true");
  // The countdown is a timer, which announces nothing by itself, and is not a live region.
  assert.equal(left.getAttribute("role"), "timer");
  assert.equal(left.getAttribute("aria-live"), null);
  const writes = code.writes;
  await w.run(3);
  assert.equal(code.writes, writes, "three ticks did not write the code");
  assert.ok(left.writes >= 3, "the countdown is written every second");
  await w.run(1);
  assert.equal(code.writes, writes + 1, "the new code was written once");
});

test("the_same_code_twice_does_not_write_the_live_region_again", async () => {
  const { w, code } = cardOf([
    { ok: true, code: "081804", seconds_left: 1 },
    { ok: true, code: "081804", seconds_left: 1 },
  ]);
  await settle();
  const writes = code.writes;
  await w.run(1);
  assert.equal(code.writes, writes);
});

test("a_refusal_clears_the_code_and_ends_the_card", async () => {
  const { w, code, left, refused, asked } = cardOf([
    { ok: true, code: "081804", seconds_left: 2 },
    { ok: false, reason: "vault_locked" },
  ]);
  await settle();
  assert.equal(code.textContent, "081 804");
  await w.run(2);
  assert.equal(code.textContent, CODE_PLACEHOLDER, "nothing of the code stays on show");
  assert.equal(left.textContent, "");
  assert.deepEqual(refused, ["vault_locked"]);
  assert.equal(w.pending(), 0, "no timer is left");
  await w.run(5);
  assert.equal(asked.length, 2, "it does not ask again");

  // A background that does not answer at all (the page was refused) ends it the same way.
  const dead = cardOf([]);
  await settle();
  assert.equal(dead.code.textContent, CODE_PLACEHOLDER);
  assert.deepEqual(dead.refused, ["vault_locked"]);
  assert.equal(dead.w.pending(), 0);
});

test("stopping_the_card_ends_its_timer_and_its_asking", async () => {
  const { w, card, asked, code } = cardOf([
    { ok: true, code: "081804", seconds_left: 2 },
    { ok: true, code: "287082", seconds_left: 30 },
  ]);
  await settle();
  assert.equal(w.pending(), 1);
  card.stop();
  assert.equal(w.pending(), 0);
  await w.run(5);
  assert.deepEqual(asked, [false]);
  assert.equal(code.textContent, "081 804");
  // An answer that lands after the stop shows nothing.
  const late = cardOf([{ ok: true, code: "111111", seconds_left: 5 }]);
  late.card.stop();
  await settle();
  assert.equal(late.code.textContent, CODE_PLACEHOLDER);
});

test("a_card_built_by_the_popup_itself_asks_quietly_the_first_time", async () => {
  const { asked } = cardOf([{ ok: true, code: "081804", seconds_left: 10 }], { quiet: true });
  await settle();
  assert.deepEqual(asked, [true]);
});

test("copy_and_fill_are_buttons_and_fill_is_absent_where_nothing_can_be_filled", async () => {
  const withFill = cardOf([{ ok: true, code: "081804", seconds_left: 10 }]);
  const copy = withFill.root.byRole("totp-copy");
  const fill = withFill.root.byRole("totp-fill");
  assert.equal(copy.tagName, "BUTTON");
  assert.equal(copy.textContent, "Copy one-time code");
  assert.equal(fill.textContent, "Fill the code");
  copy.click();
  fill.click();
  assert.deepEqual(withFill.done, { copy: 1, fill: 1 });
  const without = cardOf([{ ok: true, code: "081804", seconds_left: 10 }], { fill: false });
  assert.equal(without.root.byRole("totp-fill"), undefined);
  assert.ok(without.root.byRole("totp-copy"));
});

test("the_card_has_its_texts_in_both_languages_and_no_markup_or_style", () => {
  const code = readFileSync(join(src, "pages", "codeCard.mjs"), "utf8");
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "style="]) assert.equal(code.includes(sink), false, sink);
  for (const lang of ["en", "nb"]) {
    const texts = catalog(lang);
    for (const key of ["popup.totp.left", "popup.row.fill_totp", "popup.row.copy_totp", "popup.item.totp", "popup.filled_totp", "popup.error.no_code_field"]) {
      assert.ok(typeof texts[key] === "string" && texts[key].trim() !== "", `${lang}: ${key}`);
    }
  }
  assert.match(catalog("nb")["popup.totp.left"], /\{seconds\}/);
});
