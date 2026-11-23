// A one-time code split over one box per digit: the boxes are one field of one group (src/content/forms.mjs), and
// the fill engine (src/content/fill.mjs) puts one digit into each box, only when the code has as many digits as
// there are boxes and every box passes every check.
import assert from "node:assert/strict";
import { test } from "node:test";
import { findGroups } from "../../src/content/forms.mjs";
import { createFillEngine } from "../../src/content/fill.mjs";
import { BACKGROUND_SENDER, EXTENSION_BASE, RUNTIME_ID, addInput, createPage, decodeSent, fillMessage } from "./fakeDom.mjs";

/** @param {any} input */
const valueOf = (input) => /** @type {any} */ (Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")).get.call(input);

/**
 * A code form with `n` boxes of one digit each, side by side.
 * @param {number} n @param {Record<string, string>} [extra] attributes of every box
 */
function boxesPage(n, extra = {}) {
  const page = createPage();
  const { document } = page;
  const form = document.body.append(document.createElement("form", { id: "otp-form" }));
  const row = form.append(document.createElement("div", { role: "group", "aria-label": "Verification code" }));
  const boxes = Array.from({ length: n }, (_, i) => {
    const box = addInput(document, row, { id: `d${i + 1}`, name: `d${i + 1}`, type: "text", inputmode: "numeric", maxlength: "1", pattern: "[0-9]", "aria-label": String(i + 1), ...extra }, { left: 100 + i * 50, top: 100, width: 42, height: 40 });
    box.form = form;
    return box;
  });
  const sent = /** @type {string[]} */ ([]);
  const engine = createFillEngine({ window: page.window, document, send: (raw) => { sent.push(raw); }, runtimeId: RUNTIME_ID, extensionBase: EXTENSION_BASE });
  return { ...page, form, boxes, engine, sent };
}

/** Begins a request and returns the reported fields. @param {ReturnType<typeof boxesPage>} p */
function begin(p) {
  p.sent.length = 0;
  assert.equal(p.engine.begin("req-1"), true);
  return decodeSent(p.sent)[0].body.fields;
}

/** Sends a code and returns the answer. @param {ReturnType<typeof boxesPage>} p @param {string} code */
function fillCode(p, code) {
  p.sent.length = 0;
  p.engine.onMessage(fillMessage({ field: "totp", value: code }), BACKGROUND_SENDER);
  return decodeSent(p.sent)[0]?.body;
}

test("split_otp_boxes_are_one_group_and_get_one_digit_each", () => {
  // Six boxes: one group, one code field made of six boxes, reported once.
  const six = boxesPage(6);
  const [group] = findGroups(six.document);
  assert.equal(group.kind, "otp");
  assert.deepEqual(group.otp, six.boxes);
  assert.deepEqual(group.fields.map((f) => f.kind), Array(6).fill("otp_digit"));
  const fields = begin(six);
  assert.deepEqual(fields.map((/** @type {any} */ f) => f.kind), ["totp"]);
  assert.deepEqual(fillCode(six, "147036"), { request_id: "req-1", ok: true });
  assert.deepEqual(six.boxes.map(valueOf), ["1", "4", "7", "0", "3", "6"]);
  // Each box got its input and change events, as typing would give.
  for (const box of six.boxes) assert.deepEqual(box.events, ["input", "change"]);

  // Four to eight boxes of the numeric shape are a split code.
  for (const n of [4, 8]) {
    const p = boxesPage(n);
    assert.equal(findGroups(p.document)[0].kind, "otp", `${n} boxes`);
  }
  // Three boxes, or nine, are not a split code.
  for (const n of [3, 9]) {
    const p = boxesPage(n);
    assert.notEqual(findGroups(p.document)[0].kind, "otp", `${n} boxes`);
    assert.deepEqual(begin(p), [], `${n} boxes: nothing reported`);
  }

  // A code with another number of digits than boxes: nothing goes in.
  const four = boxesPage(4);
  begin(four);
  assert.deepEqual(fillCode(four, "147036"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.deepEqual(four.boxes.map(valueOf), ["", "", "", ""]);
  // Not digits: nothing goes in.
  const letters = boxesPage(6);
  begin(letters);
  assert.equal(fillCode(letters, "14703a")?.ok, false);
  assert.deepEqual(letters.boxes.map(valueOf), Array(6).fill(""));

  // One box hidden or covered after the report: no box gets a digit.
  const hidden = boxesPage(6);
  begin(hidden);
  hidden.boxes[3].style.opacity = "0";
  assert.deepEqual(fillCode(hidden, "147036"), { request_id: "req-1", ok: false, reason: "hidden" });
  assert.deepEqual(hidden.boxes.map(valueOf), Array(6).fill(""));
  const covered = boxesPage(6);
  begin(covered);
  const cover = covered.document.body.append(covered.document.createElement("div"));
  cover.rect = { left: 290, top: 95, width: 60, height: 50 };
  cover.z = 10;
  assert.deepEqual(fillCode(covered, "147036"), { request_id: "req-1", ok: false, reason: "covered" });
  assert.deepEqual(covered.boxes.map(valueOf), Array(6).fill(""));
  // A box hidden before the report: the boxes are no code field the user can see, and nothing is reported.
  const early = boxesPage(6);
  early.boxes[0].style.display = "none";
  assert.deepEqual(begin(early), []);

  // Masked boxes (a PIN pad typed as password): never a code field, nothing reported.
  const masked = boxesPage(6, { type: "password" });
  assert.deepEqual(begin(masked), []);

  // A box that moved to another form after the report: nothing goes in.
  const moved = boxesPage(6);
  begin(moved);
  moved.boxes[5].form = null;
  assert.deepEqual(fillCode(moved, "147036"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.deepEqual(moved.boxes.map(valueOf), Array(6).fill(""));
});

test("the_frame_check_gets_the_points_of_the_boxes", () => {
  const p = boxesPage(8);
  begin(p);
  const where = /** @type {any} */ (p.engine.where("req-1", "totp"));
  // One point per box for a code of up to eight boxes, so a cover over any box in the middle is seen by the frame check.
  assert.equal(where.points.length, 8);
  assert.deepEqual(where.points[0], [121, 120]);
  assert.deepEqual(where.points.at(-1), [100 + 7 * 50 + 21, 120]);
  p.boxes[2].style.visibility = "hidden";
  assert.deepEqual(p.engine.where("req-1", "totp"), { problem: "hidden" });
});
