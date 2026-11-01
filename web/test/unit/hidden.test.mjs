// The screens hide parts of a form with the `hidden` attribute. A style rule that
// sets `display` on the same element (a flex column on a form field, say) beats
// the browser's own rule for the attribute, and the part stays on the page: the
// secret key field was shown to a device that already held the key. One rule at
// the top of the base styles keeps the attribute working everywhere.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const css = readFileSync(new URL("../../src/styles/base.css", import.meta.url), "utf8");

test("the_hidden_attribute_beats_every_display_rule", () => {
  const rule = /\[hidden\]\s*\{([^}]*)\}/.exec(css);
  assert.ok(rule, "base.css has a rule for [hidden]");
  assert.match(rule[1], /display:\s*none\s*!important/);
});
