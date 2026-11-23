// The character rules a new-password field states (src/content/passwordRules.mjs): which of the generator's four classes it
// refuses, read from `passwordrules` and `pattern`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { classesAllowedBy, classesRefusedByPattern, refusedClasses } from "../../src/content/passwordRules.mjs";

/** A field with these attributes. @param {Record<string, string>} attributes */
const field = (attributes) => ({ getAttribute: (/** @type {string} */ name) => attributes[name] ?? null });

test("passwordrules_name_the_classes_a_field_allows", () => {
  assert.deepEqual([...(classesAllowedBy("minlength: 8; maxlength: 12; required: lower; required: digit; allowed: upper;") ?? [])].sort(), ["digit", "lower", "upper"]);
  assert.deepEqual([...(classesAllowedBy("allowed: upper, lower, digit, special") ?? [])].sort(), ["digit", "lower", "symbol", "upper"]);
  assert.deepEqual([...(classesAllowedBy("allowed: ascii-printable") ?? [])].sort(), ["digit", "lower", "symbol", "upper"]);
  assert.deepEqual([...(classesAllowedBy("allowed: unicode") ?? [])].sort(), ["digit", "lower", "symbol", "upper"]);
  // Only `required` rules restrict nothing, and a text that says nothing of the kind gives none.
  assert.equal(classesAllowedBy("required: lower; required: upper; minlength: 10"), null);
  assert.equal(classesAllowedBy(""), null);
  assert.equal(classesAllowedBy("nonsense"), null);
  assert.equal(classesAllowedBy(`allowed: lower; ${"x".repeat(2000)}`), null);
  // A custom set allows the symbol class only when it holds every symbol the generator uses.
  assert.deepEqual([...(classesAllowedBy("allowed: upper, lower, digit, [-().&@?'#,/\"+]") ?? [])].sort(), ["digit", "lower", "upper"]);
  assert.deepEqual([...(classesAllowedBy("allowed: lower, [!#$%&*+-.:=?@^_~]") ?? [])].sort(), ["lower", "symbol"]);
  // A `;` inside a set does not end the rule.
  assert.deepEqual([...(classesAllowedBy("allowed: lower, [;!]; required: digit") ?? [])].sort(), ["digit", "lower"]);
});

test("a_pattern_refuses_the_classes_its_accepted_strings_do_not_take", () => {
  const refused = (/** @type {string} */ pattern, min = null, max = null) => [...classesRefusedByPattern(pattern, min, max)].sort();
  assert.deepEqual(refused("[A-Za-z0-9]{8,12}", 8, 12), ["symbol"]);
  assert.deepEqual(refused("[A-Za-z0-9]+"), ["symbol"]);
  assert.deepEqual(refused("[a-z0-9]{8,}"), ["symbol", "upper"]);
  assert.deepEqual(refused("[A-Z0-9]{8,}"), ["lower", "symbol"]);
  assert.deepEqual(refused("[A-Za-z]{10,}"), ["digit", "symbol"]);
  // Look-aheads that ask for a class do not refuse the others.
  assert.deepEqual(refused("(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"), []);
  // A pattern that asks for a symbol has no symbol-free string it accepts: nothing is said, and the symbol class stays.
  assert.deepEqual(refused("(?=.*[!@#$%^&*]).{8,}"), []);
  assert.deepEqual(refused("[A-Za-z0-9!#$%&*+\\-.:=?@^_~]{8,32}"), []);
  // Only some of the symbols: the class is refused, the core cannot choose among them.
  assert.deepEqual(refused("[A-Za-z0-9!@#]{8,32}"), ["symbol"]);
  // A pattern no probe string satisfies, an invalid one and an empty one say nothing.
  assert.deepEqual(refused("[a-z]{4}"), []);
  assert.deepEqual(refused("[unclosed"), []);
  assert.deepEqual(refused(""), []);
  assert.deepEqual(refused("x".repeat(2000)), []);
  // The page's own limits choose the probe length.
  assert.deepEqual(refused("[A-Za-z0-9]{8,12}", null, 10), ["symbol"]);
});

test("a_field_gives_the_union_of_its_rules_and_never_all_four_classes", () => {
  assert.deepEqual(refusedClasses(field({ passwordrules: "minlength: 8; maxlength: 12; required: lower; required: digit; allowed: upper;", minlength: "8", maxlength: "12", pattern: "[A-Za-z0-9]{8,12}" })), ["symbol"]);
  assert.deepEqual(refusedClasses(field({ passwordrules: "allowed: lower, digit" })), ["upper", "symbol"]);
  assert.deepEqual(refusedClasses(field({ pattern: "[a-z]{8,}", passwordrules: "allowed: lower" })), ["upper", "digit", "symbol"]);
  assert.deepEqual(refusedClasses(field({})), []);
  assert.deepEqual(refusedClasses(field({ minlength: "8" })), []);
  // A rule that would leave no class at all is not taken as it stands.
  assert.deepEqual(refusedClasses(field({ passwordrules: "allowed: [x]" })), []);
  // An element that throws gives nothing.
  assert.deepEqual(refusedClasses({ getAttribute() { throw new Error("x"); } }), []);
});
