import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_WORKERS, installTrustedTypes } from "../../src/tt.mjs";

const location = { href: "https://vault.test/app/", origin: "https://vault.test" };

/** A window with a Trusted Types factory that wraps the string like the browser does. */
function windowWithTrustedTypes() {
  const created = [];
  const win = {
    location,
    trustedTypes: {
      createPolicy(name, rules) {
        created.push(name);
        return {
          name,
          rules,
          createScriptURL(input) {
            return { trusted: rules.createScriptURL(input) };
          },
        };
      },
    },
  };
  return { win, created };
}

test("trusted_types_policy_allows_only_the_listed_workers", () => {
  const { win, created } = windowWithTrustedTypes();
  const tt = installTrustedTypes(win);
  assert.equal(tt.available, true);
  assert.deepEqual(created, ["ferret"]);
  assert.deepEqual(tt.workerUrl("vault"), { trusted: "/js/vault.worker.mjs" });
  assert.deepEqual(tt.workerUrl("job"), { trusted: "/js/job.worker.mjs" });
  assert.throws(() => tt.workerUrl("other"), TypeError);
  assert.throws(() => tt.workerUrl("__proto__"), TypeError);
  assert.throws(() => tt.workerUrl("constructor"), TypeError);

  // The rules of the policy itself: the page cannot talk it into another URL.
  let captured;
  const probe = installTrustedTypes({
    location,
    trustedTypes: { createPolicy: (_name, r) => ((captured = r), { createScriptURL: (x) => r.createScriptURL(x) }) },
  });
  assert.ok(probe.available);
  const ok = captured.createScriptURL;
  assert.equal(ok("/js/vault.worker.mjs"), "/js/vault.worker.mjs");
  assert.equal(ok("https://vault.test/js/job.worker.mjs"), "/js/job.worker.mjs");
  for (const bad of [
    "/js/other.worker.mjs", // another file
    "/js/vault.worker.mjs?x=1", // a query
    "/js/vault.worker.mjs#x",
    "https://evil.test/js/vault.worker.mjs", // another origin
    "//evil.test/js/vault.worker.mjs",
    "http://vault.test/js/vault.worker.mjs", // another scheme
    "/js/../js/vault.worker.mjs", // dot segments
    "/js/%2e%2e/js/vault.worker.mjs",
    "/js\\vault.worker.mjs",
    "javascript:alert(1)",
    "data:text/javascript,1",
    "blob:https://vault.test/abc",
    "",
    "/js/vault.worker.mjs/",
    5,
    null,
  ]) {
    assert.throws(() => ok(bad), TypeError, String(bad));
  }
});

test("trusted_types_without_support_returns_a_plain_string", () => {
  const tt = installTrustedTypes({ location });
  assert.equal(tt.available, false);
  assert.equal(tt.workerUrl("vault"), "/js/vault.worker.mjs");
  assert.equal(typeof tt.workerUrl("job"), "string");
  assert.throws(() => tt.workerUrl("other"), TypeError);
  // A table entry that names another origin is refused even without the policy.
  const odd = installTrustedTypes({ location }, { vault: "https://evil.test/x.mjs" });
  assert.throws(() => odd.workerUrl("vault"), TypeError);
});

test("trusted_types_table_lists_exactly_the_two_workers_of_this_milestone", () => {
  assert.deepEqual(DEFAULT_WORKERS, { vault: "/js/vault.worker.mjs", job: "/js/job.worker.mjs" });
  assert.ok(Object.isFrozen(DEFAULT_WORKERS));
});
