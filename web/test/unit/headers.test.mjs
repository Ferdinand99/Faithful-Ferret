import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { STUB_HEADERS_JSON, headersFile, loadHeaders, validateHeaders } from "../serve.mjs";

const good = () => structuredClone(loadHeaders(STUB_HEADERS_JSON));
const csp = (text) => ({ ...good(), "Content-Security-Policy": text });

test("header_loader_accepts_the_stub_and_returns_the_flat_object", () => {
  const headers = good();
  assert.equal(Object.keys(headers).length, 5);
  assert.deepEqual(validateHeaders(headers), headers);
});

test("header_loader_rejects_wrong_shapes_and_types", () => {
  const { "Content-Security-Policy": _csp, ...noCsp } = good();
  const { "Referrer-Policy": _ref, ...noReferrer } = good();
  for (const [label, data] of Object.entries({
    empty: {},
    missing_csp: noCsp,
    missing_other: noReferrer,
    extra: { ...good(), "X-Extra": "1" },
    wrapped_headers: { headers: good() },
    wrapped_vault: { vault: good() },
    both_wrapped: { headers: { "Referrer-Policy": "no-referrer" }, vault: good() },
    wrong_case: Object.fromEntries(Object.entries(good()).map(([k, v]) => [k.toLowerCase(), v])),
    csp_number: { ...good(), "Content-Security-Policy": 5 },
    csp_empty: { ...good(), "Content-Security-Policy": "" },
    other_array: { ...good(), "Referrer-Policy": ["no-referrer"] },
    other_null: { ...good(), "Referrer-Policy": null },
    headers_empty_string: { headers: "" },
    array: [],
    string: "x",
    null: null,
  })) {
    assert.throws(() => validateHeaders(data), /headers:/, label);
  }
});

test("header_loader_rejects_a_weak_csp", () => {
  const full = good()["Content-Security-Policy"];
  for (const [label, text] of Object.entries({
    wildcard: "default-src *",
    default_self: full.replace("default-src 'none'", "default-src 'self'"),
    no_default: full.replace("default-src 'none'; ", ""),
    no_tt_for: full.replace("require-trusted-types-for 'script'; ", ""),
    no_tt_policy: full.replace("; trusted-types ferret", ""),
    other_tt_policy: full.replace("trusted-types ferret", "trusted-types ferret other"),
    duplicates_allowed: full.replace("trusted-types ferret", "trusted-types ferret 'allow-duplicates'"),
    tt_any: full.replace("trusted-types ferret", "trusted-types *"),
    no_frame_ancestors: full.replace("frame-ancestors 'none'; ", ""),
    unsafe_inline: full.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'"),
    unsafe_eval: full.replace("'wasm-unsafe-eval'", "'wasm-unsafe-eval' 'unsafe-eval'"),
    star_source: full.replace("connect-src 'self'", "connect-src *"),
    repeated_default_first: `default-src *; ${full}`,
  })) {
    assert.throws(() => validateHeaders(csp(text)), /CSP lacks/, label);
  }
  // 'wasm-unsafe-eval' is the one eval-like keyword the vault needs.
  assert.doesNotThrow(() => validateHeaders(csp(full)));
});

test("header_file_is_the_server_fixture_and_the_stub_needs_an_explicit_opt_in", () => {
  const repoDir = mkdtempSync(join(tmpdir(), "ferret-headers-"));
  const real = join(repoDir, "crates", "ferret-server", "tests", "fixtures", "wire", "headers.json");

  // No server crate and no opt-in: refuse.
  assert.throws(() => headersFile({ env: {}, repoDir }), /FERRET_HEADERS_STUB=1/);
  assert.throws(() => headersFile({ env: { FERRET_HEADERS_STUB: "yes" }, repoDir }), /FERRET_HEADERS_STUB=1/);
  assert.match(headersFile({ env: { FERRET_HEADERS_STUB: "1" }, repoDir }), /headers\.stub\.json$/);

  // The server crate is there but its fixture is not: refuse, even with the opt-in.
  mkdirSync(join(repoDir, "crates", "ferret-server"), { recursive: true });
  assert.throws(() => headersFile({ env: { FERRET_HEADERS_STUB: "1" }, repoDir }), /fixtures\/wire\/headers\.json is missing/);

  // With the fixture, the fixture is used.
  mkdirSync(join(real, ".."), { recursive: true });
  writeFileSync(real, "{}");
  assert.equal(headersFile({ env: {}, repoDir }), real);
  assert.equal(headersFile({ env: { FERRET_HEADERS_STUB: "1" }, repoDir }), real);
  // And a bad fixture is not served.
  assert.throws(() => loadHeaders(real), /headers:/);
});
