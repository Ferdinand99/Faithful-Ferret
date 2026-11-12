// Page addresses through the binding: `Vault.match_page`, `page_origin`,
// `same_site` and `display_host`, against the vectors of the core and the
// rules of the glue. Run against the build with `test-support`, which has
// the same exports as the release plus the vector operations.
// Run: node --test tests/node/match.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createDispatcher } from "../../bindings/wasm/js/protocol.mjs";
import { LOGIN_DRAFT, NOW, codeOf, fill, newAccount, root, wasm } from "./helpers.mjs";

const vectors = JSON.parse(readFileSync(join(root, "vectors", "internal", "url-match.json"), "utf8"));
const text = (hex) => Buffer.from(hex, "hex").toString("utf8");

function code(fn) {
  const e = codeOf(fn);
  assert.equal(e.name, "FerretError");
  assert.equal(e.message, e.code, "the message is the code and nothing else");
  return e.code;
}

let nextId = 1;

/** Seals `draft` into `vault` and opens it; returns the handle. */
function openItem(vault, draft) {
  const id = fill(16, 0x50);
  id[0] = nextId & 0xff;
  id[1] = (nextId >> 8) & 0xff;
  nextId++;
  const sealed = vault.encrypt_item(id, 1, draft, undefined, NOW);
  return vault.open_item(id, sealed.rev, sealed.envelope, sealed.tag);
}

const loginWith = (urls) => ({ ...LOGIN_DRAFT, urls });

test("binding_agrees_with_the_core_vectors_for_all_four_ops", () => {
  const { vault } = newAccount("match-vectors");
  const seen = { "url.match": 0, "url.page_origin": 0, "url.same_site": 0, "url.display_host": 0 };
  for (const c of vectors.cases) {
    seen[c.op]++;
    const i = c.input;
    switch (c.op) {
      case "url.match": {
        // Through the real export: an item with this one saved address, opened,
        // matched, closed.
        const h = openItem(vault, loginWith([{ url: text(i.entry_utf8), matching: i.match }]));
        try {
          const got = vault.match_page(text(i.page_utf8), [h]);
          const want = c.expect.result === "none" ? [] : [{ handle: h, how: c.expect.result }];
          assert.deepEqual(got, want, c.id);
        } finally {
          vault.close_item(h);
        }
        break;
      }
      case "url.page_origin":
        if (c.status === "valid") {
          assert.equal(wasm.page_origin(text(i.page_utf8)), c.expect.origin, c.id);
        } else {
          assert.equal(code(() => wasm.page_origin(text(i.page_utf8))), c.expect_error, c.id);
        }
        break;
      case "url.same_site":
        assert.equal(wasm.same_site(text(i.a_utf8), text(i.b_utf8)), c.expect.same_site, c.id);
        break;
      case "url.display_host":
        if (c.status === "valid") {
          assert.deepEqual(wasm.display_host(text(i.page_utf8)), c.expect, c.id);
        } else {
          assert.equal(code(() => wasm.display_host(text(i.page_utf8))), c.expect_error, c.id);
        }
        break;
      default:
        assert.fail(`${c.id}: unknown op ${c.op}`);
    }
  }
  for (const [op, n] of Object.entries(seen)) assert.ok(n > 10, `${op} has cases (${n})`);
  assert.equal(
    vectors.cases.every((c) => !c.tags.includes("native-only")),
    true,
    "no case of the file is native only any more",
  );
});

test("match_page_reads_no_secret_field", () => {
  const { vault } = newAccount("match-secrets");
  const h = openItem(vault, loginWith([{ url: "https://example.com", matching: "host" }]));
  const got = vault.match_page("https://example.com/login", [h]);
  assert.deepEqual(got, [{ handle: h, how: "host" }]);
  assert.deepEqual(Object.keys(got[0]).sort(), ["handle", "how"]);
  const json = JSON.stringify(got);
  for (const secret of ["hunter2-secret", "JBSWY3DPEHPK3PXP", "private note text", "alice", "otpauth", "Example"]) {
    assert.ok(!json.includes(secret), secret);
  }
  vault.close_item(h);

  // The list of the methods that return a secret did not change, and the new
  // method is not on it.
  const allowlist = readFileSync(join(root, "bindings", "wasm", "reveal-allowlist.txt"), "utf8")
    .split("\n")
    .map((l) => l.replace(/#.*/, "").trim())
    .filter(Boolean);
  assert.deepEqual(allowlist, [
    "reveal_emergency_sheet", "reveal_item_field", "reveal_item_notes", "reveal_plain_export",
    "reveal_recovery_code", "reveal_secret_key_code", "reveal_totp_secret",
  ]);

  // And the source of the method touches the saved addresses of the body and
  // no other part of it.
  const source = readFileSync(join(root, "bindings", "wasm", "src", "matching.rs"), "utf8");
  const body = source.slice(source.indexOf("pub fn match_page"), source.indexOf("/// The origin of a page address"));
  assert.match(body, /body\s*\.urls/);
  assert.ok(!/\.(fields|notes|totp|passkey|extra)\b|reveal_|view\(/.test(body), "match_page reads urls only");
});

test("match_page_gives_the_best_result_per_item_in_the_order_of_the_handles", () => {
  const { vault } = newAccount("match-best");
  const page = "https://www.example.com/login";
  const domainOnly = openItem(vault, loginWith([{ url: "https://accounts.example.com", matching: "domain" }]));
  const host = openItem(vault, loginWith([{ url: "https://www.example.com", matching: "host" }]));
  const exact = openItem(vault, loginWith([{ url: "https://www.example.com/login#x", matching: "exact" }]));
  const none = openItem(vault, loginWith([{ url: "https://example.org", matching: "domain" }]));
  const noUrls = openItem(vault, loginWith([]));
  // The strongest of the addresses of an item wins, whatever their order.
  const mixed = openItem(
    vault,
    loginWith([
      { url: "https://accounts.example.com", matching: "domain" },
      { url: "https://www.example.com/login", matching: "exact" },
      { url: "https://www.example.com", matching: "host" },
    ]),
  );
  // An address that is no web address does not stop the others of the item.
  const withJunk = openItem(
    vault,
    loginWith([{ url: "example.com", matching: "host" }, { url: "https://www.example.com", matching: "host" }]),
  );
  assert.deepEqual(vault.match_page(page, [none, domainOnly, noUrls, host, exact, mixed, withJunk]), [
    { handle: domainOnly, how: "domain" },
    { handle: host, how: "host" },
    { handle: exact, how: "exact" },
    { handle: mixed, how: "exact" },
    { handle: withJunk, how: "host" },
  ]);
  assert.deepEqual(vault.match_page(page, []), []);
  // A page that is no web page matches nothing: an empty list, not an error.
  assert.deepEqual(vault.match_page("about:blank", [domainOnly, host]), []);
  assert.deepEqual(vault.match_page("", [host]), []);
  // `https` is never offered on `http`.
  assert.deepEqual(vault.match_page("http://www.example.com", [host, domainOnly]), []);
});

test("a_closed_handle_is_invalid_state", () => {
  // The binding's code for a handle that is not open is `invalid_handle`
  // (the same as `item_view`, `reveal_*` and `close_item`).
  const { vault } = newAccount("match-closed");
  const a = openItem(vault, loginWith([{ url: "https://example.com", matching: "host" }]));
  const b = openItem(vault, loginWith([{ url: "https://example.com", matching: "host" }]));
  vault.close_item(a);
  assert.equal(code(() => vault.match_page("https://example.com", [a])), "invalid_handle");
  // One closed handle among open ones fails the whole call: nothing is returned.
  assert.equal(code(() => vault.match_page("https://example.com", [b, a])), "invalid_handle");
  assert.equal(code(() => vault.match_page("https://example.com", [b, 12345])), "invalid_handle");
  assert.deepEqual(vault.match_page("https://example.com", [b]), [{ handle: b, how: "host" }]);
  // Too long a list.
  assert.equal(code(() => vault.match_page("https://example.com", new Uint32Array(4097))), "invalid_input");
  // A locked vault.
  vault.lock();
  assert.equal(code(() => vault.match_page("https://example.com", [b])), "vault_locked");
});

test("page_functions_need_no_vault_and_fail_with_codes_only", () => {
  assert.equal(wasm.page_origin("http://127.0.0.1:8080/x"), "http://127.0.0.1:8080");
  assert.equal(code(() => wasm.page_origin("data:text/html,x")), "malformed_origin");
  assert.equal(code(() => wasm.page_origin("https://user@example.com")), "malformed_origin");
  assert.equal(code(() => wasm.display_host("example.com")), "malformed_origin");
  assert.equal(wasm.same_site("https://a.example.com", "https://b.example.com:8443"), true);
  assert.equal(wasm.same_site("https://example.com", "http://example.com"), false);
  assert.equal(wasm.same_site("about:blank", "about:blank"), false);
  assert.deepEqual(wasm.display_host("https://EXAMPLE.com./x"), { a_label: "example.com", unicode: "example.com" });
});

test("the_dispatcher_checks_the_types_of_the_page_arguments", () => {
  const dispatch = createDispatcher(wasm);
  const ask = (method, args) => dispatch({ id: 1, target: "vault", method, args }).reply;
  // The three functions without a vault work on a locked client.
  assert.deepEqual(ask("page_origin", ["https://example.com:444/a"]), {
    id: 1, ok: true, value: "https://example.com:444",
  });
  assert.equal(ask("same_site", ["https://a.example", "https://b.example"]).value, false);
  assert.deepEqual(ask("display_host", ["https://example.com"]).value, {
    a_label: "example.com", unicode: "example.com",
  });
  // A value that is not a string is `invalid_input`; it is not coerced.
  for (const [method, args] of [
    ["page_origin", [undefined]], ["page_origin", [5]], ["page_origin", [["https://example.com"]]],
    ["same_site", ["https://example.com"]], ["same_site", ["https://example.com", null]],
    ["display_host", [{}]], ["match_page", [null, []]],
  ]) {
    const r = ask(method, args);
    assert.equal(r.ok, false, method);
    assert.equal(r.code, "invalid_input", `${method} ${JSON.stringify(args)}`);
  }
  // The handle list: an array or a `Uint32Array` of whole numbers from 0 to 2^32 - 1.
  const bad = [
    undefined, null, "1", 7, { length: 1, 0: 1 }, [1.5], [-1], ["3"], [4294967296], [NaN], [null], [[1]],
    new Array(4097).fill(1),
  ];
  for (const list of bad) {
    const r = ask("match_page", ["https://example.com", list]);
    assert.equal(r.code, "invalid_input", String(list));
  }
  // A valid list reaches the vault, which is not there.
  assert.equal(ask("match_page", ["https://example.com", [1, 2]]).code, "vault_locked");
  assert.equal(ask("match_page", ["https://example.com", new Uint32Array([1])]).code, "vault_locked");
  assert.equal(ask("match_page", ["https://example.com", []]).code, "vault_locked");
});
