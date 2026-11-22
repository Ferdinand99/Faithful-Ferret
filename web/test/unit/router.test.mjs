import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createRouter, matchRoute, parseHash } from "../../src/router.mjs";
import { web } from "./helpers.mjs";

const home = { path: "/", title: "home.title", load: () => null };
const login = { path: "/login", title: "login.title", load: () => null };
const item = { path: "/items/:id", title: "items.title", load: () => null };
const fresh = { path: "/items/new", title: "items.new", load: () => null };
const routes = [home, login, item, fresh];
const notFound = { path: "*", title: "app.notfound.title", load: () => null };

/** A window whose hash change fires `hashchange` at once, like a browser's would soon after. */
function fakeWindow(initial = "") {
  const listeners = [];
  let hash = initial;
  return {
    location: {
      get hash() {
        return hash;
      },
      set hash(value) {
        hash = value;
        for (const fn of listeners) fn();
      },
    },
    addEventListener: (type, fn) => type === "hashchange" && listeners.push(fn),
  };
}

test("router_parses_hash_routes_and_rejects_unknown", () => {
  assert.equal(parseHash(""), "/");
  assert.equal(parseHash("#"), "/");
  assert.equal(parseHash("#/"), "/");
  assert.equal(parseHash("#/login"), "/login");
  assert.equal(parseHash("#/items/abc-1"), "/items/abc-1");
  for (const bad of ["#login", "#//login", "#/login/", "#/a//b", "#/login?x=1", "#/<script>", "#/a b", "#/a;b", "#/\u0000", null, 5]) {
    assert.equal(parseHash(/** @type {any} */ (bad)), null, String(bad));
  }

  assert.equal(matchRoute(routes, "/")?.route, home);
  assert.equal(matchRoute(routes, "/login")?.route, login);
  assert.deepEqual({ ...matchRoute(routes, "/items/abc")?.params }, { id: "abc" });
  assert.equal(matchRoute(routes, "/items/new")?.route, fresh, "a literal wins over a parameter");
  for (const miss of ["/nope", "/login/x", "/items", "/items/a/b", "/Login"]) {
    assert.equal(matchRoute(routes, miss), null, miss);
  }

  const seen = [];
  const win = fakeWindow("#/login");
  const router = createRouter({ routes, notFound, win, onChange: (m) => seen.push(m) });
  router.start();
  assert.equal(seen[0].route, login);
  assert.equal(seen[0].found, true);
  assert.equal(router.current(), "/login");
  router.go("/items/9");
  assert.equal(seen[1].route, item);
  assert.deepEqual({ ...seen[1].params }, { id: "9" });
  win.location.hash = "#/nowhere";
  assert.equal(seen[2].route, notFound);
  assert.equal(seen[2].found, false);
  win.location.hash = "#/a?b";
  assert.equal(seen[3].route, notFound);
  // Going where we already are shows the page again; a bad path throws.
  router.go("/a");
  assert.throws(() => router.go("javascript:alert(1)"), TypeError);
  assert.throws(() => router.go("//evil"), TypeError);
  assert.throws(() => router.go("/items/%3Cb%3E/../x"), TypeError);
});

test("router_never_executes_route_params", () => {
  // A parameter is a plain string value: markup, script and encoded dots never match.
  for (const hostile of ["%3Cscript%3Ealert(1)%3C%2Fscript%3E", "alert(1)", "%2e%2e", "..", ".", "%2F", "a%00b", "%E0%A4%A", "x".repeat(129), "a b", "%3Cimg%20src%3Dx%3E"]) {
    const hit = matchRoute(routes, `/items/${hostile}`);
    if (hit) assert.fail(`${hostile} matched as ${JSON.stringify(hit.params)}`);
  }
  // A valid value arrives as the string it is, on an object without a prototype.
  const hit = matchRoute(routes, "/items/alert.1");
  assert.equal(hit?.params.id, "alert.1");
  assert.equal(Object.getPrototypeOf(hit?.params), null);
  assert.equal(matchRoute(routes, "/items/__proto__")?.params.id, "__proto__");
  assert.equal(({}).polluted, undefined);
  // And the module has no way to run text as code.
  const source = readFileSync(join(web, "src", "router.mjs"), "utf8");
  for (const sink of [/\beval\s*\(/, /new\s+Function/, /\.innerHTML/, /document\.write/, /import\s*\(/, /setTimeout\s*\(\s*["'`]/]) {
    assert.doesNotMatch(source, sink);
  }
});

test("a_query_after_the_path_reaches_the_route_and_a_change_of_only_the_query_does_not_build_the_screen_again", () => {
  const list = { path: "/items", title: "items.list", load: () => null };
  const seen = [];
  const win = fakeWindow("#/items?type=login");
  const router = createRouter({ routes: [home, list, item], notFound, win, onChange: (m) => seen.push(m) });
  router.start();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].route, list);
  assert.equal(seen[0].query, "type=login");
  assert.equal(router.query(), "type=login");

  // Without a screen that follows its query, a new query builds the screen as for any new address.
  win.location.hash = "#/items?type=note";
  assert.equal(seen.length, 2);
  assert.equal(seen[1].query, "type=note");

  // A screen that follows the query is told, and nothing is built again.
  const told = [];
  const off = router.watchQuery((query) => told.push(query));
  win.location.hash = "#/items?fav=1";
  win.location.hash = "#/items";
  win.location.hash = "#/items";
  assert.deepEqual(told, ["fav=1", ""], "told once for each change, not for the same query");
  assert.equal(seen.length, 2);
  assert.equal(router.query(), "");

  // Another path builds a screen and drops the watchers.
  win.location.hash = "#/items/7";
  assert.equal(seen.length, 3);
  assert.equal(seen[2].route, item);
  assert.equal(seen[2].query, "");
  win.location.hash = "#/items?a=1";
  win.location.hash = "#/items?a=2";
  assert.deepEqual(told, ["fav=1", ""], "the watcher of the screen that left hears nothing");
  off();
});

test("go_and_replace_take_a_path_with_a_plain_query_and_refuse_anything_else", () => {
  const win = fakeWindow("#/");
  win.location.replaced = [];
  const original = Object.getOwnPropertyDescriptor(win.location, "hash");
  win.location.replace = (hash) => {
    win.location.replaced.push(hash);
    original.set.call(win.location, hash);
  };
  const router = createRouter({ routes: [home, { path: "/items", title: "t", load: () => null }], notFound, win, onChange() {} });
  router.start();
  router.go("/items?type=login&fav=1");
  assert.equal(win.location.hash, "#/items?type=login&fav=1");
  router.replace("/items?fav=1");
  assert.deepEqual(win.location.replaced, ["#/items?fav=1"]);
  for (const bad of ["/items?<x>", "/items?a b", "/items?a;b", "/items?" + "a".repeat(300), "//evil?x=1", "javascript:alert(1)"]) {
    assert.throws(() => router.go(bad), TypeError, bad);
    assert.throws(() => router.replace(bad), TypeError, bad);
  }
});
