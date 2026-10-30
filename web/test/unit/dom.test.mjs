import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { clear, el, mount } from "../../src/dom.mjs";
import { FakeText, web, withDocument } from "./helpers.mjs";

test("el_never_uses_innerhtml_and_sets_text_via_textcontent", () => {
  // The source never assigns to an HTML sink.
  const source = readFileSync(join(web, "src", "dom.mjs"), "utf8");
  for (const sink of [/\.innerHTML\s*=/, /\.outerHTML\s*=/, /insertAdjacentHTML/, /document\.write/, /DOMParser/, /createContextualFragment/, /\.srcdoc\s*=/]) {
    assert.doesNotMatch(source, sink);
  }
  // Markup in a string stays text.
  withDocument((document) => {
    const node = el("p", { class: "note" }, "<img src=x onerror=alert(1)>", 7, null, false, undefined);
    assert.equal(node.tagName, "p");
    assert.equal(node.getAttribute("class"), "note");
    assert.equal(node.childNodes.length, 2);
    assert.ok(node.childNodes[0] instanceof FakeText);
    assert.equal(node.childNodes[0].data, "<img src=x onerror=alert(1)>");
    assert.equal(node.childNodes[1].data, "7");
    assert.equal(document.created.length, 1);
  });
});

test("el_rejects_style_innerhtml_srcdoc_and_string_event_handlers", () => {
  withDocument(() => {
    for (const attrs of [
      { style: "color:red" },
      { innerHTML: "<b>x</b>" },
      { outerHTML: "<b>x</b>" },
      { srcdoc: "<b>x</b>" },
      { onclick: "alert(1)" },
      { onclick: 1 },
      { onClick: () => {} },
      { src: "/x.png" },
      { action: "/x" },
      { formaction: "/x" },
      { target: "_blank" },
      { "xlink:href": "#x" },
      { class: {} },
      { class: () => {} },
    ]) {
      assert.throws(() => el("div", /** @type {any} */ (attrs)), TypeError, JSON.stringify(Object.keys(attrs)));
    }
    for (const tag of ["script", "style", "iframe", "object", "embed", "link", "meta", "base", "template", "svg", "math", "DIV", "a b", "", "div>"]) {
      assert.throws(() => el(tag), TypeError, tag);
    }
    assert.throws(() => el("div", null, /** @type {any} */ ({})), TypeError);
    assert.throws(() => el("div", null, /** @type {any} */ ([])), TypeError);
    assert.throws(() => el("div", "text"), TypeError);
    // Allowed things still work.
    let clicks = 0;
    const node = el("button", { type: "button", "aria-label": "x", "data-id": "7", disabled: true, hidden: false, onclick: () => clicks++, tabindex: 0 }, "go");
    assert.equal(node.getAttribute("type"), "button");
    assert.equal(node.getAttribute("aria-label"), "x");
    assert.equal(node.getAttribute("data-id"), "7");
    assert.equal(node.getAttribute("disabled"), "");
    assert.equal(node.getAttribute("hidden"), null);
    assert.equal(node.getAttribute("tabindex"), "0");
    assert.equal(node.listeners.length, 1);
    assert.equal(node.listeners[0][0], "click");
    node.listeners[0][1]();
    assert.equal(clicks, 1);
  });
});

test("el_rejects_javascript_and_external_href", () => {
  withDocument(() => {
    for (const href of [
      "javascript:alert(1)", " javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "blob:https://x/y",
      "https://evil.example/", "http://evil.example/", "//evil.example/", "/\\evil.example", "mailto:a@b", "relative/path", "", "#ok\u0000",
      "/ok\n", 5, {},
    ]) {
      assert.throws(() => el("a", /** @type {any} */ ({ href })), TypeError, String(href));
    }
    assert.equal(el("a", { href: "#/items/1" }).getAttribute("href"), "#/items/1");
    assert.equal(el("a", { href: "/vault/login" }).getAttribute("href"), "/vault/login");
  });
});

test("clear_and_mount_replace_the_children", () => {
  withDocument(() => {
    const root = el("div", null, el("p"), el("p"));
    clear(root);
    assert.equal(root.childNodes.length, 0);
    const a = el("a");
    const b = el("b");
    mount(root, a, b);
    assert.deepEqual(root.childNodes, [a, b]);
    mount(root, b);
    assert.deepEqual(root.childNodes, [b]);
  });
});
