// The shared modules must load in any context that has ES modules: an extension
// page, the background page and its workers. Importing one must not touch
// `window`, `location` or `document` (a call of a function may, once a page
// passes what it needs).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { extensionRoot, repoRoot } from "./buildHelpers.mjs";

test("shared_modules_import_without_window_location_or_document", () => {
  /** @type {string[]} */
  const list = JSON.parse(readFileSync(join(extensionRoot, "shared.json"), "utf8"));
  assert.ok(list.length > 0);
  const urls = list.map((path) => pathToFileURL(join(repoRoot, "web", "src", ...path.split("/"))).href);
  // A fresh process in which reading any of the three names throws, importing every shared module.
  const script = `
    for (const name of ["window", "location", "document"]) {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        get() { throw new Error("a shared module touched " + name + " while it was imported"); },
      });
    }
    const failures = [];
    for (const url of ${JSON.stringify(urls)}) {
      try {
        await import(url);
      } catch (error) {
        failures.push(url + ": " + (error && error.message));
      }
    }
    if (failures.length > 0) { console.error(failures.join("\\n")); process.exit(1); }
    console.log("imported " + ${urls.length});
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, new RegExp(`imported ${list.length}`));

  // The trap itself works: a module that touches `document` at import fails the same run.
  const probe = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", `Object.defineProperty(globalThis, "document", { get() { throw new Error("trapped"); } });
      await import("data:text/javascript,export const x = document.title;").catch((e) => { console.log(e.message); });`],
    { encoding: "utf8" },
  );
  assert.match(probe.stdout, /trapped/);
});
