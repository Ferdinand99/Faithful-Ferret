import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build, ICON_SIZES, readInternalHosts, readPermissionAllow, releaseProblems } from "../../scripts/build.mjs";
import { extensionRoot, makeRoot, repoRoot } from "./buildHelpers.mjs";

const SIZES = ["16", "32", "48", "96", "128"];

/** @param {string} manifest @param {string} variant @param {Record<string, string | null>} [extra] */
async function buildIn(manifest, variant, extra = {}) {
  const env = makeRoot(extra);
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest, variant });
    return { result, json: JSON.parse(readFileSync(join(result.dir, "manifest.json"), "utf8")) };
  } finally {
    env.cleanup();
  }
}

test("the_icon_is_the_ferret_mark_of_the_server_and_the_size_list_is_the_documented_one", () => {
  const mine = readFileSync(join(extensionRoot, "icons", "ferret.svg"));
  const mark = readFileSync(join(repoRoot, "crates", "ferret-server", "static", "favicon.svg"));
  assert.ok(mine.equals(mark), "extension/icons/ferret.svg must be the same artwork as the server's favicon.svg");
  assert.deepEqual(ICON_SIZES.map(String), SIZES);
});

test("every_icon_size_is_declared_for_the_add_on_and_the_toolbar_button_and_is_in_the_package", async () => {
  const source = readFileSync(join(extensionRoot, "icons", "ferret.svg"));
  for (const manifest of ["mv3", "mv2"]) {
    for (const variant of ["release", "test"]) {
      const where = `${manifest} ${variant}`;
      const { result, json } = await buildIn(manifest, variant);
      const action = manifest === "mv3" ? json.action : json.browser_action;
      for (const [label, map] of [["icons", json.icons], ["default_icon", action.default_icon]]) {
        assert.deepEqual(Object.keys(map).sort((a, b) => Number(a) - Number(b)), SIZES, `${where}: ${label}`);
        for (const size of SIZES) {
          const file = result.files.get(map[size]);
          assert.ok(file, `${where}: ${label}[${size}] names ${map[size]}, which is not in the package`);
          assert.ok(file.equals(source), `${where}: ${map[size]} is not the artwork`);
          assert.match(map[size], /^icons\/[a-z0-9-]+\.svg$/, where);
        }
      }
      // The toolbar button keeps its popup and title next to the icon.
      assert.equal(action.default_popup, "pages/popup.html", where);
      assert.equal(action.default_title, "Faithful Ferret", where);
      // The mark has its own dark tile, so one icon serves light and dark toolbars.
      assert.equal("theme_icons" in action, false, where);
    }
  }
});

test("the_release_check_names_an_icon_that_is_missing_from_the_package", async () => {
  const { result } = await buildIn("mv2", "release");
  const files = new Map(result.files);
  assert.deepEqual(releaseProblems(files, readInternalHosts(), readPermissionAllow()), []);
  files.delete("icons/ferret.svg");
  const problems = releaseProblems(files, readInternalHosts(), readPermissionAllow());
  assert.ok(problems.some((p) => /icons\/ferret\.svg is not in the package/.test(p)), problems.join("; "));
});

test("an_icon_file_that_is_not_a_plain_picture_is_refused_by_the_build", async () => {
  const bad = {
    "script": '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    "handler": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><path d="M0 0"/></svg>',
    "remote": '<svg xmlns="http://www.w3.org/2000/svg"><path fill="url(https://example.test/x)" d="M0 0"/></svg>',
    "link": '<svg xmlns="http://www.w3.org/2000/svg"><use href="other.svg#a"/></svg>',
    "html": "<html></html>",
  };
  for (const [name, svg] of Object.entries(bad)) {
    await assert.rejects(buildIn("mv3", "release", { [`icons/${name}.svg`]: svg }), /icons\/|icon/, name);
  }
  await assert.rejects(buildIn("mv3", "release", { "icons/Bad_Name.svg": "<svg/>" }), /only <name>\.svg files/);
});
