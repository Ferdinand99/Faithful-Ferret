// The brand colour of the extension's pages (the popup, the settings, the sign-in, unlock and grant tabs, the offer):
// the turquoise of the logo, with the contrast WCAG AA asks for in both themes. The tokens are read from session.css,
// the style sheet of every page, so a token that is changed later is checked without anyone updating a list.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const styles = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "styles");
const session = readFileSync(join(styles, "session.css"), "utf8");

/** @param {string} name @returns {{ light: string, dark: string }} */
function pair(name) {
  const m = new RegExp(String.raw`${name}:\s*light-dark\(((?:rgba\([^)]*\)|#[0-9a-f]{6})),\s*((?:rgba\([^)]*\)|#[0-9a-f]{6}))\)`, "i").exec(session);
  assert.ok(m, `${name} is a light-dark() pair of colours`);
  return { light: m[1], dark: m[2] };
}

/** @param {string} text @returns {[number, number, number, number]} */
function rgba(text) {
  if (text.startsWith("#")) return [1, 3, 5].map((i) => parseInt(text.slice(i, i + 2), 16)).concat(1);
  const [r, g, b, a = "1"] = text.slice(text.indexOf("(") + 1, -1).split(",").map((p) => p.trim());
  return [Number(r), Number(g), Number(b), Number(a)];
}

/** @param {[number, number, number, number]} top @param {[number, number, number, number]} under */
const over = (top, under) => /** @type {[number, number, number, number]} */ ([0, 1, 2].map((i) => top[i] * top[3] + under[i] * (1 - top[3])).concat(1));

/** @param {[number, number, number, number]} c */
const luminance = (c) => {
  const [r, g, b] = c.slice(0, 3).map((v) => v / 255).map((s) => (s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

/** @param {[number, number, number, number]} a @param {[number, number, number, number]} b */
const ratio = (a, b) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

test("the_brand_is_the_logos_turquoise_in_the_dark_theme_and_a_darker_teal_in_the_light_one", () => {
  const brand = pair("--brand");
  assert.equal(brand.dark.toLowerCase(), "#59d9c7", "the colour of the logo");
  assert.ok(luminance(rgba(brand.light)) < luminance(rgba(brand.dark)));
  for (const value of [brand.light, brand.dark]) {
    const [r, g, b] = rgba(value);
    assert.ok(g > r * 2 && b > r * 2 && Math.abs(g - b) < 30, `${value} is turquoise`);
  }
  const fill = pair("--brand-fill");
  assert.deepEqual(rgba(fill.light).slice(0, 3), rgba(brand.light).slice(0, 3), "the tint is the brand colour");
  assert.deepEqual(rgba(fill.dark).slice(0, 3), rgba(brand.dark).slice(0, 3), "the tint is the brand colour");
});

for (const theme of /** @type {const} */ (["light", "dark"])) {
  test(`${theme}_the_brand_colour_reaches_aa_as_text_and_3_to_1_as_a_ring_on_every_surface_and_on_its_own_tint`, () => {
    const bg = rgba(pair("--bg")[theme]);
    const brand = rgba(pair("--brand")[theme]);
    for (const surface of ["--bg", "--card", "--card-raised", "--field"]) {
      const ground = over(rgba(pair(surface)[theme]), bg);
      assert.ok(ratio(brand, ground) >= 4.5, `${theme}: --brand on ${surface} is ${ratio(brand, ground).toFixed(2)}:1`);
      // Links and chosen filters sit on the tint of the brand colour over the surface as well.
      const tinted = over(rgba(pair("--brand-fill")[theme]), ground);
      assert.ok(ratio(brand, tinted) >= 4.5, `${theme}: --brand on its tint over ${surface} is ${ratio(brand, tinted).toFixed(2)}:1`);
      assert.ok(ratio(rgba(pair("--text")[theme]), tinted) >= 4.5, `${theme}: --text on the tint over ${surface}`);
    }
  });

  test(`${theme}_the_text_on_a_fill_of_the_brand_colour_reaches_aa`, () => {
    // The offer's button, the badge, the status dot and the switch knob are --on-inverse on --brand.
    const got = ratio(rgba(pair("--on-inverse")[theme]), rgba(pair("--brand")[theme]));
    assert.ok(got >= 4.5, `${theme}: --on-inverse on --brand is ${got.toFixed(2)}:1`);
  });
}

test("no_style_sheet_of_the_extension_paints_the_old_purple", () => {
  const purple = /6656e8|8b7dff|a99fff|102,\s*86,\s*232|139,\s*125,\s*255/i;
  for (const file of readdirSync(styles).filter((name) => name.endsWith(".css"))) {
    assert.ok(!purple.test(readFileSync(join(styles, file), "utf8")), `${file} has no purple`);
  }
  const badge = readFileSync(join(styles, "..", "background", "badge.mjs"), "utf8");
  assert.ok(!purple.test(badge), "the toolbar badge has no purple");
});
