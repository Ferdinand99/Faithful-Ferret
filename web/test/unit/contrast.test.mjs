// The text colours of both themes keep their contrast on the surfaces they are drawn on (WCAG AA: 4.5:1 for text,
// 3:1 for the focus ring). The colours are read from the style sheets themselves, so a token that is changed later is
// checked without anyone remembering to update a list.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const styles = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "styles");

/** Splits `a, b(c, d), e` at the commas that are not inside brackets. @param {string} text */
function splitTop(text) {
  const parts = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "(") depth += 1;
    else if (text[i] === ")") depth -= 1;
    else if (text[i] === "," && depth === 0) {
      parts.push(text.slice(from, i).trim());
      from = i + 1;
    }
  }
  parts.push(text.slice(from).trim());
  return parts;
}

/** Every `--name: value;` of the custom property blocks of the sheets, as { light, dark } texts. @returns {Map<string, { light: string, dark: string }>} */
function readTokens() {
  const tokens = new Map();
  for (const file of ["base.css", "shell.css", "list.css"]) {
    const css = readFileSync(join(styles, file), "utf8");
    for (const match of css.matchAll(/^\s*(--[a-z0-9-]+):\s*([^;]+);/gm)) {
      const value = match[2].trim();
      if (value.startsWith("url(")) continue;
      const wrapped = /^light-dark\((.*)\)$/s.exec(value);
      if (wrapped) {
        const [light, dark] = splitTop(wrapped[1]);
        tokens.set(match[1], { light, dark });
      } else {
        tokens.set(match[1], { light: value, dark: value });
      }
    }
  }
  return tokens;
}

const TOKENS = readTokens();

/** @typedef {{ r: number, g: number, b: number, a: number }} Rgba */

/** @param {string} text @param {"light" | "dark"} theme @returns {Rgba} */
function colour(text, theme) {
  const ref = /^var\((--[a-z0-9-]+)\)$/.exec(text);
  if (ref) {
    const token = TOKENS.get(ref[1]);
    assert.ok(token, `token ${ref[1]} exists`);
    return colour(token[theme], theme);
  }
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(text);
  if (hex) {
    const digits = hex[1].length === 3 ? [...hex[1]].map((d) => d + d).join("") : hex[1];
    return { r: parseInt(digits.slice(0, 2), 16), g: parseInt(digits.slice(2, 4), 16), b: parseInt(digits.slice(4, 6), 16), a: 1 };
  }
  const rgba = /^rgba?\(([^)]*)\)$/.exec(text);
  assert.ok(rgba, `a colour that the test understands: ${text}`);
  const [r, g, b, a = "1"] = rgba[1].split(",").map((part) => part.trim());
  return { r: Number(r), g: Number(g), b: Number(b), a: Number(a) };
}

/** A token as a colour in a theme. @param {string} name @param {"light" | "dark"} theme */
const token = (name, theme) => colour(`var(${name})`, theme);

/** `top` laid over `under`. @param {Rgba} top @param {Rgba} under @returns {Rgba} */
function over(top, under) {
  return {
    r: top.r * top.a + under.r * (1 - top.a),
    g: top.g * top.a + under.g * (1 - top.a),
    b: top.b * top.a + under.b * (1 - top.a),
    a: 1,
  };
}

/** @param {Rgba} c */
function luminance(c) {
  const channel = (/** @type {number} */ v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
}

/** @param {Rgba} a @param {Rgba} b */
function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** The pairs: text token, the surface it sits on (a token, or a token's tint over another), and the least ratio. */
const SURFACES = ["--bg", "--card", "--card-raised", "--field"];
const TEXT_ON_SURFACES = ["--text", "--muted", "--brand", "--brand-text", "--info-text", "--ok-text", "--warn-text", "--bad-text", "--neutral-text"];
const TINTS = [
  ["--info-text", "--info-fill"],
  ["--ok-text", "--ok-fill"],
  ["--warn-text", "--warn-fill"],
  ["--bad-text", "--bad-fill"],
  ["--neutral-text", "--neutral-fill"],
  ["--brand-text", "--brand-fill"],
  ["--text", "--brand-fill"],
  ["--muted", "--brand-fill"], // the secondary text of a ticked row
];

for (const theme of /** @type {const} */ (["light", "dark"])) {
  test(`${theme}_text_colours_reach_aa_on_every_surface_they_are_drawn_on`, () => {
    for (const text of TEXT_ON_SURFACES) {
      for (const surface of SURFACES) {
        const got = ratio(token(text, theme), over(token(surface, theme), token("--bg", theme)));
        assert.ok(got >= 4.5, `${theme}: ${text} on ${surface} is ${got.toFixed(2)}:1, needs 4.5:1`);
      }
    }
  });

  test(`${theme}_tinted_marks_and_chips_reach_aa_over_the_card`, () => {
    for (const [text, fill] of TINTS) {
      const card = over(token("--card", theme), token("--bg", theme));
      const got = ratio(token(text, theme), over(token(fill, theme), card));
      assert.ok(got >= 4.5, `${theme}: ${text} on ${fill} is ${got.toFixed(2)}:1, needs 4.5:1`);
    }
  });

  test(`${theme}_the_letter_on_an_item_tile_and_on_the_avatar_reach_aa`, () => {
    for (const tint of ["--tint-login", "--tint-note", "--tint-card", "--tint-identity", "--tint-other", "--brand"]) {
      const got = ratio(token("--on-inverse", theme), token(tint, theme));
      assert.ok(got >= 4.5, `${theme}: the letter on ${tint} is ${got.toFixed(2)}:1, needs 4.5:1`);
    }
  });

  test(`${theme}_a_fill_of_the_brand_colour_carries_its_text_and_its_tick_at_aa`, () => {
    // The avatar, the badge and a primary button of the brand colour use --on-inverse; the tick of a ticked box is the
    // mark that is drawn on the fill (white on the light theme's teal, dark on the dark theme's turquoise).
    const fill = token("--brand", theme);
    assert.ok(ratio(token("--on-inverse", theme), fill) >= 4.5, `${theme}: --on-inverse on --brand`);
    const ticks = [...readFileSync(join(styles, "base.css"), "utf8").matchAll(/--i-tick:\s*url\([^)]*stroke=%27(white|%23[0-9a-f]{6})%27/gi)].map((m) => m[1]);
    assert.deepEqual(ticks, ["white", "%230b0b0d", "%230b0b0d"], "white for the light theme, dark for the dark one (chosen by the system, and forced by data-theme)");
    const tick = colour(theme === "light" ? "#ffffff" : "#0b0b0d", theme);
    assert.ok(ratio(tick, fill) >= 4.5, `${theme}: the tick on --brand is ${ratio(tick, fill).toFixed(2)}:1`);
    // The radio's dot and the bar of a half-ticked box are --on-inverse, the same pair.
    assert.ok(readFileSync(join(styles, "base.css"), "utf8").includes("radial-gradient(circle, var(--on-inverse) 0 3.5px, var(--brand) 4px)"));
  });

  test(`${theme}_the_edge_of_a_field_and_of_a_box_reaches_3_to_1_on_every_surface_it_sits_on`, () => {
    const bg = token("--bg", theme);
    for (const edge of ["--field-line"]) {
      for (const surface of SURFACES) {
        const got = ratio(token(edge, theme), over(token(surface, theme), bg));
        assert.ok(got >= 3, `${theme}: ${edge} on ${surface} is ${got.toFixed(2)}:1, needs 3:1`);
      }
    }
  });

  test(`${theme}_placeholders_buttons_and_the_focus_ring_are_readable`, () => {
    const bg = token("--bg", theme);
    const field = over(token("--field", theme), bg);
    assert.ok(ratio(token("--placeholder", theme), field) >= 4.5, `${theme}: placeholder on a field`);
    // The primary button: the page text colour as its fill, the inverse as its text.
    assert.ok(ratio(token("--on-inverse", theme), token("--text", theme)) >= 4.5, `${theme}: primary button`);
    // The focus ring and the checked box are drawn in the brand colour against the surface: 3:1.
    for (const surface of SURFACES) {
      const got = ratio(token("--brand", theme), over(token(surface, theme), bg));
      assert.ok(got >= 3, `${theme}: the focus ring on ${surface} is ${got.toFixed(2)}:1, needs 3:1`);
    }
  });
}

test("the_brand_is_the_logos_turquoise_in_the_dark_theme_and_a_darker_teal_in_the_light_one", () => {
  const brand = TOKENS.get("--brand");
  assert.ok(brand);
  assert.equal(brand.dark, "#59d9c7", "the colour of the logo");
  assert.ok(luminance(colour(brand.light, "light")) < luminance(colour(brand.dark, "dark")), "darker in the light theme");
  // Teal, not another hue: green and blue above red, in both themes.
  for (const [value, theme] of /** @type {const} */ ([[brand.light, "light"], [brand.dark, "dark"]])) {
    const c = colour(value, theme);
    assert.ok(c.g > c.r * 2 && c.b > c.r * 2 && Math.abs(c.g - c.b) < 30, `${theme}: ${value} is turquoise`);
  }
});

/** Every file of the web vault's source that can hold a colour. @param {string} dir @returns {string[]} */
function sources(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "locales" ? [] : sources(path);
    return /\.(css|mjs|js|html|svg)$/.test(entry.name) ? [path] : [];
  });
}

test("nothing_in_the_web_vault_paints_the_old_purple_or_any_purple", () => {
  const purple = /6656e8|8b7dff|a99fff|c7c0ff|7c3aed|8b5cf6|a78bfa|6d28d9|5b21b6|102,\s*86,\s*232|139,\s*125,\s*255|\b(purple|violet|indigo|lavender)\b/i;
  const all = sources(join(styles, ".."));
  assert.ok(all.some((file) => file.endsWith("passkey.css")), "the passkey styles are among the files that are read");
  for (const file of all) {
    // The word lists of the generator hold the words "purple" and "violet"; they are not colours.
    if (/word/i.test(file)) continue;
    assert.ok(!purple.test(readFileSync(file, "utf8")), `${file} has no purple`);
  }
});
