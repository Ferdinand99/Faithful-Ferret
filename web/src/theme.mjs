// The theme: light, dark, or the system's. The choice is the one word
// "light" or "dark" in localStorage under `ferret-theme` (nothing is stored for
// "auto"), and it is applied as `data-theme` on <html>. Storage can be blocked,
// so every access is in a try block. Nothing secret is ever put there.
// The same key is read by theme-init.mjs before the first paint.
import { el } from "./dom.mjs";

export const THEME_KEY = "ferret-theme";
export const THEMES = Object.freeze(/** @type {const} */ (["auto", "light", "dark"]));

/** @typedef {{ getItem(key: string): string | null, setItem(key: string, value: string): void, removeItem(key: string): void }} ThemeStorage */

/** The page's storage, or null when the browser blocks it. @returns {ThemeStorage | null} */
function pageStorage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * The stored theme; "auto" when none is stored or storage is blocked.
 * @param {ThemeStorage | null} [storage]
 * @returns {"auto" | "light" | "dark"}
 */
export function readTheme(storage = pageStorage()) {
  try {
    const value = storage?.getItem(THEME_KEY);
    return value === "light" || value === "dark" ? value : "auto";
  } catch {
    return "auto";
  }
}

/**
 * Applies a theme to the page: "auto" follows the system.
 * @param {string} theme
 * @param {{ setAttribute(name: string, value: string): void, removeAttribute(name: string): void } | null | undefined} [root]
 */
export function applyTheme(theme, root = globalThis.document?.documentElement) {
  if (!root) return;
  if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
  else root.removeAttribute("data-theme");
}

/**
 * Stores a theme (nothing for "auto"). A blocked storage only means the choice
 * is not remembered.
 * @param {string} theme
 * @param {ThemeStorage | null} [storage]
 */
export function storeTheme(theme, storage = pageStorage()) {
  try {
    if (theme === "light" || theme === "dark") storage?.setItem(THEME_KEY, theme);
    else storage?.removeItem(THEME_KEY);
  } catch {
    // Not remembered; the page still changes.
  }
}

const ICONS = Object.freeze({ auto: "icon-auto", light: "icon-sun", dark: "icon-moon" });

/**
 * The switch: Auto, Light, Dark.
 * @param {{
 *   t: (key: string) => string,
 *   storage?: ThemeStorage | null,
 *   root?: Parameters<typeof applyTheme>[1],
 * }} options
 * @returns {HTMLElement}
 */
export function themeControl({ t, storage = pageStorage(), root = globalThis.document?.documentElement }) {
  let current = readTheme(storage);
  /** @type {Map<string, HTMLElement>} */
  const buttons = new Map();
  /** @param {string} theme */
  const choose = (theme) => {
    current = /** @type {"auto" | "light" | "dark"} */ (theme);
    applyTheme(theme, root);
    storeTheme(theme, storage);
    for (const [name, button] of buttons) button.setAttribute("aria-pressed", name === current ? "true" : "false");
  };
  for (const theme of THEMES) {
    const button = el("button", { type: "button", "data-theme-set": theme, "aria-pressed": theme === current ? "true" : "false" },
      el("span", { class: `icon ${ICONS[theme]}`, "aria-hidden": "true" }), t(`app.theme.${theme}`));
    button.addEventListener("click", () => choose(theme));
    buttons.set(theme, button);
  }
  return el("div", { class: "segmented", role: "group", "aria-label": t("app.theme.label"), "data-role": "theme" }, ...buttons.values());
}

/**
 * Fills the footer: the name and the theme switch.
 * @param {HTMLElement} footer
 * @param {{ t: (key: string) => string, storage?: ThemeStorage | null }} options
 */
export function mountFooter(footer, { t, storage }) {
  footer.appendChild(el("span", null, t("app.name")));
  footer.appendChild(themeControl({ t, storage }));
}
