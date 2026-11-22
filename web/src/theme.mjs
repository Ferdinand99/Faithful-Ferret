// The theme: light, dark, or the system's. The choice is the one word
// "light" or "dark" in localStorage under `ferret-theme` (nothing is stored for
// "auto"), and it is applied as `data-theme` on <html>. Storage can be blocked,
// so every access is in a try block. Nothing secret is ever put there: the choice is
// a per-device preference, not vault data. It is made in the account menu
// (views/sidebar.mjs); theme-init.mjs reads the same key before the first paint.

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

/**
 * The theme choice the account menu offers: Light, Dark or System. It reads the stored word, applies a new choice to the
 * page at once and stores it (nothing for System). The page's own `data-theme` is the one place the choice shows.
 * @param {{ storage?: ThemeStorage | null, root?: Parameters<typeof applyTheme>[1] }} [options]
 */
export function createThemeChoice({ storage = pageStorage(), root = globalThis.document?.documentElement } = {}) {
  return {
    /** @returns {"auto" | "light" | "dark"} the choice now; read again on every call, so two tabs agree on the last one */
    current: () => readTheme(storage),
    /** Applies the stored choice to the page again (another tab changed it). */
    sync() {
      applyTheme(readTheme(storage), root);
    },
    /** @param {string} theme */
    set(theme) {
      if (!THEMES.includes(/** @type {any} */ (theme))) return;
      applyTheme(theme, root);
      storeTheme(theme, storage);
    },
  };
}
