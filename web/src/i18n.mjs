// Translations: a flat catalog per language, `{name}` placeholders, English as
// the fallback. A key that is missing is recorded in `missing` (once) and shows
// as the English text, or as the key itself if English lacks it too.

export const SUPPORTED_LANGUAGES = Object.freeze(["en", "nb"]);

const PLACEHOLDER = /\{([A-Za-z0-9_]+)\}/g;

/** Norwegian variants that the nb catalog serves. */
const ALIASES = new Map([["no", "nb"], ["nn", "nb"]]);

/**
 * @param {Record<string, Record<string, string>>} catalogs
 * @param {string} lang
 * @returns {{ t(key: string, vars?: Record<string, string | number>): string, lang: string, missing: string[] }}
 */
export function createI18n(catalogs, lang) {
  const active = Object.hasOwn(catalogs, lang) ? lang : "en";
  const own = catalogs[active] ?? {};
  const fallback = catalogs.en ?? {};
  /** @type {string[]} */
  const missing = [];
  return {
    lang: active,
    missing,
    t(key, vars) {
      let text = Object.hasOwn(own, key) ? own[key] : undefined;
      if (text === undefined) {
        if (!missing.includes(key)) missing.push(key);
        text = Object.hasOwn(fallback, key) ? fallback[key] : key;
      }
      if (!vars) return text;
      return text.replace(PLACEHOLDER, (whole, name) =>
        Object.hasOwn(vars, name) ? String(vars[name]) : whole,
      );
    },
  };
}

/**
 * The first language in the user's list that the app has; English otherwise.
 * @param {readonly string[]} languages
 * @param {readonly string[]} supported
 * @returns {string}
 */
export function negotiate(languages, supported) {
  for (const tag of languages ?? []) {
    const primary = String(tag).toLowerCase().split("-")[0];
    const wanted = ALIASES.get(primary) ?? primary;
    if (supported.includes(wanted)) return wanted;
  }
  return supported.includes("en") ? "en" : supported[0];
}
