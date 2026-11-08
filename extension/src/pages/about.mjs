// The page the toolbar button opens until the real popup exists: the name, the
// version and a line saying what the extension is.
import { el, mount } from "./el.mjs";

/** @param {string} lang @returns {Promise<Record<string, string>>} */
async function catalog(lang) {
  const response = await fetch(browser.runtime.getURL(`locales.${lang}.json`));
  return response.json();
}

async function main() {
  const root = document.getElementById("root");
  if (!root) return;
  const language = navigator.language.toLowerCase().startsWith("nb") ? "nb" : "en";
  const text = await catalog(language);
  const manifest = browser.runtime.getManifest();
  mount(
    root,
    el("h1", null, text["about.title"] ?? manifest.name),
    el("p", null, text["about.summary"] ?? ""),
    el("p", { class: "version" }, `${text["about.version"] ?? "Version"} ${manifest.version}`),
  );
}

main().catch((error) => console.error(error));
