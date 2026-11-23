// The page the toolbar button opens until the real popup exists: the name, the
// version and a line saying what the extension is. In a build with saving from the
// extension on it also names the word list the passphrase generator draws from
// (the EFF large word list, CC BY 3.0 US), as that licence asks.
import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";

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
    ...(FEATURES.save ? [el("p", { class: "credits", "data-role": "credits-eff" }, text["generator.credits_eff"] ?? "")] : []),
  );
}

main().catch((error) => console.error(error));
