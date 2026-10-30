// Entry point of the page: the Trusted Types policy, the crypto client with
// its two workers, the translations, the services and the router.
import { createClient } from "../js/client.mjs";
import { startApp } from "./app.mjs";
import { consumeEntry } from "./flows/entry.mjs";
import { SUPPORTED_LANGUAGES, createI18n, negotiate } from "./i18n.mjs";
import routes from "./routes.gen.mjs";
import services from "./services.gen.mjs";
import { installTrustedTypes } from "./tt.mjs";

/** @param {string} lang */
async function loadCatalog(lang) {
  const response = await fetch(`/app/locales.${lang}.json`, { credentials: "same-origin" });
  if (!response.ok) throw new Error(`catalog ${lang}: ${response.status}`);
  return /** @type {Record<string, string>} */ (await response.json());
}

async function boot() {
  const tt = installTrustedTypes();
  // The workers are made from a TrustedScriptURL of the `ferret` policy.
  const client = createClient({
    createVaultWorker: () => new Worker(/** @type {string} */ (tt.workerUrl("vault")), { type: "module" }),
    createJobWorker: () => new Worker(/** @type {string} */ (tt.workerUrl("job")), { type: "module" }),
  });
  const lang = negotiate(navigator.languages ?? [navigator.language], SUPPORTED_LANGUAGES);
  const catalogs = { en: await loadCatalog("en") };
  if (lang !== "en") /** @type {Record<string, Record<string, string>>} */ (catalogs)[lang] = await loadCatalog(lang);
  const i18n = createI18n(catalogs, lang);
  document.documentElement.lang = i18n.lang;
  const root = document.getElementById("app");
  if (!root) throw new Error("no #app element");
  // /vault/login?handoff=1&challenge=... and /vault/setup#token=... : read what the
  // address carries and take it out of the address before the router starts.
  consumeEntry(window);
  const app = startApp({ root, routes, serviceDefs: services, client, i18n });
  return { client, i18n, router: app.router, services: app.services, tt };
}

/** Resolves when the page is up. Tests and features import it; nothing else is exported. */
export const ready = boot();

ready.catch(() => {
  // A last resort in plain English: the translations may be what failed.
  const root = document.getElementById("app");
  if (root) root.textContent = "The vault could not be started. Reload the page to try again.";
});
