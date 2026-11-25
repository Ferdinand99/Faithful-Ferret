// The settings page (design document, section 7.2): opened in a tab by the
// browser's "Preferences" button of the add-on. What it shows is the settings
// view (settingsView.mjs), the same one the open popup shows under "Settings".
// It talks to the background over the UI port like the other pages; it never
// sees a key or a captured value.

import { mount } from "../shared/dom.mjs";
import { loadTexts, translateStatic } from "./page.mjs";
import { createSettingsFlow } from "./settingsFlow.mjs";
import { createSettingsView } from "./settingsView.mjs";
import { connectUi } from "./ui.mjs";

async function main() {
  const root = document.getElementById("root");
  if (!root) return;
  const texts = await loadTexts();
  translateStatic(document, texts);
  const ui = connectUi(browser.runtime);
  const flow = createSettingsFlow(ui.request, {
    requestPermission: (wanted) => browser.permissions.request(wanted),
    openTab: (url) => browser.tabs.create({ url }),
  });
  const view = createSettingsView({ texts, flow });
  mount(root, ...view.nodes);
  await view.ready;
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // The page has nothing to show without the background; it never prints what went wrong.
});
