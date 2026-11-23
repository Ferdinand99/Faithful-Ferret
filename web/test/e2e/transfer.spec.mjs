// "Import and export" in real browsers (Chromium, Firefox, WebKit): the side menu entry leads to a page with both choices, and
// from the menu the import page and the export page can both be reached, the entry staying marked on all three. The frame is the
// real one over a fake engine (as in shell.spec.mjs); the page's own content is the real "Import and export" view.
import { expect, test } from "@playwright/test";

test.use({ viewport: { width: 1280, height: 800 } });

async function mountFrame(page) {
  await page.addInitScript(() => {
    const add = window.addEventListener.bind(window);
    window.__hashListening = false;
    window.addEventListener = (type, listener, options) => {
      if (type === "hashchange" && !window.__hashListening) return;
      add(type, listener, options);
    };
  });
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const { mount, el } = await import("/app/dom.mjs");
    const { shellView } = await import("/app/views/shell.mjs");
    const { transferView } = await import("/app/views/transfer.mjs");
    const { createWipeScope } = await import("/app/views/common.mjs");
    const { createUiPrefs } = await import("/app/uiPrefs.mjs");
    const routes = (await import("/app/routes.gen.mjs")).default;
    window.__hashListening = true;
    document.getElementById("app").hidden = true;
    const host = el("div", { id: "shell-test" });
    document.body.appendChild(host);
    const engine = { list: () => [], on: () => () => {} };
    mount(host, shellView({
      t: i18n.t, engine, session: { onLock() {} }, content: transferView({ t: i18n.t }),
      lock: async () => {}, touch: () => true, scope: createWipeScope(), onLocked: () => el("div"),
      routes, email: "ada.lovelace@example.com", prefs: createUiPrefs(), folders: [], signOut: async () => {},
    }));
  });
  await expect(page.locator('[data-role="side"]')).toBeAttached();
}

test("from_the_side_menu_the_import_page_and_the_export_page_can_both_be_reached", async ({ page }) => {
  await mountFrame(page);
  const entry = page.locator('[data-role="nav-transfer"]');
  await expect(entry).toBeVisible();
  await expect(entry).toHaveAttribute("href", "#/transfer");
  await entry.click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/transfer");
  await expect(entry).toHaveAttribute("aria-current", "page");

  const toImport = page.locator('[data-role="transfer-import"]');
  const toExport = page.locator('[data-role="transfer-export"]');
  await expect(toImport).toBeVisible();
  await expect(toExport).toBeVisible();
  await expect(toImport).toHaveAttribute("href", "#/import");
  await expect(toExport).toHaveAttribute("href", "#/export");

  await toImport.click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/import");
  await expect(entry).toHaveAttribute("aria-current", "page");
  await entry.click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/transfer");
  await toExport.click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/export");
  await expect(entry).toHaveAttribute("aria-current", "page");
  await expect(page.locator('#shell-test [aria-current="page"]')).toHaveCount(1);
});
