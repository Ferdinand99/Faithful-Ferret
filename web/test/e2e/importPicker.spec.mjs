// The file picker of the import page in real browsers (Chromium, Firefox, WebKit): the input is hidden from the eye only, a
// styled button opens the file chooser, the name of the chosen file is shown, a file dropped on the zone starts the same step, and
// the picker is drawn in both themes. The page is the real view over a fake session that records what it was asked.
import { expect, test } from "@playwright/test";

test.use({ viewport: { width: 1000, height: 800 } });

async function mountImport(page) {
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  await page.waitForFunction(() => document.fonts.check("16px InterVariable"), undefined, { timeout: 15_000 });
  await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const { mount, el } = await import("/app/dom.mjs");
    const { importView } = await import("/app/views/import.mjs");
    const { createWipeScope } = await import("/app/views/common.mjs");
    window.__previews = [];
    document.getElementById("app").hidden = true;
    const host = el("main", { id: "import-test", class: "page" });
    document.body.appendChild(host);
    const view = importView({
      t: i18n.t,
      previewFile: async (file) => {
        window.__previews.push(file.name);
        return { kind: "bitwarden_json", counts: { items: 1, login: 1 }, skipped: null, warnings: [], warningsDropped: 0, free: 9000, used: 0, vaultEmpty: true, fits: true, createdAt: null };
      },
      runImport: async () => ({ queued: 0 }),
      continueImport: async () => ({ remaining: 0 }),
      discard: () => {},
      status: () => ({ queued: 0, total: 0, sent: 0, windowClosed: false }),
      on: () => () => {},
      scope: createWipeScope(),
    });
    mount(host, view);
  });
  await expect(page.locator('[data-role="file-drop"]')).toBeVisible();
}

test("the_input_is_hidden_from_the_eye_only_and_the_button_names_it", async ({ page }) => {
  await mountImport(page);
  const input = page.locator('[data-role="file"]');
  const box = await input.boundingBox();
  expect(box === null || (box.width <= 1 && box.height <= 1)).toBe(true);
  await expect(input).toHaveAttribute("accept", ".ferretexport,.json,.csv,.avux");
  const button = page.locator('[data-role="file-choose"]');
  await expect(button).toBeVisible();
  await expect(button).toHaveText("Choose file");
  await expect(page.locator('[data-role="file-name"]')).toHaveText("No file chosen");
  // The input is still in the page for the keyboard and the screen reader.
  await input.focus();
  await expect(input).toBeFocused();
});

test("the_button_opens_the_file_chooser_and_choosing_a_file_starts_the_same_step", async ({ page }) => {
  await mountImport(page);
  const [chooser] = await Promise.all([page.waitForEvent("filechooser"), page.locator('[data-role="file-choose"]').click()]);
  await chooser.setFiles({ name: "moved.json", mimeType: "application/json", buffer: Buffer.from("{}") });
  await expect(page.locator('[data-role="file-name"]')).toHaveText("moved.json");
  await expect(page.locator('[data-role="preview"]')).toBeVisible();
  expect(await page.evaluate(() => window.__previews)).toEqual(["moved.json"]);
  // Cancelling the preview forgets the file.
  await page.locator('[data-role="cancel"]').click();
  await expect(page.locator('[data-role="file-name"]')).toHaveText("No file chosen");
});

test("a_file_dropped_on_the_zone_starts_the_same_step", async ({ page }) => {
  await mountImport(page);
  await page.evaluate(() => {
    const zone = document.querySelector('[data-role="file-drop"]');
    const transfer = new DataTransfer();
    transfer.items.add(new File(["{}"], "dropped.json", { type: "application/json" }));
    zone.dispatchEvent(new DragEvent("dragover", { dataTransfer: transfer, bubbles: true, cancelable: true }));
    zone.dispatchEvent(new DragEvent("drop", { dataTransfer: transfer, bubbles: true, cancelable: true }));
  });
  await expect(page.locator('[data-role="file-name"]')).toHaveText("dropped.json");
  await expect(page.locator('[data-role="preview"]')).toBeVisible();
  expect(await page.evaluate(() => window.__previews)).toEqual(["dropped.json"]);
});

for (const scheme of ["light", "dark"]) {
  test(`the_picker_is_drawn_in_the_${scheme}_theme`, async ({ page }, info) => {
    await page.emulateMedia({ colorScheme: scheme });
    await mountImport(page);
    const zone = page.locator('[data-role="file-drop"]');
    await expect(zone).toBeVisible();
    // The button has the look of the other secondary buttons: a filled background, not the browser's grey control.
    const style = await page.locator('[data-role="file-choose"]').evaluate((node) => {
      const css = getComputedStyle(node);
      return { background: css.backgroundColor, radius: parseFloat(css.borderTopLeftRadius) };
    });
    expect(style.background).not.toBe("rgba(0, 0, 0, 0)");
    expect(style.radius).toBeGreaterThan(4);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await zone.screenshot({ path: info.outputPath(`import-picker-${scheme}.png`) });
  });
}
