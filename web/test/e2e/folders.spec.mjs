// Folders in real browsers: the picker of the edit form, the Folders page (pin, rename, delete), the pinned folders in
// the side menu and the page of one folder. The screens are the real views in the real frame over a fake engine that
// keeps its items in the page (the flow against the server and the core is test/e2e-stack/03-folders). Chromium, Firefox
// and WebKit.
import { expect, test } from "@playwright/test";

/** The page is up; its own router is kept from listening to the address (it would answer with the sign-in page). */
async function ready(page) {
  await page.addInitScript(() => {
    const add = window.addEventListener.bind(window);
    window.addEventListener = (type, listener, options) => {
      if (type === "hashchange") return;
      add(type, listener, options);
    };
  });
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
}

/**
 * Builds a screen in the real frame. `which`: edit (item A), new, folders, folder (the page of "Work"). The engine is
 * shared by the screens of one page, so a change made on one shows on the next.
 */
async function scene(page, which) {
  await page.evaluate(async (which) => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const t = i18n.t;
    const { mount, el } = await import("/app/dom.mjs");
    const common = await import("/app/views/common.mjs");
    const { shellView } = await import("/app/views/shell.mjs");
    const { createUiPrefs } = await import("/app/uiPrefs.mjs");
    const { folderHref } = await import("/app/views/folderLinks.mjs");
    const routes = (await import("/app/routes.gen.mjs")).default;
    window.__violations ??= [];
    if (!window.__engine) {
      document.addEventListener("securitypolicyviolation", (event) => window.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
      const base = { favorite: false, urls: [], username: "", pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false, type: "login", modified: Date.now() };
      const items = [
        { ...base, id: "a1".repeat(16), name: "GitHub", rev: 1, folders: ["Work"] },
        { ...base, id: "b2".repeat(16), name: "Bank", rev: 1, folders: ["Money", "work"] },
        { ...base, id: "c3".repeat(16), name: "Router", rev: 1, folders: [] },
      ];
      const handlers = new Set();
      window.__writes = [];
      window.__engine = {
        list: () => items.map((item) => ({ ...item, folders: [...item.folders] })),
        on: (event, fn) => { if (event === "changed") handlers.add(fn); return () => handlers.delete(fn); },
        open: async (id) => {
          const item = items.find((i) => i.id === id);
          return { handle: 1, view: { name: item.name, item_type: "login", favorite: false, has_notes: false, has_totp: false, read_only: false, fields: [], urls: [], folders: [...item.folders] }, close: async () => {} };
        },
        update: async (id, draft, rev) => {
          window.__writes.push([id, structuredClone(draft), rev]);
          const item = items.find((i) => i.id === id);
          if (item.rev !== rev) throw Object.assign(new Error("item_changed"), { code: "item_changed" });
          Object.assign(item, draft.name ? { name: draft.name } : {}, Array.isArray(draft.folders) ? { folders: [...draft.folders] } : {}, { rev: rev + 1 });
          for (const fn of [...handlers]) fn({ ids: [id] });
        },
        create: async (draft) => {
          window.__writes.push(["new", structuredClone(draft)]);
          const id = "d4".repeat(16);
          items.push({ ...base, id, name: draft.name, rev: 1, folders: [...(draft.folders ?? [])] });
          for (const fn of [...handlers]) fn({ ids: [id] });
          return id;
        },
        remove: async () => {},
      };
      window.__prefs = createUiPrefs(window.localStorage);
      window.__went = [];
    }
    const engine = window.__engine;
    const go = (path) => window.__went.push(path);
    let content;
    if (which === "edit" || which === "new") {
      const { editView } = await import("/app/views/edit.mjs");
      content = await editView({ engine, client: { vault: {} }, id: which === "new" ? null : "a1".repeat(16), t, go });
    } else if (which === "folders") {
      const { foldersPage } = await import("/app/views/foldersPage.mjs");
      content = foldersPage({ engine, t, prefs: window.__prefs, folderLink: folderHref, locale: "en" });
    } else {
      const { listView } = await import("/app/views/list.mjs");
      const { folderBar } = await import("/app/views/foldersPage.mjs");
      content = el("div", null, folderBar({ t, name: "Work", prefs: window.__prefs }), listView({ engine, router: { go }, t, locale: "en", folder: "Work", folderLink: folderHref }));
    }
    const frame = shellView({
      t, engine, session: { current: () => null, onLock() {} }, content, lock: async () => {}, touch: () => true, scope: common.createWipeScope(),
      onLocked: () => document.createElement("div"), routes, email: "ada@example.com", prefs: window.__prefs,
    });
    mount(document.getElementById("app"), frame);
  }, which);
  await expect(page.locator('[data-role="shell"]')).toBeAttached();
}

const noSidewaysScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);

test.describe("folders on a desktop", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("the_edit_form_puts_an_item_in_a_new_folder_and_an_existing_one_and_takes_it_out_of_one", async ({ page }) => {
    await ready(page);
    await scene(page, "edit");
    const picked = page.locator('[data-role="folder-picked-chip"]');
    await expect(picked).toHaveText(["Work"]);
    // The vault's other folder is offered; "work" is the same folder as "Work" and is not.
    await expect(page.locator('[data-role="folder-offer"]')).toHaveText(["Money"]);
    // A new name, typed, and Enter: it is added and the form is not sent.
    await page.locator('[data-role="folder-input"]').fill("Taxes 2026");
    await page.locator('[data-role="folder-input"]').press("Enter");
    await expect(picked).toHaveText(["Taxes 2026", "Work"]);
    expect(await page.evaluate(() => window.__writes.length)).toBe(0);
    // A name that is too long is refused with the reason, on the spot.
    await page.locator('[data-role="folder-input"]').fill("x".repeat(65));
    await page.locator('[data-role="folder-add"]').click();
    await expect(page.locator('[data-role="folder-error"]')).toContainText("at most 64 characters");
    await page.locator('[data-role="folder-input"]').fill("");
    // Pick the existing one, and take the item out of "Work" with the cross of its chip.
    await page.locator('[data-role="folder-offer"]', { hasText: "Money" }).click();
    await page.getByRole("button", { name: "Take the item out of Work" }).click();
    await expect(picked).toHaveText(["Money", "Taxes 2026"]);
    await page.locator('[data-role="save"]').click();
    await expect.poll(() => page.evaluate(() => window.__writes)).toEqual([["a1".repeat(16), { name: "GitHub", favorite: false, urls: [], folders: ["Taxes 2026", "Money"] }, 1]]);
    expect(await page.evaluate(() => window.__violations)).toEqual([]);
  });

  test("a_new_item_is_made_in_a_folder_and_the_folder_exists_from_then_on", async ({ page }) => {
    await ready(page);
    await scene(page, "new");
    await page.locator('[data-role="name"]').fill("New one");
    await page.locator('[data-role="folder-input"]').fill("Fresh");
    await page.locator('[data-role="save"]').click();
    await expect.poll(() => page.evaluate(() => window.__writes.at(-1)?.[1]?.folders)).toEqual(["Fresh"]);
    await scene(page, "folders");
    await expect(page.locator('[data-role="folder-open"]')).toHaveText(["Fresh", "Money", "Work"]);
  });

  test("a_folder_is_pinned_renamed_and_deleted_from_the_folders_page_and_the_menu_follows", async ({ page }) => {
    await ready(page);
    await scene(page, "folders");
    await expect(page.locator('[data-role="folder-open"]')).toHaveText(["Money", "Work"]);
    await expect(page.locator('[data-role="folder-row"]', { hasText: "Work" }).locator('[data-role="folder-count"]')).toHaveText("2 items");
    // The link of a folder holds a token, never the name.
    for (const href of await page.locator('[data-role="folder-open"]').evaluateAll((links) => links.map((a) => a.getAttribute("href")))) {
      expect(href).toMatch(/^#\/folders\/[0-9a-f]{16}$/);
    }
    // Pin: the side menu shows it at once, under Pinned.
    await page.getByRole("button", { name: "Pin Work to the menu" }).click();
    await expect(page.locator('[data-role="nav-folder"]')).toHaveText(["Work"]);
    // Nothing of the folder is in the browser's storage.
    expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).not.toContain("Work");
    // Rename: both items, the one written "work" too, get the new name; the pin follows.
    await page.getByRole("button", { name: "Rename the folder Work" }).click();
    await expect(page.locator('[data-role="folder-new-name"]')).toBeFocused();
    await page.locator('[data-role="folder-new-name"]').fill("Jobb");
    await page.locator('[data-role="folder-new-name"]').press("Enter");
    await expect(page.locator('[data-role="message"]')).toContainText("renamed on 2 items");
    await expect(page.locator('[data-role="folder-open"]')).toHaveText(["Jobb", "Money"]);
    await expect(page.locator('[data-role="nav-folder"]')).toHaveText(["Jobb"]);
    expect(await page.evaluate(() => window.__writes.map(([id, draft]) => [id.slice(0, 2), draft]))).toEqual([["a1", { folders: ["Jobb"] }], ["b2", { folders: ["Money", "Jobb"] }]]);
    // Delete: the label goes, the items stay, the pin goes.
    await page.getByRole("button", { name: "Delete the folder Jobb" }).click();
    await expect(page.locator('[data-role="dialog-cancel"]')).toBeFocused();
    await page.locator('[data-role="dialog-confirm"]').click();
    await expect(page.locator('[data-role="folder-open"]')).toHaveText(["Money"]);
    await expect(page.locator('[data-role="nav-folder"]')).toHaveCount(0);
    expect(await page.evaluate(() => window.__engine.list().length)).toBe(3);
    expect(await page.evaluate(() => window.__violations)).toEqual([]);
  });

  test("the_page_of_a_folder_lists_its_items_whatever_the_case_and_can_pin_it", async ({ page }) => {
    await ready(page);
    await scene(page, "folder");
    await expect(page.locator('[data-role="list-title"]')).toHaveText("Work");
    await expect(page.locator('[data-role="item-link"]')).toHaveText(["Bank", "GitHub"]);
    await page.locator('[data-role="folder-bar"] [data-role="folder-pin"]').click();
    await expect(page.locator('[data-role="nav-folder"]')).toHaveText(["Work"]);
    await expect(page.locator('[data-role="folder-bar"] [data-role="folder-pin"]')).toHaveAttribute("aria-pressed", "true");
  });
});

test.describe("folders on a phone", () => {
  test.use({ viewport: { width: 320, height: 640 } });

  test("the_picker_and_the_folders_page_fit_a_narrow_screen", async ({ page }) => {
    await ready(page);
    await scene(page, "edit");
    await page.locator('[data-role="folder-input"]').fill("A folder name of exactly sixty-four characters for the layout xx");
    await page.locator('[data-role="folder-add"]').click();
    expect(await noSidewaysScroll(page)).toBe(true);
    await scene(page, "folders");
    expect(await noSidewaysScroll(page)).toBe(true);
    await expect(page.locator('[data-role="folder-rename"]').first()).toBeVisible();
  });
});
