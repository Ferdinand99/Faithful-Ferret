// The item list in real browsers: search, filter chips and their menus, the filters in the address (back and forward),
// the order, the menu of a row with the keyboard, select-all and the bar for several rows, the empty states, a phone
// at 320 px, and a list of ten thousand items. The list is the real view over a fake engine (the tests of the whole flow
// are in the stack tests, which need the server). Run in Chromium, Firefox and WebKit.
import { expect, test } from "@playwright/test";

/**
 * Builds the list in the page. `options`: count, hash (the address to start from), types (cycle), none (an empty vault), folders.
 * The engine is a stand-in that keeps the items, answers `update` and `remove` the way the real one shows them, and counts the calls.
 */
async function mountList(page, options = {}) {
  await page.evaluate(async (opts) => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const { mount, el } = await import("/app/dom.mjs");
    const { listView } = await import("/app/views/list.mjs");
    const { createListPrefs } = await import("/app/listPrefs.mjs");
    window.__hashListening = true;
    document.getElementById("app").hidden = true;
    document.getElementById("list-test")?.remove();
    history.replaceState(null, "", opts.hash ?? "#/items");
    const types = ["login", "note", "card", "identity"];
    const now = Date.now();
    const items = opts.none ? [] : Array.from({ length: opts.count ?? 40 }, (_, i) => ({
      id: (i + 1).toString(16).padStart(32, "0"),
      name: `Item ${String(i).padStart(5, "0")}`,
      type: types[i % types.length],
      favorite: i % 5 === 0,
      urls: [`https://site${i}.example`],
      username: `user${i}@example.test`,
      modified: now - i * 3_600_000,
      rev: 1,
      pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
      ...(opts.folders ? { folders: i % 3 === 0 ? ["Home", "Money"] : i % 3 === 1 ? ["Home"] : [] } : {}),
    }));
    const listeners = new Set();
    const engine = {
      list: () => items.map((item) => ({ ...item })).sort((a, b) => a.name.localeCompare(b.name)),
      on: (event, fn) => {
        if (event === "changed") listeners.add(fn);
        return () => listeners.delete(fn);
      },
      update: async (id, draft) => {
        window.__calls.updates.push([id, draft]);
        const item = items.find((i) => i.id === id);
        Object.assign(item, draft, { rev: item.rev + 1 });
        for (const fn of [...listeners]) fn({ ids: [id] });
      },
      remove: async (id) => {
        window.__calls.removes.push(id);
        items.splice(items.findIndex((i) => i.id === id), 1);
        for (const fn of [...listeners]) fn({ ids: [id] });
      },
    };
    window.__calls = { updates: [], removes: [], moves: 0 };
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", (event) => window.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
    const nav = {
      get query() {
        return location.hash.split("?")[1] ?? "";
      },
      set: (query) => {
        location.hash = `#/items${query === "" ? "" : `?${query}`}`;
      },
      watch: (fn) => {
        const handler = () => fn(location.hash.split("?")[1] ?? "");
        window.addEventListener("hashchange", handler);
        return () => window.removeEventListener("hashchange", handler);
      },
    };
    const host = el("div", { id: "list-test", class: "vault-ui" });
    host.style.display = "flex";
    host.style.flexDirection = "column";
    host.style.minHeight = "100vh";
    const main = el("main", { class: "vault-main" });
    host.appendChild(main);
    document.body.insertBefore(host, document.getElementById("foot"));
    const started = performance.now();
    const view = listView({
      engine, router: { go: (path) => { location.hash = `#${path}`; } }, t: i18n.t, nav, locale: "en", touch: () => true,
      prefs: createListPrefs(window.localStorage), moveToFolder: opts.moveToFolder ? () => { window.__calls.moves += 1; } : undefined,
    });
    mount(main, view);
    // Reading the height makes the browser do style and layout now: they are part of the time.
    void document.body.offsetHeight;
    window.__firstRender = performance.now() - started;
  }, options);
  await expect(page.locator('[data-role="list"]')).toBeAttached();
}

/** The page is up; its own router is kept from listening to the address (it would answer with the sign-in page). */
async function ready(page) {
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
  await page.waitForFunction(() => document.fonts.check("16px InterVariable"), undefined, { timeout: 15_000 });
}

const rowNames = (page) => page.locator('[data-role="item-link"]').allTextContents().then((all) => all.map((text) => text.replace("★", "").trim()));
const hashOf = (page) => page.evaluate(() => location.hash);
const noSidewaysScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);

test.describe("the list on a desktop", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("search_narrows_the_rows_and_clearing_it_brings_them_back", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 40 });
    await expect(page.locator('[data-role="item"]')).toHaveCount(40);
    await expect(page.locator('[data-role="count"]')).toHaveText("40 items");
    await page.locator('[data-role="search"]').fill("item 00007");
    await expect(page.locator('[data-role="item"]')).toHaveCount(1);
    await expect(page.locator('[data-role="count"]')).toHaveText("1 of 40 items");
    expect(await hashOf(page)).toBe("#/items");
    await page.locator('[data-role="search"]').fill("user12@");
    await expect(page.locator('[data-role="item"]')).toHaveCount(1);
    await page.locator('[data-role="search-clear"]').click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(40);
    await expect(page.locator('[data-role="search"]')).toBeFocused();
    expect(await page.evaluate(() => window.__violations)).toEqual([]);
  });

  test("chips_filter_and_the_filters_are_in_the_address_so_back_and_forward_work", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 40 });
    // The Type chip opens a menu with a box and a count for each type the vault has.
    await page.locator('[data-role="type-chip"]').click();
    const noteBox = page.getByRole("menuitemcheckbox", { name: /Note/ });
    await expect(noteBox).toContainText("10");
    await noteBox.click();
    await expect(noteBox).toHaveAttribute("aria-checked", "true");
    await expect(page.locator('[data-role="item"]')).toHaveCount(10);
    await expect(page.locator('[data-role="type-chip"]')).toContainText("Type: Note");
    expect(await hashOf(page)).toBe("#/items?type=note");
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-role="type-menu"]')).toBeHidden();
    await expect(page.locator('[data-role="type-chip"]')).toBeFocused();
    // The Favourites chip.
    await page.locator('[data-role="favorites-chip"]').click();
    expect(await hashOf(page)).toBe("#/items?type=note&fav=1");
    await expect(page.locator('[data-role="item"]')).toHaveCount(2);
    await expect(page.locator('[data-role="favorites-chip"]')).toHaveAttribute("aria-pressed", "true");
    // Back and forward move between the filters.
    await page.goBack();
    await expect(page.locator('[data-role="item"]')).toHaveCount(10);
    await page.goBack();
    await expect(page.locator('[data-role="item"]')).toHaveCount(40);
    await page.goForward();
    await expect(page.locator('[data-role="item"]')).toHaveCount(10);
    await page.goForward();
    await expect(page.locator('[data-role="item"]')).toHaveCount(2);
    // Each chip has its own cross.
    await page.locator('[data-role="favorites-remove"]').click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(10);
    await page.locator('[data-role="type-remove"]').click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(40);
    expect(await hashOf(page)).toBe("#/items");
    // The search text is in no address, whatever the filters.
    await page.locator('[data-role="search"]').fill("secret-looking text");
    await page.locator('[data-role="favorites-chip"]').click();
    expect(await hashOf(page)).not.toContain("secret");
  });

  test("a_list_that_starts_from_an_address_with_filters_shows_them", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 40, hash: "#/items?type=card&sort=changed&dir=asc" });
    await expect(page.locator('[data-role="item"]')).toHaveCount(10);
    await expect(page.locator('[data-role="type-chip"]')).toContainText("Type: Card");
    // Oldest change first: the item with the largest number.
    expect((await rowNames(page))[0]).toBe("Item 00038");
    await expect(page.locator('[role="columnheader"][aria-sort="ascending"]')).toContainText("Last changed");
  });

  test("the_columns_order_the_rows", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 30 });
    expect((await rowNames(page))[0]).toBe("Item 00000");
    await page.locator('[data-role="sort-name"]').click();
    expect((await rowNames(page))[0]).toBe("Item 00029");
    await expect(page.locator('[data-role="sort-name"]')).toContainText("↑");
    await page.locator('[data-role="sort-changed"]').click();
    expect((await rowNames(page))[0]).toBe("Item 00000");
    expect(await hashOf(page)).toBe("#/items?sort=changed");
    await page.locator('[data-role="sort-changed"]').click();
    expect((await rowNames(page))[0]).toBe("Item 00029");
  });

  test("select_all_and_the_bar_for_several_rows_move_the_items_to_the_trash_after_asking", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 12 });
    await page.getByRole("checkbox", { name: "Select all" }).check();
    await expect(page.locator('[data-role="bulk"]')).toBeVisible();
    await expect(page.locator('[data-role="bulk-count"]')).toHaveText("12 selected");
    await page.getByRole("checkbox", { name: "Select Item 00003" }).uncheck();
    await expect(page.locator('[data-role="bulk-count"]')).toHaveText("11 selected");
    // The bar gives the favourite to those that have none.
    await page.locator('[data-role="bulk-favorite"]').click();
    await expect(page.locator('[data-role="message"]')).toContainText("added to your favourites");
    expect(await page.evaluate(() => window.__calls.updates.length)).toBe(11 - 3);
    // Trash: a question first; cancel changes nothing.
    await page.getByRole("checkbox", { name: "Select all" }).check();
    await page.locator('[data-role="bulk-trash"]').click();
    await expect(page.getByRole("alertdialog")).toContainText("Move 12 items to the trash?");
    await page.locator('[data-role="dialog-cancel"]').click();
    expect(await page.evaluate(() => window.__calls.removes.length)).toBe(0);
    await page.locator('[data-role="bulk-trash"]').click();
    await page.locator('[data-role="dialog-confirm"]').click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(0);
    expect(await page.evaluate(() => window.__calls.removes.length)).toBe(12);
    await expect(page.locator('[data-role="list-empty"]')).toContainText("There are no items yet");
    await expect(page.locator('[data-role="empty-add"]')).toBeVisible();
  });

  test("the_empty_states_have_a_way_out", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 20 });
    await page.locator('[data-role="search"]').fill("zzzzzz");
    await expect(page.locator('[data-role="empty-text"]')).toHaveText("No item matches the search.");
    await expect(page.locator('[data-role="table"]')).toBeHidden();
    await page.locator('[data-role="empty-clear-search"]').click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(20);
    // Filters that leave nothing: the only favourite is a login, and the type is Note.
    await mountList(page, { count: 4 });
    await page.locator('[data-role="favorites-chip"]').click();
    await page.locator('[data-role="type-chip"]').click();
    await page.getByRole("menuitemcheckbox", { name: /Note/ }).click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(0);
    await expect(page.locator('[data-role="empty-text"]')).toHaveText("No item matches the filters.");
    await page.locator('[data-role="empty-clear-filters"]').click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(4);
    expect(await hashOf(page)).toBe("#/items");
    // An empty vault.
    await mountList(page, { none: true });
    await expect(page.locator('[data-role="empty-text"]')).toContainText("no items yet");
    await expect(page.locator('[data-role="search"]')).toBeHidden();
  });

  test("the_menu_of_a_row_works_with_the_keyboard", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 6, moveToFolder: true });
    const more = page.getByRole("button", { name: "Options for Item 00001" });
    await more.focus();
    await page.keyboard.press("Enter");
    await expect(more).toHaveAttribute("aria-expanded", "true");
    const menu = page.getByRole("menu", { name: "Item 00001" });
    await expect(menu).toBeVisible();
    // The first entry has the focus; the arrows move; the ends wrap.
    await expect(menu.getByRole("menuitem", { name: "View" })).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(menu.getByRole("menuitem", { name: /favourites/ })).toBeFocused();
    await page.keyboard.press("End");
    await expect(menu.getByRole("menuitem", { name: "Move to trash" })).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(menu.getByRole("menuitem", { name: "View" })).toBeFocused();
    expect((await menu.getByRole("menuitem").allTextContents()).map((text) => text.trim())).toEqual(["View", "Add to favourites", "Edit", "Move to folder", "Move to trash"]);
    // The menu is on the screen, not cut off by the table.
    const box = await menu.boundingBox();
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(1280);
    // Escape closes it and the focus is back on the button.
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
    await expect(more).toBeFocused();
    await expect(more).toHaveAttribute("aria-expanded", "false");
    // Favourite through the menu: one edit of the one field.
    await more.press("ArrowDown");
    await menu.getByRole("menuitem", { name: "Add to favourites" }).click();
    await expect(page.locator('[data-role="message"]')).toContainText("added to your favourites");
    expect(await page.evaluate(() => window.__calls.updates)).toEqual([["00000000000000000000000000000002", { favorite: true }]]);
    // Move to folder is the folder task's: it is called with the item.
    await page.getByRole("button", { name: "Options for Item 00002" }).click();
    await page.getByRole("menuitem", { name: "Move to folder" }).click();
    expect(await page.evaluate(() => window.__calls.moves)).toBe(1);
    // A press elsewhere closes an open menu.
    await page.getByRole("button", { name: "Options for Item 00003" }).click();
    await expect(page.getByRole("menu", { name: "Item 00003" })).toBeVisible();
    await page.locator("h1.list-title").click();
    await expect(page.getByRole("menu", { name: "Item 00003" })).toBeHidden();
  });

  test("the_up_and_down_keys_move_between_rows_and_the_rows_have_names", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 8 });
    await expect(page.getByRole("table")).toBeVisible();
    await expect(page.getByRole("columnheader")).toHaveCount(4); // the folders column is not there
    await expect(page.getByRole("row")).toHaveCount(9);
    const links = page.locator('[data-role="item-link"]');
    await links.nth(0).focus();
    await page.keyboard.press("ArrowDown");
    await expect(links.nth(1)).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(links.nth(2)).toBeFocused();
    await page.keyboard.press("ArrowUp");
    await expect(links.nth(1)).toBeFocused();
    // The same control of the next row: the box.
    const boxes = page.locator('[data-role="select"]');
    await boxes.nth(1).focus();
    await page.keyboard.press("ArrowDown");
    await expect(boxes.nth(2)).toBeFocused();
    // On the menu button the arrows open its own menu (and only that), with the focus inside it; Escape gives the focus back.
    const opts = page.locator('[data-role="row-menu"]');
    await opts.nth(2).focus();
    await page.keyboard.press("ArrowDown");
    await expect(opts.nth(2)).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByRole("menu", { name: "Item 00002" }).getByRole("menuitem", { name: "View" })).toBeFocused();
    await expect(opts.nth(3)).toHaveAttribute("aria-expanded", "false");
    await page.keyboard.press("Escape");
    await expect(opts.nth(2)).toBeFocused();
    await opts.nth(2).press("ArrowUp");
    await expect(page.getByRole("menu", { name: "Item 00002" }).getByRole("menuitem", { name: "Move to trash" })).toBeFocused();
    await page.keyboard.press("Escape");
    // The sort buttons and the chips are buttons with names.
    await expect(page.getByRole("button", { name: /^Name/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Last changed/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Favourites", pressed: false })).toBeVisible();
    await expect(page.getByRole("button", { name: "Clear the search" })).toBeHidden();
    await expect(page.getByRole("link", { name: "Import" })).toHaveAttribute("href", "#/import");
  });

  test("the_customise_menu_hides_a_column", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 5 });
    await expect(page.locator('[data-role="changed"]').first()).toBeVisible();
    await page.locator('[data-role="customise"]').click();
    await page.getByRole("menuitemcheckbox", { name: /Last changed/ }).click();
    await expect(page.locator('[data-role="changed"]').first()).toBeHidden();
    await page.getByRole("menuitemcheckbox", { name: /Last changed/ }).click();
    await expect(page.locator('[data-role="changed"]').first()).toBeVisible();
  });

  test("folders_show_a_chip_and_a_column_only_when_items_have_them", async ({ page }) => {
    await ready(page);
    await mountList(page, { count: 9 });
    await expect(page.locator('[data-role="chip-folders"]')).toBeHidden();
    await expect(page.locator('[data-role="folders"]').first()).toBeHidden();
    await mountList(page, { count: 9, folders: true });
    await expect(page.locator('[data-role="chip-folders"]')).toBeVisible();
    await expect(page.locator('[data-role="folders"]').first()).toContainText("Home");
    await expect(page.locator('[data-role="folders"]').first()).toContainText("+1");
    await page.locator('[data-role="folders-chip"]').click();
    await page.getByRole("menuitemcheckbox", { name: /Money/ }).click();
    await expect(page.locator('[data-role="item"]')).toHaveCount(3);
  });

  test("no_policy_violation_and_the_dark_and_light_theme_both_draw_the_list", async ({ page, browserName }, info) => {
    await ready(page);
    await mountList(page, { count: 30 });
    expect(await page.evaluate(() => window.__violations)).toEqual([]);
    for (const scheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: scheme });
      await expect(page.locator('[data-role="list-bar"]')).toBeVisible();
      await page.screenshot({ path: info.outputPath(`list-${scheme}.png`) });
    }
    // WebKit puts a style element in the page to take a screenshot; that one is its own and is let by.
    const violations = await page.evaluate(() => window.__violations);
    expect(violations.filter((v) => !(browserName === "webkit" && v === "style-src-elem inline"))).toEqual([]);
  });
});

test.describe("a long list", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("ten_thousand_items_are_drawn_as_a_window_and_filter_fast", async ({ page }, info) => {
    await ready(page);
    await mountList(page, { count: 10_000 });
    const first = await page.evaluate(() => window.__firstRender);
    info.annotations.push({ type: "first render", description: `${first.toFixed(0)} ms` });
    expect(first).toBeLessThan(300);
    const drawn = await page.locator('[data-role="item"]').count();
    expect(drawn).toBeGreaterThan(10);
    expect(drawn).toBeLessThan(80);
    await expect(page.locator('[data-role="count"]')).toHaveText("10000 items");

    // Typing in the search: the time from the input to the list drawn, over a few keys.
    const times = await page.evaluate(async () => {
      const search = document.querySelector('[data-role="search"]');
      const out = [];
      for (const text of ["i", "it", "ite", "item 0", "item 00", "item 009"]) {
        search.value = text;
        const start = performance.now();
        search.dispatchEvent(new Event("input", { bubbles: true }));
        void document.body.offsetHeight; // style and layout of the new rows count too
        out.push(performance.now() - start);
        await new Promise((resolve) => requestAnimationFrame(resolve));
      }
      return out;
    });
    info.annotations.push({ type: "filter", description: times.map((ms) => ms.toFixed(1)).join(", ") + " ms" });
    expect(Math.max(...times)).toBeLessThan(50);
    await expect(page.locator('[data-role="count"]')).toHaveText(/^\d+ of 10000 items$/);
    // A chip, on the whole list.
    await page.locator('[data-role="search-clear"]').click();
    const chip = await page.evaluate(async () => {
      const start = performance.now();
      document.querySelector('[data-role="favorites-chip"]').click();
      void document.body.offsetHeight;
      return performance.now() - start;
    });
    info.annotations.push({ type: "chip", description: `${chip.toFixed(1)} ms` });
    expect(chip).toBeLessThan(50);
    await expect(page.locator('[data-role="count"]')).toHaveText("2000 of 10000 items");
    await page.locator('[data-role="favorites-remove"]').click();

    // Scrolling to the end draws the last rows, and a window of the same size.
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    await expect(page.locator('[data-role="item-link"]', { hasText: "Item 09999" })).toBeVisible();
    expect(await page.locator('[data-role="item"]').count()).toBeLessThan(80);
    // The keys move on through rows that are not drawn yet.
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(page.locator('[data-role="item-link"]', { hasText: "Item 00000" })).toBeVisible();
    const links = page.locator('[data-role="item-link"]');
    await links.nth(0).focus();
    for (let i = 0; i < 25; i += 1) await page.keyboard.press("ArrowDown");
    await expect(page.locator('[data-role="item-link"]:focus')).toContainText("Item 00025");
    // Select all is for the whole list, not for the rows that are drawn.
    await page.getByRole("checkbox", { name: "Select all" }).check();
    await expect(page.locator('[data-role="bulk-count"]')).toHaveText("10000 selected");
  });
});

test.describe("a phone", () => {
  test.use({ viewport: { width: 320, height: 640 }, hasTouch: true });

  test("the_rows_are_cards_and_the_page_does_not_scroll_sideways_at_320px", async ({ page }, info) => {
    await ready(page);
    await mountList(page, { count: 30 });
    expect(await noSidewaysScroll(page)).toBe(true);
    // Every control of the bar is on the screen.
    for (const role of ["search", "customise", "import", "new-item", "type-chip", "favorites-chip"]) {
      const box = await page.locator(`[data-role="${role}"]`).boundingBox();
      expect(box.x, role).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width, role).toBeLessThanOrEqual(320 + 0.5);
    }
    // A card shows the name, the user name and when it changed; the menu button is on the screen.
    const row = page.locator('[data-role="item"]').first();
    await expect(row).toContainText("Item 00000");
    await expect(row).toContainText("user0@example.test");
    const more = await row.locator('[data-role="row-menu"]').boundingBox();
    expect(more.x + more.width).toBeLessThanOrEqual(320);
    expect(more.width).toBeGreaterThanOrEqual(36);
    // A very long name is cut and does not widen the page.
    await page.evaluate(() => {
      const link = document.querySelector('[data-role="item-link"]');
      link.textContent = "A".repeat(300);
    });
    expect(await noSidewaysScroll(page)).toBe(true);
    // The menu of a row opens on the screen.
    await row.locator('[data-role="row-menu"]').click();
    const menu = await page.locator('[data-role="row-menu-list"]:visible').boundingBox();
    expect(menu.x).toBeGreaterThanOrEqual(0);
    expect(menu.x + menu.width).toBeLessThanOrEqual(320);
    await page.keyboard.press("Escape");
    // The bar for several rows is on the screen when rows are marked.
    await page.getByRole("checkbox", { name: "Select all" }).check();
    const bulk = await page.locator('[data-role="bulk"]').boundingBox();
    expect(bulk.x).toBeGreaterThanOrEqual(0);
    expect(bulk.x + bulk.width).toBeLessThanOrEqual(320 + 0.5);
    expect(bulk.y + bulk.height).toBeLessThanOrEqual(640);
    expect(await noSidewaysScroll(page)).toBe(true);
    await page.screenshot({ path: info.outputPath("list-320.png") });
  });

  test("an_empty_vault_fits_at_320px", async ({ page }) => {
    await ready(page);
    await mountList(page, { none: true });
    expect(await noSidewaysScroll(page)).toBe(true);
    await expect(page.locator('[data-role="empty-add"]')).toBeVisible();
  });
});
