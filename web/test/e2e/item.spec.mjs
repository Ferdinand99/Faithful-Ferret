// One item, its edit form, the empty states, the theme choice and the height of a short page, in real browsers. The screens
// are the real views in the real frame, over a fake engine, worker client and session (the tests of the whole flow need the
// server and are in test/e2e-stack). Run in Chromium, Firefox and WebKit.
import { expect, test } from "@playwright/test";

const LONG_NAME = "A bank with a very long name that keeps going and going until it has to wrap inside the page and not push it sideways";
const LONG_URL = "https://a-very-long-address.example.org/with/a/path/that/is/long/enough/to/need/wrapping/in/a/narrow/column/1234567890";
const PASSWORD = "correct-horse-battery-1";

/**
 * The page is up, and its own router is kept from listening to the address (it would answer a click on a link with the
 * sign-in page); the frame is built by the test.
 */
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
  await page.waitForFunction(() => document.fonts.check("16px InterVariable"), undefined, { timeout: 15_000 });
}

/**
 * Builds one screen in the real frame, in #app. `which`: item, edit, new, trash-empty, trash-full, devices-empty, list-empty,
 * list-favourites-empty, list-populated (two rows, the Favourites chip on). `opts.name` and `opts.url` make long values;
 * `opts.history` (a number) gives the item that many earlier passwords, "old-password-<n>", newest first.
 */
async function scene(page, which, opts = {}) {
  await page.evaluate(async ({ which, opts }) => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const t = i18n.t;
    const { mount } = await import("/app/dom.mjs");
    const common = await import("/app/views/common.mjs");
    const { shellView } = await import("/app/views/shell.mjs");
    window.__calls = { updates: [], removes: [], copied: [], creates: [], devices: 0 };
    const view = {
      name: opts.name ?? "GitHub", item_type: "login", favorite: false, has_notes: true, has_totp: false, read_only: false,
      fields: [
        { id: "username", label: "User name", value: "ada@example.com" },
        { id: "password", label: "Password", value: null },
        { id: "recovery", label: "Recovery code", value: null },
      ],
      urls: [{ url: opts.url ?? "https://github.com/login", matching: "host" }],
      folders: opts.folders ?? [],
      password_history: Array.from({ length: opts.history ?? 0 }, (_, i) => ({ until: Date.UTC(2026, 10, 20 - i, 12, 0) })),
    };
    const entry = { id: "a1".repeat(16), name: view.name, type: "login", favorite: false, urls: [], username: "ada@example.com", rev: 3 };
    const second = { id: "d4".repeat(16), name: "Bank", type: "note", favorite: true, urls: [], username: "ola", rev: 1, modified: Date.now() - 86_400_000 };
    const handlers = new Set();
    const engine = {
      list: () => (which === "list-empty" ? [] : which === "list-populated" ? [{ ...entry, favorite: true, modified: Date.now() }, second] : [entry]),
      on: (event, fn) => { if (event === "changed") handlers.add(fn); return () => handlers.delete(fn); },
      open: async () => ({ handle: 1, view, close: async () => {} }),
      update: async (id, draft, rev) => {
        window.__calls.updates.push([id, structuredClone(draft), rev]);
        // Like the real engine: the item changed.
        for (const fn of [...handlers]) fn({ ids: [id] });
      },
      create: async (draft) => { window.__calls.creates.push(structuredClone(draft)); return "b2".repeat(16); },
      remove: async (id) => { window.__calls.removes.push(id); },
      trash: async () => (which === "trash-full" ? [{ id: "c3".repeat(16), name: "Old router", deletedAt: Date.now() - 86_400_000 }] : []),
      restoreFromTrash: async () => {}, removeFromTrash: async () => {},
    };
    const client = { vault: {
      reveal_item_field: async (_handle, index) => ["ada@example.com", "correct-horse-battery-1", "RC-1234"][index],
      reveal_item_notes: async () => "the notes",
      reveal_password_history: async (_handle, index) => `old-password-${index}`,
    } };
    const session = { current: () => null, onLock() {}, info: async () => null };
    const clipboard = { writeText: async (text) => { window.__calls.copied.push(text); } };
    const go = (path) => { window.__calls.went = path; };
    const id = entry.id;
    let content;
    if (which === "item") {
      const { itemView } = await import("/app/views/item.mjs");
      content = await itemView({ engine, sync: { discard: async () => {}, discardMissing: async () => {} }, client, id, t, go, clipboard });
    } else if (which === "edit" || which === "new") {
      const { editView } = await import("/app/views/edit.mjs");
      content = await editView({ engine, client, id: which === "new" ? null : id, t, go });
    } else if (which.startsWith("trash")) {
      const { trashView } = await import("/app/views/trash.mjs");
      content = await trashView({ engine, t, locale: i18n.lang });
    } else if (which === "devices-empty") {
      const { devicesView } = await import("/app/views/devices.mjs");
      content = devicesView({
        t, locale: i18n.lang,
        load: async () => { window.__calls.devices += 1; return { devices: [] }; },
        revoke: async () => {}, revokeAll: async () => ({ revoked: 0 }), forgetOld: async () => ({ revoked: 0 }), reauth: async () => "ok",
      });
    } else {
      const { listView } = await import("/app/views/list.mjs");
      const query = which === "list-favourites-empty" || which === "list-populated" ? "fav=1" : "";
      content = listView({ engine, router: { go }, t, nav: { query, set() {}, watch: () => () => {} }, locale: i18n.lang });
    }
    const frame = shellView({
      t, engine, session, content, lock: async () => {}, touch: () => true, scope: common.createWipeScope(), onLocked: () => document.createElement("div"),
      email: "ada@example.com", signOut: async () => {},
    });
    mount(document.getElementById("app"), frame);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }, { which, opts });
  await expect(page.locator('[data-role="shell"]')).toBeAttached();
}

const noSidewaysScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
const noPageScroll = (page) => page.evaluate(() => document.documentElement.scrollHeight <= document.documentElement.clientHeight);

test.describe("one item on a desktop", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("the_item_has_a_header_and_cards_and_a_secret_shows_only_when_asked", async ({ page }) => {
    await ready(page);
    await scene(page, "item");
    const head = page.locator('[data-role="item-head"]');
    await expect(head.locator("h1")).toHaveText("GitHub");
    await expect(head.locator(".tile")).toHaveText("G");
    await expect(head.locator('[data-role="edit"]')).toBeVisible();
    await expect(head.locator('[data-role="delete"]')).toBeVisible();
    await expect(page.locator('[data-role="folder-chips"]')).toBeHidden();
    await expect(page.locator('[data-role="item-card"]')).toHaveCount(3); // sign-in, other fields, notes
    await expect(page.locator('[data-role="urls"]')).toBeVisible();
    // Nothing secret is on the page before a click.
    const text = () => page.locator('[data-role="item"]').innerText();
    expect(await text()).not.toContain(PASSWORD);
    expect(await text()).toContain("ada@example.com");
    // The buttons say which field they are for, and "Show" puts only that value on the page.
    const show = page.getByRole("button", { name: "Show Password" });
    await show.click();
    await expect(page.locator('[data-role="value"][data-key="f1"]')).toHaveText(PASSWORD);
    await expect(page.getByRole("button", { name: "Hide Password" })).toBeVisible();
    await page.getByRole("button", { name: "Show Recovery code" }).click();
    await expect(page.locator('[data-role="value"][data-key="f1"]')).not.toHaveText(PASSWORD);
    expect(await text()).not.toContain(PASSWORD);
    await page.getByRole("button", { name: "Hide Recovery code" }).click();
    expect(await text()).not.toContain("RC-1234");
  });

  test("previous_passwords_are_hidden_until_shown_one_at_a_time_and_copy_works", async ({ page }) => {
    await ready(page);
    await scene(page, "item", { history: 3 });
    const card = page.locator('[data-card="history"]');
    await expect(card.locator("h2")).toHaveText("Previous passwords (3)");
    await expect(card.locator('[data-role="field"]')).toHaveCount(3);
    const text = () => page.locator('[data-role="item"]').innerText();
    for (const n of [0, 1, 2]) expect(await text()).not.toContain(`old-password-${n}`);
    await card.locator('[data-role="reveal"]').first().click();
    await expect(card.locator('[data-role="value"][data-key="h0"]')).toHaveText("old-password-0");
    await card.locator('[data-role="reveal"]').nth(1).click();
    await expect(card.locator('[data-role="value"][data-key="h1"]')).toHaveText("old-password-1");
    expect(await text()).not.toContain("old-password-0");
    // Showing the current password hides the old one, and the other way round.
    await page.getByRole("button", { name: "Show Password" }).click();
    await expect(page.locator('[data-role="value"][data-key="f1"]')).toHaveText(PASSWORD);
    expect(await text()).not.toContain("old-password-1");
    await card.locator('[data-role="copy"]').nth(2).click();
    expect(await page.evaluate(() => window.__calls.copied)).toEqual(["old-password-2"]);
    expect(await text()).not.toContain("old-password-2");
  });

  test("an_item_without_history_has_no_previous_passwords_card", async ({ page }) => {
    await ready(page);
    await scene(page, "item");
    await expect(page.locator('[data-card="history"]')).toHaveCount(0);
  });

  test("copy_works_from_the_keyboard_and_the_value_is_not_put_on_the_page", async ({ page }) => {
    await ready(page);
    await scene(page, "item");
    const copy = page.getByRole("button", { name: "Copy Password" });
    await copy.focus();
    await expect(copy).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator('[data-role="message"]')).toContainText("Password copied");
    expect(await page.evaluate(() => window.__calls.copied)).toEqual([PASSWORD]);
    expect(await page.locator('[data-role="item"]').innerText()).not.toContain(PASSWORD);
    await page.getByRole("button", { name: "Copy Web address" }).click();
    expect(await page.evaluate(() => window.__calls.copied)).toEqual([PASSWORD, "https://github.com/login"]);
  });

  test("the_tab_order_in_the_item_goes_through_the_actions_then_the_buttons_of_each_field", async ({ page }) => {
    await ready(page);
    await scene(page, "item");
    await page.locator('[data-role="back"]').focus();
    const seen = [];
    for (let i = 0; i < 8; i += 1) {
      await page.keyboard.press("Tab");
      seen.push(await page.evaluate(() => document.activeElement?.getAttribute("aria-label") ?? document.activeElement?.getAttribute("data-role") ?? document.activeElement?.tagName));
    }
    expect(seen.slice(0, 3)).toEqual(["edit", "delete", "More actions for GitHub"]);
    expect(seen.slice(3, 6)).toEqual(["Copy User name", "Show Password", "Copy Password"]);
  });

  test("the_menu_marks_a_favourite_with_a_patch_and_escape_gives_the_focus_back", async ({ page }) => {
    await ready(page);
    await scene(page, "item");
    const more = page.getByRole("button", { name: "More actions for GitHub" });
    await more.click();
    await expect(more).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator('[data-role="favorite"]')).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-role="more-menu"]')).toBeHidden();
    await expect(more).toBeFocused();
    // A press outside closes it as well.
    await more.click();
    await page.locator("h1").first().click();
    await expect(page.locator('[data-role="more-menu"]')).toBeHidden();
    await more.click();
    await page.locator('[data-role="favorite"]').click();
    await expect.poll(() => page.evaluate(() => window.__calls.updates)).toEqual([["a1".repeat(16), { favorite: true }, 3]]);
    // The header is built again after the change; the keyboard user stays on the menu button.
    await expect(page.getByRole("button", { name: "More actions for GitHub" })).toBeFocused();
    await expect(page.locator('[data-role="more-menu"]')).toBeHidden();
  });

  test("move_to_trash_asks_first_and_removes_through_the_engine", async ({ page }) => {
    await ready(page);
    await scene(page, "item");
    await page.locator('[data-role="delete"]').click();
    const dialog = page.locator('[data-role="dialog"]');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("Move \"GitHub\" to the trash?");
    await dialog.locator('[data-role="dialog-cancel"]').click();
    expect(await page.evaluate(() => window.__calls.removes)).toEqual([]);
    await page.locator('[data-role="delete"]').click();
    await page.locator('[data-role="dialog-confirm"]').click();
    await expect.poll(() => page.evaluate(() => window.__calls.removes)).toEqual(["a1".repeat(16)]);
    expect(await page.evaluate(() => window.__calls.went)).toBe("/items");
  });

  test("folder_labels_show_as_chips_when_the_item_has_them", async ({ page }) => {
    await ready(page);
    await scene(page, "item", { folders: ["Home", "Finance"] });
    await expect(page.locator('[data-role="folder-chips"]')).toBeVisible();
    await expect(page.locator('[data-role="folder-chip"]')).toHaveText(["Finance", "Home"]); // sorted for display
  });

  test("the_edit_form_is_in_cards_and_saves_a_draft", async ({ page }) => {
    await ready(page);
    await scene(page, "edit");
    await expect(page.locator('[data-role="details-card"]')).toBeVisible();
    await expect(page.locator('[data-role="login-fields"]')).toBeVisible();
    await expect(page.locator('[data-role="notes-slot"]')).toBeVisible();
    await expect(page.locator('[data-role="folder-slot"] [data-role="folder-picker"]')).toBeVisible();
    // Each input has its label.
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("GitHub");
    await expect(page.getByLabel("User name", { exact: true })).toHaveValue("ada@example.com");
    await page.getByLabel("Name", { exact: true }).fill("GitHub 2");
    await page.locator('[data-role="save"]').click();
    await expect.poll(() => page.evaluate(() => window.__calls.updates.length)).toBe(1);
    const [id, draft, rev] = await page.evaluate(() => window.__calls.updates[0]);
    expect([id, draft.name, rev]).toEqual(["a1".repeat(16), "GitHub 2", 3]);
    // After the save every input is empty and the draft carries no password that was not typed.
    expect(await page.evaluate(() => document.querySelector('[data-role="name"]').value)).toBe("");
    expect(JSON.stringify(draft)).not.toContain(PASSWORD);
  });
});

for (const width of [320, 375]) {
  test.describe(`one item on a phone, ${width}px`, () => {
    test.use({ viewport: { width, height: 700 } });

    test("a_long_name_and_a_long_address_do_not_push_the_page_sideways", async ({ page }) => {
      await ready(page);
      await scene(page, "item", { name: LONG_NAME, url: LONG_URL });
      await expect(page.locator('[data-role="item-head"] h1')).toHaveText(LONG_NAME);
      expect(await noSidewaysScroll(page)).toBe(true);
      await page.getByRole("button", { name: "Show Password" }).click();
      expect(await noSidewaysScroll(page)).toBe(true);
      // Every box of the page is on the screen.
      const outside = await page.evaluate(() => {
        const width = document.documentElement.clientWidth;
        return [...document.querySelectorAll('[data-role="item"] *')]
          .filter((node) => { const box = node.getBoundingClientRect(); return box.width > 1 && (box.right > width + 0.5 || box.left < -0.5); })
          .map((node) => `${node.tagName.toLowerCase()} ${node.getAttribute("data-role") ?? ""}`);
      });
      expect(outside).toEqual([]);
    });

    test("the_edit_form_fits", async ({ page }) => {
      await ready(page);
      await scene(page, "edit", { name: LONG_NAME });
      expect(await noSidewaysScroll(page)).toBe(true);
      await scene(page, "new");
      expect(await noSidewaysScroll(page)).toBe(true);
    });
  });
}

test.describe("the empty states", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("an_empty_vault_offers_the_first_item", async ({ page }) => {
    await ready(page);
    await scene(page, "list-empty");
    const empty = page.locator('[data-role="list-empty"]');
    await expect(empty).toBeVisible();
    await expect(empty).toContainText("There are no items yet");
    await expect(empty.getByRole("button")).toHaveCount(1);
    await empty.getByRole("button", { name: "Add" }).click();
    expect(await page.evaluate(() => window.__calls.went)).toBe("/items/new");
  });

  test("favourites_with_none_say_how_to_make_one_and_offer_to_clear_the_filter", async ({ page }) => {
    await ready(page);
    await scene(page, "list-favourites-empty");
    const empty = page.locator('[data-role="list-empty"]');
    await expect(empty).toContainText("No favourites yet");
    await expect(empty.locator('[data-role="empty-clear-filters"]')).toBeVisible();
  });

  test("an_empty_trash_says_so_and_leads_back_to_the_items", async ({ page }) => {
    await ready(page);
    await scene(page, "trash-empty");
    const empty = page.locator('[data-role="trash-empty-state"]');
    await expect(empty).toContainText("The trash is empty");
    await expect(empty.getByRole("link", { name: "Go to all items" })).toHaveAttribute("href", "#/items");
    await scene(page, "trash-full");
    await expect(page.locator('[data-role="trash-empty-state"]')).toHaveCount(0);
  });

  test("a_list_of_no_devices_says_so_and_can_be_checked_again", async ({ page }) => {
    await ready(page);
    await scene(page, "devices-empty");
    const empty = page.locator('[data-role="devices-empty-state"]');
    await expect(empty).toContainText("No devices are signed in");
    const before = await page.evaluate(() => window.__calls.devices);
    await empty.getByRole("button", { name: "Check again" }).click();
    await expect.poll(() => page.evaluate(() => window.__calls.devices)).toBe(before + 1);
  });

  test("an_empty_state_is_centred_and_inside_the_screen_on_a_phone", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 640 });
    await ready(page);
    for (const which of ["list-empty", "trash-empty", "devices-empty"]) {
      await scene(page, which);
      expect(await noSidewaysScroll(page), which).toBe(true);
    }
  });
});

for (const scheme of ["light", "dark"]) {
  test.describe(`the theme choice, starting from ${scheme}`, () => {
    test.use({ viewport: { width: 1280, height: 800 }, colorScheme: scheme });

    test("the_account_menu_chooses_light_dark_or_system_and_the_choice_is_remembered_as_one_word", async ({ page }) => {
      await ready(page);
      await scene(page, "item");
      const background = () => page.evaluate(() => getComputedStyle(document.documentElement).backgroundColor);
      const LIGHT = "rgb(245, 245, 247)";
      const DARK = "rgb(11, 11, 13)";
      expect(await background()).toBe(scheme === "light" ? LIGHT : DARK);
      // The page has no footer and no switch of its own any more.
      await expect(page.locator("#foot")).toHaveCount(0);
      await expect(page.locator('#app [data-role="theme"]')).toBeHidden();

      await page.locator('[data-role="account-menu-button"]').click();
      const radio = (name) => page.locator(`[data-role="theme-choice"][data-theme-set="${name}"]`);
      await expect(page.getByRole("group", { name: "Theme" })).toBeVisible();
      await expect(page.getByRole("menuitemradio")).toHaveText(["Light", "Dark", "System"]);
      await expect(radio("auto")).toHaveAttribute("aria-checked", "true");

      await radio("dark").click();
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      expect(await background()).toBe(DARK);
      await expect(radio("dark")).toHaveAttribute("aria-checked", "true");
      await expect(radio("auto")).toHaveAttribute("aria-checked", "false");
      await expect(page.locator('[data-role="account-menu"]')).toBeVisible(); // still open
      expect(await page.evaluate(() => Object.entries(localStorage).filter(([key]) => key.startsWith("ferret-theme")))).toEqual([["ferret-theme", "dark"]]);

      await radio("light").click();
      expect(await background()).toBe(LIGHT);
      await radio("auto").click();
      await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.*/);
      expect(await page.evaluate(() => localStorage.getItem("ferret-theme"))).toBeNull();
      expect(await background()).toBe(scheme === "light" ? LIGHT : DARK);

      // The chosen theme is back after a reload, before the first paint.
      await radio("dark").click();
      await page.reload();
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      expect(await background()).toBe(DARK);
    });

    test("the_theme_choice_works_from_the_keyboard", async ({ page }) => {
      await ready(page);
      await scene(page, "item");
      const button = page.locator('[data-role="account-menu-button"]');
      await button.focus();
      await page.keyboard.press("Enter");
      await expect(page.locator('[data-role="nav-account"]')).toBeFocused();
      await page.keyboard.press("ArrowDown"); // help
      await page.keyboard.press("ArrowDown"); // light
      await expect(page.locator('[data-theme-set="light"]')).toBeFocused();
      await page.keyboard.press("Space");
      await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      await page.keyboard.press("Escape");
      await expect(button).toBeFocused();
    });
  });
}

/** How far the page is taller than its screen and its content together: what something under the content (a footer) would add. */
const extraHeight = (page) =>
  page.evaluate(() => {
    const main = document.querySelector(".vault-main");
    const bottom = Math.ceil(main.getBoundingClientRect().bottom + window.scrollY);
    return document.documentElement.scrollHeight - Math.max(window.innerHeight, bottom);
  });

test.describe("a short page does not scroll", () => {
  for (const [width, height] of [[1280, 800], [1024, 700]]) {
    test(`a_short_page_has_no_page_scroll_at_${width}x${height}`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      await ready(page);
      for (const which of ["list-empty", "trash-empty"]) {
        await scene(page, which);
        expect(await noPageScroll(page), `${which} at ${width}x${height}`).toBe(true);
      }
    });
  }

  for (const [width, height] of [[1280, 800], [375, 700], [320, 640]]) {
    test(`nothing_under_the_content_adds_height_at_${width}x${height}`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      await ready(page);
      for (const which of ["list-empty", "trash-empty", "devices-empty", "item", "new"]) {
        await scene(page, which);
        expect(await extraHeight(page), `${which} at ${width}x${height}`).toBeLessThanOrEqual(1);
      }
    });
  }
});

/**
 * Every visible text on the page against the colour behind it: 4.5:1 (WCAG AA), in the theme the page is in. The colours are the
 * computed ones, so a token that is wrong in one theme is caught where it is used. Inactive things (disabled, aria-disabled) are
 * left out, as the guideline does.
 */
const lowContrast = (page) =>
  page.evaluate(() => {
    const parse = (text) => {
      const m = /^rgba?\(([^)]*)\)$/.exec(text);
      if (m) {
        const [r, g, b, a = "1"] = m[1].split(/[ ,/]+/).filter(Boolean);
        return { r: Number(r), g: Number(g), b: Number(b), a: Number(a) };
      }
      const c = /^color\(srgb ([^)]*)\)$/.exec(text);
      if (c) {
        const [r, g, b, a = "1"] = c[1].split(/[ /]+/).filter(Boolean);
        return { r: Number(r) * 255, g: Number(g) * 255, b: Number(b) * 255, a: Number(a) };
      }
      return null;
    };
    const over = (top, under) => ({
      r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a), b: top.b * top.a + under.b * (1 - top.a), a: 1,
    });
    const lum = (c) => {
      const f = (v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a, b) => { const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
    const backdrop = (node) => {
      const layers = [];
      for (let n = node; n; n = n.parentElement) {
        const bg = parse(getComputedStyle(n).backgroundColor);
        if (bg && bg.a > 0) layers.push(bg);
        if (bg && bg.a === 1) break;
      }
      let base = parse(getComputedStyle(document.documentElement).backgroundColor) ?? { r: 255, g: 255, b: 255, a: 1 };
      if (base.a < 1) base = over(base, { r: 255, g: 255, b: 255, a: 1 });
      for (const layer of layers.reverse()) base = over(layer, base);
      return base;
    };
    const out = [];
    let checked = 0;
    for (const node of document.querySelectorAll("#app *")) {
      const own = [...node.childNodes].some((child) => child.nodeType === 3 && child.data.trim() !== "");
      if (!own) continue;
      const box = node.getBoundingClientRect();
      if (box.width < 2 || box.height < 2) continue;
      if (node.closest("[hidden], [aria-hidden='true'], [disabled], [aria-disabled='true']")) continue;
      const style = getComputedStyle(node);
      if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) < 1) continue;
      if (node.closest(".visually-hidden, .vh, .skip-link")) continue;
      const colour = parse(style.color);
      if (!colour) continue;
      checked += 1;
      const bg = backdrop(node);
      const fg = over(colour, bg);
      const got = ratio(fg, bg);
      if (got < 4.5) out.push(`${node.tagName.toLowerCase()}${node.getAttribute("data-role") ? `[${node.getAttribute("data-role")}]` : ""} "${node.textContent.trim().slice(0, 30)}" ${got.toFixed(2)}:1`);
    }
    return { checked, low: out };
  });

for (const scheme of ["light", "dark"]) {
  test.describe(`contrast in the ${scheme} theme`, () => {
    test.use({ viewport: { width: 1280, height: 800 }, colorScheme: scheme });

    for (const which of ["item", "edit", "list-populated", "list-empty", "trash-full", "trash-empty", "devices-empty"]) {
      test(`the_${which}_page_reads_at_aa`, async ({ page }) => {
        await ready(page);
        await scene(page, which, which === "item" ? { folders: ["Home"], history: 2 } : {});
        if (which === "list-populated") {
          // The chosen chip, a row that is ticked (so the bar for several rows is up), and the open menu of a row.
          await expect(page.locator('[data-role="favorites-chip"]')).toHaveAttribute("aria-pressed", "true");
          await page.locator('[data-role="select"]').first().check();
          await expect(page.locator('[data-role="bulk"]')).toBeVisible();
          await page.locator('[data-role="row-menu"]').first().click();
        }
        if (which === "item") {
          await page.getByRole("button", { name: "Show Password" }).click();
          await page.getByRole("button", { name: "More actions for GitHub" }).click();
        }
        const first = await lowContrast(page);
        expect(first.checked, `the test looked at the texts of ${which}`).toBeGreaterThan(8);
        expect(first.low, `${which}, ${scheme}`).toEqual([]);
        // The account menu with the theme choice open.
        await page.locator('[data-role="account-menu-button"]').click();
        const second = await lowContrast(page);
        expect(second.checked).toBeGreaterThan(first.checked);
        expect(second.low, `${which} with the account menu, ${scheme}`).toEqual([]);
      });
    }
  });
}
