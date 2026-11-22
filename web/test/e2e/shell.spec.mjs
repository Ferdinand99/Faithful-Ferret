// The frame of the vault in real browsers: the side menu, its entries, the account menu, the drawer of a phone, the
// keyboard, and both themes. The frame is the real view with a fake engine and session (the tests of the whole flow
// need the server); it stands beside the page's own content, which is hidden. Run in Chromium, Firefox and WebKit.
// The screenshots are kept in test-results (the workflow uploads them; they are not part of the repository).
import { expect, test } from "@playwright/test";

const LONG_EMAIL = "a.very.long.user.name.that.keeps.going.and.going@a-very-long-domain-name-for-an-example.example.org";
// The longest a folder name may be is 64 characters.
const LONG_FOLDER = "A folder with a very long name that keeps going until it is cut";

/** Builds the frame in the page. `options`: admin, email, collapsed, pinned (folder names), withFolders. */
async function mountShell(page, options = {}) {
  await page.evaluate(async (opts) => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const { mount, el } = await import("/app/dom.mjs");
    const { shellView } = await import("/app/views/shell.mjs");
    const { createWipeScope } = await import("/app/views/common.mjs");
    const { createUiPrefs } = await import("/app/uiPrefs.mjs");
    const routes = (await import("/app/routes.gen.mjs")).default;
    window.__hashListening = true;
    document.getElementById("app").hidden = true;
    document.getElementById("shell-test")?.remove();
    const host = el("div", { id: "shell-test" });
    host.style.display = "flex";
    host.style.flexDirection = "column";
    host.style.minHeight = "100vh";
    document.body.appendChild(host);
    const prefs = createUiPrefs();
    if (opts.collapsed !== undefined) prefs.setCollapsed(opts.collapsed);
    for (const id of opts.pinned ?? []) prefs.pin(id);
    const items = Array.from({ length: 248 }, (_, i) => ({ id: (i + 1).toString(16).padStart(32, "0"), name: `Item ${i}`, favorite: i % 20 === 0, urls: [] }));
    const handlers = new Map();
    const engine = { list: () => items, on: (event, fn) => { handlers.set(event, fn); return () => {}; } };
    // The items change from the test: more of them, and the engine says so.
    window.__changeItems = (count) => {
      while (items.length < count) items.push({ id: (items.length + 1).toString(16).padStart(32, "0"), name: `Item ${items.length}`, favorite: false, urls: [] });
      handlers.get("changed")?.({});
    };
    window.__calls = { lock: 0, signOut: 0, admin: 0 };
    const frame = shellView({
      t: i18n.t, engine, session: { onLock() {} },
      content: el("section", { class: "list-view" }, el("h1", null, "All items"), el("p", { "data-role": "page-text" }, "The screen.")),
      lock: async () => { window.__calls.lock += 1; }, touch: () => true, scope: createWipeScope(), onLocked: () => el("div"),
      routes, email: opts.email ?? "ada.lovelace@example.com", prefs,
      folders: opts.withFolders ? [{ id: "home", name: "Home", parentId: null }, { id: "net", name: "Network", parentId: "home" }, { id: "long", name: opts.longFolder, parentId: null }] : [],
      admin: opts.admin ? { check: async () => true, go: () => { window.__calls.admin += 1; } } : undefined,
      signOut: async () => { window.__calls.signOut += 1; },
    });
    mount(host, frame);
  }, { longFolder: LONG_FOLDER, ...options });
  await expect(page.locator('[data-role="side"]')).toBeAttached();
}

/**
 * The page is up. Its own router is kept from listening to the address (it would take the address bar and
 * answer a click on an entry with the sign-in page); the frame listens, once the test has built it.
 */
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

/** The drawer slides in; what is measured is measured when it has stopped. */
const settled = (page) => page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));

const noSidewaysScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);

/** Every box of the open menu that is outside the screen, as words. */
const outside = (page) =>
  page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    const out = [];
    for (const node of document.querySelectorAll("#shell-test *")) {
      const box = node.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      // The one-pixel boxes of text that is only for a screen reader are clipped by design.
      if (box.width <= 1 && box.height <= 1) continue;
      if (box.right > width + 0.5 || box.left < -0.5) out.push(`${node.tagName.toLowerCase()} ${node.getAttribute("data-role") ?? ""} ${Math.round(box.left)}..${Math.round(box.right)}`);
    }
    return out;
  });

const ENTRIES = [
  ["nav-items", "#/items"],
  ["nav-favorites", "#/favorites"],
  ["nav-transfer", "#/transfer"],
  ["nav-folders", "#/folders"],
  ["nav-trash", "#/trash"],
];

test.describe("the side menu on a desktop", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("every_entry_of_the_menu_leads_to_its_page_and_is_marked_while_it_is_open", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    // The numbers beside the entries come from the items.
    await expect(page.locator('[data-role="nav-items"] .side-count')).toHaveText("248");
    await expect(page.locator('[data-role="nav-favorites"] .side-count')).toHaveText("13");
    for (const [role, hash] of ENTRIES) {
      await page.locator(`[data-role="${role}"]`).click();
      await expect.poll(() => page.evaluate(() => location.hash)).toBe(hash);
      await expect(page.locator(`[data-role="${role}"]`)).toHaveAttribute("aria-current", "page");
      await expect(page.locator('#shell-test [aria-current="page"]')).toHaveCount(1);
    }
    // The pages that are planned are in the menu, say so, and are not links.
    for (const role of ["nav-generator", "nav-health"]) {
      const entry = page.locator(`[data-role="${role}"]`);
      await expect(entry).toBeVisible();
      await expect(entry).toContainText(/coming soon/i);
      await expect(entry).not.toHaveAttribute("href", /.*/);
    }
    // The account menu leads to the account page.
    await page.locator('[data-role="account-menu-button"]').click();
    // Help is a link to a page outside the vault, in a window of its own with no way back.
    await expect(page.locator('[data-role="help"]')).toHaveAttribute("target", "_blank");
    await expect(page.locator('[data-role="help"]')).toHaveAttribute("rel", /noopener/);
    await page.locator('[data-role="nav-account"]').click();
    await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/account");
    await expect(page.locator('[data-role="nav-account"]')).toHaveAttribute("aria-current", "page");
  });

  test("a_new_count_changes_the_number_and_keeps_the_focus_on_the_entry", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    const link = page.locator('[data-role="nav-items"]');
    await link.focus();
    await expect(link).toBeFocused();
    await page.evaluate(() => window.__changeItems(260));
    await expect(page.locator('[data-role="nav-items"] .side-count')).toHaveText("260");
    await expect(link).toBeFocused();
  });

  test("lock_now_locks_and_sign_out_signs_out", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    const button = page.locator('[data-role="account-menu-button"]');
    await expect(page.locator('[data-role="account-menu"]')).toBeHidden();
    await button.click();
    await expect(button).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator('[data-role="account-menu"]')).toBeVisible();
    await page.locator('[data-role="lock"]').click();
    expect(await page.evaluate(() => window.__calls.lock)).toBe(1);
    await expect(page.locator('[data-role="account-menu"]')).toBeHidden();
    await button.click();
    await page.locator('[data-role="sign-out"]').click();
    expect(await page.evaluate(() => window.__calls.signOut)).toBe(1);
  });

  test("the_account_menu_works_from_the_keyboard_and_escape_gives_the_focus_back", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    const button = page.locator('[data-role="account-menu-button"]');
    await button.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator('[data-role="account-menu"]')).toBeVisible();
    await expect(page.locator('[data-role="nav-account"]')).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(page.locator('[data-role="help"]')).toBeFocused();
    await page.keyboard.press("End");
    await expect(page.locator('[data-role="sign-out"]')).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(page.locator('[data-role="nav-account"]')).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-role="account-menu"]')).toBeHidden();
    await expect(button).toBeFocused();
    await expect(button).toHaveAttribute("aria-expanded", "false");
    // A press outside closes it as well.
    await button.click();
    await expect(page.locator('[data-role="account-menu"]')).toBeVisible();
    await page.locator('[data-role="page-text"]').click();
    await expect(page.locator('[data-role="account-menu"]')).toBeHidden();
  });

  test("tab_goes_through_the_menu_in_order_and_the_skip_link_reaches_the_screen", async ({ page, browserName }) => {
    test.skip(browserName === "webkit", "WebKit does not put links in the tab order the way the other browsers do");
    await ready(page);
    await mountShell(page);
    await page.locator("#shell-test").evaluate((node) => node.scrollIntoView());
    const seen = [];
    for (let i = 0; i < 10; i += 1) {
      await page.keyboard.press("Tab");
      seen.push(await page.evaluate(() => document.activeElement?.getAttribute("data-role") ?? document.activeElement?.tagName));
    }
    expect(seen.slice(0, 9)).toEqual(["skip", "brand", "collapse", "nav-items", "nav-favorites", "nav-transfer", "nav-folders", "nav-trash", "account-menu-button"]);
    // The skip link puts the focus on the screen.
    await page.locator('[data-role="skip"]').focus();
    await expect(page.locator('[data-role="skip"]')).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page.locator('[data-role="content"]')).toBeFocused();
  });

  test("every_control_without_text_has_a_name", async ({ page }) => {
    await ready(page);
    await mountShell(page, { withFolders: true, pinned: ["Home"], admin: true });
    const unnamed = await page.evaluate(() =>
      [...document.querySelectorAll("#shell-test button, #shell-test a[href], #shell-test [role=menuitem]")]
        .filter((node) => (node.getAttribute("aria-label") ?? node.textContent ?? "").trim() === "")
        .map((node) => node.getAttribute("data-role") ?? node.tagName));
    expect(unnamed).toEqual([]);
    await expect(page.getByRole("button", { name: /collapse the menu/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /options for the folder home/i })).toBeAttached();
    await expect(page.getByRole("navigation", { name: /main menu/i })).toBeVisible();
  });

  test("the_switch_to_admin_shows_only_for_an_administrator_and_goes_to_the_admin_pages", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    await expect(page.locator('[data-role="switch-admin"]')).toBeHidden();
    await mountShell(page, { admin: true });
    const switcher = page.locator('[data-role="switch-admin"]');
    await expect(switcher).toBeVisible();
    await expect(switcher).toContainText("Vault");
    await expect(switcher).toContainText("Admin");
    await switcher.click();
    expect(await page.evaluate(() => window.__calls.admin)).toBe(1);
  });

  test("folding_the_menu_keeps_the_pictures_and_the_names_and_is_remembered", async ({ page }) => {
    await ready(page);
    await mountShell(page, { admin: true });
    const side = page.locator('[data-role="side"]');
    expect((await side.boundingBox()).width).toBe(264);
    await page.locator('[data-role="collapse"]').click();
    await expect(side).toHaveAttribute("data-collapsed", "true");
    expect((await side.boundingBox()).width).toBe(64);
    // The names are still there for a screen reader, and the labels are not on the screen.
    await expect(page.getByRole("link", { name: /all items/i })).toBeVisible();
    expect((await page.locator('[data-role="nav-items"] .side-label').boundingBox()).width).toBeLessThanOrEqual(1);
    await expect(page.getByRole("button", { name: /expand the menu/i })).toBeVisible();
    expect(await page.evaluate(() => JSON.parse(localStorage.getItem("ferret-ui")).collapsed)).toBe(true);
    expect(await noSidewaysScroll(page)).toBe(true);
    // The account menu still opens, and is on the screen.
    await page.locator('[data-role="account-menu-button"]').click();
    const menu = page.locator('[data-role="account-menu"]');
    await expect(menu).toBeVisible();
    expect(await outside(page)).toEqual([]);
    await page.keyboard.press("Escape");
    // A new page of the same device starts folded; unfolding is remembered as well.
    await mountShell(page);
    await expect(page.locator('[data-role="side"]')).toHaveAttribute("data-collapsed", "true");
    await page.locator('[data-role="collapse"]').click();
    expect(await page.evaluate(() => localStorage.getItem("ferret-ui"))).toBeNull();
  });

  test("a_pinned_folder_is_in_the_menu_with_its_sub_folders_and_can_be_unpinned_from_its_menu", async ({ page }) => {
    await ready(page);
    await mountShell(page, { withFolders: true, pinned: ["Home"] });
    await expect(page.locator('[data-role="nav-folder"]')).toHaveText(["Home", "Network"]);
    // A folder name is an encrypted label: the pin is in memory only, and nothing of it is at rest on the device.
    expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).not.toContain("Home");
    expect(await page.evaluate(async () => JSON.stringify(await indexedDB.databases?.() ?? []))).not.toContain("Home");
    await page.locator('[data-role="nav-folder"]').first().hover();
    await page.locator('[data-role="folder-menu-button"]').click();
    await page.locator('[data-role="unpin"]').click();
    await expect(page.locator('[data-role="nav-folder"]')).toHaveCount(0);
    expect(await page.evaluate(() => localStorage.getItem("ferret-ui"))).toBeNull();
  });
});

for (const scheme of ["light", "dark"]) {
  test(`the_menu_renders_in_the_${scheme}_theme`, async ({ page }, testInfo) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 1280, height: 800 });
    await ready(page);
    await mountShell(page, { admin: true, withFolders: true, pinned: ["Home"] });
    await page.locator('[data-role="nav-items"]').click();
    await expect(page.locator('[data-role="nav-items"]')).toHaveAttribute("aria-current", "page");
    await settled(page); // the tint fades in
    const look = await page.evaluate(() => {
      const css = (selector, property, pseudo) => getComputedStyle(document.querySelector(selector), pseudo)[property];
      return {
        side: css('[data-role="side"]', "backgroundColor"),
        page: css("body", "backgroundColor"),
        text: css('[data-role="nav-trash"]', "color"),
        current: css('[data-role="nav-items"]', "backgroundColor"),
        mark: css(".vault-side .brand", "backgroundImage", "::before"),
        avatar: css(".vault-side .avatar", "backgroundColor"),
        avatarText: css(".vault-side .avatar", "color"),
      };
    });
    const lightness = (rgb) => {
      const [r, g, b] = rgb.match(/[\d.]+/g).map(Number);
      return (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    };
    if (scheme === "dark") {
      expect(lightness(look.side)).toBeLessThan(0.2);
      expect(lightness(look.text)).toBeGreaterThan(0.8);
    } else {
      expect(lightness(look.side)).toBeGreaterThan(0.9);
      expect(lightness(look.text)).toBeLessThan(0.3);
    }
    // The current entry is tinted, the mark is the page's own picture, the round mark has readable letters in the brand
    // colour. There is no "New item" entry: the list page has the filled "Add" button.
    expect(look.current).not.toBe("rgba(0, 0, 0, 0)");
    expect(look.mark).toContain("data:image/svg+xml");
    expect(Math.abs(lightness(look.avatar) - lightness(look.avatarText))).toBeGreaterThan(0.4);
    await page.screenshot({ path: testInfo.outputPath(`shell-desktop-${scheme}.png`) });
    // Folded to a rail as well.
    await page.locator('[data-role="collapse"]').click();
    await page.screenshot({ path: testInfo.outputPath(`shell-rail-${scheme}.png`) });
  });

  test(`the_drawer_renders_in_the_${scheme}_theme`, async ({ page }, testInfo) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 375, height: 760 });
    await ready(page);
    await mountShell(page, { admin: true, withFolders: true, pinned: ["Home"] });
    await page.locator('[data-role="menu-open"]').click();
    await expect(page.locator('[data-role="side"]')).toBeVisible();
    await settled(page);
    await page.screenshot({ path: testInfo.outputPath(`shell-drawer-${scheme}.png`) });
  });
}

test.describe("the drawer of a phone", () => {
  test.use({ viewport: { width: 375, height: 760 } });

  test("the_menu_is_a_drawer_that_the_menu_button_opens_and_escape_closes", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    const side = page.locator('[data-role="side"]');
    const open = page.locator('[data-role="menu-open"]');
    await expect(side).toBeHidden();
    await expect(open).toBeVisible();
    await expect(open).toHaveAttribute("aria-label", /open the menu/i);
    expect(await noSidewaysScroll(page)).toBe(true);

    await open.click();
    await expect(side).toBeVisible();
    await expect(open).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator('[data-role="menu-close"]')).toBeFocused();
    // The screen behind it cannot be reached while it is open.
    expect(await page.evaluate(() => document.querySelector(".vault-body").inert)).toBe(true);
    expect(await noSidewaysScroll(page)).toBe(true);

    await page.keyboard.press("Escape");
    await expect(side).toBeHidden();
    await expect(open).toBeFocused();
    expect(await page.evaluate(() => document.querySelector(".vault-body").inert)).toBe(false);

    // Its own button, the dark area beside it, and a chosen entry close it too.
    await open.click();
    await page.locator('[data-role="menu-close"]').click();
    await expect(side).toBeHidden();
    await open.click();
    await page.mouse.click(365, 400);
    await expect(side).toBeHidden();
    await open.click();
    await page.locator('[data-role="nav-trash"]').click();
    await expect(side).toBeHidden();
    await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/trash");
  });

  test("the_focus_stays_inside_the_open_drawer_whichever_way_tab_goes", async ({ page }) => {
    await ready(page);
    await mountShell(page, { admin: true, withFolders: true, pinned: ["Home"] });
    await page.locator('[data-role="menu-open"]').click();
    await expect(page.locator('[data-role="menu-close"]')).toBeFocused();
    const inside = () => page.evaluate(() => document.activeElement?.closest('[data-role="side"]') !== null && document.activeElement?.closest('[data-role="side"]') !== undefined);
    // Forward past the last control and on round: never the skip link or the screen behind.
    for (let i = 0; i < 30; i += 1) {
      await page.keyboard.press("Tab");
      expect(await inside(), `Tab ${i + 1}`).toBe(true);
    }
    for (let i = 0; i < 30; i += 1) {
      await page.keyboard.press("Shift+Tab");
      expect(await inside(), `Shift+Tab ${i + 1}`).toBe(true);
    }
    // The parts outside the drawer are out of reach.
    expect(await page.evaluate(() => document.querySelector('[data-role="skip"]').inert)).toBe(true);
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-role="side"]')).toBeHidden();
    expect(await page.evaluate(() => document.querySelector('[data-role="skip"]').inert)).toBe(false);
  });

  test("the_account_menu_opens_inside_the_drawer_and_escape_closes_the_menu_before_the_drawer", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    await page.locator('[data-role="menu-open"]').click();
    await page.locator('[data-role="account-menu-button"]').click();
    await expect(page.locator('[data-role="account-menu"]')).toBeVisible();
    await settled(page);
    expect(await outside(page)).toEqual([]);
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-role="account-menu"]')).toBeHidden();
    await expect(page.locator('[data-role="side"]')).toBeVisible();
    await expect(page.locator('[data-role="account-menu-button"]')).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-role="side"]')).toBeHidden();
    await expect(page.locator('[data-role="menu-open"]')).toBeFocused();
  });

  test("lock_now_locks_from_the_drawer", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    await page.locator('[data-role="menu-open"]').click();
    await page.locator('[data-role="account-menu-button"]').click();
    await page.locator('[data-role="lock"]').click();
    expect(await page.evaluate(() => window.__calls.lock)).toBe(1);
  });

  test("a_wide_window_ends_the_drawer", async ({ page }) => {
    await ready(page);
    await mountShell(page);
    await page.locator('[data-role="menu-open"]').click();
    await expect(page.locator('[data-role="side"]')).toBeVisible();
    await page.setViewportSize({ width: 1100, height: 760 });
    await expect(page.locator('[data-role="side"]')).toBeVisible();
    await expect(page.locator('[data-role="menu-open"]')).toBeHidden();
    // Nothing is left out of reach.
    await expect.poll(() => page.evaluate(() => document.querySelector(".vault-body").inert)).toBe(false);
    await page.locator('[data-role="nav-items"]').click();
  });
});

for (const width of [320, 375]) {
  test(`nothing_sticks_out_and_there_is_no_sideways_scroll_at_${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 700 });
    await ready(page);
    await mountShell(page, { admin: true, email: LONG_EMAIL, withFolders: true, pinned: ["Home", LONG_FOLDER] });
    expect(await noSidewaysScroll(page), "menu closed").toBe(true);
    expect(await outside(page)).toEqual([]);
    await page.locator('[data-role="menu-open"]').click();
    await settled(page);
    expect(await noSidewaysScroll(page), "menu open").toBe(true);
    expect(await outside(page)).toEqual([]);
    await page.locator('[data-role="account-menu-button"]').click();
    await settled(page);
    expect(await noSidewaysScroll(page), "account menu open").toBe(true);
    expect(await outside(page)).toEqual([]);
  });
}
