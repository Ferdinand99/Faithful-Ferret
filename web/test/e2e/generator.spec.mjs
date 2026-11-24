// The generator page and the generate button of the item form, in real browsers with the real core (WASM, in the vault worker):
// a password and a passphrase are made, the options are kept without the value, "Copy" and "Use as new item" work, and the
// value goes when the page does. The screens are the real views in the real frame, over a fake engine and session (the tests of
// the whole flow need the server and are in test/e2e-stack). Run in Chromium, Firefox and WebKit.
import { expect, test } from "@playwright/test";

/**
 * The page is up. Its own router is kept from listening to the address (it would answer a change of the address with the sign-in
 * page); the views listen once the test has built them (`window.__hashListening`).
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

/**
 * Builds a screen in the real frame, in #app. `which`: generator, new (the form of a new item), edit.
 * The generator's "Use as new item" opens the new form the way the route does: it takes the value from the handoff, once.
 */
async function scene(page, which) {
  await page.evaluate(async ({ which }) => {
    const { ready, } = await import("/app/boot.mjs");
    const { i18n, client } = await ready;
    const t = i18n.t;
    const { mount } = await import("/app/dom.mjs");
    const common = await import("/app/views/common.mjs");
    const { shellView } = await import("/app/views/shell.mjs");
    const { generatedHandoff } = await import("/app/views/generatorModel.mjs");
    window.__calls = { copied: [], creates: [], went: [] };
    const id = "a1".repeat(16);
    const entry = { id, name: "GitHub", type: "login", favorite: false, urls: [], username: "ada@example.com", rev: 3 };
    const view = {
      name: "GitHub", item_type: "login", favorite: false, has_notes: false, has_totp: false, read_only: false,
      fields: [{ id: "username", label: "User name", value: "ada@example.com" }, { id: "password", label: "Password", value: null }],
      urls: [{ url: "https://github.com/login", matching: "host" }], folders: [],
    };
    const engine = {
      list: () => [entry],
      on: () => () => {},
      open: async () => ({ handle: 1, view, close: async () => {} }),
      update: async () => {},
      create: async (draft) => { window.__calls.creates.push(structuredClone(draft)); return "b2".repeat(16); },
    };
    const session = { current: () => null, onLock() {}, info: async () => null };
    const scope = common.createWipeScope();
    window.__scope = scope;
    const frameOf = (content) => shellView({
      t, engine, session, content, lock: async () => {}, touch: () => true, scope, onLocked: () => document.createElement("div"),
      email: "ada@example.com", signOut: async () => {},
    });
    const show = (content) => mount(document.getElementById("app"), frameOf(content));
    window.__hashListening = true;
    let content;
    if (which === "generator") {
      const { generatorView } = await import("/app/views/generator.mjs");
      const clipboard = { writeText: async (text) => { window.__calls.copied.push(text); } };
      content = generatorView({
        t, client, scope, clipboard,
        go: async (path) => {
          window.__calls.went.push(path);
          // What the route of the new item does: it takes the value once and builds the form.
          const { editView } = await import("/app/views/edit.mjs");
          show(await editView({ engine, client, id: null, t, go: () => {}, initialPassword: generatedHandoff.take() }));
        },
      });
    } else {
      const { editView } = await import("/app/views/edit.mjs");
      content = await editView({ engine, client, id: which === "new" ? null : id, t, go: () => {} });
    }
    show(content);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }, { which });
  await expect(page.locator('[data-role="shell"]')).toBeAttached();
}

const valueBox = (page) => page.locator('[data-role="generated-value"]');
const noSidewaysScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);

/** The value, once it is there. */
async function shown(page) {
  await expect(valueBox(page)).not.toHaveText("");
  return (await valueBox(page).innerText()).trim();
}

/** The next new value after `before`. */
async function changedFrom(page, before) {
  await expect(valueBox(page)).not.toHaveText(before);
  return shown(page);
}

test.describe("the generator page on a desktop", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("a_password_is_made_by_the_core_on_arrival_and_again_on_request_with_the_chosen_classes", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    await expect(page.locator("h1")).toHaveText("Generator");
    const first = await shown(page);
    expect(first).toHaveLength(20);
    await expect(page.locator('[data-role="generator-strength"]')).toContainText(/about \d+ bits/);
    await page.locator('[data-role="regenerate"]').click();
    const second = await changedFrom(page, first);
    expect(second).toHaveLength(20);
    // The length, from the box.
    await page.locator('[data-role="option-length"]').fill("40");
    await page.locator('[data-role="option-length"]').blur();
    await expect.poll(async () => (await valueBox(page).innerText()).trim().length).toBe(40);
    await expect(page.locator('[data-role="option-length-range"]')).toHaveValue("40");
    // Letters only: digits and symbols off.
    await page.locator('[data-role="option-digits"]').uncheck();
    await page.locator('[data-role="option-symbols"]').uncheck();
    await expect.poll(async () => /^[A-Za-z]{40}$/.test((await valueBox(page).innerText()).trim())).toBe(true);
    // The last classes: one of them is kept on.
    await page.locator('[data-role="option-upper"]').uncheck();
    await expect(page.locator('[data-role="option-lower"]')).toBeDisabled();
    await expect.poll(async () => /^[a-z]{40}$/.test((await valueBox(page).innerText()).trim())).toBe(true);
  });

  test("a_passphrase_has_the_words_the_separator_and_the_number_that_were_chosen", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    await page.locator('[data-role="kind-passphrase"]').click();
    await expect(page.locator('[data-role="options-passphrase"]')).toBeVisible();
    await expect(page.locator('[data-role="options-password"]')).toBeHidden();
    // The word list has a few hyphenated words, so the separator in these tests is not the hyphen.
    await page.locator('[data-role="option-separator"]').selectOption("_");
    await expect.poll(async () => /^([A-Z][a-z-]+_){4}[A-Z][a-z-]+$/.test((await valueBox(page).innerText()).trim())).toBe(true);
    await page.locator('[data-role="option-words"]').fill("3");
    await page.locator('[data-role="option-words"]').blur();
    await page.locator('[data-role="option-separator"]').selectOption(".");
    await page.locator('[data-role="option-capitalize"]').uncheck();
    await expect.poll(async () => /^[a-z-]+\.[a-z-]+\.[a-z-]+$/.test((await valueBox(page).innerText()).trim())).toBe(true);
    await page.locator('[data-role="option-number"]').check();
    await expect.poll(async () => /^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+$/.test((await valueBox(page).innerText()).trim()) && /\d/.test(await valueBox(page).innerText())).toBe(true);
  });

  test("the_options_come_back_on_the_next_visit_and_the_value_is_never_stored", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    await page.locator('[data-role="kind-passphrase"]').click();
    await page.locator('[data-role="option-separator"]').selectOption("_");
    await page.locator('[data-role="option-words"]').fill("6");
    await page.locator('[data-role="option-words"]').blur();
    await expect.poll(async () => (await valueBox(page).innerText()).trim().split("_").length).toBe(6);
    const value = (await valueBox(page).innerText()).trim();
    const stored = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
    expect(stored).toContain("ferret-generator");
    for (const word of value.split("_")) expect(stored).not.toContain(word);
    expect(await page.evaluate(() => location.href)).not.toContain(value);
    await page.reload();
    await expect(page.locator("#app h1")).toBeVisible();
    await scene(page, "generator");
    await expect(page.locator('[data-role="kind-passphrase"]')).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator('[data-role="option-words"]')).toHaveValue("6");
    await expect(page.locator('[data-role="option-separator"]')).toHaveValue("_");
    await expect.poll(async () => (await valueBox(page).innerText()).trim().split("_").length).toBe(6);
  });

  test("copy_puts_the_shown_value_on_the_clipboard_and_says_so_without_repeating_it", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    const value = await shown(page);
    await page.locator('[data-role="copy"]').click();
    await expect(page.locator('[data-role="generator-status"]')).toContainText("copied");
    expect(await page.evaluate(() => window.__calls.copied)).toEqual([value]);
    expect(await page.locator('[data-role="generator-status"]').innerText()).not.toContain(value);
  });

  test("the_copied_value_is_cleared_from_the_clipboard_after_30_seconds_and_by_a_lock", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    const value = await shown(page);
    await page.evaluate(() => {
      const original = window.setTimeout.bind(window);
      window.__clears = [];
      window.setTimeout = (fn, ms, ...rest) => (ms === 30000 ? (window.__clears.push(fn), 0) : original(fn, ms, ...rest));
    });
    await page.locator('[data-role="copy"]').click();
    await expect(page.locator('[data-role="generator-status"]')).toContainText("Ferret clears it in 30 seconds if this tab is open");
    expect(await page.evaluate(() => window.__clears.length)).toBe(1);
    await page.evaluate(() => window.__clears[0]());
    await expect.poll(() => page.evaluate(() => window.__calls.copied)).toEqual([value, ""]);
    // A second copy, and a lock: it is cleared at once.
    await page.locator('[data-role="regenerate"]').click();
    const second = await changedFrom(page, value);
    await page.locator('[data-role="copy"]').click();
    await expect.poll(() => page.evaluate(() => window.__calls.copied)).toEqual([value, "", second]);
    await page.evaluate(() => window.__scope.run());
    await expect.poll(() => page.evaluate(() => window.__calls.copied)).toEqual([value, "", second, ""]);
  });

  test("use_as_new_item_opens_the_new_form_with_the_password_in_it_hidden_and_the_page_forgets_it", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    const value = await shown(page);
    await page.locator('[data-role="use-as-new"]').click();
    await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
    expect(await page.evaluate(() => window.__calls.went)).toEqual(["/items/new"]);
    const password = page.locator('[data-role="password"]');
    await expect(password).toHaveValue(value);
    await expect(password).toHaveAttribute("type", "password");
    expect(await page.evaluate(() => document.body.innerText)).not.toContain(value);
    await page.locator('[data-role="password-toggle"]').click();
    await expect(password).toHaveAttribute("type", "text");
    await page.locator('[data-role="name"]').fill("GitHub");
    await page.locator('[data-role="save"]').click();
    await expect.poll(() => page.evaluate(() => window.__calls.creates.length)).toBe(1);
    const draft = await page.evaluate(() => window.__calls.creates[0]);
    expect(draft.fields.find((field) => field.id === "password").value).toBe(value);
  });

  test("the_value_goes_when_the_vault_locks_and_when_the_page_is_left", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    await shown(page);
    await page.evaluate(() => window.__scope.run());
    await expect(valueBox(page)).toHaveText("");
    await expect(page.locator('[data-role="copy"]')).toBeDisabled();
    await scene(page, "generator");
    const value = await shown(page);
    expect(value).not.toBe("");
    await page.evaluate(() => { location.hash = "#/items"; });
    await expect(valueBox(page)).toHaveText("");
    await expect(page.locator('[data-role="use-as-new"]')).toBeDisabled();
  });

  test("the_page_makes_no_random_number_of_its_own", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    const first = await shown(page);
    await page.evaluate(() => {
      window.__random = 0;
      const getRandomValues = crypto.getRandomValues.bind(crypto);
      crypto.getRandomValues = (array) => { window.__random += 1; return getRandomValues(array); };
      const random = Math.random;
      Math.random = () => { window.__random += 1; return random(); };
    });
    await page.locator('[data-role="regenerate"]').click();
    const second = await changedFrom(page, first);
    await page.locator('[data-role="kind-passphrase"]').click();
    await changedFrom(page, second);
    expect(await page.evaluate(() => window.__random)).toBe(0);
  });

  test("it_can_be_used_with_the_keyboard_alone_and_nothing_is_styled_inline", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    const first = await shown(page);
    await page.locator('[data-role="regenerate"]').focus();
    await page.keyboard.press("Enter");
    const second = await changedFrom(page, first);
    // The slider moves by key, the box follows, and a new value of that length is made.
    await page.locator('[data-role="option-length-range"]').focus();
    await page.keyboard.press("ArrowRight");
    await expect(page.locator('[data-role="option-length"]')).toHaveValue("21");
    await expect.poll(async () => (await valueBox(page).innerText()).trim().length).toBe(21);
    expect((await valueBox(page).innerText()).trim()).not.toBe(second);
    // The kind switch is two buttons that say which is pressed.
    await page.locator('[data-role="kind-passphrase"]').focus();
    await page.keyboard.press("Space");
    await expect(page.locator('[data-role="kind-passphrase"]')).toHaveAttribute("aria-pressed", "true");
    // The value is announced politely.
    await expect(valueBox(page)).toHaveAttribute("aria-live", "polite");
    expect(await page.locator('[data-role="generator-page"] [style]').count()).toBe(0);
    // The page is named for a screen reader: it has labels for every field.
    for (const id of ["gen-length", "gen-words", "gen-separator"]) await expect(page.locator(`label[for="${id}"]`)).toHaveCount(1);
  });

  test("the_page_fits_in_both_themes", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    await shown(page);
    for (const scheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: scheme });
      expect(await noSidewaysScroll(page)).toBe(true);
      await expect(valueBox(page)).toBeVisible();
      await page.screenshot({ path: `test-results/generator-${scheme}.png`, fullPage: true });
    }
  });
});

test.describe("the generator page on a phone", () => {
  test.use({ viewport: { width: 375, height: 720 } });

  test("a_long_password_and_the_options_stay_inside_the_screen", async ({ page }) => {
    await ready(page);
    await scene(page, "generator");
    await shown(page);
    await page.locator('[data-role="option-length"]').fill("128");
    await page.locator('[data-role="option-length"]').blur();
    await expect.poll(async () => (await valueBox(page).innerText()).trim().length).toBe(128);
    expect(await noSidewaysScroll(page)).toBe(true);
    await page.locator('[data-role="kind-passphrase"]').click();
    await page.locator('[data-role="option-separator"]').selectOption("_");
    await page.locator('[data-role="option-words"]').fill("20");
    await page.locator('[data-role="option-words"]').blur();
    await expect.poll(async () => (await valueBox(page).innerText()).trim().split("_").length).toBe(20);
    expect(await noSidewaysScroll(page)).toBe(true);
    await page.screenshot({ path: "test-results/generator-phone.png", fullPage: true });
  });
});

test.describe("the generate button of the item form", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  for (const which of ["new", "edit"]) {
    test(`it_fills_the_password_of_the_${which}_form_with_a_value_from_the_core_and_shows_it_and_the_toggle_hides_it`, async ({ page }) => {
      await ready(page);
      await scene(page, which);
      const password = page.locator('[data-role="password"]');
      await expect(password).toHaveValue("");
      await page.locator('[data-role="password-generate"]').click();
      await expect(password).not.toHaveValue("");
      const first = await password.inputValue();
      expect(first).toHaveLength(20);
      await expect(password).toHaveAttribute("type", "text");
      await expect(page.locator('[data-role="status"]')).toContainText("filled in");
      await page.locator('[data-role="password-toggle"]').click();
      await expect(password).toHaveAttribute("type", "password");
      await page.locator('[data-role="password-generate"]').click();
      await expect(password).not.toHaveValue(first);
    });
  }
});
