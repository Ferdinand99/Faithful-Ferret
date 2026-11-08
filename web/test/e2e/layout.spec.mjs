// How the screens lay out: at phone and desktop widths, in English and Norwegian, and on
// paper. The screens are the real views, built in the page with fake sessions and data
// (the browser tests of the whole flow need the server). Run in Chromium, Firefox and WebKit.
import { expect, test } from "@playwright/test";

const WIDTHS = [320, 375, 1100];

/** Everything that is cut off or outside what holds it, as a list of words. */
const clipped = (page) =>
  page.evaluate(() => {
    const out = [];
    const width = document.documentElement.clientWidth;
    const describe = (node) => `${node.tagName.toLowerCase()}${node.getAttribute("data-role") ? `[${node.getAttribute("data-role")}]` : ""} "${(node.textContent ?? "").trim().slice(0, 40)}"`;
    for (const node of document.querySelectorAll("#app *, #foot *")) {
      const box = node.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      // `overflow-x: clip` on the body hides what sticks out, so the edges are measured here.
      if (box.right > width + 0.5 || box.left < -0.5) out.push(`outside the screen: ${describe(node)}`);
    }
    for (const button of document.querySelectorAll("#app .btn")) {
      if (button.scrollWidth > button.clientWidth + 1) out.push(`label cut off: ${describe(button)}`);
      const holder = button.closest(".auth-card, .card, .items, .dialog");
      if (!holder) continue;
      const inner = holder.getBoundingClientRect();
      const box = button.getBoundingClientRect();
      if (box.right > inner.right + 0.5 || box.left < inner.left - 0.5) out.push(`button outside its card: ${describe(button)}`);
    }
    return out;
  });

/** Builds one screen from the real views. */
async function scene(page, which) {
  await page.evaluate(async (name) => {
    const { ready } = await import("/app/boot.mjs");
    const { i18n } = await ready;
    const t = i18n.t;
    const { mount } = await import("/app/dom.mjs");
    const root = document.getElementById("app");
    const common = await import("/app/views/common.mjs");
    const handlers = new Map();
    const items = [
      { id: "a1", name: "GitHub", username: "ada@example.com", urls: ["https://github.com"], favorite: true },
      { id: "a2", name: "Bank of Elm Street with a very long name that keeps going and going and ends differently", username: "ada", urls: ["https://bank.example.org/login"], pending: true },
      { id: "a3", name: "Old router", username: "admin", urls: [], damaged: true },
      { id: "a4", name: "Wi-Fi hjemme", username: "", urls: [], blocked: true, readOnly: true },
    ];
    const view = {
      name: "GitHub", item_type: "login", favorite: true, has_notes: true, has_totp: true, read_only: false,
      fields: [{ id: "username", label: "Username", value: "ada@example.com" }, { id: "password", label: "Password", value: null }],
      urls: [{ url: "https://github.com/login", matching: "host" }],
    };
    const engine = (list) => ({
      list: () => list,
      on: (event, fn) => { handlers.set(event, fn); return () => {}; },
      open: async () => ({ handle: 1, view, close: async () => {} }),
    });
    const session = (extra = {}) => ({
      current: () => null, deviceStatus: async () => ({ pinned: false, skBit: null, skStored: false }), freshReauth: () => false,
      info: async () => null, onLock() {}, ...extra,
    });
    const frame = async (eng, content) => {
      const { shellView } = await import("/app/views/shell.mjs");
      return shellView({ t, engine: eng, session: session(), content, lock: async () => {}, touch: () => true, scope: common.createWipeScope(), onLocked: () => document.createElement("div") });
    };
    const flow = {
      sheet: {
        recoveryKeyCode: "R1-7QK2M-9DXPT-4WHVA-C8N3E-JY6LB",
        access: { server_url: "https://vault.example.com", email: "ada@example.com", account_id: "0f6c9b1e2a7d4c58b3e1a9d047c25f66", ksf_profile: "argon2id-m64-t3-p1", secret_key_code: "A3-QZ7K4M-8PXD2T-V9HW5C-N6EJ3Y-B2LRA4", qr_payload: "ferret://setup?s=vault.example.com&a=0f6c9b1e" },
      },
      confirm: async () => {}, finish: async () => {}, abort: async () => {},
    };

    if (name === "signed-in") {
      const { loginView } = await import("/app/views/login.mjs");
      mount(root, loginView({
        t, session: session({ current: () => ({}) }), entry: { handoff: null, brokenHandoff: false }, adminUrl: "https://admin.example.com", api: {}, go() {},
        handoff: { completeHandoff: async () => {}, goToAdmin: async () => {} }, info: { accountId: "x", email: "ada@example.com" },
      }));
    } else if (name === "setup") {
      const { setupView } = await import("/app/views/setup.mjs");
      mount(root, setupView({ t, session: session({ register: async () => flow }), setupToken: null, adminUrl: "https://admin.example.com", go() {}, handoff: { goToAdmin: async () => {} } }));
    } else if (name === "list") {
      const { listView } = await import("/app/views/list.mjs");
      const eng = engine(items);
      mount(root, await frame(eng, listView({ engine: eng, router: { go() {} }, t })));
      handlers.get("state")?.({ kind: "unauthorized" });
      handlers.get("state")?.({ kind: "warning", code: "server_behind" });
    } else if (name === "warnings" || name === "restored") {
      // Every warning at once (the longest page), and a stop with two actions or the page for a restored server.
      const { WARNING_TABLE } = await import("/app/sync/checkpoint.mjs");
      const halted = name === "restored" ? "server_restored" : "restore_epoch_lowered";
      const health = () => ({ halted, warnings: Object.keys(WARNING_TABLE).filter((code) => WARNING_TABLE[code].kind !== "stop") });
      const eng = { ...engine([]), health, verifyNow: async () => "ok", resumeAfterHalt: async () => {},
        restorePreview: async () => ({ reupload: 12, conflicts: 3 }), acceptOlderState: async () => ({ reuploaded: 12, conflicts: 3 }) };
      let content = document.createElement("div");
      if (name === "restored") {
        const { restoredView } = await import("/app/views/restored.mjs");
        content = restoredView({ engine: eng, t, router: { go() {} } });
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const { shellView } = await import("/app/views/shell.mjs");
      mount(root, shellView({ t, engine: eng, session: session(), content, lock: async () => {}, touch: () => true, scope: common.createWipeScope(), onLocked: () => document.createElement("div") }));
      handlers.get("state")?.({ kind: "halted", code: halted });
    } else if (name === "forget") {
      const { forgetView } = await import("/app/views/forget.mjs");
      const forget = ({ confirm }) => confirm({ pending: 3 }).then(() => "cancelled");
      const view = forgetView({ t, session: session(), store: {}, api: {}, serverUrl: "https://vault.example.com", accountId: "0f6c9b1e2a7d4c58b3e1a9d047c25f66", go() {}, forget });
      mount(root, view);
      view.querySelector('[data-role="forget-start"]').click();
      await new Promise((resolve) => setTimeout(resolve, 50));
    } else if (name === "item") {
      const { itemView } = await import("/app/views/item.mjs");
      const eng = engine([{ id: "a1", name: "GitHub", damaged: true, blocked: true, blockedReason: "conflict", missingOnServer: true }]);
      const sync = { discard: async () => {}, discardMissing: async () => {} };
      const client = { vault: { reveal_item_field: async () => "x", reveal_item_notes: async () => "x" } };
      mount(root, await frame(eng, await itemView({ engine: eng, sync, client, id: "a1", t })));
    }
  }, which);
}

/** The page is up in the language the test asked for, and Inter is in, so the measures are the real ones. */
async function pageIsReady(page, locale) {
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const language = locale.split("-")[0];
  await expect(page.locator("html")).toHaveAttribute("lang", language);
  await page.waitForFunction(() => document.fonts.check("16px InterVariable") && [...document.fonts].some((face) => face.status === "loaded"), undefined, { timeout: 15_000 });
}

/** The setup page, filled in and sent, so that the sheet is on the page the way the flow puts it there. */
async function setupSheet(page) {
  await scene(page, "setup");
  await page.fill("#email", "ada@example.com");
  await page.fill("#password", "correct horse battery staple");
  await page.fill("#password-repeat", "correct horse battery staple");
  await page.locator('[data-role="submit"]').click();
  await expect(page.locator('[data-role="sheet-page"]')).toBeVisible();
}

for (const locale of ["en", "nb-NO"]) {
  test.describe(`layout in ${locale}`, () => {
    test.use({ locale });

    for (const width of WIDTHS) {
      test(`nothing_is_cut_off_or_outside_at_${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 800 });
        await pageIsReady(page, locale);
        for (const name of ["signed-in", "list", "item", "warnings", "restored", "forget"]) {
          await scene(page, name);
          expect(await clipped(page), `${name} at ${width}px`).toEqual([]);
        }
        await setupSheet(page);
        expect(await clipped(page), `the sheet at ${width}px`).toEqual([]);
      });
    }

    for (const width of [320, 360, 1100]) {
      test(`the_live_field_keeps_the_bar_and_its_own_width_the_same_in_every_state_at_${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 800 });
        await pageIsReady(page, locale);
        const rows = await page.evaluate(async () => {
          const { ready } = await import("/app/boot.mjs");
          const { i18n } = await ready;
          const { mount } = await import("/app/dom.mjs");
          const common = await import("/app/views/common.mjs");
          const { shellView } = await import("/app/views/shell.mjs");
          const root = document.getElementById("app");
          const out = [];
          for (const sync of ["syncing", "idle", "retrying", "offline", "unauthorized"]) {
            for (const withLive of [false, true]) {
              for (const state of withLive ? ["connecting", "live", "fallback", "offline", "unauthorized"] : [""]) {
                /** @type {Map<string, Function>} */
                const handlers = new Map();
                const engine = { list: () => [], on: (/** @type {string} */ event, /** @type {Function} */ fn) => { handlers.set(event, fn); return () => {}; } };
                const listeners = new Set();
                const live = withLive
                  ? { current: state, state() { return this.current; }, on: (/** @type {string} */ _event, /** @type {Function} */ fn) => { listeners.add(fn); return () => listeners.delete(fn); } }
                  : undefined;
                const frame = shellView({
                  t: i18n.t, engine, session: { onLock() {} }, content: document.createElement("div"), lock: async () => {}, touch: () => true,
                  scope: common.createWipeScope(), onLocked: () => document.createElement("div"), live,
                });
                mount(root, frame);
                handlers.get("state")?.({ kind: sync });
                const bar = /** @type {HTMLElement} */ (frame.querySelector(".vault-bar"));
                const pill = frame.querySelector('[data-role="live-status"]');
                out.push({
                  sync, state, withLive,
                  bar: Math.round(bar.getBoundingClientRect().height * 100) / 100,
                  pill: pill ? Math.round(pill.getBoundingClientRect().width * 100) / 100 : null,
                  parts: [...bar.children].map((c) => `${c.getAttribute("data-role") ?? c.className ?? c.tagName}@${Math.round(c.getBoundingClientRect().left)},${Math.round(c.getBoundingClientRect().top)}+${Math.round(c.getBoundingClientRect().width)}x${Math.round(c.getBoundingClientRect().height)}${[...c.querySelectorAll(".pill")].map((p) => `[${Math.round(p.getBoundingClientRect().width)}x${Math.round(p.getBoundingClientRect().height)}]`).join("")}`).join(" "),
                  sideways: bar.scrollWidth > bar.clientWidth + 1 || document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
                });
              }
            }
          }
          return out;
        });
        for (const sync of ["syncing", "idle", "retrying", "offline", "unauthorized"]) {
          const mine = rows.filter((row) => row.sync === sync);
          const bare = mine.find((row) => !row.withLive);
          const live = mine.filter((row) => row.withLive);
          // The same bar in every live state, and no taller than the bar was without the field.
          expect(new Set(live.map((row) => row.bar)).size, `bar height by live state, sync ${sync}, ${width}px: ${JSON.stringify(live.map((r) => [r.state, r.bar]))}`).toBe(1);
          // A bar that is wrapped already without the field (the Norwegian links and a long sync text on a phone) may grow by the
          // difference between the stacked pair and one pill, never by a row of its own.
          expect(live[0].bar, `the field adds no row, sync ${sync}, ${width}px, bare ${bare.bar}: ${bare.parts} | live ${live[0].bar}: ${live[0].parts}`).toBeLessThanOrEqual(bare.bar <= 90 ? bare.bar : bare.bar + 20);
          // The field has one width in every state.
          expect(new Set(live.map((row) => row.pill)).size, `field width by live state, sync ${sync}, ${width}px: ${JSON.stringify(live.map((r) => [r.state, r.pill]))}`).toBe(1);
          expect(live.some((row) => row.sideways), `no sideways scroll, sync ${sync}, ${width}px`).toBe(false);
        }
      });
    }

    for (const width of [320, 360, 1100]) {
      test(`the_warning_banners_do_not_change_the_bar_and_nothing_sticks_out_at_${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 800 });
        await pageIsReady(page, locale);
        const rows = await page.evaluate(async () => {
          const { ready } = await import("/app/boot.mjs");
          const { i18n } = await ready;
          const { mount } = await import("/app/dom.mjs");
          const common = await import("/app/views/common.mjs");
          const { shellView } = await import("/app/views/shell.mjs");
          const { WARNING_TABLE } = await import("/app/sync/checkpoint.mjs");
          const root = document.getElementById("app");
          const out = [];
          for (const sync of ["idle", "syncing", "halted"]) {
            for (const withBanners of [false, true]) {
              /** @type {Map<string, Function>} */
              const handlers = new Map();
              const engine = {
                list: () => [], on: (/** @type {string} */ event, /** @type {Function} */ fn) => { handlers.set(event, fn); return () => {}; },
                ...(withBanners ? {
                  health: () => ({ halted: null, warnings: Object.keys(WARNING_TABLE).filter((code) => WARNING_TABLE[code].kind !== "stop") }),
                  verifyNow: async () => "ok",
                } : {}),
              };
              const frame = shellView({
                t: i18n.t, engine, session: { onLock() {} }, content: document.createElement("div"), lock: async () => {}, touch: () => true,
                scope: common.createWipeScope(), onLocked: () => document.createElement("div"),
              });
              mount(root, frame);
              handlers.get("state")?.({ kind: sync, code: "server_restored" });
              const bar = /** @type {HTMLElement} */ (frame.querySelector(".vault-bar"));
              out.push({
                sync, withBanners,
                bar: Math.round(bar.getBoundingClientRect().height * 100) / 100,
                banners: frame.querySelectorAll('[data-role="sync-banner"]').length,
                sideways: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
              });
            }
          }
          return out;
        });
        for (const sync of ["idle", "syncing", "halted"]) {
          const [bare, banners] = rows.filter((row) => row.sync === sync);
          expect(banners.banners, "every warning of the table has a banner").toBeGreaterThan(5);
          expect(banners.bar, `the bar is as high with the banners as without, ${sync}, ${width}px`).toBe(bare.bar);
          expect(banners.sideways || bare.sideways, `no sideways scroll, ${sync}, ${width}px`).toBe(false);
        }
        // The stopped text takes no more room than the longest text sync has already (the bar differs between idle and syncing
        // on a phone in Norwegian, as it did before).
        const bare = rows.filter((row) => !row.withBanners);
        const longest = Math.max(...bare.filter((row) => row.sync !== "halted").map((row) => row.bar));
        expect(bare.find((row) => row.sync === "halted").bar, `the stopped text adds no row, ${width}px: ${JSON.stringify(bare)}`).toBeLessThanOrEqual(longest);
      });
    }

    test("the_emergency_sheet_is_one_wide_card_with_one_mark", async ({ page }) => {
      await page.setViewportSize({ width: 1100, height: 900 });
      await pageIsReady(page, locale);
      await setupSheet(page);
      const shape = await page.evaluate(() => {
        const cards = [...document.querySelectorAll("#app .auth-card")];
        const marks = cards.filter((card) => getComputedStyle(card, "::before").display !== "none");
        const sheet = /** @type {HTMLElement} */ (document.querySelector('[data-role="sheet-page"]'));
        const outer = /** @type {HTMLElement} */ (sheet.parentElement);
        return {
          marks: marks.length,
          sheetWidth: sheet.getBoundingClientRect().width,
          outerBorder: getComputedStyle(outer).borderTopWidth,
          outerPadding: getComputedStyle(outer).paddingLeft,
        };
      });
      expect(shape.marks).toBe(1);
      expect(shape.sheetWidth).toBeGreaterThan(26 * 16);
      expect(shape.outerBorder).toBe("0px");
      expect(shape.outerPadding).toBe("0px");
    });
  });
}

test("the_sheet_prints_dark_on_white_in_any_theme_with_the_recovery_key_on_a_page_of_its_own", async ({ page, browserName }) => {
  await page.setViewportSize({ width: 1100, height: 900 });
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  // A chosen dark theme must not reach the paper.
  await page.locator('[data-theme-set="dark"]').click();
  await setupSheet(page);
  const onScreen = await page.evaluate(() => getComputedStyle(document.querySelector('[data-role="sheet-secret-key"]')).color);
  await page.emulateMedia({ media: "print" });
  const paper = await page.evaluate(() => {
    const color = (selector) => getComputedStyle(document.querySelector(selector)).color;
    const shown = (selector) => getComputedStyle(document.querySelector(selector)).display !== "none";
    const recovery = document.querySelector('[data-role="sheet"] + h2');
    return {
      key: color('[data-role="sheet-secret-key"]'),
      recovery: color('[data-role="sheet-recovery-key"]'),
      heading: color("h1"),
      label: color('[data-role="sheet-recovery"] dt'),
      scheme: getComputedStyle(document.documentElement).colorScheme,
      page: recovery ? getComputedStyle(recovery).breakBefore : null,
      app: getComputedStyle(document.getElementById("app")).display,
      buttons: [...document.querySelectorAll("#app .btn")].filter((b) => getComputedStyle(b).display !== "none").length,
      forms: shown("form"),
      typeBack: [...document.querySelectorAll(".no-print")].filter((n) => getComputedStyle(n).display !== "none").length,
      footer: shown("#foot"),
      marks: [...document.querySelectorAll("#app .auth-card")].filter((c) => getComputedStyle(c, "::before").display !== "none").length,
    };
  });
  expect(onScreen).not.toBe("rgb(29, 29, 31)"); // dark on screen: light text
  expect(paper.scheme).toBe("light");
  for (const color of [paper.key, paper.recovery, paper.heading]) expect(color).toBe("rgb(29, 29, 31)");
  expect(paper.label).toBe("rgb(110, 110, 115)");
  expect(paper.page).toBe("page");
  expect(paper.app).toBe("block");
  expect(paper).toMatchObject({ buttons: 0, forms: false, typeBack: 0, footer: false, marks: 0 });

  if (browserName === "chromium") {
    // The recovery key is on a second sheet of paper: the page breaks before it.
    const pdf = await page.pdf({ format: "A4" });
    const sheets = pdf.toString("latin1").match(/\/Type\s*\/Page[^s]/g) ?? [];
    expect(sheets.length).toBeGreaterThanOrEqual(2);
  }
});
