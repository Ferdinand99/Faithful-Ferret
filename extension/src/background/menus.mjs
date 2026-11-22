// The context menu (design document section 10.3.1): one fixed item, "Fill
// with Ferret", on editable fields, and nothing else.
//
// The item is the same on every page and in every state. It never names an
// item, a user name or a site: before the click the extension has no access to
// the page (no `<all_urls>`), and a menu that changed with the page would tell
// the page what the vault holds. A click grants `activeTab` and runs the step
// the shortcut runs (commands.mjs), for the clicked frame only:
//
//   - the page matching for the tab, with every frame rule, and only the
//     matches in the frame of the click (`info.frameId`) count;
//   - the frame must still show the address the menu saw (`info.frameUrl`, or
//     `info.pageUrl` for the top frame);
//   - the fill script of that frame is aimed at the clicked field
//     (`menus.getTargetElement(info.targetElementId)`, in the frame), so the
//     fill goes into the clicked field's group, and a password goes into the
//     clicked field only when it is a password input;
//   - exactly one match fills, anything else opens the popup.

/** The id of the one menu item. */
export const MENU_ID = "ferret-fill";

/** The only context of the item: editable fields. */
export const MENU_CONTEXTS = /** @type {readonly ["editable"]} */ (Object.freeze(["editable"]));

/** The key of the item's title in the catalogs (src/locales/<lang>/menus.json). */
export const TITLE_KEY = "menus.fill";

/** The title when no catalog can be read; the English catalog has the same text. */
export const FALLBACK_TITLE = "Fill with Ferret";

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** Norwegian in any of its tags reads the nb catalog; anything else reads English (the pages choose the same way). */
const NORWEGIAN = new Set(["nb", "no", "nn"]);

/**
 * The language of the item's title: the first of the user's languages that the
 * extension has, else English.
 * @param {readonly string[]} languages
 * @returns {"en" | "nb"}
 */
export function titleLanguage(languages) {
  for (const tag of languages ?? []) {
    const primary = String(tag).toLowerCase().split("-")[0];
    if (NORWEGIAN.has(primary)) return "nb";
    if (primary === "en") return "en";
  }
  return "en";
}

/**
 * The title of the item in the user's language (the built catalog `locales.<lang>.json`).
 *
 * @param {{ fetch: (url: string) => Promise<{ ok: boolean, json(): Promise<any> }>, getURL: (path: string) => string, languages: readonly string[] }} deps
 * @returns {Promise<string>}
 */
export async function menuTitle({ fetch, getURL, languages }) {
  /** @param {string} code @returns {Promise<unknown>} */
  const read = async (code) => {
    try {
      const response = await fetch(getURL(`locales.${code}.json`));
      const catalog = response.ok ? await response.json() : null;
      return catalog !== null && typeof catalog === "object" ? catalog[TITLE_KEY] : undefined;
    } catch {
      return undefined;
    }
  };
  const lang = titleLanguage(languages);
  for (const code of lang === "en" ? ["en"] : [lang, "en"]) {
    const title = await read(code);
    if (typeof title === "string" && title.trim() !== "") return title;
  }
  return FALLBACK_TITLE;
}

/**
 * Registers the click listener at once (call it while the background page
 * loads) and then makes the one item.
 *
 * @param {{
 *   menus: {
 *     create(properties: { id: string, title: string, contexts: Array<"editable"> }): unknown,
 *     remove(id: string): Promise<unknown>,
 *     onClicked: { addListener(fn: (info: any, tab?: { id?: number }) => void): void },
 *   },
 *   quickFill: {
 *     fillOrOpen(tabId: unknown, click?: import("./commands.mjs").Click | null): Promise<import("./commands.mjs").Outcome>,
 *     open(): unknown,
 *   },
 *   title: Promise<string> | string,
 * }} options
 * @returns {Promise<void>} resolves when the item is made
 */
export function listenForMenus({ menus, quickFill, title }) {
  menus.onClicked.addListener((info, tab) => {
    if (info?.menuItemId !== MENU_ID) return;
    const frameId = info.frameId ?? 0;
    const frameUrl = frameId === 0 ? info.pageUrl : info.frameUrl;
    const targetElementId = info.targetElementId;
    // Without the frame, its address and the clicked element there is nothing to aim at: the popup decides.
    if (!isIndex(frameId) || typeof frameUrl !== "string" || typeof targetElementId !== "number" || !Number.isSafeInteger(targetElementId)) {
      quickFill.open();
      return;
    }
    quickFill.fillOrOpen(tab?.id, { frameId, frameUrl, targetElementId }).catch(() => {});
  });

  // An item that an earlier page of this profile made (an event page's menus outlive it) is replaced, so there is
  // only ever the one.
  return (async () => {
    const text = await Promise.resolve(title).catch(() => FALLBACK_TITLE);
    await Promise.resolve(menus.remove(MENU_ID)).catch(() => {});
    menus.create({ id: MENU_ID, title: typeof text === "string" && text !== "" ? text : FALLBACK_TITLE, contexts: [...MENU_CONTEXTS] });
  })().catch(() => {});
}
