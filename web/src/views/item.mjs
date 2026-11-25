// One item. Fields that are secret show as dots. "Show" asks the worker for ONE
// field's value, on the user's click, and puts it in the page; showing another
// field hides the first. "Copy" asks the worker for the value and hands it to
// the clipboard without putting it on the page. A secret is taken off the clipboard again after 30 seconds, and by a lock
// (secretClipboard.mjs); a user name and an address are not secrets and are copied as they are.
//
// The view never keeps an item open. It opens the item to read what the core
// shows without secrets, closes it again, and opens it once more for each
// reveal or copy, so a handle lives for the length of one call. Because the
// item can change between the two, a reveal checks that the field it asks for
// still has the same id and stops with `item_changed` if not.
//
// "Previous passwords" lists the passwords the item had before (the core keeps up to five inside the item). The view
// carries their dates only. Each value is hidden like any secret field, is fetched on its own click with
// `reveal_password_history(handle, index)` (after checking that the entry still has the same date), shows one at a
// time together with every other secret on the page, and goes with the same wipes: a lock, leaving the page, a rebuild.
//
// An item with a one-time password shows its current code in a card of its own (always on the page, like a code on a phone: it
// is good for seconds only). The code is made in the worker by `totp_code` from the page's clock, once when the page is drawn
// and again each time it runs out (totpTicker.mjs); the seconds left count down on the page between. The code element is the only
// live region: a screen reader hears a new code when there is one, and the countdown is plain text that is read on request, so
// nothing is announced every second. "Copy" asks for a fresh code and hands it to the clipboard helper (cleared after 30 seconds).
import { el, mount } from "../dom.mjs";
import { secretClipboardFor } from "../secretClipboard.mjs";
import { askConfirm, canChange, describeError, formatMoment, listenWhileShown, markBadges } from "./common.mjs";
import { MAX_FOLDER_CHIPS, favouriteDraft, folderLabels, groupFields, historyEntries, passkeyOf, tileLetter, tileType } from "./itemModel.mjs";
import { focusNode, popMenu, within } from "./popMenu.mjs";
import { groupCode } from "./totpModel.mjs";
import { codeTicker, realClock } from "./totpTicker.mjs";

/** What a hidden value looks like. */
const DOTS = "••••••••";

/** What the code looks like until the worker has made it. */
const CODE_DOTS = "••• •••";

/** A page that is still not on the screen after this many ticks (seconds) is not coming: its code stops. */
const MAX_TICKS_BEFORE_SHOWN = 30;

/** From this many seconds left the countdown is marked, so it can be drawn in another colour (the number says it too). */
const LOW_SECONDS = 5;

/** The name of an item type; a type this version does not know shows as it is written. @param {import("./common.mjs").Translate} t @param {unknown} type */
export function typeLabel(t, type) {
  return ["login", "note", "card", "identity"].includes(String(type)) ? t(`vault.type.${String(type)}`) : String(type ?? "");
}

/** @param {unknown} error */
const isNotFound = (error) => /** @type {any} */ (error)?.code === "not_found";

/**
 * @param {{
 *   engine: any,
 *   sync: { discard(id: string): Promise<unknown>, discardMissing(id: string): Promise<unknown> },
 *   client: { vault: Record<string, (...args: any[]) => Promise<any>> },
 *   id: string,
 *   t: import("./common.mjs").Translate,
 *   go?: (path: string) => void,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 *   clipboard?: { writeText(text: string): Promise<void> } | null,
 *   moveToFolder?: (id: string, where: { host: HTMLElement, say: (text: string) => void }) => void,
 *   folderChip?: (label: string) => Node,
 *   locale?: string,
 *   clock?: import("./totpTicker.mjs").Clock,
 * }} options `clock` is the page's clock (the one-time code is made for the time it tells; tests give their own);
 *   `moveToFolder` and `folderChip` are the folder task's way in: with `moveToFolder` the ⋮ menu has "Move to folder",
 *   without it the entry is not there; `folderChip` makes the chip of one folder label (a plain label by default)
 * @returns {Promise<HTMLElement>}
 */
export async function itemView({
  engine, sync, client, id, t, go = () => {}, touch = () => true, scope,
  clipboard = globalThis.navigator?.clipboard ?? null, moveToFolder, folderChip, locale, clock = realClock,
}) {
  const root = el("section", { class: "item-view", "data-role": "item" });
  const message = el("p", { class: "message", role: "status", "data-role": "message" });
  const host = el("div", { class: "dialog-host", "data-role": "dialog-host" });

  /** Which secret is on the page: its key only, never the value. @type {string | null} */
  let revealedKey = null;
  /** The slots that show a value, by key. @type {Map<string, { slot: HTMLElement, toggle: HTMLButtonElement, label: string }>} */
  const slots = new Map();
  /** The menu of the ⋮ button, when the item has one; closed on a press outside it and on a lock. @type {ReturnType<typeof popMenu> | null} */
  let moreMenu = null;
  /** The ⋮ button of the page as built last, and whether the next build should give it the focus (the favourite switch rebuilds the header). @type {HTMLElement | null} */
  let moreButton = null;
  let refocusMore = false;
  /** The ticker of the one-time code on the page, when the item has one. @type {ReturnType<typeof codeTicker> | null} */
  let totpTicker = null;

  /** @param {string} text */
  function say(text) {
    mount(message, document.createTextNode(text));
  }

  /** Hides whatever is shown. */
  function hideAll() {
    revealedKey = null;
    for (const { slot, toggle, label } of slots.values()) {
      mount(slot, document.createTextNode(DOTS));
      mount(toggle, document.createTextNode(t("vault.item.show")));
      toggle.setAttribute("aria-label", t("vault.item.show_label", { label }));
    }
  }
  /** A press outside the open ⋮ menu closes it; a page that has left the screen stops listening. @type {boolean} */
  let seenOnPage = false;
  const doc = /** @type {any} */ (globalThis).document;
  const pointerOutside = (/** @type {any} */ event) => {
    if (/** @type {any} */ (root).isConnected === true) seenOnPage = true;
    else if (seenOnPage) {
      doc?.removeEventListener?.("pointerdown", pointerOutside);
      return;
    }
    if (moreMenu?.isOpen() && !within(event.target, moreMenu.menu) && !within(event.target, moreMenu.trigger)) moreMenu.close(false);
  };
  doc?.addEventListener?.("pointerdown", pointerOutside);
  scope?.add(() => {
    doc?.removeEventListener?.("pointerdown", pointerOutside);
    moreMenu = null;
    totpTicker?.stop();
    totpTicker = null;
    hideAll();
    slots.clear();
    mount(root);
  });

  /**
   * Opens the item for one call, runs `fn` with the handle, closes it.
   * @template T
   * @param {(opened: { handle: number, view: any }) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async function withOpen(fn) {
    const opened = await engine.open(id);
    try {
      return await fn(opened);
    } finally {
      await opened.close();
    }
  }

  /**
   * The value of one field, checked against the id the page saw.
   * @param {number} index @param {string} fieldId
   */
  function fieldValue(index, fieldId) {
    return withOpen(async ({ handle, view }) => {
      if (view.fields?.[index]?.id !== fieldId) throw Object.assign(new Error("item_changed"), { code: "item_changed" });
      return client.vault.reveal_item_field(handle, index);
    });
  }

  /**
   * One earlier password, checked against the date the page saw: another device may have changed the item since, and a value
   * that is now at that place is not shown as the one the user clicked.
   * @param {number} index @param {number | null} until
   */
  function historyValue(index, until) {
    return withOpen(async ({ handle, view }) => {
      const entry = historyEntries(view).find((e) => e.index === index);
      if (entry === undefined || entry.until !== until) throw Object.assign(new Error("item_changed"), { code: "item_changed" });
      return client.vault.reveal_password_history(handle, index);
    });
  }

  const secrets = secretClipboardFor(clipboard);
  // A copied secret stays on the clipboard for its 30 seconds when this screen is left; a lock and a sign-out clear it at once
  // (clearOnLock, from the frame).

  /** @param {string} text @param {boolean} [secret] a secret is cleared again after 30 seconds */
  async function toClipboard(text, secret = false) {
    if (secret) return secrets.copy(text);
    if (!clipboard?.writeText) throw Object.assign(new Error("clipboard"), { code: "clipboard" });
    try {
      await clipboard.writeText(text);
    } catch {
      throw Object.assign(new Error("clipboard"), { code: "clipboard" });
    }
  }

  /**
   * One value that may be secret: its label, the value (dots when it is secret) and the buttons. The buttons name the
   * field they act on ("Copy Password"), so a screen reader hears more than "Copy" and "Show" over and over.
   * @param {{ key: string, label: string, speak?: string, plain: string | null, get(): Promise<string> }} spec
   *   `plain` is the value when the core shows it, else null; `get` asks the worker; `speak` is the name the buttons give
   *   the value when the visible label is not enough alone (default: the label)
   */
  function valueRow({ key, label, speak = label, plain, get }) {
    const slot = el("span", { class: "value", "data-role": "value", "data-key": key }, plain ?? DOTS);
    const copy = el("button", {
      type: "button", class: "btn btn-secondary btn-sm i-copy", "aria-label": t("vault.item.copy_label", { label: speak }), "data-role": "copy", "data-key": key,
    }, t("vault.item.copy"));
    /** @type {HTMLButtonElement | null} */
    let toggle = null;
    if (plain === null) {
      toggle = /** @type {HTMLButtonElement} */ (el("button", {
        type: "button", class: "btn btn-secondary btn-sm", "aria-label": t("vault.item.show_label", { label: speak }), "data-role": "reveal", "data-key": key,
      }, t("vault.item.show")));
      slots.set(key, { slot, toggle, label: speak });
      toggle.addEventListener("click", async () => {
        if (!touch()) return;
        if (revealedKey === key) {
          hideAll();
          return;
        }
        try {
          const value = await get();
          if (!touch()) return;
          hideAll(); // one at a time: the first goes before the second shows
          revealedKey = key;
          mount(slot, document.createTextNode(value));
          mount(/** @type {HTMLButtonElement} */ (toggle), document.createTextNode(t("vault.item.hide")));
          /** @type {HTMLButtonElement} */ (toggle).setAttribute("aria-label", t("vault.item.hide_label", { label: speak }));
        } catch (error) {
          hideAll();
          say(describeError(t, error));
        }
      });
    }
    copy.addEventListener("click", async () => {
      if (!touch()) return;
      try {
        await toClipboard(plain ?? (await get()), plain === null);
        say(t(plain === null ? "vault.item.copied_secret" : "vault.item.copied", { label: speak }));
      } catch (error) {
        say(describeError(t, error));
      }
    });
    return el("div", { class: "field-row", "data-role": "field", "data-key": key },
      el("span", { class: "label" }, label),
      slot,
      el("span", { class: "actions" }, toggle, copy));
  }

  /** A card of the page: a heading, then its rows. @param {string | null} heading @param {string} kind @param {Node[]} rows */
  function card(heading, kind, rows) {
    return el("section", { class: "card item-section", "data-role": "item-card", "data-card": kind },
      ...(heading === null ? [] : [el("h2", null, heading)]), ...rows);
  }

  /** Whether the page has been on the screen, so that one that has left it is told apart from one that is not on it yet. */
  let shownOnce = false;
  /** How many ticks the code has run for a page that is still not on the screen. */
  let ticksBeforeShown = 0;

  /**
   * The card of the one-time password: the code in two groups, the seconds it still holds, and Copy. The ticker is started by
   * `load` once the page is on the screen.
   * @returns {HTMLElement}
   */
  function totpCard() {
    const label = t("vault.item.totp_label");
    const code = el("span", {
      class: "totp-code", "data-role": "totp-code", "aria-live": "polite", "aria-atomic": "true",
    }, CODE_DOTS);
    const left = el("span", { class: "totp-left", "data-role": "totp-left" });
    const copy = el("button", {
      type: "button", class: "btn btn-secondary btn-sm i-copy", "aria-label": t("vault.item.copy_label", { label }), "data-role": "copy", "data-key": "totp",
    }, t("vault.item.copy"));
    /** @param {number} seconds */
    const showLeft = (seconds) => {
      mount(left, document.createTextNode(t("vault.item.totp_left", { seconds })));
      left.setAttribute("data-state", seconds <= LOW_SECONDS ? "low" : "ok");
    };
    /** @param {number} seconds */
    const makeCode = (seconds) => withOpen(({ handle }) => client.vault.totp_code(handle, seconds));
    totpTicker?.stop();
    totpTicker = codeTicker({
      clock,
      load: makeCode,
      onCode: (value, seconds) => {
        mount(code, document.createTextNode(groupCode(value)));
        showLeft(seconds);
      },
      onLeft: showLeft,
      onError: () => {
        mount(code, document.createTextNode(CODE_DOTS));
        mount(left, document.createTextNode(t("vault.item.totp_error")));
        left.setAttribute("data-state", "error");
      },
      active: () => {
        const connected = /** @type {any} */ (root).isConnected;
        if (connected !== false) shownOnce = true; // (a stand-in DOM without `isConnected` counts as shown)
        // A page that has left the screen stops; so does one that was built and never put on it (a fast navigation).
        ticksBeforeShown += shownOnce ? 0 : 1;
        return !(shownOnce && connected === false) && ticksBeforeShown <= MAX_TICKS_BEFORE_SHOWN;
      },
    });
    copy.addEventListener("click", async () => {
      if (!touch()) return;
      try {
        // A new code for this moment, not the one on the page: that may be about to run out.
        const fresh = await makeCode(Math.floor(clock.now() / 1000));
        await toClipboard(String(fresh.code), true);
        say(t("vault.item.copied_secret", { label }));
      } catch (error) {
        say(describeError(t, error));
      }
    });
    return el("section", { class: "card item-section", "data-role": "item-card", "data-card": "totp" },
      el("h2", null, t("vault.item.totp_heading")),
      el("div", { class: "field-row totp-row", "data-role": "totp-row" },
        el("span", { class: "label" }, label),
        el("span", { class: "totp-value" }, code, left),
        el("span", { class: "actions" }, copy)));
  }

  /**
   * The card of the passkey: the site it belongs to (the relying party id: the identity), the user name the site gave, when it was
   * made and what kind it is. The two texts a site chooses for itself are shown apart, labelled as the site's, each in an isolated
   * element, and never take the place of the site. The key and the seeds are not on the page, and no button asks for them.
   * @param {import("./itemModel.mjs").PasskeyFacts} pk @param {boolean} editable
   * @returns {HTMLElement}
   */
  function passkeyCard(pk, editable) {
    /** @param {string} label @param {string} role @param {string} text */
    const row = (label, role, text) => el("div", { class: "field-row passkey-row", "data-role": "passkey-row", "data-key": role },
      el("span", { class: "label" }, label),
      el("bdi", { class: "value", "data-role": "passkey-value", "data-key": role }, text),
      el("span", { class: "actions" }));
    const when = pk.created === null ? null : formatMoment(pk.created, locale);
    const rows = [
      row(t("passkey.site"), "site", pk.site),
      row(t("passkey.user"), "user", pk.user),
      ...(pk.siteName === null ? [] : [row(t("passkey.site_name"), "site_name", pk.siteName)]),
      ...(pk.displayName === null ? [] : [row(t("passkey.display_name"), "display_name", pk.displayName)]),
      ...(when === null ? [] : [row(t("passkey.created"), "created", when)]),
    ];
    const kind = el("p", { class: "passkey-kind", "data-role": "passkey-kind" }, el("strong", null, t("passkey.kind")), " ", t("passkey.kind_help"));
    /** @type {HTMLElement[]} */
    const tail = [];
    if (editable) {
      const remove = el("button", {
        type: "button", class: "btn btn-secondary btn-sm", "aria-label": t("passkey.remove_label", { site: pk.site }), "data-role": "remove-passkey",
      }, t("passkey.remove"));
      remove.addEventListener("click", async () => {
        if (!touch()) return;
        const yes = await askConfirm({
          t, host, title: "passkey.remove_title", body: "passkey.remove_body", confirm: "passkey.remove_confirm", vars: { site: pk.site },
        });
        if (!yes) return;
        try {
          // The newest revision, as for the favourite mark; the item stays, only its passkey goes.
          const now = engine.list().find((/** @type {any} */ i) => i.id === id);
          await engine.update(id, { remove_passkey: true }, now?.rev);
          say(t("passkey.removed", { site: pk.site }));
        } catch (error) {
          say(describeError(t, error));
        }
      });
      tail.push(el("div", { class: "actions passkey-actions" }, remove));
    }
    return el("section", { class: "card item-section passkey-card", "data-role": "item-card", "data-card": "passkey" },
      el("h2", null, t("passkey.heading")), ...rows, kind, ...tail);
  }

  /** Reads the item and builds the screen again. */
  async function load() {
    totpTicker?.stop();
    totpTicker = null;
    hideAll();
    slots.clear();
    /** @type {any} */
    let view;
    try {
      view = await withOpen(async ({ view: v }) => v);
    } catch (error) {
      const known = engine.list().find((/** @type {any} */ i) => i.id === id);
      if (known?.conflict) {
        // The server deleted the item while this device changed it: there is nothing to open, but the conflict is there to settle.
        const open = el("a", { class: "btn btn-primary btn-sm", href: `#/items/${id}/conflict`, "data-role": "open-conflict" }, t("conflict.open"));
        mount(root,
          el("h1", null, String(known.name ?? "") === "" ? t("vault.item.unnamed") : String(known.name)),
          el("div", { class: "marks" }, ...markBadges(t, known)),
          notice("conflict", t("conflict.notice"), open),
          el("p", { class: "aside" }, el("a", { href: "#/items", "data-role": "back" }, t("vault.item.back"))));
        return;
      }
      mount(root, el("p", { role: "alert", "data-role": "unavailable" },
        t(isNotFound(error) && !known ? "vault.item.not_found" : "vault.item.cannot_open")),
      el("p", null, el("a", { href: "#/items" }, t("vault.item.back"))));
      return;
    }
    const entry = engine.list().find((/** @type {any} */ i) => i.id === id) ?? {};
    const marks = markBadges(t, entry);
    /** @type {Node[]} */
    const notices = [];
    if (entry.damaged) notices.push(notice("damaged", t("vault.notice.damaged"), keepMineButton("damaged")));
    if (entry.quarantined) notices.push(notice("quarantined", t("vault.notice.quarantined"), keepMineButton("quarantined")));
    if (entry.readOnly) notices.push(notice("read_only", t("vault.notice.read_only")));
    if (entry.missingOnServer) {
      const discard = el("button", { type: "button", class: "btn btn-danger btn-sm", "data-role": "discard-missing" }, t("vault.notice.discard_missing"));
      discard.addEventListener("click", async () => {
        if (!touch()) return;
        const yes = await askConfirm({
          t, host, title: "vault.dialog.missing_title", body: "vault.dialog.missing_body", confirm: "vault.dialog.missing_confirm",
        });
        if (!yes) return;
        try {
          await sync.discardMissing(id);
          go("/items");
        } catch (error) {
          say(describeError(t, error));
        }
      });
      notices.push(notice("missing", t("vault.notice.missing"), discard));
    }
    if (entry.conflict) {
      // Both versions are kept until the user chooses; the choice is made on the conflict screen.
      const open = el("a", { class: "btn btn-primary btn-sm", href: `#/items/${id}/conflict`, "data-role": "open-conflict" }, t("conflict.open"));
      notices.push(notice("conflict", t("conflict.notice"), open));
    } else if (entry.blocked) {
      const discard = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "discard-change" }, t("vault.notice.discard_change"));
      discard.addEventListener("click", async () => {
        if (!touch()) return;
        try {
          await sync.discard(id);
          await load();
        } catch (error) {
          say(describeError(t, error));
        }
      });
      const why = describeError(t, { code: "blocked", reason: entry.blockedReason });
      notices.push(notice("blocked", why, discard));
    }

    const name = String(view.name ?? "") === "" ? t("vault.item.unnamed") : String(view.name);
    const groups = groupFields(view.fields);
    const passkey = passkeyOf(view);
    /** @param {import("./itemModel.mjs").FieldSpec} field */
    const fieldRow = (field) => valueRow({
      key: field.key, label: field.label || t("vault.item.field"), plain: field.plain,
      get: () => fieldValue(field.index, field.id),
    });
    /** @type {any[]} */
    const urls = Array.isArray(view.urls) ? view.urls : [];

    // The cards: the sign-in fields, the other fields, the addresses and the notes; a card with nothing in it is not drawn.
    /** @type {HTMLElement[]} */
    const cards = [];
    if (groups.login.length > 0) cards.push(card(t("vault.item.card_login"), "login", groups.login.map(fieldRow)));
    if (view.has_totp === true) cards.push(totpCard());
    if (passkey !== null) cards.push(passkeyCard(passkey, canChange(entry)));
    // The passwords the item had before, newest first; a card is drawn only for an item that has some.
    const earlier = historyEntries(view);
    if (earlier.length > 0) {
      cards.push(card(t("vault.item.history_heading", { count: earlier.length }), "history", earlier.map(({ index, until }) => {
        const when = until === null ? null : formatMoment(until, locale);
        return valueRow({
          key: `h${index}`,
          label: t(when === null ? "vault.item.history_unknown" : "vault.item.history_replaced", { date: when ?? "" }),
          speak: t(when === null ? "vault.item.history_speak_unknown" : "vault.item.history_speak", { date: when ?? "" }),
          plain: null,
          get: () => historyValue(index, until),
        });
      })));
    }
    if (groups.custom.length > 0) cards.push(card(t(groups.login.length > 0 ? "vault.item.card_fields" : "vault.item.card_details"), "fields", groups.custom.map(fieldRow)));
    if (urls.length > 0) {
      cards.push(el("section", { class: "card item-section urls", "data-role": "urls", "data-card": "urls" },
        el("h2", null, t("vault.item.addresses")),
        el("ul", null, ...urls.map((u) => {
          const address = String(u.url ?? "");
          const copy = el("button", {
            type: "button", class: "btn btn-secondary btn-sm i-copy", "aria-label": t("vault.item.copy_label", { label: t("vault.item.address") }), "data-role": "copy-url",
          }, t("vault.item.copy"));
          copy.addEventListener("click", async () => {
            if (!touch()) return;
            try {
              await toClipboard(address);
              say(t("vault.item.copied", { label: t("vault.item.address") }));
            } catch (error) {
              say(describeError(t, error));
            }
          });
          return el("li", { "data-role": "url-row" }, el("span", { class: "value", "data-role": "url" }, address), el("span", { class: "actions" }, copy));
        }))));
    }
    if (view.has_notes) {
      cards.push(card(null, "notes", [valueRow({
        key: "notes", label: t("vault.item.notes"), plain: null,
        get: () => withOpen(({ handle }) => client.vault.reveal_item_notes(handle)),
      })]));
    }

    // The header: the tile, the name with its star, the type and marks, the folder labels, and the actions.
    const editable = canChange(entry);
    const labels = folderLabels(view, locale);
    // Hidden until the item is in a folder. The first labels are chips (links to the folder when the page gives `folderChip`);
    // the rest are one "+N" chip that names them in its title.
    const shownLabels = labels.slice(0, MAX_FOLDER_CHIPS);
    const moreLabels = labels.slice(MAX_FOLDER_CHIPS);
    const chips = el("div", { class: "item-folders", role: "list", "aria-label": t("vault.item.folders"), "data-role": "folder-chips" },
      ...shownLabels.map((label) => el("span", { class: "folder-chip", role: "listitem", "data-role": "folder-chip" }, typeof folderChip === "function" ? folderChip(label) : label)),
      ...(moreLabels.length === 0 ? [] : [el("span", {
        class: "folder-chip folder-chip-more", role: "listitem", "data-role": "folder-chip-more", title: moreLabels.join(", "),
        "aria-label": t("folders.more_label", { count: moreLabels.length, names: moreLabels.join(", ") }),
      }, `+${moreLabels.length}`)]));
    chips.hidden = labels.length === 0;

    const actions = el("div", { class: "actions item-actions", "data-role": "actions" });
    moreMenu = null;
    moreButton = null;
    if (editable) {
      const del = el("button", { type: "button", class: "btn btn-danger i-trash", "data-role": "delete" }, t("vault.item.trash"));
      del.addEventListener("click", async () => {
        if (!touch()) return;
        // An item with a passkey says which site has the public key and what happens to the passkey here.
        const yes = await askConfirm({
          t, host, title: "list.trash_title_one", body: passkey === null ? "list.trash_body" : "passkey.delete_body", confirm: "list.trash_confirm",
          vars: { name, site: passkey?.site ?? "" },
        });
        if (!yes) return;
        try {
          await engine.remove(id);
          go("/items");
        } catch (error) {
          say(describeError(t, error));
        }
      });
      const edit = el("a", { class: "btn btn-primary i-pencil", href: `#/items/${id}/edit`, "data-role": "edit" }, t("vault.item.edit"));

      // The ⋮ menu holds what is not the main action. The favourite mark switches with a patch of that one key.
      const favorite = el("button", { type: "button", role: "menuitem", tabindex: "-1", class: "side-menuitem", "data-role": "favorite" },
        el("span", { class: "icon", "data-icon": "star", "aria-hidden": "true" }), t(view.favorite ? "vault.item.favorite_remove" : "vault.item.favorite_add"));
      /** @type {HTMLElement[]} */
      const entries = [favorite];
      if (typeof moveToFolder === "function") {
        const move = el("button", { type: "button", role: "menuitem", tabindex: "-1", class: "side-menuitem", "data-role": "move" },
          el("span", { class: "icon", "data-icon": "folder", "aria-hidden": "true" }), t("list.menu_move"));
        move.addEventListener("click", () => {
          moreMenu?.close(false);
          moveToFolder(id, { host, say });
        });
        entries.push(move);
      }
      const more = el("button", {
        type: "button", class: "btn btn-secondary btn-icon", "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": t("vault.item.more", { name }), "data-role": "more",
      }, el("span", { class: "icon", "data-icon": "more", "aria-hidden": "true" }));
      const menu = el("div", { class: "side-menu item-menu", role: "menu", "aria-label": t("vault.item.more", { name }), "data-role": "more-menu" }, ...entries);
      const pop = popMenu({ trigger: more, menu, items: () => entries, escape: true });
      moreMenu = pop;
      moreButton = more;
      favorite.addEventListener("click", async () => {
        pop.close(true);
        if (!touch()) return;
        // The newest revision: a change that came in since the page was drawn is not overwritten (the engine refuses a stale one).
        const now = engine.list().find((/** @type {any} */ i) => i.id === id);
        const draft = favouriteDraft({ favorite: view.favorite === true });
        // The page is built again when the engine says the item changed (once, not twice); the focus then goes back to the ⋮ button.
        refocusMore = true;
        try {
          await engine.update(id, draft, now?.rev);
          say(t(draft.favorite ? "vault.item.favorited" : "vault.item.unfavorited"));
        } catch (error) {
          refocusMore = false;
          say(describeError(t, error));
        }
      });
      mount(actions, edit, del, el("span", { class: "item-more" }, more, menu));
    }

    const header = el("header", { class: "item-head", "data-role": "item-head" },
      el("span", { class: "tile item-tile", "data-type": tileType(view.item_type), "aria-hidden": "true" }, tileLetter(view.name)),
      el("div", { class: "item-title" },
        el("h1", null, name, view.favorite ? el("span", { class: "star", role: "img", "aria-label": t("vault.item.favorite") }, " ★") : null),
        el("div", { class: "item-sub" },
          el("p", { class: "type", "data-role": "type" }, typeLabel(t, view.item_type)),
          el("div", { class: "marks" }, ...marks),
          chips)),
      actions);

    mount(root, ...[
      el("p", { class: "back-row" }, el("a", { class: "back-link i-back", href: "#/items", "data-role": "back" }, t("vault.item.back"))),
      header,
      ...notices,
      message,
      host,
      ...cards].filter((node) => node !== null));
    // The code is asked for once the page is built, so its first value has a place to go.
    void /** @type {ReturnType<typeof codeTicker> | null} */ (totpTicker)?.start();
    if (refocusMore) {
      refocusMore = false;
      // The button that had the focus was in the header that is gone: the new one takes it, so a keyboard user keeps their place.
      focusNode(moreButton ?? root.querySelector?.('[data-role="back"]'));
    }
  }

  /**
   * "Keep mine" for an item the server's newest version of which cannot be used: the version on this device is written
   * to the server as the newest one, after the user has said yes.
   * @param {"damaged" | "quarantined"} kind
   * @returns {HTMLElement | null} null when the engine has no such action
   */
  function keepMineButton(kind) {
    if (typeof engine.keepMine !== "function") return null;
    const button = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "keep-mine" }, t(`conflict.keep_mine_${kind}`));
    button.addEventListener("click", async () => {
      if (!touch()) return;
      const yes = await askConfirm({
        t, host, title: "conflict.dialog.keep_mine_title", body: `conflict.dialog.keep_mine_${kind}_body`, confirm: "conflict.dialog.keep_mine_confirm",
      });
      if (!yes) return;
      try {
        await engine.keepMine(id);
        await load();
      } catch (error) {
        say(describeError(t, error));
      }
    });
    return button;
  }

  /** @param {string} kind @param {string} text @param {Node | null} [action] */
  function notice(kind, text, action) {
    return el("div", { class: `notice notice-${kind}`, role: "note", "data-role": "notice", "data-notice": kind },
      el("p", null, text), action ?? null);
  }

  await load();
  listenWhileShown(root, engine, "changed", (/** @type {{ ids?: string[] }} */ event) => {
    if (Array.isArray(event?.ids) && event.ids.includes(id)) void load();
  });
  return root;
}
