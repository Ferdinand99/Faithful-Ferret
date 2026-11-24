// The offer to save or update a password, in the popup (design document, sections 8.2 to 8.6, 10.3 and 10.9), in a build
// with saving from the extension on (the build flag `save`; without it nothing here is built). Every control carries
// `data-feature="save"`.
//
// An offer comes from a form the user submitted on a page (or from a password Ferret generated for one). The background
// holds it in memory; the popup is told of it (`offer_list`), asks what it means for the vault (`offer_classify`: the core
// decides), and shows one card:
//
//   "Save in Ferret?"          a new login: the site (the host the core shows, with its A-label beside it), the name, the
//                              user name and the folder, which the user can change, and the password, hidden. Buttons:
//                              Save, Not now, Never for this site.
//   "Update the password?"     the one saved login this password belongs to: its name and user name. Buttons: Update,
//                              Save as new, Not now.
//   "Update a saved password?" more than one candidate: a list to pick from, never an automatic choice.
//
// A saved login that matches the site only by its main domain (not its host) is never the target by itself; it is listed
// apart with its host and updated only when the user picks it. Other saved logins that use the same password are named in
// a warning above the buttons.
//
// Ferret's UI is the only place an offer is shown and the click is the only thing that writes (`offer_save`,
// `offer_update`); the card is built to be safe when the popup opens by itself, under the user's hand:
//
//   - there is no default button and no form (Enter does nothing, in a field or anywhere on the card);
//   - the focus starts on the card's heading, never on a button that writes;
//   - a click on any control of the card is ignored for the first 400 milliseconds after the card appears;
//   - nothing is sent but the offer's id and what the user chose: the password is never in a message from here.
//
// The password is shown as hidden. A button beside it (the same eye button as the web vault's edit form) asks the
// background for it and shows it until the user hides it again, or the card goes away; the value is held in the field's
// text and nowhere else.
//
// Nothing here makes a password or keeps one: the card has the offer's id, the choices of the user and the answers of
// the background, which are codes, names, hosts and item ids.

import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { actionErrorKey } from "./popupFlow.mjs";
import { UiError } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {{ a_label: string, unicode: string }} Host */
/** @typedef {{ offerId: string, kind: string, host: Host, username: string | null, generated: boolean, incognito: boolean }} Offer */
/**
 * @typedef {{
 *   action: "save" | "update" | "choose" | "none",
 *   targets: Array<{ id: string, rev: number, name: string, username: string, how: string }>,
 *   domainOnly: Array<{ id: string, rev: number, name: string, host: Host | null }>,
 *   reused: Array<{ name: string, host: Host | null }>,
 *   usernameFrom: string | null,
 * }} Classification
 */

/** How long a click on the card is ignored after the card appears. */
export const GUARD_MS = 400;

/** The reasons the card has a text for (`offer.error.<reason>`); any other is `unknown`. */
export const OFFER_ERRORS = Object.freeze([
  "not_offered",
  "item_changed",
  "not_found",
  "not_a_target",
  "not_updatable",
  "origin_changed",
  "invalid_input",
  "busy",
  "vault_locked",
  "sync_not_running",
  "worker_failed",
  "read_only",
]);

/** The i18n key of a refused answer. @param {unknown} reason */
export const offerErrorKey = (reason) => `offer.error.${typeof reason === "string" && OFFER_ERRORS.includes(reason) ? reason : "unknown"}`;

/** @param {unknown} host @returns {Host | null} */
const hostOf = (host) => {
  const h = /** @type {any} */ (host);
  return typeof h?.a_label === "string" && typeof h?.unicode === "string" ? { a_label: h.a_label, unicode: h.unicode } : null;
};

/** @param {unknown} failure */
const reasonOf = (failure) => (failure instanceof UiError ? failure.code : "unknown");

/** @param {any} reply @returns {Classification} */
function classificationOf(reply) {
  return {
    action: ["save", "update", "choose", "none"].includes(reply?.action) ? reply.action : "save",
    targets: (Array.isArray(reply?.targets) ? reply.targets : []).map((/** @type {any} */ t) => ({ id: t.id, rev: t.rev, name: String(t.name ?? ""), username: String(t.username ?? ""), how: String(t.how ?? "") })),
    domainOnly: (Array.isArray(reply?.domain_only) ? reply.domain_only : []).map((/** @type {any} */ d) => ({ id: d.id, rev: d.rev, name: String(d.name ?? ""), host: hostOf(d.host) })),
    reused: (Array.isArray(reply?.reused) ? reply.reused : []).map((/** @type {any} */ r) => ({ name: String(r.name ?? ""), host: hostOf(r.host) })),
    usernameFrom: typeof reply?.username_from === "string" ? reply.username_from : null,
  };
}

/**
 * The offer's requests, with no DOM.
 * @param {import("./ui.mjs").Request} request
 */
export function createOfferFlow(request) {
  return {
    /**
     * The offers ready for a tab, and the reason of a refused shortcut or menu click that the tab shows.
     * @param {number} tabId
     * @param {boolean} [automatic] the open popup looks again by itself (not the user): the auto-lock's deadline does not move
     * @returns {Promise<{ ok: true, offers: Offer[], notice: string | null } | { ok: false, reason: string }>}
     */
    async list(tabId, automatic = false) {
      try {
        const reply = await request("offer_list", automatic ? { tab_id: tabId, automatic: true } : { tab_id: tabId });
        if (reply?.ok !== true) return { ok: false, reason: String(reply?.reason ?? "unknown") };
        /** @type {Offer[]} */
        const offers = [];
        for (const o of Array.isArray(reply.offers) ? reply.offers : []) {
          const host = hostOf(o.host);
          if (host === null || typeof o.offer_id !== "string") continue;
          offers.push({ offerId: o.offer_id, kind: String(o.kind), host, username: typeof o.username === "string" ? o.username : null, generated: o.generated === true, incognito: o.incognito === true });
        }
        return { ok: true, offers, notice: typeof reply.notice === "string" ? reply.notice : null };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** What the offer means for the vault now. @param {string} offerId @returns {Promise<({ ok: true } & Classification) | { ok: false, reason: string }>} */
    async classify(offerId) {
      try {
        const reply = await request("offer_classify", { offer_id: offerId });
        return reply?.ok === true ? { ok: true, ...classificationOf(reply) } : { ok: false, reason: String(reply?.reason ?? "unknown") };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** The folders of the vault. @returns {Promise<string[]>} */
    async folders() {
      try {
        const reply = await request("folder_names", {});
        return reply?.ok === true && Array.isArray(reply.folders) ? reply.folders.filter((/** @type {unknown} */ f) => typeof f === "string") : [];
      } catch {
        return [];
      }
    },

    /**
     * "Save": the offer's password, with the name, user name and folder the user chose. Never the password in the message.
     * @param {string} offerId @param {{ name: string, username: string | null, folder: string | null }} choice
     * @returns {Promise<{ ok: true, pending: boolean } | { ok: false, reason: string, classification?: Classification }>}
     */
    async save(offerId, { name, username, folder }) {
      try {
        const reply = await request("offer_save", {
          offer_id: offerId,
          name,
          ...(username !== null && username.trim() !== "" ? { username } : {}),
          ...(folder !== null && folder !== "" ? { folder } : {}),
        });
        return writtenOf(reply);
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /**
     * "Update": the new password into one saved login. `picked`: the user chose a login that matches by domain only.
     * @param {string} offerId @param {{ id: string, rev: number, picked?: boolean }} target
     * @returns {Promise<{ ok: true, pending: boolean } | { ok: false, reason: string, classification?: Classification }>}
     */
    async updatePassword(offerId, { id, rev, picked = false }) {
      try {
        return writtenOf(await request("offer_update", { offer_id: offerId, id, rev, ...(picked ? { picked: true } : {}) }));
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** "Not now". @param {string} offerId @returns {Promise<{ ok: boolean, reason?: string }>} */
    async dismiss(offerId) {
      try {
        const reply = await request("offer_dismiss", { offer_id: offerId });
        return reply?.ok === true ? { ok: true } : { ok: false, reason: String(reply?.reason ?? "unknown") };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** "Never for this site". @param {string} offerId @returns {Promise<{ ok: boolean, reason?: string }>} */
    async never(offerId) {
      try {
        const reply = await request("offer_never", { offer_id: offerId });
        return reply?.ok === true ? { ok: true } : { ok: false, reason: String(reply?.reason ?? "unknown") };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** The offer's password, for the card's "Show". @param {string} offerId @returns {Promise<{ ok: true, value: string } | { ok: false, reason: string }>} */
    async reveal(offerId) {
      try {
        const reply = await request("offer_reveal", { offer_id: offerId });
        return reply?.ok === true && typeof reply.value === "string" ? { ok: true, value: reply.value } : { ok: false, reason: String(reply?.reason ?? "unknown") };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },
  };
}

/** @param {any} reply @returns {{ ok: true, pending: boolean } | { ok: false, reason: string, classification?: Classification }} */
function writtenOf(reply) {
  if (reply?.ok === true) return { ok: true, pending: reply.pending !== false };
  return { ok: false, reason: String(reply?.reason ?? "unknown"), ...(reply?.classification !== undefined ? { classification: classificationOf(reply.classification) } : {}) };
}

/** @typedef {ReturnType<typeof createOfferFlow>} OfferFlow */

/** The host as the card shows it: the Unicode form, with the A-label beside it when the two differ, each left to right. @param {Host} host */
function hostLine(host) {
  const same = host.a_label === host.unicode;
  return el(
    "span",
    { class: "ff-offer-host", dir: "ltr", "data-role": "offer-host", "data-a-label": host.a_label },
    el("strong", null, host.unicode),
    same ? null : el("span", { class: "ff-offer-alabel", "data-role": "offer-a-label" }, ` (${host.a_label})`),
  );
}

/** The name a new login gets unless the user changes it: the host without `www.`. @param {Host} host */
const defaultName = (host) => host.unicode.replace(/^www\./i, "");

/**
 * One card.
 *
 * @param {{
 *   texts: Texts,
 *   flow: OfferFlow,
 *   offer: Offer,
 *   now?: () => number,
 *   onClosed?: (outcome: "saved" | "updated" | "dismissed" | "never") => void,
 * }} deps `now` is the clock the 400 milliseconds are counted on; `onClosed` runs after the offer was answered
 * @returns {{ root: HTMLElement, loaded: Promise<void>, focus: () => void, hide: () => void }}
 */
export function createOfferCard({ texts, flow, offer, now = () => Date.now(), onClosed = () => {} }) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const t = texts.t;
  /** When the buttons of the card appeared: the guard counts from here (each build of the card starts it again). */
  let shownAt = now();
  const FEATURE = { "data-feature": "save" };
  const titleId = `ff-offer-title-${offer.offerId.slice(0, 8)}`;
  const root = el("section", { class: "ff-offer", "data-role": "offer-card", "data-offer": offer.offerId, "data-hold": "1", "aria-labelledby": titleId, ...FEATURE });
  const status = el("p", { class: "ff-error", role: "alert", "data-role": "offer-error", hidden: true });
  /** @type {Classification | null} */
  let classification = null;
  /** @type {string[]} */
  let folders = [];
  let busy = false;
  let closed = false;
  /** The password input, while the card shows one; emptied when the card is rebuilt or closed. @type {HTMLInputElement | null} */
  let secret = null;
  /** The card's heading (where the focus starts) and its buttons, as the last build made them. @type {HTMLElement | null} */
  let titleNode = null;
  /** @type {HTMLElement[]} */
  let controls = [];

  /** The card's heading: the focus starts here, never on a button. @param {string} key */
  function heading(key) {
    titleNode = el("h2", { id: titleId, class: "ff-offer-title", tabindex: "-1", "data-role": "offer-title" }, t(key));
    return titleNode;
  }

  /** @param {(node: HTMLElement) => void} fn */
  const eachControl = (fn) => {
    for (const node of controls) fn(node);
  };

  /** @param {string | null} key */
  const say = (key) => {
    status.textContent = key === null ? "" : t(key);
    status.hidden = key === null;
  };

  /** Whether a click counts yet: not in the first moments after the card appeared. */
  const ready = () => now() - shownAt >= GUARD_MS;

  /**
   * Enter does nothing on the card: there is no form to submit and no default button. (A button that the user moved the
   * focus to still answers Enter and Space as a button does; the focus never starts on one.)
   * @param {any} event
   */
  const noEnter = (event) => {
    if (event?.key === "Enter" && event.target?.tagName !== "BUTTON") event.preventDefault();
  };
  root.addEventListener("keydown", noEnter);

  /** Empties the password field, if there is one. */
  function wipeSecret() {
    if (secret !== null) {
      secret.value = "";
      secret.setAttribute("type", "password");
    }
    secret = null;
  }

  /**
   * A button of the card: a click is ignored while the card is busy and in the first moments.
   * @param {{ role: string, label: string, primary?: boolean, danger?: boolean, aria?: string, run: () => Promise<void> }} spec
   */
  function button({ role, label, primary = false, danger = false, aria, run }) {
    const node = el("button", { type: "button", class: `ff-button${primary ? " ff-primary" : ""}${danger ? " ff-danger" : ""}`, "data-role": role, ...(aria !== undefined ? { "aria-label": aria } : {}), ...FEATURE }, label);
    node.addEventListener("click", () => {
      if (closed || busy || !ready()) return;
      busy = true;
      eachControl((other) => other.setAttribute("aria-busy", "true"));
      say(null);
      run()
        .catch(() => say("offer.error.unknown"))
        .finally(() => {
          busy = false;
          eachControl((other) => other.removeAttribute("aria-busy"));
        });
    });
    controls.push(node);
    return node;
  }

  /** The card is answered: only the result stays. @param {string} key @param {"saved" | "updated" | "dismissed" | "never"} outcome @param {Record<string, string | number>} [vars] */
  function finish(key, outcome, vars) {
    closed = true;
    wipeSecret();
    mount(root, el("p", { class: "ff-offer-result", role: "status", "data-role": "offer-result", "data-outcome": outcome, ...FEATURE }, t(key, vars)));
    onClosed(outcome);
  }

  /** A refused write: the reason; and when the item changed meanwhile, the card as the new classification says. @param {{ reason: string, classification?: Classification }} refused */
  function refused(refused) {
    if (refused.reason === "not_offered" || refused.reason === "vault_locked") {
      // The offer is gone (it ran out, or the vault locked): nothing more to answer here.
      closed = true;
      wipeSecret();
      mount(root, el("p", { class: "ff-error", role: "alert", "data-role": "offer-gone", ...FEATURE }, t(offerErrorKey(refused.reason))));
      return;
    }
    if (refused.classification !== undefined) {
      classification = refused.classification;
      render();
    }
    say(offerErrorKey(refused.reason));
  }

  /** The password row: dots, and the eye button (the web vault's) that shows the value until it is hidden again. */
  function passwordRow() {
    const input = /** @type {HTMLInputElement} */ (
      el("input", { id: `${titleId}-pw`, type: "password", readonly: true, autocomplete: "off", class: "ff-input", placeholder: "••••••••", "aria-describedby": `${titleId}-pwhint`, "data-role": "offer-password", ...FEATURE })
    );
    const eye = el("span", { class: "ff-eye", "aria-hidden": "true", "data-icon": "eye" });
    // One state for a screen reader: a fixed name and `aria-pressed` (the label does not flip).
    const toggle = el("button", { type: "button", class: "ff-reveal-toggle", "aria-pressed": "false", "aria-label": t("offer.password.show"), "data-role": "offer-password-toggle", ...FEATURE }, eye);
    const hint = el("p", { class: "ff-hint", id: `${titleId}-pwhint`, "data-role": "offer-password-hint" }, t("offer.password.hidden"));
    let shown = false;
    let asking = false;
    /** @param {boolean} on */
    const display = (on) => {
      shown = on;
      input.setAttribute("type", on ? "text" : "password");
      toggle.setAttribute("aria-pressed", on ? "true" : "false");
      hint.textContent = t(on ? "offer.password.shown" : "offer.password.hidden");
      eye.setAttribute("data-icon", on ? "eye-off" : "eye");
    };
    toggle.addEventListener("click", async () => {
      if (closed || busy || asking || !ready()) return;
      if (shown) {
        input.value = "";
        display(false);
        return;
      }
      asking = true;
      try {
        const got = await flow.reveal(offer.offerId);
        // An answer that lands after the card was closed or built again belongs to a field that is gone.
        if (closed || secret !== input) return;
        if (!got.ok) {
          say(offerErrorKey(got.reason));
          return;
        }
        input.value = got.value;
        display(true);
      } finally {
        asking = false;
      }
    });
    secret = input;
    return el(
      "div",
      { class: "ff-field", "data-role": "offer-password-row" },
      el("label", { for: `${titleId}-pw`, class: "ff-label" }, t("offer.password")),
      el("div", { class: "ff-secret-input" }, input, toggle),
      hint,
    );
  }

  /** "Made by Ferret", the warning about reuse, the info line about a main-domain match. */
  function notes() {
    /** @type {HTMLElement[]} */
    const out = [];
    if (offer.generated) out.push(el("p", { class: "ff-hint", "data-role": "offer-generated" }, t("offer.generated")));
    return out;
  }

  /** @param {Classification} c */
  function reuseWarning(c) {
    if (c.reused.length === 0) return null;
    return el(
      "div",
      { class: "ff-notice", role: "note", "data-role": "offer-reuse" },
      el("p", null, t("offer.reuse.title")),
      el(
        "ul",
        { class: "ff-offer-reuse" },
        ...c.reused.map((r) =>
          el("li", { "data-role": "offer-reuse-item" }, r.name === "" ? t("popup.item.unnamed") : r.name, r.host === null ? null : el("span", { class: "ff-hint" }, " "), r.host === null ? null : hostLine(r.host)),
        ),
      ),
    );
  }

  /** The logins that match by the site's main domain only: listed apart, updated only on an explicit pick. @param {Classification} c */
  function domainList(c) {
    if (c.domainOnly.length === 0) return null;
    return el(
      "div",
      { class: "ff-offer-domain", "data-role": "offer-domain" },
      el("p", { class: "ff-hint", "data-role": "offer-domain-info" }, t("offer.domain.info")),
      el(
        "ul",
        { class: "ff-offer-rows" },
        ...c.domainOnly.map((d) => {
          const label = d.name === "" ? t("popup.item.unnamed") : d.name;
          return el(
            "li",
            { class: "ff-offer-row", "data-role": "offer-domain-item", "data-item": d.id },
            el("span", { class: "ff-offer-row-name" }, label),
            d.host === null ? null : hostLine(d.host),
            button({
              role: "offer-domain-update",
              label: t("offer.update_button"),
              aria: t("offer.update_named", { name: label }),
              run: async () => {
                const done = await flow.updatePassword(offer.offerId, { id: d.id, rev: d.rev, picked: true });
                if (done.ok) finish(done.pending ? "offer.updated_pending" : "offer.updated", "updated");
                else refused(done);
              },
            }),
          );
        }),
      ),
    );
  }

  /** The fields the user may change before saving. */
  function saveFields() {
    const name = /** @type {HTMLInputElement} */ (el("input", { id: `${titleId}-name`, type: "text", class: "ff-input", autocomplete: "off", "data-role": "offer-name", ...FEATURE }));
    name.value = defaultName(offer.host);
    const username = /** @type {HTMLInputElement} */ (
      el("input", { id: `${titleId}-user`, type: "text", class: "ff-input", autocomplete: "off", inputmode: "email", "data-role": "offer-username", "data-from": classification?.usernameFrom ?? "", ...FEATURE })
    );
    username.value = offer.username ?? "";
    const folder = /** @type {HTMLSelectElement} */ (
      el("select", { id: `${titleId}-folder`, class: "ff-input", "data-role": "offer-folder", ...FEATURE }, el("option", { value: "" }, t("offer.folder.none")), ...folders.map((f) => el("option", { value: f }, f)))
    );
    for (const field of [name, username, folder]) field.addEventListener("keydown", noEnter);
    return {
      name,
      username,
      folder,
      rows: [
        el("div", { class: "ff-field" }, el("label", { for: `${titleId}-name`, class: "ff-label" }, t("offer.name")), name),
        el("div", { class: "ff-field" }, el("label", { for: `${titleId}-user`, class: "ff-label" }, t("offer.username")), username),
        el("div", { class: "ff-field" }, el("label", { for: `${titleId}-folder`, class: "ff-label" }, t("offer.folder")), folder),
      ],
    };
  }

  /** "Not now" and "Never": the buttons the save card and the update card share. @param {boolean} withNever */
  function dismissButtons(withNever) {
    return [
      button({
        role: "offer-not-now",
        label: t("offer.not_now"),
        run: async () => {
          const done = await flow.dismiss(offer.offerId);
          if (done.ok) finish("offer.dismissed", "dismissed");
          else refused({ reason: done.reason ?? "unknown" });
        },
      }),
      ...(withNever
        ? [
            button({
              role: "offer-never",
              label: t("offer.never"),
              run: async () => {
                const done = await flow.never(offer.offerId);
                if (done.ok) finish(offer.incognito ? "offer.never_done_private" : "offer.never_done", "never", { host: offer.host.unicode });
                else refused({ reason: done.reason ?? "unknown" });
              },
            }),
          ]
        : []),
    ];
  }

  /** The save card. @param {Classification} c */
  function saveCard(c) {
    const fields = saveFields();
    const save = button({
      role: "offer-save",
      label: t("offer.save"),
      primary: true,
      run: async () => {
        const done = await flow.save(offer.offerId, { name: fields.name.value, username: fields.username.value, folder: fields.folder.value === "" ? null : fields.folder.value });
        if (done.ok) finish(done.pending ? "offer.saved_pending" : "offer.saved", "saved");
        else refused(done);
      },
    });
    return [
      heading("offer.title.save"),
      el("p", { class: "ff-offer-site" }, t("offer.site"), " ", hostLine(offer.host)),
      ...notes(),
      ...fields.rows,
      passwordRow(),
      domainList(c),
      reuseWarning(c),
      el("div", { class: "ff-actions ff-offer-actions", "data-role": "offer-actions" }, save, ...dismissButtons(!offer.generated)),
      offer.incognito ? el("p", { class: "ff-hint", "data-role": "offer-private" }, t("offer.never.private")) : null,
    ];
  }

  /** The update card for the one login the password belongs to. @param {Classification} c */
  function updateCard(c) {
    const [target] = c.targets;
    const label = target.name === "" ? t("popup.item.unnamed") : target.name;
    const update = button({
      role: "offer-update",
      label: t("offer.update_button"),
      primary: true,
      run: async () => {
        const done = await flow.updatePassword(offer.offerId, { id: target.id, rev: target.rev });
        if (done.ok) finish(done.pending ? "offer.updated_pending" : "offer.updated", "updated");
        else refused(done);
      },
    });
    const saveNew = button({
      role: "offer-save-new",
      label: t("offer.save_new"),
      run: async () => {
        const done = await flow.save(offer.offerId, { name: defaultName(offer.host), username: offer.username, folder: null });
        if (done.ok) finish(done.pending ? "offer.saved_pending" : "offer.saved", "saved");
        else refused(done);
      },
    });
    return [
      heading("offer.title_update"),
      el("p", { class: "ff-offer-site" }, t("offer.site"), " ", hostLine(offer.host)),
      ...notes(),
      el(
        "dl",
        { class: "ff-offer-facts" },
        el("dt", null, t("offer.name")),
        el("dd", { "data-role": "offer-target-name" }, label),
        el("dt", null, t("offer.username")),
        el("dd", { "data-role": "offer-target-username" }, target.username === "" ? t("offer.username.none") : target.username),
      ),
      passwordRow(),
      domainList(c),
      reuseWarning(c),
      el("p", { class: "ff-hint", "data-role": "offer-history" }, t("offer.update_history")),
      el("div", { class: "ff-actions ff-offer-actions", "data-role": "offer-actions" }, update, saveNew, ...dismissButtons(false)),
    ];
  }

  /** The list to pick from when more than one login may be the one. @param {Classification} c */
  function chooseCard(c) {
    const rows = c.targets.map((target) => {
      const label = target.name === "" ? t("popup.item.unnamed") : target.name;
      return el(
        "li",
        { class: "ff-offer-row", "data-role": "offer-choice", "data-item": target.id },
        el("span", { class: "ff-offer-row-name" }, label),
        target.username === "" ? null : el("span", { class: "ff-hint", "data-role": "offer-choice-username" }, target.username),
        button({
          role: "offer-choice-update",
          label: t("offer.update_button"),
          aria: t("offer.update_named", { name: label }),
          run: async () => {
            const done = await flow.updatePassword(offer.offerId, { id: target.id, rev: target.rev });
            if (done.ok) finish(done.pending ? "offer.updated_pending" : "offer.updated", "updated");
            else refused(done);
          },
        }),
      );
    });
    const saveNew = button({
      role: "offer-save-new",
      label: t("offer.save_new"),
      run: async () => {
        const done = await flow.save(offer.offerId, { name: defaultName(offer.host), username: offer.username, folder: null });
        if (done.ok) finish(done.pending ? "offer.saved_pending" : "offer.saved", "saved");
        else refused(done);
      },
    });
    return [
      heading("offer.title.choose"),
      el("p", { class: "ff-offer-site" }, t("offer.site"), " ", hostLine(offer.host)),
      ...notes(),
      el("p", { class: "ff-hint", "data-role": "offer-choose-hint" }, t("offer.choose.hint")),
      el("ul", { class: "ff-offer-rows", "data-role": "offer-choices" }, ...rows),
      passwordRow(),
      domainList(c),
      reuseWarning(c),
      el("div", { class: "ff-actions ff-offer-actions", "data-role": "offer-actions" }, saveNew, ...dismissButtons(false)),
    ];
  }

  /** What the vault already holds: nothing to save. */
  function noneCard() {
    return [
      heading("offer.title.none"),
      el("p", { "data-role": "offer-none" }, t("offer.none")),
      el("div", { class: "ff-actions ff-offer-actions" }, ...dismissButtons(false)),
    ];
  }

  function render() {
    wipeSecret();
    controls = [];
    // The buttons appear now: a click counts only 400 ms after this (not from when the card was made, which the
    // classification may have used up).
    shownAt = now();
    if (classification === null) return;
    const c = classification;
    const parts = c.action === "update" && c.targets.length > 0 ? updateCard(c) : c.action === "choose" && c.targets.length > 0 ? chooseCard(c) : c.action === "none" ? noneCard() : saveCard(c);
    root.setAttribute("data-kind", c.action === "update" && c.targets.length > 0 ? "update" : c.action === "choose" && c.targets.length > 0 ? "choose" : c.action === "none" ? "none" : "save");
    mount(
      root,
      .../** @type {HTMLElement[]} */ (parts.filter((part) => part !== null)),
      el("p", { class: "ff-hint ff-offer-master", "data-role": "offer-master" }, t("offer.master")),
      status,
    );
  }

  const loaded = (async () => {
    mount(root, heading("offer.loading"));
    const [found, names] = await Promise.all([flow.classify(offer.offerId), flow.folders()]);
    if (closed) return;
    if (!found.ok) {
      closed = true;
      mount(root, el("p", { class: "ff-error", role: "alert", "data-role": "offer-gone", ...FEATURE }, t(offerErrorKey(found.reason))));
      return;
    }
    folders = names;
    classification = found;
    render();
  })();

  return {
    root,
    loaded,
    // The focus starts on the heading: a card that appears under the user's hand has no button to press.
    focus() {
      /** @type {any} */ (titleNode)?.focus?.();
    },
    hide() {
      closed = true;
      wipeSecret();
    },
  };
}

/**
 * The offers of the tab the popup is about, above the vault. Nothing is shown when there are none.
 *
 * @param {{
 *   texts: Texts,
 *   flow: OfferFlow,
 *   tabId: number | null,
 *   now?: () => number,
 *   onChange?: () => void,
 * }} deps `onChange`: an offer was answered (the list of the vault may have a new item)
 * @returns {{ root: HTMLElement, reload: (automatic?: boolean) => Promise<number>, refresh: () => Promise<number | null>, loaded: Promise<number>, focus: () => void, hide: () => void }}
 */
export function createOfferSection({ texts, flow, tabId, now = () => Date.now(), onChange = () => {} }) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const root = el("div", { class: "ff-offers", "data-role": "offers", "data-feature": "save", hidden: true });
  /** The reason a refused shortcut or menu click left on the tab, kept for as long as this popup is open. @type {string | null} */
  let notice = null;
  /** @type {Array<ReturnType<typeof createOfferCard>>} */
  let cards = [];
  /** The ids of the offers the cards show now. @type {string[]} */
  let shown = [];

  function hide() {
    for (const card of cards) card.hide();
    cards = [];
  }

  /** Reads the offers again and shows one card for each; resolves with how many there are. @returns {Promise<number>} */
  async function reload(automatic = false) {
    hide();
    if (tabId === null) {
      root.hidden = true;
      return 0;
    }
    const found = await flow.list(tabId, automatic);
    if (!found.ok) {
      root.hidden = true;
      return 0;
    }
    if (found.notice !== null) notice = found.notice;
    shown = found.offers.map((o) => o.offerId);
    /** @type {HTMLElement[]} */
    const parts = [];
    if (notice !== null) {
      parts.push(
        el(
          "div",
          { class: "ff-notice ff-offer-notice", role: "status", "data-role": "refusal-notice", "data-reason": notice, "data-feature": "save" },
          el("p", null, texts.t("offer.notice.title")),
          el("p", { "data-role": "refusal-reason" }, texts.t(actionErrorKey(notice))),
        ),
      );
    }
    cards = found.offers.map((offer) => createOfferCard({ texts, flow, offer, now, onClosed: () => onChange() }));
    parts.push(...cards.map((c) => c.root));
    mount(root, ...parts);
    root.hidden = parts.length === 0;
    await Promise.all(cards.map((c) => c.loaded));
    return found.offers.length;
  }

  /**
   * The popup is open and the background may have a new offer for the page (one that arrived while the popup was showing:
   * the browser cannot open a popup that is open already). Only an offer that is not on a card yet, or a new refusal
   * notice, builds the cards again; a card the user works on is left alone, and so is one that shows its answer.
   * Resolves with the number of offers after a rebuild, or null when nothing changed.
   * @returns {Promise<number | null>}
   */
  async function refresh() {
    if (tabId === null) return null;
    const found = await flow.list(tabId, true);
    if (!found.ok) return null;
    const fresh = found.offers.some((o) => !shown.includes(o.offerId));
    if (found.notice !== null) notice = found.notice;
    if (!fresh && found.notice === null) return null;
    return reload(true);
  }

  const loaded = reload();
  return {
    root,
    reload,
    refresh,
    loaded,
    focus: () => cards[0]?.focus(),
    hide,
  };
}
