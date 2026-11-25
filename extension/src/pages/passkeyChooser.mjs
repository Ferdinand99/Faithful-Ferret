// The chooser window's page (the `passkeys` feature; design document § 9.4 and § 10.3.3): what a person sees and presses when a
// website asks for a passkey and Ferret is the provider. The steps and the cleaning of the website's texts are in
// passkeyFlow.mjs; this file builds the page with `el()` (no markup from strings, ever).
//
// What the window shows, top to bottom:
//   1. the site: its host as the core says it (and its exact address when that is more), and the RP ID the passkeys are tied to (each left to
//      right, in isolation). This is the identity. Nothing a website wrote ever stands in its place;
//   2. what the website wrote, apart, under a label that says whose it is and that Ferret did not check it (the name it calls
//      itself, the user name and display name of the account), each in `<bdi>` and cleaned of control and direction characters;
//   3. Ferret's choices, first: for `get` the passkeys Ferret has for this exact RP ID (or "No Ferret passkey for this website"
//      with the browser as the clear way on, so the website cannot tell a miss from a refusal); for `create` a new item or an
//      item to add to (and a note when Ferret already has a passkey for the account);
//   4. beside them: the browser (Windows Hello, Touch ID, a phone or a security key), "Never on this site" and Cancel.
//
// What makes the window safe to open under a person's hand (design § 10.3.3, as the offer card):
//   - there is no form and no default button, the focus starts on the heading, and Enter does nothing in a field;
//   - a click counts only when the person made it (`isTrusted`) and only 400 ms after the window got the focus or its content
//     changed (a new list, a new step), not just after it was made. The window shows it is guarded while that runs;
//   - nothing is sent but the request's id and the choice: no password, key, user name or text of the website.
// The window claims neither "user present" nor "user verified". The click is the background's evidence of the first; the second
// comes from a recent unlock or the verification step, which has its place in the window (`passkey-verify`) and is built later.
//
// A locked vault is unlocked here with U3's own parts (master password, PIN, passkey window); that counts as an unlock for the
// background. Every field is emptied when a choice is sent, when the window closes and when the vault locks.

import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { field } from "./page.mjs";
import { chooserErrorKey, createGuard, defaultItemName, GUARD_MS, isGone, POLL_MS } from "./passkeyFlow.mjs";
import { createPinUnlockPart } from "./pinUnlockView.mjs";
import { UiError } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {import("./passkeyFlow.mjs").View} View */

/** The feature mark on every control of the window (the build's checks look for it). */
const FEATURE = Object.freeze({ "data-feature": "passkeys" });

/** How long the window stays after an answer (milliseconds), so the person sees what happened. */
export const CLOSE_AFTER_MS = 600;

/** The longest item name the window sends. */
const NAME_MAX = 200;

/** @param {unknown} reason */
const reasonKey = (reason) => `session.error.${typeof reason === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(reason) ? reason : "unknown"}`;

/**
 * @param {{
 *   texts: Texts,
 *   backend: ReturnType<typeof import("./passkeyFlow.mjs").createChooserBackend>,
 *   unlock?: ReturnType<typeof import("./popupFlow.mjs").createPopupFlow> | null,
 *   now?: () => number,
 *   schedule?: (fn: () => void, ms: number) => unknown,
 *   cancel?: (handle: any) => void,
 *   closeWindow?: () => void,
 *   formatDate?: (ms: number) => string,
 *   pollMs?: number,
 * }} deps
 *   `unlock`: the popup's flow, for a vault that is locked (null: only the master password is offered through it, so nothing).
 *   `now`, `schedule`, `cancel`: the clock and the timers (the tests set them). `closeWindow`: closes this window.
 * @returns {{ root: HTMLElement, loaded: Promise<void>, focus: () => void, touch: () => void, focused: () => void, refresh: () => Promise<void>, wipe: () => void, stop: () => void }}
 */
export function createChooser({
  texts,
  backend,
  unlock = null,
  now = () => Date.now(),
  schedule = (fn, ms) => setTimeout(fn, ms),
  cancel = (handle) => clearTimeout(handle),
  closeWindow = () => {},
  formatDate = (ms) => new Date(ms).toISOString().slice(0, 10),
  pollMs = POLL_MS,
}) {
  if (!FEATURES.passkeys) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  const guard = createGuard({ now });
  const root = el("section", { class: "ff-chooser", "data-role": "passkey-chooser", "aria-labelledby": "ff-pk-title", ...FEATURE });

  /** @type {View | null} */
  let view = null;
  let closed = false;
  let busy = false;
  /** What the person has typed that is not sent yet: emptied by `wipe`. */
  let nameDraft = "";
  let folderDraft = "";
  /** The fields the vault's unlock reads (emptied by `wipe`). @type {Array<HTMLInputElement>} */
  let secrets = [];
  /** What the unlock part must do when the window is wiped. @type {(() => void) | null} */
  let teardown = null;
  /** @type {HTMLElement | null} */
  let titleNode = null;
  /** The line the window speaks errors through. @type {HTMLElement | null} */
  let alertNode = null;
  /** The line that says a new passkey is being saved with the server. @type {HTMLElement | null} */
  let savingNode = null;
  /** The timers: the guard's end, the poll, the close. @type {unknown} */
  let guardTimer = null;
  /** @type {unknown} */
  let pollTimer = null;
  /** The content that is on screen, as text: the poll builds the window again only when it changed. */
  let shownSignature = "";
  /** Counts the builds, so an answer for a window that is gone is dropped. */
  let build = 0;

  // ------------------------------------------------------------ small pieces

  /** @param {string} value */
  const bdi = (value) => el("bdi", { "data-site-text": "" }, value);
  /** A name or address that is read left to right whatever the text around it. @param {string} value */
  const ltr = (value) => el("bdi", { dir: "ltr", class: "ff-host" }, value);

  /** @param {Record<string, string | number | boolean | null>} attrs @param {string} label @param {() => void | Promise<void>} run */
  function action(attrs, label, run) {
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", ...attrs, ...FEATURE }, label));
    button.addEventListener("click", (event) => {
      // A click counts only when the person made it, after the guard, and while nothing else is being answered.
      if (busy || closed || !guard.accepts(/** @type {any} */ (event))) return;
      void run();
    });
    return button;
  }

  /** @param {string | null} key @param {Record<string, string | number>} [vars] */
  function say(key, vars = {}) {
    if (alertNode === null) return;
    alertNode.textContent = key === null ? "" : t(key, vars);
    alertNode.hidden = key === null;
  }

  /** Disables or enables every control while a choice is on its way. @param {boolean} on */
  function holding(on) {
    busy = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
    for (const node of root.querySelectorAll?.("button, input, select") ?? []) {
      if (on) node.setAttribute("disabled", "");
      else node.removeAttribute("disabled");
    }
  }

  /** Empties what the person typed and what is held for the vault's unlock. */
  function wipe() {
    nameDraft = "";
    folderDraft = "";
    for (const input of secrets) input.value = "";
    secrets = [];
    teardown?.();
    teardown = null;
  }

  function stop() {
    closed = true;
    if (guardTimer !== null) cancel(guardTimer);
    if (pollTimer !== null) cancel(pollTimer);
    guardTimer = null;
    pollTimer = null;
    wipe();
  }

  /** The 400 ms start again: the focus came to the window, or what it shows changed. */
  function touch() {
    guard.touch();
    root.setAttribute("data-guarded", "1");
    if (guardTimer !== null) cancel(guardTimer);
    guardTimer = schedule(() => {
      guardTimer = null;
      root.removeAttribute("data-guarded");
    }, GUARD_MS);
  }

  // ------------------------------------------------------------ the parts

  /**
   * The title row: the small mark and the heading. The heading takes the focus (programmatically, never shown as a ring) so a
   * screen reader starts there.
   * @param {string} key
   */
  function heading(key) {
    titleNode = el("h1", { id: "ff-pk-title", class: "ff-pk-title", tabindex: "-1", "data-role": "passkey-title" }, t(key));
    return el("div", { class: "ff-pk-head" }, el("span", { class: "ff-mark", "aria-hidden": "true" }), titleNode);
  }

  /**
   * The site: its identity as the core says it, in two lines. The host (bold) and "Passkey for <RP ID>", with the exact address
   * (its A-label form) added only when it is more than \`https://\` and the host.
   * @param {View} v
   */
  function siteBlock(v) {
    const site = v.site;
    if (site === null) {
      // The vault is locked: the core cannot say the site yet. What the browser gave (the calling frame's origin) is shown.
      return el(
        "section",
        { class: "ff-pk-site", "data-role": "passkey-site", "aria-label": t("passkeys.site.label") },
        el("p", { class: "ff-pk-host", "data-role": "passkey-origin", dir: "ltr" }, ltr(v.origin)),
      );
    }
    const aLabelRp = site.rpIdUnicode !== site.rpId ? el("span", { class: "ff-pk-ascii" }, " (", ltr(site.rpId), ")") : null;
    const plain = site.origin === `https://${site.hostUnicode}`;
    return el(
      "section",
      { class: "ff-pk-site", "data-role": "passkey-site", "aria-label": t("passkeys.site.label") },
      el("p", { class: "ff-pk-host", "data-role": "passkey-host", dir: "ltr" }, ltr(site.hostUnicode)),
      plain ? null : el("p", { class: "ff-hint ff-pk-origin", "data-role": "passkey-origin" }, ltr(site.origin)),
      el("p", { class: "ff-pk-rp", "data-role": "passkey-rp-id" }, t("passkeys.site.rp"), " ", ltr(site.rpIdUnicode), aLabelRp),
    );
  }

  /**
   * What the website wrote: the name it calls itself and, for a new passkey, the account's user name and display name. Apart
   * from the site, under a label that says whose it is. Nothing here is an identity.
   * @param {View} v
   */
  function siteTexts(v) {
    /** @type {Array<[string, string, string]>} */
    const rows = [];
    if (v.rpName !== "") rows.push(["rp-name", t("passkeys.claims.name"), v.rpName]);
    if (v.kind === "create" && v.userName !== "") rows.push(["user-name", t("passkeys.claims.user_name"), v.userName]);
    if (v.kind === "create" && v.displayName !== "" && v.displayName !== v.userName) rows.push(["display-name", t("passkeys.claims.display_name"), v.displayName]);
    if (rows.length === 0) return null;
    // One line for each text; a longer one ends with an ellipsis and has its full text in the title.
    return el(
      "section",
      { class: "ff-pk-claims", "data-role": "passkey-site-texts", "aria-label": t("passkeys.claims.label") },
      el("p", { class: "ff-pk-eyebrow" }, t("passkeys.claims.label")),
      el(
        "dl",
        { class: "ff-pk-claim-list" },
        ...rows.flatMap(([role, label, value]) => [el("dt", null, label), el("dd", { "data-role": `passkey-${role}` }, el("bdi", { "data-site-text": "", title: value }, value))]),
      ),
    );
  }

  /** @param {View} v */
  function foreignNote(v) {
    return v.foreign ? el("p", { class: "ff-notice", "data-role": "passkey-foreign" }, t("passkeys.foreign")) : null;
  }

  /** The place the verification step builds into (the step itself comes with the background's verification). */
  function verifySlot(/** @type {View} */ v) {
    return el(
      "div",
      { class: "ff-pk-verify", "data-role": "passkey-verify", "aria-live": "polite" },
      v.recent ? el("p", { class: "ff-hint", "data-role": "passkey-recent" }, t("passkeys.verify.recent")) : null,
    );
  }

  /** @param {{ itemId: string, name: string, userName: string }} row @param {string} extra @param {string} verb @param {string} role @param {() => void | Promise<void>} run */
  function itemRow(row, extra, verb, role, run) {
    const name = row.name !== "" ? bdi(row.name) : el("span", { class: "ff-pk-none" }, t("passkeys.unnamed"));
    const user = row.userName !== "" ? bdi(row.userName) : el("span", { class: "ff-pk-none" }, t("passkeys.no_username"));
    const button = action(
      { class: "ff-pk-row", "data-role": role, "data-item": row.itemId },
      "",
      run,
    );
    // The user name and the extra word (the date, "same user name") share one muted line.
    button.append(
      el(
        "span",
        { class: "ff-pk-row-main" },
        el("span", { class: "ff-pk-row-name" }, name),
        el("span", { class: "ff-pk-row-sub" }, user, extra !== "" ? ` · ${extra}` : null),
      ),
      el("span", { class: "ff-pk-row-go", "aria-hidden": "true" }, verb),
    );
    return button;
  }

  /**
   * The choices beside Ferret's: the browser (the clear way on when Ferret has nothing), then one row with "Never on this site"
   * and Cancel, then the explanations in one disclosure. "Never" is left out while the vault is locked: the core says the RP ID
   * it would keep only with the vault open.
   * @param {View} v @param {string[]} [notes] the i18n keys of the explanations that belong to this window, before the common ones
   */
  function others(v, notes = []) {
    const browserLabel = v.kind === "get" ? t("passkeys.browser.get") : t("passkeys.browser.new");
    const primary = v.state === "ready" && (v.kind === "get" ? v.candidates.length === 0 : !v.online);
    const browserButton = action({ class: primary ? "ff-button ff-primary" : "ff-button", "data-role": "passkey-browser" }, browserLabel, () =>
      send(() => backend.browser(), "passkeys.done.browser"),
    );
    const never =
      v.state === "locked" ? null : action({ class: "ff-pk-link", "data-role": "passkey-never" }, t("passkeys.never"), () => send(() => backend.never(), "passkeys.done.never"));
    const cancelButton = action({ class: "ff-pk-link", "data-role": "passkey-cancel" }, t("passkeys.cancel"), () => send(() => backend.cancel(), "passkeys.done.cancel"));
    const keys = [...notes, "passkeys.more.browser", ...(v.state === "locked" ? [] : ["passkeys.more.never"])];
    return el(
      "div",
      { class: "ff-pk-others", "data-role": "passkey-others" },
      browserButton,
      el("div", { class: "ff-pk-foot" }, never, cancelButton),
      el(
        "details",
        { class: "ff-pk-more", "data-role": "passkey-more" },
        el("summary", null, t("passkeys.more")),
        ...keys.map((key) => el("p", { class: "ff-hint" }, t(key))),
      ),
    );
  }

  /** @param {View} v */
  function getParts(v) {
    const list = v.candidates;
    const choose = (/** @type {import("./passkeyFlow.mjs").Candidate} */ c) => () => send(() => backend.choose({ kind: "get", itemId: c.itemId }), "passkeys.done.used");
    const ferret =
      list.length === 0
        ? el(
            "section",
            { class: "ff-pk-ferret ff-pk-empty", "data-role": "passkey-ferret", "data-count": "0" },
            el("h2", { class: "ff-pk-h2", "data-role": "passkey-none" }, t("passkeys.get.none")),
            el("p", { class: "ff-hint" }, t("passkeys.get.none_help")),
          )
        : el(
            "section",
            { class: "ff-pk-ferret", "data-role": "passkey-ferret", "data-count": String(list.length), role: "group", "aria-labelledby": "ff-pk-ferret-title" },
            el("h2", { class: "ff-pk-h2", id: "ff-pk-ferret-title" }, list.length === 1 ? t("passkeys.get.one") : t("passkeys.get.many")),
            el(
              "div",
              { class: "ff-pk-rows", "data-role": "passkey-candidates", tabindex: list.length > 3 ? "0" : null },
              // The date shows only when there is more than one passkey to tell apart.
              ...list.map((c) => itemRow(c, list.length > 1 && c.created !== null ? formatDate(c.created) : "", t("passkeys.get.use"), "passkey-candidate", choose(c))),
            ),
          );
    return [ferret, verifySlot(v), others(v, list.length === 0 ? ["passkeys.more.private"] : [])];
  }

  /** @param {View} v */
  function createParts(v) {
    if (!v.online) {
      // Nothing is saved without the server (design UK111): said before any verification, the browser is the way on.
      return [el("p", { class: "ff-notice", role: "status", "data-role": "passkey-offline" }, t("passkeys.make.offline")), others(v)];
    }
    const name = field({ id: "ff-pk-name", label: t("passkeys.make.name"), role: "passkey-name", autocomplete: "off" });
    name.row.classList.add("ff-pk-name");
    name.input.setAttribute("maxlength", String(NAME_MAX));
    name.input.value = nameDraft !== "" ? nameDraft : defaultItemName(v.site?.hostUnicode ?? "");
    nameDraft = name.input.value;
    name.input.addEventListener("input", () => {
      nameDraft = name.input.value;
    });
    // Enter in a field does nothing: there is no form and no default button.
    name.input.addEventListener("keydown", noEnter);
    secrets.push(name.input);
    /** @type {HTMLSelectElement | null} */
    let folder = null;
    let folderRow = null;
    if (v.folders.length > 0) {
      folder = /** @type {HTMLSelectElement} */ (
        el(
          "select",
          { id: "ff-pk-folder", class: "ff-input", "data-role": "passkey-folder" },
          el("option", { value: "" }, t("passkeys.make.no_folder")),
          ...v.folders.map((f) => el("option", { value: f.id, selected: f.id === folderDraft }, f.name)),
        )
      );
      folder.value = folderDraft;
      folder.addEventListener("change", () => {
        folderDraft = /** @type {HTMLSelectElement} */ (folder).value;
      });
      folderRow = el("div", { class: "ff-field ff-pk-folder" }, el("label", { for: "ff-pk-folder", class: "ff-label" }, t("passkeys.make.folder")), folder);
    }
    const make = action({ class: "ff-button ff-primary", "data-role": "passkey-create-new" }, t("passkeys.make.make"), () => {
      const chosen = name.input.value.trim();
      if (chosen === "") {
        say("passkeys.error.name_required");
        name.input.focus();
        return;
      }
      const folderId = folder !== null && folder.value !== "" ? folder.value : null;
      return send(() => backend.choose({ kind: "create", mode: "new", name: chosen, folderId }), "passkeys.done.created");
    });
    // Name and folder share a row; the box has no visible heading (the button says what it does) but a name for a screen reader.
    const fresh = el(
      "section",
      { class: "ff-pk-ferret", "data-role": "passkey-new", role: "group", "aria-label": t("passkeys.make.new") },
      el("div", { class: "ff-pk-namerow" }, name.row, folderRow),
      make,
    );
    const attach =
      v.targets.length === 0
        ? null
        : el(
            "section",
            { class: "ff-pk-ferret", "data-role": "passkey-attach", role: "group", "aria-labelledby": "ff-pk-attach-title" },
            el("h2", { class: "ff-pk-h2", id: "ff-pk-attach-title" }, t("passkeys.make.attach")),
            el(
              "div",
              { class: "ff-pk-rows", "data-role": "passkey-targets", tabindex: v.targets.length > 3 ? "0" : null },
              ...v.targets.map((target) =>
                itemRow(target, target.sameUser ? t("passkeys.make.same_user") : "", t("passkeys.make.add"), "passkey-target", () =>
                  send(() => backend.choose({ kind: "create", mode: "attach", itemId: target.itemId }), "passkeys.done.added"),
                ),
              ),
            ),
          );
    const existing =
      v.existing === null
        ? null
        : el("p", { class: "ff-notice", role: "status", "data-role": "passkey-existing" }, t("passkeys.make.existing", { item: v.existing.name !== "" ? v.existing.name : t("passkeys.unnamed") }));
    return [existing, fresh, attach, verifySlot(v), others(v, v.targets.length > 0 ? ["passkeys.more.attach"] : [])];
  }

  /**
   * Enter does nothing in a field of the window: no form to submit, no default button.
   * @param {any} event
   */
  function noEnter(event) {
    if (event?.key === "Enter") event.preventDefault();
  }
  /** The roles of the forms that unlock the vault: typing a secret there is not a choice, and Enter may submit it. */
  const UNLOCK_FORMS = ["passkey-unlock-form", "pin-unlock-form"];
  /** @param {any} node */
  const inUnlockForm = (node) => {
    for (let at = node; at; at = at.parentNode) if (UNLOCK_FORMS.includes(at.getAttribute?.("data-role"))) return true;
    return false;
  };
  root.addEventListener("keydown", (/** @type {any} */ event) => {
    if (event?.key === "Enter" && event.target?.tagName !== "BUTTON" && !inUnlockForm(event.target)) event.preventDefault();
  });

  // ------------------------------------------------------------ a locked vault

  /** @param {View} v */
  function lockedParts(v) {
    const password = field({ id: "ff-pk-password", label: t("session.password"), role: "passkey-password", type: "password", autocomplete: "current-password" });
    const secretKey = field({ id: "ff-pk-sk", label: t("session.sk.code"), role: "passkey-sk", autocomplete: "off" });
    secretKey.row.hidden = true;
    secrets.push(password.input, secretKey.input);
    const error = el("p", { class: "ff-error", role: "alert", "data-role": "passkey-unlock-error", hidden: true });
    const submit = el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "passkey-unlock", ...FEATURE }, t("session.unlock.submit"));
    const form = el("form", { class: "ff-form", "data-role": "passkey-unlock-form", ...FEATURE }, password.row, secretKey.row, submit, error);
    const mine = build;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (unlock === null || busy || closed) return;
      error.hidden = true;
      const fields = { password: password.input.value, secretKey: secretKey.input.value };
      // The fields are emptied before the request goes out, and again when the answer comes.
      password.input.value = "";
      secretKey.input.value = "";
      submit.setAttribute("disabled", "");
      form.setAttribute("aria-busy", "true");
      try {
        const { result } = await unlock.unlock(fields);
        if (mine !== build) return;
        if (result.ok) {
          await reload();
          return;
        }
        if (result.reason === "sk_required") secretKey.row.hidden = false;
        error.textContent = t(reasonKey(result.reason));
        error.hidden = false;
      } catch (failure) {
        if (mine !== build) return;
        error.textContent = t(reasonKey(failure instanceof UiError ? failure.code : "unknown"));
        error.hidden = false;
      } finally {
        submit.removeAttribute("disabled");
        form.setAttribute("aria-busy", "false");
      }
      password.input.focus();
    });
    const parts = [form];
    if (unlock !== null && FEATURES.unlock) {
      const flow = unlock;
      void flow.pinPolicy().then((offer) => {
        if (offer === null || mine !== build || closed) return;
        const usePin = el("button", { type: "button", class: "ff-button", "data-role": "passkey-use-pin", ...FEATURE }, t("unlock.pin.use_pin"));
        /** @type {ReturnType<typeof createPinUnlockPart>} */
        const pin = createPinUnlockPart({
          texts,
          flow,
          offer,
          onDone: () => void reload(),
          onUseMaster: () => {
            pin?.root.setAttribute("hidden", "");
            form.hidden = false;
            password.input.focus();
          },
          onEnded: (message) => {
            pin?.wipe();
            pin?.root.setAttribute("hidden", "");
            usePin.setAttribute("hidden", "");
            form.hidden = false;
            error.textContent = message;
            error.hidden = false;
            password.input.focus();
          },
        });
        if (pin === null) return;
        usePin.addEventListener("click", () => {
          password.input.value = "";
          secretKey.input.value = "";
          form.hidden = true;
          pin.root.removeAttribute("hidden");
          pin.focus();
        });
        form.before(pin.root);
        form.append(usePin);
        const previous = teardown;
        teardown = () => {
          previous?.();
          pin.wipe();
        };
        // The PIN part takes the master password's place, but not the focus: the window opens under the person's hand, and what
        // they type must not land in a field before they chose to click it.
        if (password.input.value === "" && secretKey.input.value === "") {
          form.hidden = true;
        } else {
          pin.root.setAttribute("hidden", "");
        }
      });
      void flow.passkeyOffer().then((offered) => {
        if (!offered || mine !== build || closed) return;
        const passkeyError = el("p", { class: "ff-error", role: "alert", "data-role": "passkey-unlock-passkey-error", hidden: true });
        const passkeyButton = el("button", { type: "button", class: "ff-button", "data-role": "passkey-unlock-passkey", ...FEATURE }, t("passkey.button"));
        passkeyButton.addEventListener("click", async () => {
          passkeyError.hidden = true;
          // The unlock window opens; the vault opens there, and this window finds it open by itself (the poll reads the view while locked).
          if (!(await flow.openPasskeyWindow())) {
            passkeyError.textContent = t("passkey.error.prf_unavailable");
            passkeyError.hidden = false;
          }
        });
        form.after(el("div", { class: "ff-actions", "data-role": "passkey-unlock-passkey-row" }, passkeyButton, passkeyError));
      });
    }
    // The site is not shown while the vault is locked: the core says it only with the vault open. What is known is said plainly.
    return [siteBlock(v), foreignNote(v), ...parts, others(v)];
  }

  // ------------------------------------------------------------ building, sending, ending

  /** What decides whether the window must be built again: the content, not the person's typing. @param {View} v */
  const signature = (v) => JSON.stringify({ ...v, folders: v.folders.map((f) => f.id) });

  function render() {
    if (view === null) return;
    build += 1;
    secrets = [];
    teardown?.();
    teardown = null;
    touch();
    shownSignature = signature(view);
    alertNode = el("p", { class: "ff-error", role: "alert", tabindex: "-1", "data-role": "passkey-error", hidden: true });
    savingNode = el("p", { class: "ff-hint", role: "status", "data-role": "passkey-saving", hidden: true }, t("passkeys.make.saving"));
    const v = view;
    const key = v.state === "locked" ? "passkeys.title.locked" : v.kind === "get" ? "passkeys.title.get" : "passkeys.title.make";
    const parts =
      v.state === "locked"
        ? lockedParts(v)
        : [siteBlock(v), siteTexts(v), foreignNote(v), ...(v.kind === "get" ? getParts(v) : createParts(v))];
    root.setAttribute("data-kind", v.kind);
    root.setAttribute("data-state", v.state);
    root.setAttribute("aria-busy", "false");
    busy = false;
    mount(root, heading(key), ...(/** @type {HTMLElement[]} */ ([...parts, savingNode, alertNode].filter((part) => part !== null))));
  }

  /** The request is over: the window says so and closes. @param {string} key */
  function ended(key) {
    stop();
    mount(root, heading(key));
    root.setAttribute("data-state", "ended");
    root.setAttribute("aria-busy", "false");
    root.removeAttribute("data-guarded");
    schedule(() => closeWindow(), CLOSE_AFTER_MS);
  }

  /**
   * The request is over (answered, aborted, timed out or the page moved on), or the core refused the site: the window says so and
   * closes. @param {string} reason
   */
  function finished(reason) {
    ended(reason === "security_error" || reason === "type_error" || reason === "site_refused" ? chooserErrorKey(reason) : "passkeys.gone");
  }

  /**
   * Sends a choice. The fields are emptied before it goes out. An answer closes the window; a refusal says why and leaves the
   * window as it was, unless the request is over (it closes) or the vault locked (it shows the unlock).
   * @param {() => Promise<{ ok: true } | { ok: false, reason: string }>} run @param {string} doneKey
   */
  async function send(run, doneKey) {
    if (busy || closed) return;
    say(null);
    holding(true);
    // A new passkey is saved with the server before the website gets it (it may take a while when the connection is poor).
    const saving = doneKey === "passkeys.done.created" || doneKey === "passkeys.done.added";
    if (saving && savingNode !== null) savingNode.hidden = false;
    const mine = build;
    const kept = { name: nameDraft, folder: folderDraft };
    /** @type {{ ok: true } | { ok: false, reason: string }} */
    let outcome;
    try {
      outcome = await run();
    } catch {
      outcome = { ok: false, reason: "internal_error" };
    }
    if (closed || mine !== build) return;
    if (savingNode !== null) savingNode.hidden = true;
    if (outcome.ok) {
      wipe();
      ended(doneKey);
      // The window closes as soon as the background has answered the page: the done text is only what is seen meanwhile.
      return;
    }
    holding(false);
    if (isGone(outcome.reason)) {
      finished(outcome.reason);
      return;
    }
    if (outcome.reason === "vault_locked") {
      wipe();
      await reload();
      return;
    }
    nameDraft = kept.name;
    folderDraft = kept.folder;
    say(chooserErrorKey(outcome.reason));
    alertNode?.focus?.();
  }

  /** Reads the view again and builds the window from it. */
  async function reload() {
    const answer = await backend.view();
    if (closed) return;
    if (!answer.ok) {
      if (isGone(answer.reason)) finished(answer.reason);
      else {
        view = null;
        stop();
        mount(root, /** @type {HTMLElement} */ (heading("passkeys.title.error")), el("p", { class: "ff-error", role: "alert", "data-role": "passkey-error" }, t(chooserErrorKey(answer.reason))));
        schedule(() => closeWindow(), CLOSE_AFTER_MS * 3);
      }
      return;
    }
    const wasLocked = view?.state === "locked";
    view = answer.view;
    // A lock empties what was typed; an unlock starts clean.
    if (wasLocked || answer.view.state === "locked") nameDraft = "";
    render();
    titleNode?.focus?.();
  }

  /**
   * Reads the view again and builds the window only when what it shows changed (the content, not the person's typing). Used when
   * the window gets the focus again. It asks the core for the site, which is a use of the vault: not something to do on a timer.
   */
  async function refresh() {
    if (closed || busy) return;
    const answer = await backend.view();
    if (closed || busy) return;
    if (!answer.ok) {
      if (isGone(answer.reason)) finished(answer.reason);
      return;
    }
    if (signature(answer.view) === shownSignature) return;
    // A lock empties what was typed.
    if (answer.view.state === "locked" && view?.state !== "locked") wipe();
    view = answer.view;
    render();
  }

  /**
   * The poll: is the request still there? It asks the one message that does not count as a use of the vault (the background
   * closes the window itself on a lock, so the vault is not asked here and an open window does not keep it from locking).
   */
  async function poll() {
    pollTimer = null;
    if (closed) return;
    // While the window shows the unlock, it reads the view (no idle timer runs while the vault is locked): the vault may have been
    // opened somewhere else (the unlock window of a passkey, the popup), and this window must leave "Unlock Ferret" by itself.
    if (!busy && view?.state === "locked") {
      await refresh();
    } else if (!busy) {
      const answer = await backend.alive();
      if (closed) return;
      if (!answer.ok && isGone(answer.reason)) {
        finished(answer.reason);
        return;
      }
    }
    if (!closed) pollTimer = schedule(() => void poll(), pollMs);
  }

  /** The window got the focus (again): the 400 ms start again, and what it shows is read again. */
  function focused() {
    touch();
    void refresh();
  }

  /** @type {Promise<void>} */
  const loaded = (async () => {
    mount(root, /** @type {HTMLElement} */ (heading("passkeys.title.loading")));
    touch();
    await reload();
    if (!closed && pollMs > 0) pollTimer = schedule(() => void poll(), pollMs);
  })();

  return {
    root,
    loaded,
    // The focus starts on the heading: a window that opens under the person's hand has no control to press.
    focus() {
      titleNode?.focus?.();
    },
    touch,
    focused,
    refresh,
    wipe,
    stop,
  };
}
