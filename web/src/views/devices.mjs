// `#/devices`: the devices of the account. It lists the browsers with a session
// of the web vault (one row per browser) and the devices that signed in for
// tokens, such as the browser extension, with their name, kind, platform and
// when they were last seen. Each row but this browser's can be revoked; "Forget
// old devices" revokes the devices not seen for a week; "Revoke all" asks for
// the master password again first (spec Fase 1 § 4.6) and leaves only this
// browser signed in.
//
// The page says what revoking does and does not do (spec Fase 1 § 7.6): the
// device loses its access to the server at once and must sign in again, but it
// keeps what it has already stored. Only a full rotation of the vault's keys,
// which comes later, makes that useless.
//
// Nothing here is secret: the list holds names, kinds, platforms and times, and
// no token or key ever reaches the page. Every text is set with `textContent`,
// so a device name is shown as it is and never read as markup.
import { el, mount } from "../dom.mjs";
import { askConfirm, codeOf, formatMoment } from "./common.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/**
 * One row of the list, as the server sends it (`devices_res`).
 * @typedef {{ id: string, kind: "device" | "web", name: string, platform?: string, created_at: number, last_seen: number, current: boolean }} DeviceRow
 */

/** The platforms with a text of their own. */
const PLATFORMS = Object.freeze(["windows", "macos", "linux", "android", "ios", "chromeos", "other"]);

/** The error codes with a text under `devices.error.`. */
const ERRORS = Object.freeze([
  "bad_request", "busy", "forbidden", "network", "not_found", "reauth_required", "second_factor_required", "throttled", "unauthorized",
]);

/**
 * The text of an error. Only the code is used; the message of an error is never shown.
 * @param {Translate} t
 * @param {unknown} error
 */
export function devicesErrorText(t, error) {
  const code = codeOf(error);
  return t(ERRORS.includes(code) ? `devices.error.${code}` : "devices.error.unknown");
}

/**
 * @param {{
 *   t: Translate,
 *   load: () => Promise<{ devices: DeviceRow[], more?: number }>,
 *   revoke: (id: string) => Promise<unknown>,
 *   revokeAll: () => Promise<{ revoked: number }>,
 *   forgetOld: () => Promise<{ revoked: number }>,
 *   reauth: () => Promise<"ok" | "cancelled">,
 *   locale?: string,
 *   host?: HTMLElement,
 * }} options `load` reads the list; `revoke` revokes one row by its id; `revokeAll` and `forgetOld` revoke many;
 * `reauth` opens the dialog that asks for the master password again (`reauthDialog`) and answers how it ended.
 * `host` is where the confirmation dialog sits (the page itself by default).
 * @returns {HTMLElement}
 */
export function devicesView({ t, load, revoke, revokeAll, forgetOld, reauth, locale, host }) {
  const root = el("section", { class: "card devices-page", "data-role": "devices-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "devices-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "devices-error" });
  errorBox.hidden = true;
  const done = el("p", { class: "ok", role: "status", "data-role": "devices-done" });
  done.hidden = true;
  const list = el("ul", { class: "devices-list", "data-role": "devices-list" });
  const more = el("p", { class: "help", "data-role": "devices-more" });
  more.hidden = true;
  const forgetButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "devices-forget-old" }, t("devices.forget_old.button")));
  const revokeAllButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-danger", "data-role": "devices-revoke-all" }, t("devices.revoke_all.button")));
  const dialogHost = host ?? root;

  /** @type {HTMLButtonElement[]} */
  let rowButtons = [];
  /** @param {boolean} on */
  function busy(on) {
    for (const button of [forgetButton, revokeAllButton, ...rowButtons]) button.disabled = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
  }

  /** @param {unknown} error */
  function showError(error) {
    mount(errorBox, document.createTextNode(devicesErrorText(t, error)));
    errorBox.hidden = false;
  }

  /** @param {string} text */
  function showDone(text) {
    mount(done, document.createTextNode(text));
    done.hidden = false;
  }

  /**
   * @param {DeviceRow} row
   * @param {string | null} ownId the device id of this browser's own row
   */
  function rowView(row, ownId) {
    const isDevice = row.kind === "device";
    const name = row.name === "" ? t("devices.unnamed") : row.name;
    const kind = t(isDevice ? "devices.kind.device" : "devices.kind.web");
    const platform = isDevice && typeof row.platform === "string" && PLATFORMS.includes(row.platform) ? t(`devices.platform.${row.platform}`) : null;
    const seen = formatMoment(row.last_seen * 1000, locale);
    const since = formatMoment(row.created_at * 1000, locale);
    const facts = [kind, platform].filter((part) => part !== null).join(" · ");
    const item = el("li", { class: "devices-row", "data-role": "devices-row", "data-kind": row.kind, "data-current": row.current ? "true" : "false" },
      el("div", { class: "devices-name" },
        el("strong", { "data-role": "devices-name" }, name),
        row.current ? el("span", { class: "pill devices-current", "data-role": "devices-current" }, t("devices.current")) : null),
      el("p", { class: "devices-facts", "data-role": "devices-facts" }, facts),
      el("p", { class: "devices-seen", "data-role": "devices-seen" },
        seen === null ? t("devices.seen_unknown") : t("devices.seen", { time: seen }),
        since === null ? "" : ` · ${t("devices.since", { time: since })}`));
    if (row.current) {
      item.appendChild(el("p", { class: "help", "data-role": "devices-current-help" }, t("devices.current_help")));
      return item;
    }
    // Another session that carries this browser's device id: a browser chooses its id, so another one can claim it.
    if (row.kind === "web" && row.id === ownId) {
      item.appendChild(el("p", { class: "help devices-shares-id", "data-role": "devices-shares-id" }, t("devices.shares_id")));
    }
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "devices-revoke" }, t("devices.revoke.button")));
    button.addEventListener("click", async () => {
      errorBox.hidden = true;
      done.hidden = true;
      const sure = await askConfirm({ t, host: dialogHost, title: "devices.revoke.title", body: "devices.revoke.body", confirm: "devices.revoke.confirm", cancel: "devices.dialog.cancel", vars: { name } });
      if (!sure) return;
      busy(true);
      try {
        await revoke(row.id);
        showDone(t("devices.revoke.done", { name }));
      } catch (error) {
        showError(error);
      } finally {
        busy(false);
      }
      await refresh();
    });
    rowButtons.push(button);
    item.appendChild(el("div", { class: "actions" }, button));
    return item;
  }

  async function refresh() {
    mount(status, document.createTextNode(t("devices.loading")));
    /** @type {{ devices: DeviceRow[], more?: number }} */
    let answer;
    try {
      answer = await load();
    } catch (error) {
      mount(status, document.createTextNode(""));
      mount(list);
      showError(error);
      return;
    }
    mount(status, document.createTextNode(""));
    rowButtons = [];
    const ownId = answer.devices.find((row) => row.current)?.id ?? null;
    mount(list, ...answer.devices.map((row) => rowView(row, ownId)));
    if (answer.devices.length === 0) list.appendChild(el("li", { class: "help", "data-role": "devices-empty" }, t("devices.empty")));
    if (typeof answer.more === "number" && answer.more > 0) {
      mount(more, document.createTextNode(t("devices.more", { count: answer.more })));
      more.hidden = false;
    } else {
      more.hidden = true;
    }
  }

  forgetButton.addEventListener("click", async () => {
    errorBox.hidden = true;
    done.hidden = true;
    busy(true);
    try {
      const { revoked } = await forgetOld();
      showDone(t("devices.forget_old.done", { count: revoked }));
    } catch (error) {
      showError(error);
    } finally {
      busy(false);
    }
    await refresh();
  });

  revokeAllButton.addEventListener("click", async () => {
    errorBox.hidden = true;
    done.hidden = true;
    busy(true);
    try {
      // The master password again first: revoking every device is a sensitive operation.
      const answer = await reauth();
      if (answer !== "ok") return;
      const { revoked } = await revokeAll();
      showDone(t("devices.revoke_all.done", { count: revoked }));
    } catch (error) {
      showError(error);
    } finally {
      busy(false);
    }
    await refresh();
  });

  mount(root,
    el("h1", null, t("devices.heading")),
    el("p", { "data-role": "devices-intro" }, t("devices.intro")),
    el("div", { class: "devices-note", "data-role": "devices-what" },
      el("h2", null, t("devices.what.heading")),
      el("p", { "data-role": "devices-what-does" }, t("devices.what.does")),
      el("p", { "data-role": "devices-what-not" }, t("devices.what.does_not")),
      el("p", { "data-role": "devices-what-stolen" }, t("devices.what.stolen"))),
    status,
    errorBox,
    done,
    list,
    more,
    el("div", { class: "devices-many stack" },
      el("h2", null, t("devices.forget_old.heading")),
      el("p", null, t("devices.forget_old.body")),
      el("div", { class: "actions" }, forgetButton),
      el("h2", null, t("devices.revoke_all.heading")),
      el("p", null, t("devices.revoke_all.body")),
      el("div", { class: "actions" }, revokeAllButton)));
  void refresh();
  return root;
}
