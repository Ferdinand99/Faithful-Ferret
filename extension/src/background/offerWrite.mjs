// The write path of an offer to save or update a password (design document,
// sections 8.2 to 8.6 and 10.9): what a captured form means for the vault, and
// the one write the user's click on the offer makes.
//
// The sync (sync.mjs) makes one writer per unlock and hands it the sync engine;
// this is the only module of the extension's own code that calls the engine's
// `create` or `update` (a test of the built package checks it). It is given a
// captured form (`Capture`), which the background holds in its memory only; it
// keeps no capture itself and never hands one on.
//
// classify   Which items the capture is about, decided in the core with the
//            vault open. The candidates are the items whose saved addresses
//            match the frame's address by the fill rules (the core's
//            `match_page`). Passwords are compared inside the core
//            (`items_with_field_value` on the field with the id `password`,
//            fixed here and never taken from a caller); no password of an item
//            is ever read out. The captured user name is compared with each
//            item's user name, or its email field when it has no user name
//            (NFC, trimmed, lower case). The outcome is `none` (the item already
//            holds this user name and password), `update` (one item, by its user
//            name, by the current password of a change form, or because Ferret
//            filled that item's password into this document), `choose` (a list
//            the user picks from: never an automatic target) or `save`. Only an
//            item that matches by host or by its exact address can be a target:
//            an item that matches by its registrable domain alone is listed
//            apart (`domainOnly`, with its host) and is updated only when the
//            user picks it from that list. Items that are read only, damaged, in
//            quarantine, blocked, in conflict or missing on the server are never
//            targets. Items of another host that hold the same password are named
//            (at most three, with their hosts) as a warning.
// save       A new login: the web vault's field ids, labels and kinds, the
//            frame's origin as its address with host matching, and the folder
//            the user chose (none by default).
// update     The password of one item, and nothing else: every field the item
//            has is sent by its id alone (the core keeps its label, kind, value
//            and unknown keys), the password field gets the new value, and the
//            old password goes into the item's history in the core
//            (`keep_password_history`). The draft has no `folders`, `urls`,
//            `totp`, `notes` or any other key, so all of them stay. It is made
//            from the revision the classification saw: when the item has changed
//            since, the engine refuses it with `item_changed` and nothing is
//            written. The target is checked again here: it must still match the
//            frame by host or exact address (or by domain, when the user picked it
//            explicitly).
//
// A write goes into the engine's outbox first, so it is kept across a lock and
// a restart and sent when the sync can; `pending` says it has not reached the
// server yet.

import { clip } from "./match.mjs";

/** The id of the password field: the only field a captured password is compared with or written to. */
export const PASSWORD_FIELD = "password";

/** The web vault's labels of a new login's fields, by language (web/src/locales/<lang>/vault.json). */
export const FIELD_LABELS = Object.freeze({
  en: Object.freeze({ username: "User name", password: "Password" }),
  nb: Object.freeze({ username: "Brukernavn", password: "Passord" }),
});

/**
 * The language of a new item's labels, from the browser's languages, as the web vault picks its own: the first one it
 * has (Norwegian for `nb`, `no` and `nn`), English otherwise.
 * @param {readonly string[]} languages
 * @returns {"en" | "nb"}
 */
export function labelLanguage(languages) {
  for (const tag of languages ?? []) {
    const primary = String(tag).toLowerCase().split("-")[0];
    if (primary === "en") return "en";
    if (primary === "nb" || primary === "no" || primary === "nn") return "nb";
  }
  return "en";
}

/** The most items of other hosts a reuse warning names. */
export const MAX_REUSED = 3;

/** The most items a choice list or the list of domain matches holds. */
export const MAX_LISTED = 32;

/** How many items are opened at once. */
const BATCH = 64;

/** The kinds of form a capture comes from. */
const FORM_KINDS = Object.freeze(["login", "signup", "change", "reset"]);

/** Where a captured user name came from. */
const USERNAME_FROM = Object.freeze(["typed", "page", "identifier", "fill"]);

/** Where a user name is known, not guessed: typed, from an identifier step, or filled by Ferret. */
const SURE_USERNAME = Object.freeze(["typed", "identifier", "fill"]);

const MATCH_HOW = Object.freeze(["exact", "host", "domain"]);

const ITEM_ID = /^[0-9a-f]{32}$/;

/** The longest name and user name a reply carries. */
const MAX_TEXT = 256;

/** The errors that mean the vault is gone (a lock, a failed worker, a stopped engine). */
const LOCKED = Object.freeze(["vault_locked", "worker_failed", "stopped", "locked"]);

/** The error of this module: a short code. */
export class OfferWriteError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "OfferWriteError";
    this.code = code;
  }
}

/**
 * @typedef {{
 *   tabId: number, frameId: number, documentId?: string, frameUrl: string, origin: string, kind: string,
 *   username: string | null, usernameFrom: "typed" | "page" | "identifier" | "fill" | null,
 *   password: string, currentPassword: string | null, generated: boolean,
 * }} Capture a submitted form, held in the background's memory only
 * @typedef {{ a_label: string, unicode: string }} Host
 * @typedef {{ id: string, rev: number, name: string, username: string, how: string }} Target
 * @typedef {{
 *   action: "save" | "update" | "choose" | "none",
 *   targets: Target[],
 *   domainOnly: Array<{ id: string, rev: number, name: string, host: Host | null }>,
 *   reused: Array<{ name: string, host: Host | null }>,
 *   usernameFrom: Capture["usernameFrom"],
 * }} Classification
 * @typedef {{
 *   id: string, rev: number, name: string, username: string, urls: string[], folders?: string[],
 *   readOnly?: boolean, damaged?: boolean, quarantined?: boolean, blocked?: boolean, conflict?: boolean,
 *   missingOnServer?: boolean, pending?: boolean,
 * }} Summary the part of the sync engine's item summary this module reads
 * @typedef {{
 *   list(): Summary[],
 *   open(id: string): Promise<{ handle: number, view: any, close(): Promise<void> }>,
 *   create(draft: object): Promise<string>,
 *   update(id: string, draft: object, expectedRev: number): Promise<void>,
 * }} WriteEngine the part of the sync engine this module uses
 * @typedef {{ lookup(place: { tabId: number, frameId: number, documentId?: string, url: string, fieldKind: string }): string | null }} FillContextReader
 * @typedef {{ summary: Summary, how: string, name: string, via: "username" | "email" | null, samePassword: boolean, sameCurrent: boolean }} Hit
 */

/** @param {unknown} n */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** @param {unknown} s @param {number} max @returns {s is string} */
const isText = (s, max) => typeof s === "string" && s !== "" && s.length <= max;

/** A user name as two of them are compared: NFC, trimmed, lower case. @param {string} s */
const fold = (s) => s.normalize("NFC").trim().toLowerCase();

/** @param {unknown} error @returns {string} */
const codeOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" ? code : "internal";
};

/**
 * Checks a capture and returns a plain copy of the fields this module reads. A capture comes from the background's
 * own store; a wrong shape is a bug and refuses the call.
 * @param {unknown} capture
 * @returns {Capture}
 */
export function checkCapture(capture) {
  const c = /** @type {any} */ (capture);
  const ok =
    c !== null && typeof c === "object" && isIndex(c.tabId) && isIndex(c.frameId) &&
    (c.documentId === undefined || c.documentId === null || isText(c.documentId, 64)) &&
    isText(c.frameUrl, 8192) && /^https:\/\//i.test(c.frameUrl) && isText(c.origin, 300) && FORM_KINDS.includes(c.kind) &&
    (c.username === null || (typeof c.username === "string" && c.username.length <= 512)) &&
    (c.usernameFrom === null || USERNAME_FROM.includes(c.usernameFrom)) &&
    isText(c.password, 1024) &&
    (c.currentPassword === null || (typeof c.currentPassword === "string" && c.currentPassword.length <= 1024)) &&
    typeof c.generated === "boolean";
  if (!ok) throw new OfferWriteError("invalid_input");
  const username = c.username === null || c.username.trim() === "" ? null : c.username;
  return {
    tabId: c.tabId,
    frameId: c.frameId,
    ...(typeof c.documentId === "string" ? { documentId: c.documentId } : {}),
    frameUrl: c.frameUrl,
    origin: c.origin,
    kind: c.kind,
    username,
    usernameFrom: username === null ? null : c.usernameFrom,
    password: c.password,
    currentPassword: c.currentPassword === "" ? null : c.currentPassword,
    generated: c.generated,
  };
}

/**
 * Whether an item may be the target of a write: read-only, damaged, quarantined, blocked, conflicted and missing items
 * never are.
 * @param {Summary} s
 */
export const writable = (s) =>
  s.readOnly !== true && s.damaged !== true && s.quarantined !== true && s.blocked !== true && s.conflict !== true && s.missingOnServer !== true;

/**
 * The folders of the vault for the save card to offer: each name once (two names that differ only in case are one
 * folder; the first spelling is kept), sorted.
 * @param {Summary[]} summaries
 * @returns {string[]}
 */
export function folderNames(summaries) {
  /** @type {Map<string, string>} */
  const seen = new Map();
  for (const s of summaries) {
    for (const name of Array.isArray(s.folders) ? s.folders : []) {
      if (typeof name !== "string" || name === "") continue;
      const key = fold(name);
      if (!seen.has(key)) seen.set(key, name);
    }
  }
  return [...seen.values()].sort((a, b) => a.localeCompare(b)).slice(0, 500);
}

/**
 * The user name of an opened item as the write path compares it: its `username` field, or its `email` field when it
 * has no user name (an AliasVault import keeps the address there).
 * @param {any} view
 * @returns {{ name: string, via: "username" | "email" | null }}
 */
function nameOf(view) {
  /** @type {any[]} */
  const fields = Array.isArray(view?.fields) ? view.fields : [];
  const value = (/** @type {string} */ id) => {
    const field = fields.find((f) => f?.id === id);
    return typeof field?.value === "string" ? field.value : "";
  };
  const username = value("username");
  if (username.trim() !== "") return { name: username, via: "username" };
  const email = value("email");
  if (email.trim() !== "") return { name: email, via: "email" };
  return { name: "", via: null };
}

/**
 * The writer of one unlock.
 * @param {{
 *   engine: WriteEngine,
 *   liveClient: { vault: any },
 *   fillContext?: FillContextReader | null,
 *   now?: () => number,
 *   language?: string,
 * }} options `liveClient`: the core client of the vault that is open (every call of it is refused after a lock);
 *   `fillContext`: what Ferret filled where (fillContext.mjs); `now`: the clock (the fill context keeps its own, so
 *   nothing here reads it yet); `language`: the language of the labels of a new item's fields (the web vault's)
 */
export function createOfferWriter({ engine, liveClient, fillContext = null, now = Date.now, language = "en" }) {
  const labels = language === "nb" ? FIELD_LABELS.nb : FIELD_LABELS.en;
  const vault = liveClient.vault;

  /**
   * The capture's origin, read again by the core from the frame's address: it must be the one the capture names, and
   * https.
   * @param {Capture} c
   */
  async function originOf(c) {
    const origin = await vault.page_origin(c.frameUrl);
    if (origin !== c.origin || typeof origin !== "string" || !/^https:\/\//.test(origin)) throw new OfferWriteError("origin_changed");
    return origin;
  }

  /** How the core shows the host of an address, or null when it is no web address. @param {string} url @returns {Promise<Host | null>} */
  async function hostOf(url) {
    const shown = await Promise.resolve()
      .then(() => vault.display_host(url))
      .catch(() => null);
    if (!isText(shown?.a_label, 300) || !isText(shown?.unicode, 300)) return null;
    return { a_label: shown.a_label, unicode: shown.unicode };
  }

  /** The host of the first web address of an item, or null. @param {Summary} s */
  async function itemHost(s) {
    for (const url of Array.isArray(s.urls) ? s.urls : []) {
      if (typeof url !== "string" || !/^https?:\/\//i.test(url)) continue;
      const host = await hostOf(url);
      if (host !== null) return host;
    }
    return null;
  }

  /**
   * One pass over every item, in batches: which items match the frame and how, which hold the captured password, and
   * which hold the current password of a change form. Every handle opened is closed before this returns or throws.
   * @param {Capture} c
   * @returns {Promise<{ hits: Hit[], reused: Summary[] }>}
   */
  async function scan(c) {
    const items = engine.list().filter((s) => typeof s?.id === "string" && ITEM_ID.test(s.id) && s.damaged !== true && s.quarantined !== true);
    /** @type {Hit[]} */
    const hits = [];
    /** @type {Summary[]} */
    const reused = [];
    for (let at = 0; at < items.length; at += BATCH) {
      const batch = items.slice(at, at + BATCH);
      /** @type {Array<{ handle: number, view: any, close(): Promise<void>, summary: Summary }>} */
      const opened = [];
      try {
        const results = await Promise.allSettled(batch.map((s) => engine.open(s.id)));
        results.forEach((result, i) => {
          if (result.status === "fulfilled") opened.push({ ...result.value, close: result.value.close, summary: batch[i] });
        });
        if (results.some((r) => r.status === "rejected" && LOCKED.includes(codeOf(/** @type {PromiseRejectedResult} */ (r).reason)))) {
          throw new OfferWriteError("vault_locked");
        }
        if (opened.length === 0) continue;
        const handles = opened.map((o) => o.handle);
        const answer = await vault.match_page(c.frameUrl, handles);
        if (!Array.isArray(answer)) throw new OfferWriteError("internal");
        /** @type {Map<number, string>} */
        const how = new Map();
        for (const hit of answer) {
          const h = /** @type {any} */ (hit);
          if (MATCH_HOW.includes(h?.how)) how.set(h.handle, h.how);
        }
        // Compared inside the core, on the password field only; nothing of an item's password comes back.
        const same = new Set(await vault.items_with_field_value(handles, PASSWORD_FIELD, c.password));
        const current = c.currentPassword === null ? new Set() : new Set(await vault.items_with_field_value(handles, PASSWORD_FIELD, c.currentPassword));
        for (const o of opened) {
          const matched = how.get(o.handle);
          if (matched === undefined) {
            if (same.has(o.handle)) reused.push(o.summary);
            continue;
          }
          const { name, via } = nameOf(o.view);
          hits.push({ summary: o.summary, how: matched, name, via, samePassword: same.has(o.handle), sameCurrent: current.has(o.handle) });
        }
      } finally {
        await Promise.all(opened.map((o) => Promise.resolve().then(() => o.close()).catch(() => {})));
      }
    }
    return { hits, reused };
  }

  /** @param {Hit} h @param {string} how @returns {Target} */
  const targetOf = (h, how) => ({
    id: h.summary.id,
    rev: h.summary.rev,
    name: clip(String(h.summary.name ?? ""), MAX_TEXT),
    username: clip(h.name, MAX_TEXT),
    how,
  });

  /**
   * @param {Capture} capture
   * @returns {Promise<Classification>}
   */
  async function classify(capture) {
    const c = checkCapture(capture);
    await originOf(c);
    const { hits, reused } = await scan(c);
    const captured = c.username === null ? null : fold(c.username);
    /** @param {Hit} h */
    const sameName = (h) => captured !== null && h.name !== "" && fold(h.name) === captured;
    const strong = hits.filter((h) => h.how !== "domain" && writable(h.summary));

    /** @type {Classification["domainOnly"]} */
    const domainOnly = [];
    for (const h of hits.filter((x) => x.how === "domain" && writable(x.summary)).slice(0, MAX_LISTED)) {
      domainOnly.push({ id: h.summary.id, rev: h.summary.rev, name: clip(String(h.summary.name ?? ""), MAX_TEXT), host: await itemHost(h.summary) });
    }
    /** @type {Classification["reused"]} */
    const named = [];
    for (const s of [...reused].sort((a, b) => String(a.name).localeCompare(String(b.name))).slice(0, MAX_REUSED)) {
      named.push({ name: clip(String(s.name ?? ""), MAX_TEXT), host: await itemHost(s) });
    }

    /** @param {"save" | "update" | "choose" | "none"} action @param {Target[]} [targets] @returns {Classification} */
    const outcome = (action, targets = []) => ({ action, targets: targets.slice(0, MAX_LISTED), domainOnly, reused: named, usernameFrom: c.usernameFrom });
    /** @param {Hit} h */
    const byName = (h) => /** @type {string} */ (h.via ?? "username");

    // Already saved: an item for this page holds this password, with this user name (or with none, or none was typed).
    if (hits.some((h) => h.samePassword && (captured === null || h.name === "" || sameName(h)))) return outcome("none");

    const sure = captured !== null && SURE_USERNAME.includes(/** @type {string} */ (c.usernameFrom));

    // A change form: the item Ferret filled the current password from, or the item whose password is the current one.
    if (c.currentPassword !== null) {
      const filled = fillContext?.lookup({
        tabId: c.tabId, frameId: c.frameId, ...(c.documentId !== undefined ? { documentId: c.documentId } : {}), url: c.frameUrl, fieldKind: PASSWORD_FIELD,
      }) ?? null;
      const byFill = filled === null ? undefined : strong.find((h) => h.summary.id === filled);
      if (byFill !== undefined) return outcome("update", [targetOf(byFill, "filled")]);
      const byCurrent = strong.filter((h) => h.sameCurrent);
      if (byCurrent.length === 1) return outcome("update", [targetOf(byCurrent[0], "current_password")]);
      if (byCurrent.length > 1) {
        const narrowed = sure ? byCurrent.filter(sameName) : [];
        if (narrowed.length === 1) return outcome("update", [targetOf(narrowed[0], byName(narrowed[0]))]);
        return outcome("choose", byCurrent.map((h) => targetOf(h, "current_password")));
      }
    }

    // A user name the page put there, or none at all, never picks one of several items.
    if (!sure && strong.length > 1) return outcome("choose", strong.map((h) => targetOf(h, h.via ?? "list")));
    if (captured === null) return strong.length === 1 ? outcome("update", [targetOf(strong[0], "only")]) : outcome("save");
    const matching = strong.filter(sameName);
    if (matching.length === 1) return outcome("update", [targetOf(matching[0], byName(matching[0]))]);
    if (matching.length > 1) return outcome("choose", matching.map((h) => targetOf(h, byName(h))));
    return outcome("save");
  }

  /**
   * Whether the write has not reached the server yet (it waits in the outbox).
   * @param {string} id
   */
  const pendingOf = (id) => engine.list().find((s) => s.id === id)?.pending !== false;

  /**
   * A new login from the capture.
   * @param {Capture} capture
   * @param {{ name: string, username: string | null, folder: string | null }} choice what the user chose on the card
   * @returns {Promise<{ id: string, pending: boolean }>}
   */
  async function save(capture, choice) {
    const c = checkCapture(capture);
    const ch = /** @type {any} */ (choice);
    const ok =
      ch !== null && typeof ch === "object" && typeof ch.name === "string" && ch.name.length <= 512 &&
      (ch.username === null || (typeof ch.username === "string" && ch.username.length <= 512)) &&
      (ch.folder === null || (typeof ch.folder === "string" && ch.folder.length <= 256));
    if (!ok) throw new OfferWriteError("invalid_input");
    const origin = await originOf(c);
    let name = ch.name.trim();
    if (name === "") {
      // The host, as the core shows it, without `www.`.
      const host = await hostOf(origin);
      name = (host?.unicode ?? new URL(origin).hostname).replace(/^www\./i, "");
    }
    /** @type {Array<{ id: string, label: string, kind: string, value: string }>} */
    const fields = [];
    if (typeof ch.username === "string" && ch.username.trim() !== "") fields.push({ id: "username", label: labels.username, kind: "text", value: ch.username });
    fields.push({ id: PASSWORD_FIELD, label: labels.password, kind: "password", value: c.password });
    /** @type {Record<string, unknown>} */
    const draft = { item_type: "login", name, fields, urls: [{ url: origin, matching: "host" }] };
    if (ch.folder !== null) draft.folders = [ch.folder];
    const id = await engine.create(draft);
    return { id, pending: pendingOf(id) };
  }

  /**
   * The new password into one item, and nothing else.
   * @param {Capture} capture
   * @param {{ id: string, rev: number, picked?: boolean }} target `picked`: the user chose the item from the list of
   *   items that match by domain only
   * @returns {Promise<{ pending: boolean }>}
   */
  async function update(capture, target) {
    const c = checkCapture(capture);
    const t = /** @type {any} */ (target);
    if (t === null || typeof t !== "object" || typeof t.id !== "string" || !ITEM_ID.test(t.id) || !Number.isSafeInteger(t.rev) || t.rev < 1) {
      throw new OfferWriteError("invalid_input");
    }
    await originOf(c);
    const summary = engine.list().find((s) => s.id === t.id);
    if (summary === undefined) throw new OfferWriteError("not_found");
    if (!writable(summary)) throw new OfferWriteError("not_a_target");
    // Made from the revision the classification saw, or not at all.
    if (summary.rev !== t.rev) throw new OfferWriteError("item_changed");
    const opened = await engine.open(t.id);
    /** @type {Array<{ id: string, label?: string, kind?: string, value?: string }>} */
    let fields;
    try {
      const answer = await vault.match_page(c.frameUrl, [opened.handle]);
      const how = Array.isArray(answer) ? /** @type {any} */ (answer.find((h) => /** @type {any} */ (h)?.handle === opened.handle))?.how : undefined;
      if (how !== "exact" && how !== "host" && !(how === "domain" && t.picked === true)) throw new OfferWriteError("not_a_target");
      /** @type {any[]} */
      const existing = Array.isArray(opened.view?.fields) ? opened.view.fields : [];
      const ids = existing.map((f) => f?.id);
      // Every field by its id alone: two fields with one id could not both be named, and one would be lost.
      if (ids.some((id) => typeof id !== "string" || id === "") || new Set(ids).size !== ids.length) throw new OfferWriteError("not_updatable");
      fields = ids.map((id) => (id === PASSWORD_FIELD ? { id, value: c.password } : { id }));
      if (!ids.includes(PASSWORD_FIELD)) fields.push({ id: PASSWORD_FIELD, label: labels.password, kind: "password", value: c.password });
    } finally {
      await opened.close().catch(() => {});
    }
    // No `folders`, `urls`, `totp`, `notes` or any other key: the core keeps them as they are.
    await engine.update(t.id, { fields, keep_password_history: true }, t.rev);
    return { pending: pendingOf(t.id) };
  }

  return Object.freeze({ classify, save, update });
}
