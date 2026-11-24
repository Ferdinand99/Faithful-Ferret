// The PIN host: the background's side of unlocking with a PIN (design document, sections 7.2 and 7.6; build flag
// `unlock`). It joins the PIN store (which it never opens itself: the entry hands it over), the account
// session (session.mjs, pinSession.mjs) and the core host. A build without the flag has no store and makes no host.
//
// Operations (the core host's `ops`, reached only through the handler of `unlock.handler.mjs`):
//
//   unlock_policy  the rule and what this device has of a PIN, while locked too (no key)
//   pin_set        sets or changes the PIN: the open vault, the network, the master password again, the rule fresh from
//                  the server; the PIN's Argon2id runs in a job worker (`client.pinWrap`), never in the vault worker
//   pin_unlock     opens the vault with the PIN: the rule, the window, the attempt (counted before the Argon2id), and
//                  then the checks that follow every unlock when the server answers
//   pin_off        deletes the PIN
//
// What the store's caller must do (the header of the PIN store, "What the caller must do"), and where it is done:
//
//   * the window always applies: `pin_unlock` renews the device's tokens first when the store says the window has run out
//     (a success is a contact, a refusal that ends the tokens wipes the PIN), and only then calls `attempt`;
//   * the unlock passed to `attempt` has a timeout, and a timeout counts as a wrong PIN;
//   * `save`, `markContact`, `markOnline`, `resetFailures` and `tick` are called from here and from nowhere a message can
//     reach: no handler hands a record, a time or a wipe reason on. The messages carry a PIN, a location and a
//     yes or no, and the reasons of a wipe are fixed in this file.
//
// The renewal of the device's tokens runs on a schedule (an alarm) whether or not a PIN is set: a PIN that is set must not
// be the thing that makes a device renew its tokens (the server could tell which devices have a PIN), and a device that
// has not renewed for the window has a PIN that asks for the server first.
//
// `tick` of the store is called from `pin_unlock` too, and a message can therefore make it run: it only raises the highest
// time seen, which tightens the clock guard, so that is no way to extend the window.
//
// The PIN and the master password come in as text in a request, go to the core as bytes that the client wipes, and are
// never stored, logged or put in a reply or an error. The strings of a request cannot be wiped (L6).

// This module does not import the PIN store: a package with the `unlock` flag off does not hold its file, and the
// entry hands the store over only through the generated module (unlockStore.gen.mjs). The types below are the shapes
// this module uses of it.

/** @typedef {string} WipeReason one of the PIN store's reasons for a wipe */
/** @typedef {{ pin: { allowed: boolean, after_restart: boolean, min_length: number }, prf: { enabled: boolean } }} Policy */
/** @typedef {{ set: boolean, location: "disk" | "session" | null, failuresLeft: number, waitMs: number, offlineOk: boolean }} PinStatus */
/** @typedef {{ methodId: Uint8Array, wrap: Uint8Array, deviceSalt: Uint8Array, pinProfile: number, vkEpoch: number, rule: { minLength: number } }} PinBlob */

/** The alarm that renews the tokens and moves the clock guard. */
export const CONTACT_ALARM = "ferret-contact";
/** How often it runs. */
export const CONTACT_PERIOD_MINUTES = 60;
/** The longest a PIN's unlock may run before it counts as a wrong PIN and the worker is ended. */
export const PIN_UNLOCK_TIMEOUT_MS = 60_000;
/** The longest a read of the rule waits for the server before the cached rule is used. */
export const POLICY_TIMEOUT_MS = 5000;

/** What the rule is taken to be for a server that has no PIN route (`GET /api/vault/policy` is a 404): no PIN. */
const NO_PIN_POLICY = Object.freeze({ pin: Object.freeze({ allowed: false, after_restart: false, min_length: 6 }), prf: Object.freeze({ enabled: false }) });

/** Codes of a worker that was ended or a lock that came: not a refusal of anything, so no reason to delete a PIN. */
const NOT_A_REFUSAL = new Set(["locked", "vault_locked", "worker_failed", "internal"]);

/** @param {unknown} error @returns {string} */
const codeOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" ? code : "unknown";
};

/** @param {unknown} error */
const statusOf = (error) => {
  const status = /** @type {{ status?: unknown }} */ (error)?.status;
  return typeof status === "number" ? status : null;
};

/**
 * @param {{ ok: false, reason: string, left?: number, wait_ms?: number }} reply
 * @returns {{ ok: false, reason: string, left?: number, wait_ms?: number }}
 */
const refused = (reply) => reply;

/**
 * @param {{
 *   store: any,
 *   sessionHost: ReturnType<typeof import("./session.mjs").createSessionHost>,
 *   alarms?: { create: (name: string, info: any) => unknown, onAlarm: { addListener: (fn: (alarm: { name: string }) => unknown) => void } } | null,
 *   now?: () => number,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 *   timers?: { setTimeout: (fn: () => void, ms: number) => unknown, clearTimeout: (id: any) => void },
 *   unlockTimeoutMs?: number,
 *   policyTimeoutMs?: number,
 * }} options
 */
export function createPinHost({
  store,
  sessionHost,
  alarms = null,
  now = Date.now,
  random = (bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)),
  timers = { setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms), clearTimeout: (id) => globalThis.clearTimeout(id) },
  unlockTimeoutMs = PIN_UNLOCK_TIMEOUT_MS,
  policyTimeoutMs = POLICY_TIMEOUT_MS,
}) {
  /** The core host's lock, set by `attach`. @type {((reason: "manual" | "sign_out") => Promise<void>) | null} */
  let hostLock = null;

  /**
   * `promise`, or `fallback` when it has not settled in `ms` (the promise goes on; its outcome is dropped).
   * @template T, F
   * @param {Promise<T>} promise @param {number} ms @param {F} fallback
   * @returns {Promise<T | F>}
   */
  function within(promise, ms, fallback) {
    return new Promise((resolve, reject) => {
      const id = timers.setTimeout(() => resolve(fallback), ms);
      promise.then(
        (value) => {
          timers.clearTimeout(id);
          resolve(value);
        },
        (error) => {
          timers.clearTimeout(id);
          reject(error);
        },
      );
    });
  }

  /** Locks the core host (and so ends the worker). */
  async function lockHost() {
    await hostLock?.("manual");
  }

  /** @param {string} server @returns {Promise<any>} the session of the server */
  const sessionOf = (server) => sessionHost.sessionFor(server);

  /**
   * The account this device is signed in with at `server`, from the device's own record, or null.
   * @param {string} server
   * @returns {Promise<string | null>}
   */
  async function accountOf(server) {
    try {
      return (await (await sessionOf(server)).deviceAccount?.()) ?? null;
    } catch {
      return null;
    }
  }

  /** Deletes every PIN of a server. Never throws. @param {string} server @param {WipeReason} reason */
  async function wipeServer(server, reason) {
    try {
      await store.wipeServer(server, reason);
    } catch {
      // A store that cannot be written cannot be told more: the next contact tries again.
    }
  }

  // ------------------------------------------------------------------ the rule

  /**
   * Reads the administrator's rule from the server and caches it (which applies it at once: a rule that forbids a PIN,
   * or is stricter than the one a PIN was made under, deletes it). A server without the route has no PIN: that too is
   * cached and applied.
   * @param {string} server
   * @returns {Promise<{ kind: "ok", policy: Policy } | { kind: "none" } | { kind: "offline" } | { kind: "ended", code: string }>}
   */
  async function fetchPolicy(server) {
    let body;
    try {
      const session = await sessionOf(server);
      body = await session.api.get("/api/vault/policy");
    } catch (error) {
      const status = statusOf(error);
      if (status === 404) {
        await store.cachePolicy(server, NO_PIN_POLICY).catch(() => {});
        return { kind: "none" };
      }
      if (status === 401) {
        const code = codeOf(error);
        const ended = await endedAfter(server, code);
        if (ended) return { kind: "ended", code };
      }
      return { kind: "offline" };
    }
    try {
      await store.cachePolicy(server, /** @type {any} */ (body));
    } catch {
      // A rule of the wrong shape is no rule: the cached one stays.
      return { kind: "offline" };
    }
    const policy = await store.cachedPolicy(server);
    return policy === null ? { kind: "offline" } : { kind: "ok", policy };
  }

  /**
   * After a refusal of a request: when the device's tokens have ended, deletes the PIN. True when they have.
   * @param {string} server @param {string} code
   */
  async function endedAfter(server, code) {
    const session = await sessionOf(server).catch(() => null);
    const state = await session?.deviceState?.().catch(() => null);
    const ended = state === "revoked" || state === "signed_out" || code === "device_revoked" || code === "token_reused" || code === "token_expired";
    if (ended) await wipeServer(server, code === "token_reused" ? "token_reused" : code === "token_expired" ? "token_expired" : "device_revoked");
    return ended;
  }

  /**
   * Renews the device's tokens now. A success is a contact (the offline window counts from it). A refusal that ends the
   * tokens deletes the PIN.
   * @param {string} server @param {string} account
   * @returns {Promise<"ok" | "offline" | "ended">}
   */
  async function renew(server, account) {
    try {
      const session = await sessionOf(server);
      await session.renewTokens();
    } catch (error) {
      if (statusOf(error) === 401 || codeOf(error) === "signed_out") {
        const code = codeOf(error);
        if (await endedAfter(server, code)) return "ended";
        // A refusal that left the tokens alive says nothing about the device: it is no contact.
      }
      return "offline";
    }
    await store.markContact(server, account).catch(() => {});
    return "ok";
  }

  // ------------------------------------------------------------------ the schedule

  /** The renewal of the tokens and the clock guard, whether or not a PIN is set. */
  async function contactRun() {
    const server = await sessionHost.storedServer().catch(() => null);
    if (server === null) return;
    await store.tick().catch(() => {});
    const account = await accountOf(server);
    if (account === null) return;
    // The read of the rule renews the tokens when the access token has run out, which is every run but one that
    // follows other traffic of the sync. Its renewal is a contact (`renewed`); a refusal ends the PIN.
    await fetchPolicy(server);
  }

  // ------------------------------------------------------------------ what the session tells

  const events = {
    /** @param {string} server */
    async signedIn(server) {
      await wipeServer(server, "new_sign_in");
    },
    /** @param {string} server @param {string | null} accountId @param {boolean} signedInAgain */
    async unlocked(server, accountId, signedInAgain) {
      if (signedInAgain) {
        await wipeServer(server, "new_sign_in");
        return;
      }
      if (accountId === null) return;
      // An unlock with the master password gives the PIN its attempts back, and passed the checks while online.
      await store.resetFailures(server, accountId).catch(() => {});
      await store.markOnline(server, accountId).catch(() => {});
    },
    /** @param {string} server */
    async renewed(server) {
      const account = await accountOf(server);
      if (account !== null) await store.markContact(server, account);
    },
    /** @param {string} server @param {"revoked" | "signed_out"} state */
    async deviceEnded(server, state) {
      await wipeServer(server, state === "revoked" ? "device_revoked" : "signed_out");
    },
  };

  // ------------------------------------------------------------------ the operations

  /**
   * What `unlock_policy` answers: the rule as last seen and what this device has of a PIN.
   * @param {Policy | null} policy
   * @param {PinStatus | null} status
   */
  function policyReply(policy, status) {
    const pin = policy?.pin ?? { allowed: false, after_restart: false, min_length: 6 };
    return {
      pin: {
        allowed: pin.allowed,
        after_restart: pin.after_restart,
        min_length: pin.min_length,
        set: status?.set === true,
        ...(status?.set === true && status.location !== null ? { location: status.location } : {}),
        failures_left: status?.set === true ? status.failuresLeft : 0,
        wait_ms: status?.waitMs ?? 0,
        offline_ok: status?.offlineOk === true,
      },
      prf: { enabled: policy?.prf.enabled === true, count: 0 },
    };
  }

  /** @type {import("./coreHost.mjs").CoreOp} */
  const unlockPolicy = {
    vault: false,
    worker: "vault",
    async run() {
      const server = await sessionHost.storedServer();
      if (server === null) return policyReply(null, null);
      const account = await accountOf(server);
      // The rule as this device last saw it, at once: a slow or absent server must not keep the popup from offering the
      // PIN. The rule is read again in the background (it deletes a PIN a stricter rule forbids; the next call sees that).
      void fetchPolicy(server).catch(() => {});
      const policy = await store.cachedPolicy(server).catch(() => null);
      const status = account === null ? null : await store.status(server, account).catch(() => null);
      return policyReply(policy, status);
    },
  };

  /**
   * The reason of a failed `pin_set` for the page.
   * @param {unknown} error
   * @returns {string | null} null: not a refusal of the user's input (the caller rethrows)
   */
  function setReasonOf(error) {
    const code = codeOf(error);
    switch (code) {
      case "decrypt":
      case "denied":
      case "pinned_auth_key":
      case "sk_required":
      case "sk_answer_required":
      case "password_required":
      case "input_not_utf8":
        return "wrong_credentials";
      case "input_too_short":
      case "input_too_long":
      case "input_forbidden_character":
        return "pin_rule";
      case "pin_not_allowed":
        return "pin_not_allowed";
      case "kdf_out_of_memory":
        return "out_of_memory";
      case "pin_too_slow":
        return "too_slow";
      case "network":
        return "network";
      default:
        return statusOf(error) === 0 ? "network" : null;
    }
  }

  /** @type {import("./coreHost.mjs").CoreOp} */
  const pinSet = {
    vault: true,
    worker: "vault",
    async run(client, args) {
      const { mp, sk, pin, location, acknowledged } = args;
      if (location !== "disk" && location !== "session") return refused({ ok: false, reason: "invalid_input" });
      if (location === "disk" && acknowledged !== true) return refused({ ok: false, reason: "not_acknowledged" });
      const server = await sessionHost.storedServer();
      if (server === null) return refused({ ok: false, reason: "signed_out" });
      const session = await sessionOf(server);
      const account = await session.deviceAccount?.();
      const opened = session.current();
      if (typeof account !== "string" || opened?.accountId !== account) return refused({ ok: false, reason: "vault_locked" });

      // The rule, fresh from the server: a PIN is only set with the network (and a server that has a rule).
      const fetched = await fetchPolicy(server);
      if (fetched.kind === "offline") return refused({ ok: false, reason: "network" });
      if (fetched.kind === "ended") return refused({ ok: false, reason: "signed_out" });
      if (fetched.kind === "none" || !fetched.policy.pin.allowed) return refused({ ok: false, reason: "pin_not_allowed" });
      const { policy } = fetched;
      if (location === "disk" && !policy.pin.after_restart) return refused({ ok: false, reason: "after_restart_not_allowed" });

      // The master password again (and the secret key where this device does not keep it).
      try {
        await session.verifyPassword({ password: mp, ...(typeof sk === "string" ? { skCode: sk } : {}) });
      } catch (error) {
        const reason = setReasonOf(error);
        if (reason !== null) return refused({ ok: false, reason });
        throw error;
      }

      // The PIN, as bytes the client wipes. Its Argon2id runs in a job worker.
      const pinBytes = new TextEncoder().encode(pin);
      const methodId = random(new Uint8Array(16));
      /** @type {any} */
      let made;
      try {
        made = await client.pinWrap(pinBytes, methodId, { allowed: policy.pin.allowed, after_restart: policy.pin.after_restart, min_length: policy.pin.min_length });
      } catch (error) {
        const reason = setReasonOf(error);
        // The Argon2id's own failures end the job worker only: the vault stays open.
        if (reason !== null) return refused({ ok: false, reason });
        throw error;
      } finally {
        pinBytes.fill(0);
      }
      const vkEpoch = Number(made.vk_epoch);
      /** @type {PinBlob} */
      const blob = {
        methodId: made.method_id instanceof Uint8Array ? made.method_id : methodId,
        wrap: made.wrap,
        deviceSalt: made.device_salt,
        pinProfile: Number(made.profile),
        vkEpoch,
        rule: { minLength: policy.pin.min_length },
      };
      try {
        await store.save(server, account, blob, { location, acknowledged: acknowledged === true });
        // A lock, a sign-out or a revocation while this ran (the wipe of that came before the save): the new record has no
        // device behind it. It goes, and the vault is said to be locked.
        if (session.current() !== opened || (await session.deviceState()) !== "ok") {
          await store.wipe(server, account, "signed_out");
          return refused({ ok: false, reason: "vault_locked" });
        }
      } catch (error) {
        if (/** @type {any} */ (error)?.name === "PinStoreError") {
          if (codeOf(error) === "acknowledgement_required") return refused({ ok: false, reason: "not_acknowledged" });
          if (codeOf(error) === "rule_forbids") return refused({ ok: false, reason: "pin_not_allowed" });
        }
        throw error;
      } finally {
        for (const bytes of [made?.wrap, made?.device_salt]) if (bytes instanceof Uint8Array) bytes.fill(0);
      }
      return { ok: true };
    },
  };

  /**
   * What the core's refusal of a PIN means for the store: the reason it counts, and whether the blob goes.
   * @param {unknown} error
   * @returns {{ answer: { ok: false, reason: "wrong" | "stale" | "out_of_memory" }, wipe: WipeReason | null }}
   */
  function pinRefusal(error) {
    const code = codeOf(error);
    switch (code) {
      case "pin_stale":
        return { answer: { ok: false, reason: "stale" }, wipe: null };
      case "kdf_out_of_memory":
        return { answer: { ok: false, reason: "out_of_memory" }, wipe: null };
      case "pinned_auth_key":
        return { answer: { ok: false, reason: "wrong" }, wipe: "pk_mismatch" };
      case "kdf_profile_unknown":
      case "kdf_profile_downgrade":
        return { answer: { ok: false, reason: "wrong" }, wipe: "unknown_profile" };
      case "pin_not_allowed":
        return { answer: { ok: false, reason: "wrong" }, wipe: "pin_forbidden" };
      case "pinned_missing":
        return { answer: { ok: false, reason: "wrong" }, wipe: "pinned_missing" };
      default:
        // A wrong PIN (`decrypt`), a PIN that is too short for the rule, a worker that died: all count.
        return { answer: { ok: false, reason: "wrong" }, wipe: null };
    }
  }

  /** @type {import("./coreHost.mjs").CoreOp} */
  const pinUnlock = sessionHost.opener(async (args, context) => {
    const server = await sessionHost.storedServer();
    if (server === null) return refused({ ok: false, reason: "pin_unavailable" });
    const session = await sessionOf(server);
    // A device whose tokens have ended has no PIN that is any use, whether or not an earlier wipe went through.
    const deviceState = await session.deviceState().catch(() => null);
    if (deviceState === "revoked" || deviceState === "signed_out") {
      await wipeServer(server, deviceState === "revoked" ? "device_revoked" : "signed_out");
      return refused({ ok: false, reason: "pin_wiped" });
    }
    if (deviceState !== "ok") return refused({ ok: false, reason: "pin_unavailable" });
    const account = await session.deviceAccount?.();
    if (typeof account !== "string") return refused({ ok: false, reason: "pin_unavailable" });
    await store.tick().catch(() => {});
    if (!(await store.status(server, account)).set) return refused({ ok: false, reason: "pin_unavailable" });

    // The rule is read when the server answers soon (it deletes a PIN a stricter rule or a switch-off forbids).
    await within(fetchPolicy(server), policyTimeoutMs, null).catch(() => null);
    let status = await store.status(server, account);
    if (!status.set) return refused({ ok: false, reason: "pin_wiped" });
    // The window: a PIN works without the server for seven days after the last contact. After that, and when the clock
    // was set back, the device shows the server it is not revoked first.
    if (!status.offlineOk) {
      const renewed = await renew(server, account);
      if (renewed === "ended") return refused({ ok: false, reason: "pin_wiped" });
      if (renewed === "offline") return refused({ ok: false, reason: "pin_offline_expired" });
      status = await store.status(server, account);
      if (!status.set) return refused({ ok: false, reason: "pin_wiped" });
      if (!status.offlineOk) return refused({ ok: false, reason: "pin_offline_expired" });
    }

    const cached = await store.cachedPolicy(server);
    const pin = typeof args.pin === "string" ? args.pin : "";
    // A PIN shorter than the rule, or longer than a PIN can be, can never be the right one: it is a typo, it costs no
    // attempt and has a reason of its own for the popup. (The length is what the person just typed, compared with
    // public numbers.)
    const length = [...pin.normalize("NFKD")].length;
    if (length < Math.max(4, cached?.pin.min_length ?? 0) || length > 64 || new TextEncoder().encode(pin.normalize("NFKD")).length > 256) {
      return refused({ ok: false, reason: "pin_rule", left: status.failuresLeft, wait_ms: status.waitMs });
    }
    const pinBytes = new TextEncoder().encode(pin);
    /** The refusal to act on once the attempt is counted. @type {WipeReason | null} */
    let wipeAfter = null;
    /** What the unlock opened in the worker, until the session is opened. @type {any} */
    let ready = null;
    /** @type {{ result: string, failuresLeft: number, waitMs: number }} */
    let outcome;
    try {
      outcome = await store.attempt(server, account, { online: true }, async (/** @type {PinBlob} */ blob) => {
        // A rule that is not here is no permission: the core refuses it (`pin_not_allowed`) and the PIN goes.
        const rule = { allowed: cached?.pin.allowed ?? false, after_restart: cached?.pin.after_restart ?? false, min_length: cached?.pin.min_length ?? blob.rule.minLength };
        try {
          const timedOut = Symbol("timeout");
          const opened = await within(session.pinUnlock({ pin: pinBytes, blob, rule }), unlockTimeoutMs, timedOut);
          if (opened === timedOut) {
            // The worker is ended; the attempt was counted before it started and stays counted.
            await lockHost().catch(() => {});
            return { ok: false, reason: "wrong" };
          }
          ready = opened;
          return { ok: true };
        } catch (error) {
          const refusal = pinRefusal(error);
          if (refusal.wipe !== null) wipeAfter = refusal.wipe;
          return refusal.answer;
        }
      });
    } finally {
      pinBytes.fill(0);
    }

    // The core opened the vault in the worker but the store does not stand behind it (the record was wiped while the
    // unlock ran: a sign-out, a revocation): the unlock is not to be trusted, and the worker is ended.
    // The Argon2id of a PIN grows the vault worker by 256 MiB and the browser does not take that back: after an attempt
    // that did not open the vault, the worker is ended and the next call starts a small one.
    if ((ready !== null && outcome.result !== "ok") || ["wrong", "out_of_memory", "stale"].includes(outcome.result)) await lockHost().catch(() => {});
    if (wipeAfter !== null) {
      await store.wipe(server, account, wipeAfter).catch(() => {});
      if (outcome.result !== "ok") return refused({ ok: false, reason: "pin_wiped" });
    }
    switch (outcome.result) {
      case "ok":
        break;
      case "wrong":
        return refused({ ok: false, reason: "wrong_pin", left: outcome.failuresLeft, wait_ms: outcome.waitMs });
      case "out_of_memory":
        return refused({ ok: false, reason: "out_of_memory", left: outcome.failuresLeft, wait_ms: outcome.waitMs });
      case "wait":
        return refused({ ok: false, reason: "pin_wait", left: outcome.failuresLeft, wait_ms: outcome.waitMs });
      case "wiped":
        return refused({ ok: false, reason: "pin_wiped" });
      case "stale":
        return refused({ ok: false, reason: "pin_stale" });
      case "offline_expired":
        return refused({ ok: false, reason: "pin_offline_expired" });
      default:
        return refused({ ok: false, reason: "pin_unavailable" });
    }
    if (ready === null) {
      await lockHost().catch(() => {});
      return refused({ ok: false, reason: "pin_unavailable" });
    }

    // The checks that follow every unlock, while the server answers. A refusal locks and deletes the PIN.
    let checked = false;
    try {
      checked = (await session.finishLocalUnlock(ready)).checked;
    } catch (error) {
      await lockHost().catch(() => {});
      const code = codeOf(error);
      if (code === "epoch_mismatch") {
        await store.wipe(server, account, "vk_epoch").catch(() => {});
        return refused({ ok: false, reason: "pin_stale" });
      }
      if (statusOf(error) === 401) {
        await endedAfter(server, code);
        await store.wipe(server, account, "device_revoked").catch(() => {});
        return refused({ ok: false, reason: "pin_wiped" });
      }
      // Any refusal that is not an answer of the server (a core refusal of what the server says against what this device
      // has pinned, a list or a row that cannot be read) deletes the PIN, whatever its code: no list of codes decides it.
      // An answer of the server that is not a revocation (too many requests, a server error) leaves it. The core's code
      // is what the page shows (the attack warning), as after a master password.
      if (statusOf(error) === null && !NOT_A_REFUSAL.has(code)) await store.wipe(server, account, "pinned_rejected").catch(() => {});
      throw error;
    }
    // The session opens the vault for the rest of the background (the sync starts); a lock in the meantime refuses it.
    await sessionHost.open(context, server, session);
    if (checked) await store.markOnline(server, account).catch(() => {});
    return { ok: true, account_email: ready.email, server };
  });

  /** @type {import("./coreHost.mjs").CoreOp} */
  const pinOff = {
    vault: false,
    worker: "vault",
    async run() {
      const server = await sessionHost.storedServer();
      if (server === null) return { ok: true };
      const account = await accountOf(server);
      if (account === null) await wipeServer(server, "pin_off");
      else await store.wipe(server, account, "pin_off");
      return { ok: true };
    },
  };

  const ops = Object.freeze({ unlock_policy: unlockPolicy, pin_set: pinSet, pin_unlock: pinUnlock, pin_off: pinOff });

  // The alarm's listener is added now, so the alarm that wakes an unloaded page reaches it.
  alarms?.onAlarm.addListener((alarm) => {
    if (alarm?.name !== CONTACT_ALARM) return undefined;
    return contactRun().catch(() => {});
  });

  return {
    ops,

    /**
     * Joins the core host and the session: a lock for "sign out" deletes the PIN, the session's events reach this host,
     * and the rule is read whenever an unlock has opened the vault.
     * @param {{ lock: (reason: "manual") => Promise<void>, onLocked: (listener: (reason: string) => void) => unknown }} coreHost
     */
    attach(coreHost) {
      hostLock = (reason) => coreHost.lock(/** @type {"manual"} */ (reason));
      sessionHost.setPins(events);
      // The device was signed out (forget this server, or its tokens have ended): no PIN is any use.
      coreHost.onLocked((reason) => {
        if (reason !== "sign_out") return;
        void sessionHost
          .storedServer()
          .then((server) => (server === null ? null : wipeServer(server, "signed_out")))
          .catch(() => {});
      });
      sessionHost.onOpen(({ server }) => {
        void fetchPolicy(server).catch(() => {});
      });
    },

    /** The first run, and the schedule: call it once from the entry. */
    start() {
      void store.tick().catch(() => {});
      try {
        const result = /** @type {any} */ (alarms?.create(CONTACT_ALARM, { periodInMinutes: CONTACT_PERIOD_MINUTES }));
        result?.catch?.(() => {});
      } catch {
        // No alarm: the run at every start of the page remains.
      }
      void contactRun().catch(() => {});
    },

    /** What the session tells it (for the tests). */
    events,
  };
}
