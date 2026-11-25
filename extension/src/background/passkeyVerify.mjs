// User verification for a page's passkey request (the `passkeys` feature, design document § 9.3): when Ferret may say "user
// verified" (UV) in its answer to a website.
//
// UV is true only with a one-time mark issued here for that one request, after one of these, in this order:
//
//   recent    the vault was unlocked by the person (master password, PIN or passkey) or verified for a request at most
//             RECENT_UNLOCK_MS ago, and the setting allows it (on by default). The click in Ferret's window is then enough.
//   prf       Windows Hello, Touch ID or another passkey of the vault, in Ferret's window only (never the toolbar popup): a
//             real WebAuthn call against the vault's host, whose 32 bytes must open the vault key of the open account (the
//             core checks it against the pinned account key, pk_a). It needs the server (the list of the vault's passkeys
//             is read now).
//   pin       the PIN, checked like an unlock: the attempt is counted before the slow part runs, and without the server it
//             works only within seven days of the last contact.
//   password  the master password: a full sign-in exchange with the server (OPAQUE) and the password wrap opened against
//             the pinned account key. The window says that it signs in.
//
// What starts the five minutes (`markUnlocked`): only an unlock the person made (master password, PIN or passkey) and a
// verification in Ferret's window. Never a sign-in of a new device, a session or a background page that comes back, a
// renewal of the device's tokens, or an answer given through the recent unlock itself. The time is measured on two clocks, a
// monotonic one (`performance.now()` of the background page) and the wall clock, and the five minutes are over when either says
// so or went backwards: setting the system clock back cannot stretch them, and neither can a machine asleep (a monotonic clock
// may stand still then). A background page that was unloaded starts without one. Every lock forgets it.
//
// The decision for a request (`decide`), the same for a get and a create: `discouraged` gives the click only (a mark that is there
// is dropped); otherwise the request's mark, or the recent unlock (which issues one), gives UV; without either, the window is told
// to verify when there is a way to (`verification_needed`); when there is none, `preferred` is answered without UV after the click
// and `required` is told `verification_unavailable` (the window offers the browser). A mark is used when it is taken; a create
// whose write the server refused gives it back (`restore`), so the person's next try of the same request needs no new verification.
//
// The marks themselves are the request broker's (`markVerified`/`takeVerified`): bound to the request and the window session
// that owns it, used once, and gone with the request and at every lock. Nothing here signs or reads a key: the checks are
// those of the unlock (pinHost.mjs, pinSession.mjs), run in a worker of their own that is ended as soon as they are done, so
// the vault that is open is never touched.

/** How long an unlock or a verification by the person counts as verification (milliseconds). */
export const RECENT_UNLOCK_MS = 5 * 60_000;

/** The ways to verify, in the order the window offers them. */
export const VERIFY_METHODS = Object.freeze(["recent", "prf", "pin", "password"]);

/** The core host's operations that open the vault because the person unlocked it (`sign_in` is not one: a new device). */
export const UNLOCK_OPS = Object.freeze(["unlock", "pin_unlock", "prf_unlock"]);

/**
 * @typedef {{ request_id: string, session: string }} RequestRef the request and the window session that owns it
 * @typedef {{ recent: boolean, prf: boolean, pin: boolean, password: boolean, online: boolean }} Methods
 * @typedef {{ ok: true } | { ok: false, reason: string, left?: number, wait_ms?: number }} Outcome
 * @typedef {{
 *   status(): Promise<{ set: boolean, offlineOk: boolean } | null>,
 *   verify(pin: string): Promise<Outcome>,
 * }} LocalUnlock the PIN (pinHost.mjs), or null in a build without it
 * @typedef {{
 *   available(): Promise<boolean>,
 *   verify(input: { credential_id: string, prf_output: string }): Promise<Outcome>,
 * }} PrfUnlock the vault's passkeys (pinHost.mjs), or null
 * @typedef {{ verify(input: { mp: string, sk?: string }): Promise<Outcome> }} PasswordCheck the master password (the session)
 */

/**
 * @param {{
 *   password: PasswordCheck | null,
 *   pin?: LocalUnlock | null,
 *   prf?: PrfUnlock | null,
 *   settings: { recentAllowed(): Promise<boolean> },
 *   marks: { mark(id: string, session: string): boolean, take(id: string, session: string): boolean },
 *   online?: () => Promise<boolean>,
 *   now?: () => number,
 *   wall?: () => number,
 * }} deps `password`: the master password (`passwordCheck`); `pin` and `prf`: the checks of the unlock (pinHost.mjs's `verifier`; null
 *   where the build has none); `now` is a monotonic clock (`performance.now()`), `wall` the wall clock; `marks` are the broker's
 *   one-time marks of a request
 */
export function createPasskeyVerify({
  password,
  pin = null,
  prf = null,
  settings,
  marks,
  online = async () => true,
  now = () => globalThis.performance.now(),
  wall = () => Date.now(),
}) {
  /** When the person last unlocked or verified, on both clocks; null: not since this page started or the last lock. @type {{ mono: number, wall: number } | null} */
  let lastVerifiedAt = null;
  /** Moves at every lock: a verification that ends after a lock counts for nothing. */
  let epoch = 0;

  /** The five minutes start now. */
  const start = () => {
    lastVerifiedAt = { mono: now(), wall: wall() };
  };

  /** @param {number} at @param {number} since */
  const within = (at, since) => Number.isFinite(at) && at >= since && at - since < RECENT_UNLOCK_MS;

  /** Whether the last unlock or verification is within the five minutes on both clocks (a clock that went back counts as expired). */
  const withinWindow = () => lastVerifiedAt !== null && within(now(), lastVerifiedAt.mono) && within(wall(), lastVerifiedAt.wall);

  /** The recent unlock counts now: within the window and the setting on (read now; an error is "off"). */
  const recent = async () => {
    if (!withinWindow()) return false;
    try {
      return (await settings.recentAllowed()) === true;
    } catch {
      return false;
    }
  };

  /** @returns {Promise<boolean>} */
  const isOnline = async () => {
    try {
      return (await online()) === true;
    } catch {
      return false;
    }
  };

  /** @param {RequestRef} ref */
  const valid = (ref) => typeof ref?.request_id === "string" && typeof ref?.session === "string" && ref.session !== "";

  /**
   * The person was verified for this request: the mark for it, and (unless it was the recent unlock itself) the five
   * minutes start again. Nothing when a lock came while the check ran, or the request has ended.
   * @param {RequestRef} ref @param {number} started the epoch when the check began @param {boolean} renews
   * @returns {Outcome}
   */
  const issue = (ref, started, renews) => {
    if (epoch !== started) return { ok: false, reason: "vault_locked" };
    if (!marks.mark(ref.request_id, ref.session)) return { ok: false, reason: "gone" };
    if (renews) start();
    return { ok: true };
  };

  return Object.freeze({
    /**
     * What the person can verify with now, in the order the window offers it.
     * @returns {Promise<Methods>}
     */
    async methods() {
      const net = await isOnline();
      const isRecent = await recent();
      let prfOk = false;
      if (net && prf !== null) {
        try {
          prfOk = (await prf.available()) === true;
        } catch {
          prfOk = false;
        }
      }
      let pinOk = false;
      if (pin !== null) {
        try {
          const status = await pin.status();
          pinOk = status?.set === true && (status.offlineOk === true || net);
        } catch {
          pinOk = false;
        }
      }
      return { recent: isRecent, prf: prfOk, pin: pinOk, password: net && password !== null, online: net };
    },

    /** Whether the recent unlock counts now (the window says "one click is enough"). */
    recent,

    /**
     * Verifies the person for a request, and issues the request's one-time mark when it holds.
     * `recent` needs nothing typed; `prf` the credential and its 32 bytes (from Ferret's window only: the handler checks
     * that); `pin` the PIN; `password` the master password (and the secret key when this device does not keep it).
     * @param {RequestRef} ref @param {string} method @param {Record<string, unknown>} [input]
     * @returns {Promise<Outcome>}
     */
    async verify(ref, method, input = {}) {
      if (!valid(ref)) return { ok: false, reason: "gone" };
      const started = epoch;
      switch (method) {
        case "recent":
          // The click within the five minutes: the mark, but the five minutes do not start again.
          if (!(await recent())) return { ok: false, reason: "verification_needed" };
          return issue(ref, started, false);
        case "prf": {
          if (prf === null) return { ok: false, reason: "not_available" };
          if (typeof input.credential_id !== "string" || typeof input.prf_output !== "string") return { ok: false, reason: "invalid_input" };
          const done = await prf.verify({ credential_id: input.credential_id, prf_output: input.prf_output });
          return done.ok ? issue(ref, started, true) : done;
        }
        case "pin": {
          if (pin === null) return { ok: false, reason: "not_available" };
          if (typeof input.pin !== "string") return { ok: false, reason: "invalid_input" };
          const done = await pin.verify(input.pin);
          return done.ok ? issue(ref, started, true) : done;
        }
        case "password": {
          if (password === null) return { ok: false, reason: "not_available" };
          if (typeof input.mp !== "string") return { ok: false, reason: "invalid_input" };
          const done = await password.verify({ mp: input.mp, ...(typeof input.sk === "string" ? { sk: input.sk } : {}) });
          return done.ok ? issue(ref, started, true) : done;
        }
        default:
          return { ok: false, reason: "invalid_input" };
      }
    },

    /** The person unlocked the vault (master password, PIN or passkey): the five minutes start. */
    markUnlocked() {
      start();
    },

    /** Every lock: the five minutes are forgotten, and a check that is under way counts for nothing. */
    onLock() {
      lastVerifiedAt = null;
      epoch += 1;
    },

    /**
     * Takes the request's mark: true once, when the person was verified for this request. Used when Ferret signs.
     * @param {RequestRef} ref
     */
    take(ref) {
      return valid(ref) && marks.take(ref.request_id, ref.session) === true;
    },

    /**
     * Gives a taken mark back to its request (a create whose write the server refused: the page got nothing, and the person's next
     * try of the same request needs no new verification). Nothing when the request has ended.
     * @param {RequestRef} ref
     */
    restore(ref) {
      if (valid(ref)) marks.mark(ref.request_id, ref.session);
    },

    /**
     * User verification for a request, as a get and a create both decide it (see the head of the file): UV when the request has
     * the person's mark or the recent unlock counts (the mark is used), else what the window must do.
     * @param {RequestRef} ref @param {unknown} level the page's `userVerification` (anything else is `preferred`)
     * @returns {Promise<{ ok: true, uv: boolean } | { ok: false, reason: "verification_needed" | "verification_unavailable" }>}
     */
    async decide(ref, level) {
      const wanted = level === "required" || level === "discouraged" ? level : "preferred";
      if (wanted === "discouraged") {
        // The click is enough. A mark that is there is not used for anything.
        this.take(ref);
        return { ok: true, uv: false };
      }
      if (this.take(ref)) return { ok: true, uv: true };
      if ((await this.verify(ref, "recent")).ok && this.take(ref)) return { ok: true, uv: true };
      const ways = await this.methods();
      if (ways.recent || ways.prf || ways.pin || ways.password) return { ok: false, reason: "verification_needed" };
      // No way to verify now: `preferred` is answered without UV after the click; `required` goes to the browser.
      return wanted === "required" ? { ok: false, reason: "verification_unavailable" } : { ok: true, uv: false };
    },
  });
}

/**
 * The master password as a way to verify: the session's `verifyPassword` (the sign-in exchange with the server, OPAQUE, and the
 * password wrap opened against the pinned account key `pk_a`, as setting a PIN asks for it), for the vault that is open. No vault is
 * made and nothing is posted. It needs the session only, so a build without the PIN has it too.
 * @param {{ sessionHost: { storedServer(): Promise<string | null>, sessionFor(server: string): Promise<any> } }} deps
 * @returns {PasswordCheck}
 */
export function passwordCheck({ sessionHost }) {
  /** @param {unknown} error */
  const codeOf = (error) => {
    const code = /** @type {{ code?: unknown }} */ (error)?.code;
    return typeof code === "string" ? code : "unknown";
  };
  /** @param {unknown} error */
  const statusOf = (error) => {
    const status = /** @type {{ status?: unknown }} */ (error)?.status;
    return typeof status === "number" ? status : null;
  };
  return Object.freeze({
    /** @param {{ mp: string, sk?: string }} input @returns {Promise<Outcome>} */
    async verify(input) {
      const server = await sessionHost.storedServer();
      if (server === null) return { ok: false, reason: "signed_out" };
      const session = await sessionHost.sessionFor(server);
      const account = await session.deviceAccount?.();
      if (typeof account !== "string" || session.current?.()?.accountId !== account) return { ok: false, reason: "vault_locked" };
      try {
        await session.verifyPassword({ password: input.mp, ...(typeof input.sk === "string" ? { skCode: input.sk } : {}) });
      } catch (error) {
        const code = codeOf(error);
        const status = statusOf(error);
        if (code === "sk_required" || code === "sk_answer_required") return { ok: false, reason: "sk_required" };
        if (status === 401 || code === "signed_out" || code === "session_ended") return { ok: false, reason: "signed_out" };
        if (code.startsWith("pinned_") || code.startsWith("method_list_")) return { ok: false, reason: "attack_warning" };
        if (code === "decrypt" || code === "denied" || code === "password_required" || code === "input_not_utf8") return { ok: false, reason: "wrong_credentials" };
        if (status === 0 || code === "network" || (status !== null && status >= 500)) return { ok: false, reason: "network" };
        return { ok: false, reason: "not_verified" };
      }
      return { ok: true };
    },
  });
}

/**
 * The core host's operations with the unlocks the person makes marked: after `unlock`, `pin_unlock` or `prf_unlock` has
 * opened the vault (its answer is ok and the host is open), the five minutes start. Nothing else is touched.
 * @template {Record<string, any>} T
 * @param {T} ops @param {{ markUnlocked(): void }} verify @param {() => boolean} isOpen whether the core host is open now
 * @returns {T}
 */
export function markingUnlocks(ops, verify, isOpen) {
  /** @type {Record<string, any>} */
  const out = { ...ops };
  for (const name of UNLOCK_OPS) {
    const op = ops[name];
    if (op === undefined) continue;
    out[name] = Object.freeze({
      ...op,
      /** @param {any} client @param {any} args @param {any} context */
      async run(client, args, context) {
        const value = await op.run(client, args, context);
        if (/** @type {any} */ (value)?.ok === true && isOpen()) verify.markUnlocked();
        return value;
      },
    });
  }
  return /** @type {T} */ (Object.freeze(out));
}
