// The web vault's account session: the shared session (`session.mjs`: sign-in,
// unlock, lock, sign-out) and the account operations that only the web vault
// has: registration, re-authentication, password change, export, import, the
// recovery key, the secret key and the emergency sheet. This file is not
// shared with the extension; it brings the flows (and the PDF, QR and download
// code under them) that the extension never carries.
import { changePassword } from "../flows/changePassword.mjs";
import { encryptedExport, plainExport } from "../flows/export.mjs";
import { continueImport, discardImport, previewImport, runImport } from "../flows/import.mjs";
import { browserDeps } from "../flows/passkeyCeremony.mjs";
import { preparePasskeyUnlock, unlockWithPasskey } from "../flows/prfUnlock.mjs";
import { reauthenticate } from "../flows/reauth.mjs";
import { reapplyMethods, reapplyOffer } from "../flows/reapplyMethods.mjs";
import { register } from "../flows/register.mjs";
import { renewRecoveryKey } from "../flows/renewRecovery.mjs";
import { findRemembered, forgetRememberedAccount, rememberAccount, rememberedAccountId } from "../flows/rememberedAccount.mjs";
import { accessSheet, showSecretKey } from "../flows/showSecretKey.mjs";
import { beginAddPasskey, listPasskeys, passkeysOffered, removePasskeyMethod } from "../flows/unlockMethods.mjs";
import { createSessionCore } from "./session.mjs";
import { AccountError } from "./errors.mjs";

/**
 * The web vault's session: the session of `session.mjs` in its cookie mode,
 * with the web vault's own operations.
 * @param {Omit<Parameters<typeof createSessionCore>[0], "mode" | "platform" | "fetchImpl" | "locks">} options
 */
export function createVaultSession(options) {
  const { session, inner } = createSessionCore({ ...options, mode: "cookie" });
  const { env } = inner;
  /** The previews of an import that are held (sealed items, ciphertext): a lock lets go of them. @type {Set<object>} */
  const previews = new Set();
  // The first lock listener: a lock drops the previews before anything else hears of it.
  session.onLock(() => {
    for (const preview of [...previews]) discardImport(preview);
    previews.clear();
  });

  const { store } = options;
  /** Notes the account that was opened, so the next visit without a session is "Unlock" (see `flows/rememberedAccount.mjs`). @param {{ accountId: string }} opened */
  const remember = async (opened) => {
    await rememberAccount(store, env.server, opened.accountId);
    return opened;
  };

  return {
    ...session,

    /** Sign in with the e-mail and the master password; this browser remembers the account. @param {Parameters<typeof session.signIn>[0]} args */
    async signIn(args) {
      return remember(await session.signIn(args));
    },

    /**
     * Opens the vault again: in the live session, or with a full sign-in when it has ended and `email` is given (the
     * remembered account's, from the Unlock page). This browser remembers the account.
     * @param {Parameters<typeof session.unlock>[0]} args
     */
    async unlock(args) {
      return remember(await session.unlock(args));
    },

    /**
     * Whether the Unlock page can offer a passkey, and what its click needs (see `flows/prfUnlock.mjs`): null unless the
     * vault is closed, the vault session is valid, this device has the pinned record, the server offers passkeys and
     * the account has a passkey method. Nothing is asked of the passkey here.
     * @param {{ rpId?: string }} [options] `rpId`: the exact host of the vault (left out: the page's)
     */
    async preparePasskeyUnlock({ rpId = globalThis.location?.hostname } = {}) {
      if (inner.current() !== null) return null;
      return preparePasskeyUnlock(env, { rpId });
    },

    /**
     * Opens the vault with a passkey, in the live vault session. Call it from the click: the WebAuthn call is made before
     * anything else happens. This browser remembers the account, as after any unlock.
     * @param {import("../flows/prfUnlock.mjs").PasskeyOffer} offer what `preparePasskeyUnlock` gave
     * @param {{ getAssertion?: (publicKey: any) => Promise<any>, deps?: Parameters<typeof unlockWithPasskey>[2]["deps"] }} [how]
     */
    unlockWithPasskey(offer, { getAssertion = (publicKey) => globalThis.navigator.credentials.get({ publicKey }), deps = browserDeps() } = {}) {
      // No `await` before the flow starts: its first act is the WebAuthn call, and it has to come from the click.
      if (inner.current() !== null) return Promise.reject(new AccountError("passkey_sequence"));
      return unlockWithPasskey(env, offer, { getAssertion, deps }).then(async (result) => remember(await inner.opened(result)));
    },

    /**
     * Signs out (see `session.mjs`), and this browser forgets the account it remembered: the next visit is the full
     * sign-in page. The cached rows of that account go too, also when no session named it (the Unlock page's "Not you?").
     */
    async signOut() {
      const remembered = await rememberedAccountId(store, env.server).catch(() => null);
      try {
        await session.signOut();
      } finally {
        await forgetRememberedAccount(store, env.server).catch(() => undefined);
        if (remembered !== null) await store.open().then((/** @type {any} */ db) => store.cache.clearAccount(db, remembered)).catch(() => undefined);
      }
    },

    /** What this browser remembers for the Unlock page, or null (see `flows/rememberedAccount.mjs`). */
    remembered: () => findRemembered(store, env.server),

    /**
     * Forgets the remembered account (with `accountId`, only when it is that one): the next visit is the full sign-in page.
     * @param {string} [accountId]
     */
    forgetRemembered: (accountId) => forgetRememberedAccount(store, env.server, accountId),

    /**
     * Confirms the master password again for the open session (spec Fase 1 § 4.6 (a)). The vault stays open.
     * @param {Parameters<typeof reauthenticate>[1]} args
     */
    async reauthenticate(args) {
      const before = inner.locks();
      const done = await reauthenticate(env, args);
      inner.markFresh(before, done.until);
      return done;
    },

    /**
     * Changes the master password of the open account (see `flows/changePassword.mjs`). The vault stays open
     * and the session goes on; every other session of the account is ended by the server.
     * @param {Parameters<typeof changePassword>[1]} args
     */
    async changePassword(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      const before = inner.locks();
      const done = await changePassword(env, args);
      inner.markFresh(before, done.until);
      return done;
    },

    /**
     * The encrypted export of the open vault (see `flows/export.mjs`): a fresh sign-in with the master password, then the
     * file for the browser. The vault stays open; a lock while it runs ends it with `locked`.
     * @param {Omit<Parameters<typeof encryptedExport>[1], "scope">} args
     */
    async exportEncrypted(args) {
      const current = inner.current();
      if (current === null) throw new AccountError("session_ended");
      const { accountId, vaultId, vkEpoch } = current;
      return encryptedExport(env, { ...args, scope: { accountId, vaultId, vkEpoch } });
    },

    /**
     * The plain export of the open vault (see `flows/export.mjs`): behind the master password again and an explicit
     * confirmation. The file holds every secret in the clear.
     * @param {Omit<Parameters<typeof plainExport>[1], "scope">} args
     */
    async exportPlain(args) {
      const current = inner.current();
      if (current === null) throw new AccountError("session_ended");
      const { accountId, vaultId, vkEpoch } = current;
      return plainExport(env, { ...args, scope: { accountId, vaultId, vkEpoch } });
    },

    /**
     * Reads an import file and says what is in it (see `flows/import.mjs`). The import worker reads a JSON or CSV file and
     * the vault seals what it makes; the plain text never reaches this thread. A lock of the vault ends the worker and drops
     * the preview. `engine` is the sync engine of the open vault. `signal`: the page that asked has gone (the user left it); the worker is
     * ended and nothing is kept, as for a lock.
     * @param {Blob & { name?: string }} file
     * @param {{ engine: any, labels?: unknown, timeoutMs?: number, signal?: AbortSignal }} options
     */
    async importPreview(file, options) {
      if (inner.current() === null) throw new AccountError("session_ended");
      const { signal: given, ...rest } = options;
      const controller = new AbortController();
      const stop = () => controller.abort();
      if (given?.aborted) throw new AccountError("locked");
      given?.addEventListener("abort", stop, { once: true });
      const off = session.onLock(stop);
      try {
        const preview = await previewImport(env, file, { ...rest, signal: controller.signal });
        // A lock that came while the worker was running leaves nothing behind.
        if (controller.signal.aborted || inner.current() === null) {
          discardImport(preview);
          throw new AccountError("locked");
        }
        previews.add(preview);
        return preview;
      } finally {
        off();
        given?.removeEventListener("abort", stop);
      }
    },

    /**
     * Imports a previewed file (see `flows/import.mjs`): a fresh sign-in with the master password, an import window, and the
     * engine stores all of it in the outbox before it sends anything. A lock while it runs ends it.
     * @param {Parameters<typeof runImport>[1]} preview
     * @param {Omit<Parameters<typeof runImport>[2], "signal">} args
     */
    async importRun(preview, args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      const controller = new AbortController();
      const off = session.onLock(() => controller.abort());
      try {
        const done = await runImport(env, preview, { ...args, signal: controller.signal });
        previews.delete(preview);
        return done;
      } finally {
        off();
      }
    },

    /**
     * "Continue import" (see `flows/import.mjs`): a fresh sign-in, a new import window for the items that are left, and the
     * engine sends only those.
     * @param {Omit<Parameters<typeof continueImport>[1], never>} args
     */
    async importContinue(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      return continueImport(env, args);
    },

    /** Lets go of a preview (the sealed items it holds). @param {object} preview */
    importDiscard(preview) {
      previews.delete(preview);
      discardImport(preview);
    },

    /**
     * Registers an account up to the sheet. The returned flow's `finish()`
     * also makes the new account the open one.
     * @param {Parameters<typeof register>[1]} args
     */
    async register(args) {
      if (inner.current() !== null) await inner.lock();
      const flow = await register(env, args);
      const email = args.email.trim();
      return {
        ...flow,
        async finish() {
          const done = await flow.finish();
          const unlocked = await inner.opened({ ...done, email });
          await rememberAccount(store, env.server, done.accountId);
          return { ...unlocked, accountId: done.accountId, vaultId: done.vaultId };
        },
      };
    },

    /**
     * A new recovery key for the open account (see `flows/renewRecovery.mjs`). The vault stays open and no
     * session ends.
     * @param {Parameters<typeof renewRecoveryKey>[1]} args
     */
    async renewRecoveryKey(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      return renewRecoveryKey(env, args);
    },

    /** What "reapply the unlock methods" can do after an accepted restore (see `flows/reapplyMethods.mjs`). */
    async reapplyOffer() {
      if (inner.current() === null) throw new AccountError("session_ended");
      return reapplyOffer(env);
    },

    /**
     * Renews the recovery key over a wrap that went below the floor with an accepted restore.
     * @param {Parameters<typeof reapplyMethods>[1]} args
     */
    async reapplyMethods(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      return reapplyMethods(env, args);
    },

    /** Whether the server offers passkeys as unlock methods (`GET /api/vault/policy`); false when it cannot be told. */
    passkeysOffered: () => passkeysOffered(env.api),

    /** The passkeys that unlock the open vault, for the list (see `flows/unlockMethods.mjs`). */
    async listPasskeys() {
      if (inner.current() === null) throw new AccountError("session_ended");
      return listPasskeys(env);
    },

    /**
     * The first part of adding a passkey as an unlock method (see `flows/unlockMethods.mjs`): the password check and
     * the checks of the server's list. The page then makes the two WebAuthn calls, each from a click.
     * @param {Omit<Parameters<typeof beginAddPasskey>[1], "scope">} args
     */
    async beginAddPasskey(args) {
      const current = inner.current();
      if (current === null) throw new AccountError("session_ended");
      const { accountId, vaultId, vkEpoch } = current;
      return beginAddPasskey(env, { ...args, scope: { accountId, vaultId, vkEpoch } });
    },

    /**
     * Removes a passkey from the unlock methods of the open vault, after the password check.
     * @param {Parameters<typeof removePasskeyMethod>[1]} args
     */
    async removePasskey(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      return removePasskeyMethod(env, args);
    },

    /**
     * The secret key this device remembers, after the password check (see `flows/showSecretKey.mjs`).
     * @param {Parameters<typeof showSecretKey>[1]} args
     */
    async showSecretKey(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      return showSecretKey(env, args);
    },

    /**
     * Page 1 of the emergency sheet again, as a PDF (see `flows/showSecretKey.mjs`).
     * @param {Parameters<typeof accessSheet>[1]} args
     */
    async accessSheet(args) {
      if (inner.current() === null) throw new AccountError("session_ended");
      return accessSheet(env, args);
    },
  };
}
