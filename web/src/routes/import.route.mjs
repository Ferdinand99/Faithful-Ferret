import { importView } from "../views/import.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * The labels an imported item's fields carry, in the language of the page (the keys of `DEFAULT_LABELS` of the import).
 * @param {(key: string) => string} t
 */
function labelsOf(t) {
  /** @type {Record<string, string>} */
  const labels = {};
  for (const key of [
    "username", "password", "totp", "address", "field", "untitled", "cardholder_name", "brand", "number", "exp_month", "exp_year", "code",
    "title", "first_name", "middle_name", "last_name", "address1", "address2", "address3", "city", "state", "postal_code", "country",
    "company", "email", "phone", "ssn", "identity_username", "passport_number", "license_number",
  ]) labels[key] = t(`import.label.${key}`);
  return labels;
}

/**
 * `#/import`: bring items in from a file of Ferret's own or an unencrypted Bitwarden export. It is listed on the account page.
 * @type {import("../app.mjs").Route}
 */
export default {
  path: "/import",
  title: "import.title",
  menu: "account",
  menuOrder: 60,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const engine = vault.engine;
    const open = session.current?.() ?? null;
    const email = open?.email ?? null;
    /** @type {{ pinned: boolean, skBit: boolean | null, skStored: boolean } | null} */
    let account = null;
    try {
      account = email === null ? null : await session.deviceStatus(email);
    } catch {
      account = null;
    }
    const t = ctx.i18n.t;
    return vault.page(importView({
      t,
      previewFile: (file, options) => session.importPreview(file, { engine, labels: labelsOf(t), ...options }),
      runImport: (preview, args) => session.importRun(preview, { ...args, engine }),
      continueImport: (args) => session.importContinue({ ...args, engine }),
      discard: (preview) => session.importDiscard(preview),
      status: () => engine.importStatus(),
      on: (event, fn) => engine.on(event, fn),
      skRequired: account?.skBit === true && account.skStored !== true,
      locale: ctx.i18n.lang,
      scope: vault.scope,
    }));
  },
};
