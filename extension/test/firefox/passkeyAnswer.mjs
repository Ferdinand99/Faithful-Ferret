// The builder of the passkey script's answer objects (src/content/passkeyResponse.mjs), joined the way the build joins the
// page's script and put on `window.__credentialFrom`, for the specs that compare the objects with the browser's own and
// that run relying parties against them. Not a spec (run.sh picks up *.spec.mjs only).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classicScript, passkeyMainMayInclude } from "../../scripts/lib/classic.mjs";

const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/** The joined script that makes `window.__credentialFrom` (kind, fields) -> the credential, or null. */
export function builderScript() {
  const entry = "content/passkey.expose.entry.mjs";
  const files = new Map([
    ["content/passkeyResponse.mjs", readFileSync(resolve(src, "content", "passkeyResponse.mjs"))],
    [entry, Buffer.from('import { credentialFrom } from "./passkeyResponse.mjs";\nObject.defineProperty(window, "__credentialFrom", { value: credentialFrom, configurable: true });\n')],
  ]);
  return classicScript(entry, files, passkeyMainMayInclude, { slim: true, name: "passkey.answer.js" });
}

/**
 * Page code that makes the page's `navigator.credentials.create` and `get` answer with the objects of the builder, built from
 * what the browser's own function answered (a virtual authenticator): a stand-in for Ferret's answer, so the relying parties
 * and the client libraries see the objects Ferret makes. `window.__answered` counts the answers built.
 */
export const SHIM_SCRIPT = `(() => {
  const container = navigator.credentials;
  const own = { create: CredentialsContainer.prototype.create, get: CredentialsContainer.prototype.get };
  window.__answered = 0;
  const fieldsOf = (kind, n) => {
    const r = n.response;
    return kind === "create"
      ? { id: n.rawId, clientDataJSON: r.clientDataJSON, authenticatorData: r.getAuthenticatorData(), authenticatorAttachment: n.authenticatorAttachment, attestationObject: r.attestationObject,
          publicKey: r.getPublicKey(), publicKeyAlgorithm: r.getPublicKeyAlgorithm(), transports: r.getTransports(), clientExtensionResults: n.getClientExtensionResults() }
      : { id: n.rawId, clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, authenticatorAttachment: n.authenticatorAttachment, signature: r.signature, userHandle: r.userHandle,
          clientExtensionResults: n.getClientExtensionResults() };
  };
  for (const kind of ["create", "get"]) {
    container[kind] = { async [kind](options) {
      const native = await own[kind].call(container, options);
      if (native === null || !options || !options.publicKey) return native;
      const ours = window.__credentialFrom(kind, fieldsOf(kind, native));
      if (ours === null) throw new Error("the builder gave no answer");
      window.__answered += 1;
      return ours;
    } }[kind];
  }
})();`;
