// Helpers for the tests of the sheet's QR text: the text itself, and a stand-in for the core's
// `setup_qr_parse` that reads the frozen format (`ferret-setup:v1?u=...&a=...&k=...&s=...&o=...`,
// see crates/ferret-core/src/sheet.rs) and answers the way the binding does.
import { hex16 } from "../../src/b64.mjs";
import { ACCOUNT, SERVER, coded } from "./accountHelpers.mjs";

/** The server key the fake server proves (accountHelpers: `filled(32, 9)`). */
export const SERVER_KEY = new Uint8Array(32).fill(9);

const hex = (bytes) => Array.from(bytes, (n) => n.toString(16).padStart(2, "0")).join("");
const encodeUrl = (url) => url.replace(/[^A-Za-z0-9\-._~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`);

/** The text of the QR code of a sheet. */
export function qrText({ url = SERVER, account = ACCOUNT, profile = 1, sk = true, key = SERVER_KEY } = {}) {
  return `ferret-setup:v1?u=${encodeUrl(url)}&a=${account}&k=${profile}&s=${sk ? 1 : 0}&o=${hex(key)}`;
}

/** The binding's `setup_qr_parse`, for texts of the frozen form; anything else is `malformed_setup_qr`. */
export function parseQr(text) {
  if (text.startsWith("ferret-setup:v2?")) throw coded("unsupported");
  const match = /^ferret-setup:v1\?u=([A-Za-z0-9%\-._~]+)&a=([0-9a-f]{32})&k=([1-9][0-9]*)&s=([01])&o=([0-9a-f]{64})$/.exec(text);
  if (!match) throw coded("malformed_setup_qr");
  const url = decodeURIComponent(match[1]);
  const address = /^(https?):\/\/([^/:?#]+|\[[^\]]+\])(?::([0-9]{1,5}))?/.exec(url);
  if (!address) throw coded("malformed_setup_qr");
  return {
    server_url: url,
    scheme: address[1],
    host: address[2].toLowerCase(),
    port: address[3] === undefined ? null : Number(address[3]),
    account_id: hex16.decode(match[2]),
    ksf_profile: Number(match[3]),
    sk_bit: match[4] === "1",
    server_public_key: Uint8Array.from(match[5].match(/../g), (h) => parseInt(h, 16)),
  };
}

/** The handlers a fake client needs to read sheet texts. */
export const qrHandlers = { setup_qr_parse: parseQr };
