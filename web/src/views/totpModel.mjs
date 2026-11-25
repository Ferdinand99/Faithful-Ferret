// What the one-time password screens need that has no DOM and no secret of its own: how a code is written in groups, how
// the text a user typed into the field is read, the address a bare secret becomes, and the warning about Ferret's own host.
// Nothing here makes a code or checks a secret: the core does that (`totp_parse`, `totp_code`). A secret that passes through
// is the user's own text and is handed on, never kept.

/** The longest label an address is given, in bytes (the core takes 256; the name of the item is cut to this). */
const MAX_LABEL_BYTES = 200;

/** The label of an address made for a name that is empty. */
const FALLBACK_LABEL = "account";

/**
 * A code written in two groups to be read at a glance: 6 digits as 3 + 3, 8 as 4 + 4 (7 as 3 + 4). The copy button copies the code
 * without the space.
 * @param {string} code
 */
export function groupCode(code) {
  const digits = String(code);
  if (digits.length === 8) return `${digits.slice(0, 4)} ${digits.slice(4)}`;
  if (digits.length === 6 || digits.length === 7) return `${digits.slice(0, 3)} ${digits.slice(3)}`;
  return digits;
}

/** The parameters of an address that the core reads; `counter` is kept so that a counter-based address stays refused. */
const READ_PARAMS = new Set(["secret", "issuer", "algorithm", "digits", "period", "counter"]);

/**
 * A time-based address without the parameters the core does not read (`image`, `color`, ...: real QR codes carry them), which
 * are dropped. Everything else is left to the core, which still refuses `counter`, HOTP and other schemes.
 * @param {string} uri
 */
export function withoutUnknownParams(uri) {
  if (!uri.startsWith("otpauth://totp/")) return uri;
  const at = uri.indexOf("?");
  const hash = uri.indexOf("#");
  if (at < 0 || (hash >= 0 && hash < at)) return uri;
  const end = hash < 0 ? uri.length : hash;
  const kept = uri.slice(at + 1, end).split("&").filter((pair) => {
    const eq = pair.indexOf("=");
    return pair === "" || eq < 1 || READ_PARAMS.has(pair.slice(0, eq));
  });
  return `${uri.slice(0, at)}?${kept.join("&")}${uri.slice(end)}`;
}

/**
 * What the field holds: nothing, a bare Base32 secret (any case, with spaces, with or without the `=` fill), or something else
 * that is passed to the core as an address (`otpauth://totp/...`; anything that is not one, like `otpauth://hotp/...` or
 * `steam://...`, is refused there).
 * @param {unknown} text
 * @returns {{ kind: "empty" } | { kind: "secret", secret: string } | { kind: "uri", uri: string }}
 */
export function readInput(text) {
  const trimmed = String(text ?? "").trim();
  if (trimmed === "") return { kind: "empty" };
  if (/^[A-Za-z2-7\s]+=*$/.test(trimmed)) return { kind: "secret", secret: trimmed.replace(/\s+/g, "").toUpperCase() };
  return { kind: "uri", uri: withoutUnknownParams(trimmed) };
}

/**
 * The label for an address: the name of the item, without what the address format reads as a separator, at most 200 bytes.
 * @param {unknown} name
 */
export function labelOf(name) {
  // eslint-disable-next-line no-control-regex
  let label = String(name ?? "").replace(/[\u0000-\u001f\u007f-\u009f:]+/g, " ").replace(/\s+/g, " ").trim();
  // Cut by characters first (a byte is at least a character, so 200 characters is the most that can fit), then by bytes: at most
  // 200 short passes, however long the name is.
  const chars = [...label.slice(0, MAX_LABEL_BYTES * 2)].slice(0, MAX_LABEL_BYTES);
  const encoder = new TextEncoder();
  while (chars.length > 0 && encoder.encode(chars.join("")).length > MAX_LABEL_BYTES) chars.pop();
  label = chars.join("").trim();
  return label === "" ? FALLBACK_LABEL : label;
}

/**
 * The address of a bare secret: the defaults written out (SHA-1, 6 digits, 30 seconds) and the name of the item as the label.
 * @param {string} secret Base32, upper case, without spaces (from `readInput`)
 * @param {unknown} name
 */
export function uriFromSecret(secret, name) {
  const label = encodeURIComponent(labelOf(name)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `otpauth://totp/${label}?secret=${secret}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Whether the issuer or the label of a parsed address names this server's own host. A one-time password for Ferret's own
 * sign-in must not be kept inside Ferret: lose the vault and the second factor is gone with it.
 * @param {{ issuer?: unknown, label?: unknown } | null | undefined} info what `totp_parse` returned (no secret)
 * @param {...string} hosts the host names of this page (`hostname`, and `host` with the port)
 */
export function namesOwnHost(info, ...hosts) {
  const names = [info?.issuer, info?.label].filter((v) => typeof v === "string").map((v) => String(v).toLowerCase());
  return hosts
    .map((h) => String(h ?? "").trim().toLowerCase())
    .filter((h) => h !== "")
    .some((h) => names.some((n) => n.includes(h)));
}
