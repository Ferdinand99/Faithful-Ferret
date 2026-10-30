// The address of the admin pages, as the page that delivered this code states
// it: `<meta name="ferret-admin-url" content="https://admin.example">`. It is
// never taken from the address bar or any request parameter: a hand-over code
// goes to this origin, so a value an outsider could choose would let a crafted
// link send the code anywhere. The vault already trusts the server that
// delivers its code (spec Fase 1 § 2.4), so its own page is the right place.

/**
 * @param {{ querySelector?(selector: string): { getAttribute(name: string): string | null } | null } | undefined} [doc]
 * @param {string} [pageOrigin] the vault's own origin
 * @returns {string | null} the admin origin, or null when none is configured or it is not usable
 */
export function configuredAdminUrl(doc = globalThis.document, pageOrigin = globalThis.location?.origin) {
  try {
    const raw = doc?.querySelector?.('meta[name="ferret-admin-url"]')?.getAttribute("content");
    if (typeof raw !== "string" || raw === "") return null;
    const url = new URL(raw);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username !== "" || url.password !== "") return null;
    // The admin pages are another origin by design (spec § 2.4).
    if (url.origin === pageOrigin) return null;
    return url.origin;
  } catch {
    return null;
  }
}
