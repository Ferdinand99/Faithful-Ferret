// Inter, added to the page by script. The page's policy has no font source, so
// a stylesheet could not load a font file; a font made from bytes the page
// already holds needs none. The build puts the bytes of fonts/InterVariable.woff2
// in app/inter.mjs as base64. Until it is added (and if it never is) the system
// font stands in, so nothing depends on it.

/** The module the build writes. */
export const FONT_MODULE = "/app/inter.mjs";

/** The family name the stylesheet uses. */
export const FONT_FAMILY = "InterVariable";

/**
 * @param {string} base64 standard base64 with padding
 * @returns {Uint8Array}
 */
export function bytesFromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Adds Inter to the page. Never throws; answers whether the font was added.
 * @param {{
 *   importModule?: (url: string) => Promise<{ default: string }>,
 *   FontFaceClass?: any,
 *   fonts?: { add(face: unknown): unknown } | null,
 * }} [options]
 * @returns {Promise<boolean>}
 */
export async function loadInter({
  importModule = (url) => import(url),
  FontFaceClass = globalThis.FontFace,
  fonts = globalThis.document?.fonts ?? null,
} = {}) {
  try {
    if (typeof FontFaceClass !== "function" || !fonts) return false;
    const module = await importModule(FONT_MODULE);
    const face = new FontFaceClass(FONT_FAMILY, bytesFromBase64(module.default), { weight: "100 900", style: "normal", display: "swap" });
    await face.load();
    fonts.add(face);
    return true;
  } catch {
    return false;
  }
}
