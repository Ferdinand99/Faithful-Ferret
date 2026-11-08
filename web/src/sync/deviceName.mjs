// The name of this browser as other devices see it in a conflict ("changed on
// Firefox on Windows"). It is the setting `device.name` when the user has set
// one, else the browser and the platform, worked out from what the browser says
// about itself. It is written into the body of the items this device saves, so
// it is sealed with them and never shown to the server.

export const DEVICE_NAME_SETTING = "device.name";

/** The longest name kept, in characters. */
const MAX_LENGTH = 64;

/** Control and invisible characters have no place in a name. */
const FORBIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** @param {unknown} value @returns {string | null} a name that can be used, or null */
export function cleanDeviceName(value) {
  if (typeof value !== "string") return null;
  const name = value.trim();
  if (name === "" || [...name].length > MAX_LENGTH || FORBIDDEN.test(name)) return null;
  return name;
}

/**
 * "Firefox on Windows", "Safari on iOS", ... from the user agent; "Web vault" when it says nothing useful.
 * @param {{ userAgent?: string, userAgentData?: { platform?: string } } | undefined} nav
 */
export function defaultDeviceName(nav = /** @type {any} */ (globalThis).navigator) {
  const agent = typeof nav?.userAgent === "string" ? nav.userAgent : "";
  const browser = /Edg\//.test(agent) ? "Edge"
    : /OPR\/|Opera/.test(agent) ? "Opera"
    : /Firefox\/|FxiOS\//.test(agent) ? "Firefox"
    : /Chrome\/|CriOS\/|Chromium\//.test(agent) ? "Chrome"
    : /Safari\//.test(agent) ? "Safari"
    : null;
  const hinted = typeof nav?.userAgentData?.platform === "string" ? nav.userAgentData.platform : "";
  const platform = /iPhone|iPad|iPod/.test(agent) ? "iOS"
    : /Android/.test(agent) || hinted === "Android" ? "Android"
    : /Windows/.test(agent) || hinted === "Windows" ? "Windows"
    : /Mac OS X|Macintosh/.test(agent) || hinted === "macOS" ? "macOS"
    : /CrOS/.test(agent) ? "ChromeOS"
    : /Linux|X11/.test(agent) || hinted === "Linux" ? "Linux"
    : null;
  if (browser && platform) return `${browser} on ${platform}`;
  return browser ?? platform ?? "Web vault";
}

/**
 * The name this device writes into items: the setting, else the default.
 * @param {{ open(): Promise<any>, getSetting(db: any, key: string): Promise<unknown> }} store
 * @param {Parameters<typeof defaultDeviceName>[0]} [nav]
 */
export async function deviceNameFor(store, nav) {
  const saved = cleanDeviceName(await store.getSetting(await store.open(), DEVICE_NAME_SETTING));
  return saved ?? defaultDeviceName(nav);
}
