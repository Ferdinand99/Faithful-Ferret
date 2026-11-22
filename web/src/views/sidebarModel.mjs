// What the side menu holds, as plain data: no DOM, no secrets. The entries come
// from the routes (a route that says `sidebar: { section, order, ... }` is listed),
// so there is no second list of pages here. Two things are not routes yet and
// are listed as "coming soon" entries without a link (the generator and the
// health check, and the folder page), and the folders the user pinned are
// entries of their own. sidebar.mjs draws this.

/** The sections of the menu, in order. `primary` and `main` have no heading. */
export const SECTIONS = Object.freeze(["primary", "main", "pinned", "tools", "manage"]);

/** The heading of a section (an i18n key), or null for none. @type {Readonly<Record<string, string | null>>} */
const HEADINGS = Object.freeze({
  primary: null, main: null, pinned: "shell.section.pinned", tools: "shell.section.tools", manage: "shell.section.manage",
});

/** The icons the menu draws (styles/shell.css has one picture for each). */
export const ICONS = Object.freeze([
  "plus", "items", "star", "folder", "generator", "health", "transfer", "trash",
]);

/**
 * @typedef {object} SidebarMeta what a route says about its place in the menu
 * @property {"primary" | "main" | "tools" | "manage"} section
 * @property {number} [order] lower first (100 when not given)
 * @property {string} icon one of ICONS
 * @property {string} role the `data-role` of the link, `nav-` and lower-case letters
 * @property {string} [title] an i18n key; the route's own title when not given
 * @property {"all" | "favorites"} [count] a number shown beside the entry
 * @property {readonly string[]} [activeFor] more paths that belong to this entry (whole pages, or `/x/` for everything below `/x`)
 *
 * @typedef {object} SidebarEntry
 * @property {string} id
 * @property {"link" | "soon" | "folder"} kind
 * @property {string} label an i18n key, or the folder's name for a folder
 * @property {string} icon
 * @property {string | null} href `#/path`, or null for an entry that is not a link
 * @property {string} role
 * @property {number | null} count
 * @property {number} depth how far a folder stands below a pinned one (0 for everything else)
 * @property {readonly string[]} paths what makes it the current entry
 * @property {string | null} folder the id of a folder entry
 *
 * @typedef {object} SidebarSection
 * @property {string} id
 * @property {string | null} heading an i18n key
 * @property {SidebarEntry[]} entries
 */

/** What is listed before any route says so: the pages that are planned and have no page yet. */
const SOON = Object.freeze([
  { id: "generator", section: "tools", order: 10, icon: "generator", label: "shell.nav.generator", role: "nav-generator" },
  { id: "health", section: "tools", order: 20, icon: "health", label: "shell.nav.health", role: "nav-health" },
  { id: "folders", section: "manage", order: 10, icon: "folder", label: "shell.nav.folders", role: "nav-folders" },
]);

const ROLE = /^nav-[a-z][a-z-]{0,30}$/;
const PATH = /^\/[A-Za-z0-9_./-]*$/;

/** @param {unknown} value @returns {value is SidebarMeta} */
function isMeta(value) {
  const meta = /** @type {any} */ (value);
  return meta !== null && typeof meta === "object"
    && ["primary", "main", "tools", "manage"].includes(meta.section)
    && typeof meta.icon === "string" && ICONS.includes(meta.icon)
    && typeof meta.role === "string" && ROLE.test(meta.role)
    && (meta.order === undefined || Number.isFinite(meta.order))
    && (meta.title === undefined || typeof meta.title === "string")
    && (meta.count === undefined || meta.count === "all" || meta.count === "favorites")
    && (meta.activeFor === undefined || (Array.isArray(meta.activeFor) && meta.activeFor.every((/** @type {unknown} */ p) => typeof p === "string" && PATH.test(p))));
}

/**
 * The counts that entries show.
 * @param {readonly { id: string, favorite?: boolean }[]} items
 * @param {string} [manifestId] a row that is never an item
 * @returns {{ all: number, favorites: number }}
 */
export function countItems(items, manifestId = "") {
  const real = items.filter((item) => item.id !== manifestId);
  return { all: real.length, favorites: real.filter((item) => item.favorite === true).length };
}

/**
 * A pinned folder and the folders below it, in order, each with how deep it is.
 * A folder that is pinned and also below another pinned one stands once, below it.
 * Folders that point at each other cannot loop: every folder is visited once.
 * @param {readonly { id: string, name: string, parentId?: string | null }[]} folders
 * @param {readonly string[]} pinned
 * @returns {{ id: string, name: string, depth: number, pinned: boolean }[]}
 */
export function pinnedTree(folders, pinned) {
  const byId = new Map(folders.map((f) => [f.id, f]));
  /** @type {Map<string, string[]>} */
  const children = new Map();
  for (const folder of folders) {
    const parent = folder.parentId ?? null;
    if (parent === null || !byId.has(parent)) continue;
    children.set(parent, [...(children.get(parent) ?? []), folder.id]);
  }
  const roots = pinned.filter((id) => byId.has(id));
  /** @type {{ id: string, name: string, depth: number, pinned: boolean }[]} */
  const out = [];
  const seen = new Set();
  /** @param {string} id @param {number} depth */
  const visit = (id, depth) => {
    if (seen.has(id)) return;
    seen.add(id);
    const folder = /** @type {{ id: string, name: string }} */ (byId.get(id));
    out.push({ id, name: folder.name, depth, pinned: pinned.includes(id) });
    const named = [...(children.get(id) ?? [])].sort((a, b) => {
      const x = /** @type {{ name: string }} */ (byId.get(a)).name;
      const y = /** @type {{ name: string }} */ (byId.get(b)).name;
      return x.localeCompare(y);
    });
    for (const child of named) visit(child, depth + 1);
  };
  // Folders that are pinned below another pinned folder are shown by that folder.
  const below = (/** @type {string} */ id) => {
    let parent = byId.get(id)?.parentId ?? null;
    for (let guard = 0; parent !== null && guard < 64; guard += 1) {
      if (roots.includes(parent)) return true;
      parent = byId.get(parent)?.parentId ?? null;
    }
    return false;
  };
  for (const id of roots) if (!below(id)) visit(id, 0);
  // A cycle of pinned folders has no top: the first of them stands for it.
  for (const id of roots) visit(id, 0);
  return out;
}

/**
 * The menu.
 * @param {{
 *   routes: readonly any[],
 *   counts?: { all: number, favorites: number },
 *   folders?: readonly { id: string, name: string, parentId?: string | null }[],
 *   pinned?: readonly string[],
 *   folderHref?: (id: string) => string,
 * }} options `folderHref` is where a folder entry leads
 * @returns {SidebarSection[]}
 */
export function sidebarModel({ routes, counts = { all: 0, favorites: 0 }, folders = [], pinned = [], folderHref = (id) => `#/folders/${id}` }) {
  /** @type {Record<string, { order: number, entry: SidebarEntry }[]>} */
  const bySection = { primary: [], main: [], pinned: [], tools: [], manage: [] };
  for (const route of routes) {
    const meta = route?.sidebar;
    if (!isMeta(meta) || typeof route.path !== "string" || !PATH.test(route.path) || route.path.includes(":")) continue;
    const title = meta.title ?? route.title;
    if (typeof title !== "string") continue;
    bySection[meta.section].push({
      order: meta.order ?? 100,
      entry: {
        id: route.path, kind: "link", label: title, icon: meta.icon, href: `#${route.path}`, role: meta.role,
        count: meta.count ? counts[meta.count] : null, depth: 0, paths: [route.path, ...(meta.activeFor ?? [])], folder: null,
      },
    });
  }
  for (const soon of SOON) {
    bySection[soon.section].push({
      order: soon.order,
      entry: { id: soon.id, kind: "soon", label: soon.label, icon: soon.icon, href: null, role: soon.role, count: null, depth: 0, paths: [], folder: null },
    });
  }
  bySection.pinned = pinnedTree(folders, pinned).map((folder, index) => ({
    order: index,
    entry: {
      id: `folder:${folder.id}`, kind: /** @type {const} */ ("folder"), label: folder.name, icon: "folder", href: folderHref(folder.id),
      role: "nav-folder", count: null, depth: folder.depth, paths: [folderHref(folder.id).slice(1)], folder: folder.pinned ? folder.id : null,
    },
  }));
  return SECTIONS
    .map((id) => ({
      id,
      heading: HEADINGS[id],
      // Stable by order, then by the order the routes came in.
      entries: bySection[id].map((slot, index) => ({ ...slot, index })).sort((a, b) => a.order - b.order || a.index - b.index).map((slot) => slot.entry),
    }))
    .filter((section) => section.entries.length > 0);
}

/**
 * The entry that the open page belongs to: the one whose path is the page, or
 * failing that the longest path (or `/x/` prefix) that holds it. At most one.
 * @param {readonly SidebarSection[]} sections
 * @param {string} path the page, `/items/abc`
 * @returns {string | null} the id of the entry
 */
export function currentEntry(sections, path) {
  let best = null;
  let bestLength = -1;
  for (const section of sections) {
    for (const entry of section.entries) {
      if (entry.kind === "soon") continue;
      for (const own of entry.paths) {
        const prefix = own.endsWith("/");
        const hit = path === own || (prefix ? path.startsWith(own) : path.startsWith(`${own}/`));
        // A whole-page match beats any prefix match, then the longer path wins.
        const rank = (path === own ? 1000 : 0) + own.length;
        if (hit && rank > bestLength) {
          best = entry.id;
          bestLength = rank;
        }
      }
    }
  }
  return best;
}

/**
 * Two letters for the round mark of the account: from the user part of the
 * e-mail address ("ada.lovelace@x" gives AL, "ada@x" gives AD).
 * @param {string | null | undefined} email
 */
export function initialsOf(email) {
  const local = String(email ?? "").split("@")[0] ?? "";
  const parts = local.split(/[^\p{L}\p{N}]+/u).filter((p) => p !== "");
  const letters = parts.length >= 2 ? [...parts[0]][0] + [...parts[1]][0] : [...(parts[0] ?? "")].slice(0, 2).join("");
  return letters === "" ? "?" : letters.toLocaleUpperCase();
}
