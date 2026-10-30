// The application shell: resolves the services in dependency order, starts the
// router, and mounts what a route's `load` returns. Features add files
// (`routes/*.route.mjs`, `services/*.service.mjs`); `scripts/build.mjs` lists
// them in `routes.gen.mjs` and `services.gen.mjs`, so this file never changes
// when a feature is added.
import { el, mount } from "./dom.mjs";
import { createRouter } from "./router.mjs";

/** Services the page makes before any feature service: a feature may depend on them. */
export const BASE_SERVICES = Object.freeze(["client", "i18n"]);

/**
 * @typedef {object} RouteContext
 * @property {Record<string, string>} params
 * @property {string} path
 * @property {{ t(key: string, vars?: Record<string, string | number>): string, lang: string, missing: string[] }} i18n
 * @property {any} client
 * @property {Record<string, any>} services
 * @property {(path: string) => void} go
 *
 * @typedef {object} Route
 * @property {string} path    `/`, `/items`, `/items/:id`
 * @property {string} title   an i18n key
 * @property {(ctx: RouteContext) => Node | Promise<Node>} load
 *
 * @typedef {object} ServiceDef
 * @property {string} name
 * @property {readonly string[]} deps
 * @property {(deps: Record<string, any>) => any} create
 */

/**
 * The services in an order where every service comes after its dependencies.
 * Throws on a duplicate name, an unknown dependency or a cycle.
 * @param {readonly ServiceDef[]} defs
 * @param {readonly string[]} [base]
 * @returns {ServiceDef[]}
 */
export function orderServices(defs, base = BASE_SERVICES) {
  /** @type {Map<string, ServiceDef>} */
  const byName = new Map();
  for (const def of defs) {
    if (base.includes(def.name) || byName.has(def.name)) {
      throw new Error(`service name used twice: ${def.name}`);
    }
    byName.set(def.name, def);
  }
  /** @type {ServiceDef[]} */
  const order = [];
  const done = new Set();
  /** @param {ServiceDef} def @param {string[]} trail */
  const visit = (def, trail) => {
    if (done.has(def.name)) return;
    if (trail.includes(def.name)) {
      throw new Error(`service dependency cycle: ${[...trail, def.name].join(" -> ")}`);
    }
    for (const dep of def.deps) {
      if (base.includes(dep)) continue;
      const next = byName.get(dep);
      if (!next) throw new Error(`service ${def.name} needs unknown service ${dep}`);
      visit(next, [...trail, def.name]);
    }
    done.add(def.name);
    order.push(def);
  };
  const sorted = [...byName.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const def of sorted) visit(def, []);
  return order;
}

/**
 * Makes every service once, in dependency order. A service is given only the
 * services it names in `deps`.
 * @param {readonly ServiceDef[]} defs
 * @param {Record<string, any>} base
 * @returns {Record<string, any>}
 */
export function resolveServices(defs, base) {
  /** @type {Record<string, any>} */
  const made = { ...base };
  for (const def of orderServices(defs, Object.keys(base))) {
    /** @type {Record<string, any>} */
    const deps = {};
    for (const dep of def.deps) deps[dep] = made[dep];
    made[def.name] = def.create(deps);
  }
  return made;
}

/** @type {Route} */
const NOT_FOUND = {
  path: "*",
  title: "app.notfound.title",
  load: ({ i18n }) =>
    el("section", { class: "card" },
      el("h1", null, i18n.t("app.notfound.title")),
      el("p", null, i18n.t("app.notfound.body")),
      el("p", null, el("a", { href: "#/" }, i18n.t("app.notfound.home")))),
};

/**
 * @param {{
 *   root: HTMLElement,
 *   routes: readonly Route[],
 *   serviceDefs: readonly ServiceDef[],
 *   client: any,
 *   i18n: RouteContext["i18n"],
 *   win?: any,
 * }} options
 */
export function startApp({ root, routes, serviceDefs, client, i18n, win = window }) {
  const services = resolveServices(serviceDefs, { client, i18n });
  let token = 0;

  /** @param {import("./router.mjs").Match} match */
  async function show(match) {
    const mine = ++token;
    /** @type {Node} */
    let view;
    try {
      view = await match.route.load({
        params: match.params,
        path: match.path,
        i18n,
        client,
        services,
        go: (/** @type {string} */ path) => router.go(path),
      });
    } catch {
      // No detail on the page: an error can carry what the user typed.
      view = el("section", { class: "card", role: "alert" }, el("p", null, i18n.t("app.error.load")));
    }
    if (mine !== token) return;
    win.document.title = `${i18n.t(match.route.title)} · ${i18n.t("app.name")}`;
    mount(root, view);
  }

  const router = createRouter({
    routes,
    notFound: NOT_FOUND,
    win,
    onChange: (match) => {
      void show(match);
    },
  });
  router.start();
  return { router, services };
}
