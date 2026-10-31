import { el } from "../dom.mjs";

/** @type {import("../app.mjs").Route} */
export default {
  path: "/",
  title: "home.title",
  load: ({ i18n, services, go }) => {
    // An open vault goes straight to its items; everyone else sees the start page.
    if (services.crypto?.current?.()) go("/items");
    return el("section", { class: "card" },
      el("h1", null, i18n.t("home.heading")),
      el("p", null, i18n.t("home.body")),
      el("p", null, el("a", { href: "#/items" }, i18n.t("home.open"))));
  },
};
