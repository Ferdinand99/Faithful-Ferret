import { el } from "../dom.mjs";

/** @type {import("../app.mjs").Route} */
export default {
  path: "/",
  title: "home.title",
  load: ({ i18n }) =>
    el("section", { class: "card" },
      el("h1", null, i18n.t("home.heading")),
      el("p", null, i18n.t("home.body"))),
};
