import { passwordView } from "../views/password.mjs";

/** `/vault/password`: a page of its own, not a sign-in. @type {import("../app.mjs").Route} */
export default {
  path: "/password",
  title: "account.password.title",
  load: ({ i18n }) => passwordView({ t: i18n.t }),
};
