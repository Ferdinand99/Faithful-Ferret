// The vault's API client as a service: same-origin calls to the JSON API.
import { createApi } from "../api.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "api",
  deps: [],
  create: () => createApi(),
};
