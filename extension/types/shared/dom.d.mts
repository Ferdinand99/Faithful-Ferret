// Types of the files that the build copies from web/src to dist/shared/ (see
// shared.json). A page imports "../shared/dom.mjs", which exists only in the
// package; the type check (jsconfig.json, rootDirs) finds this file in its
// place, and it points at the real source in the web vault.
export * from "../../../web/src/dom.mjs";
