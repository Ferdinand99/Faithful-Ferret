// The start of the content script. The build joins this file and what it
// imports into one classic script (content/fill.inject.js), which the extension
// injects; see scripts/lib/classic.mjs for why it is not loaded as a module.
import { start } from "./fill.mjs";

start();
