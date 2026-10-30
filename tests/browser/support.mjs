// Shared helpers of the browser specs.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const repo = join(here, "..", "..");

/** Opens the test page and waits for the harness. */
export async function openHarness(page) {
  page.on("pageerror", (e) => console.error(`page error: ${e.message}`));
  await page.goto("/index.html");
  await page.waitForFunction(() => window.__ferretReady === true);
}

/** Keeps a result of a test for the report: `results/<browser>-<name>.json`. */
export function keep(browserName, name, data) {
  const dir = join(here, "results");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${browserName}-${name}.json`), `${JSON.stringify(data, null, 2)}\n`);
}
