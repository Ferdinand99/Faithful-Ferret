#!/usr/bin/env node
// Writes the update manifest (updates.json) for a signed release package.
//
//   node scripts/updates-json.mjs --xpi <signed .xpi> --sha256 <hex> --version <version>
//                                 [--previous <current updates.json>] --out <file>
//
// --sha256 is the SHA-256 the signing job reported for the signed file. The writer
// hashes the file itself and refuses to go on when the two differ, so the
// update_hash it writes is the hash of exactly the file that is published. It also
// refuses a file that is not named as the signing job names it, that carries no
// Mozilla signature (META-INF/), or whose manifest.json has another add-on id,
// another version or another update_url. Without --previous it starts a new update
// manifest (the first publication); with it, every older entry is kept (see
// lib/updates.mjs). Prints whether the file changed.
//
// No network, no token: the workflow fetches the current file and uploads the new one.
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readZip, sha256 } from "./lib/archive.mjs";
import { appendUpdate, assetName, isVersion, RELEASE_ID, UPDATE_URL } from "./lib/updates.mjs";

/**
 * Checks the signed package and returns the new update manifest.
 * @param {{ xpi: Buffer, name: string, sha256: string, version: string, previous: string | null }} input
 * @returns {{ text: string, changed: boolean }}
 */
export function writeUpdates({ xpi, name, sha256: expected, version, previous }) {
  if (!isVersion(version)) throw new Error(`--version ${JSON.stringify(version)} is not a plain dotted version`);
  if (typeof expected !== "string" || !/^[0-9a-f]{64}$/.test(expected)) throw new Error("--sha256 must be 64 lower-case hex digits");
  const actual = sha256(xpi);
  if (actual !== expected) throw new Error(`the package has sha256 ${actual}, the signing job reported ${expected}`);
  if (name !== assetName(version)) throw new Error(`the package is named ${name}, expected ${assetName(version)}`);
  const files = readZip(xpi);
  if (![...files.keys()].some((path) => path.startsWith("META-INF/"))) throw new Error("the package carries no signature (META-INF/)");
  const raw = files.get("manifest.json");
  if (raw === undefined) throw new Error("the package has no manifest.json");
  /** @type {any} */
  let manifest;
  try {
    manifest = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("the manifest.json of the package is not valid JSON");
  }
  const gecko = manifest?.browser_specific_settings?.gecko;
  if (gecko?.id !== RELEASE_ID) throw new Error(`the add-on id of the package is ${JSON.stringify(gecko?.id)}, not ${RELEASE_ID}`);
  if (manifest.version !== version) throw new Error(`the package has version ${JSON.stringify(manifest.version)}, not ${version}`);
  if (gecko.update_url !== UPDATE_URL) throw new Error(`the package's update_url is ${JSON.stringify(gecko.update_url)}, not ${UPDATE_URL}`);
  return appendUpdate(previous, { version, sha256: actual });
}

/** @param {string[]} args */
function main(args) {
  /** @type {Record<string, string>} */
  const values = {};
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    const value = args[i + 1];
    if (!["--xpi", "--sha256", "--version", "--previous", "--out"].includes(flag)) throw new Error(`unknown option ${flag}`);
    if (value === undefined || value === "") throw new Error(`${flag} needs a value`);
    if (flag.slice(2) in values) throw new Error(`${flag} is given twice`);
    values[flag.slice(2)] = value;
  }
  for (const required of ["xpi", "sha256", "version", "out"]) {
    if (!values[required]) throw new Error(`--${required} is required`);
  }
  const result = writeUpdates({
    xpi: readFileSync(values.xpi),
    name: basename(values.xpi),
    sha256: values.sha256,
    version: values.version,
    previous: values.previous === undefined ? null : readFileSync(values.previous, "utf8"),
  });
  writeFileSync(values.out, result.text);
  console.log(`updates-json: ${values.version} ${result.changed ? "added" : "already listed (unchanged)"}; ${values.out} written`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`updates-json: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}
