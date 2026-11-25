#!/usr/bin/env node
// The server and the Firefox extension carry the same version number: server 0.12.0 ships with
// extension 0.12.0. Release-please bumps the Rust crates and, through extra-files in
// release-please-config.json, the extension's package.json and package-lock.json in the same
// release pull request. This check fails when the numbers drift apart, for example when one of
// those lines is changed by hand or an extra-files entry is removed.
//
// Compared (all must be equal): .release-please-manifest.json ("."), Cargo.toml
// ([workspace.package] version), crates/ferret-server/Cargo.toml ([package] version),
// extension/package.json (version) and extension/package-lock.json (version and
// packages[""].version). The extension's manifests take their version from package.json at build
// time, so they are not listed separately.
//
// Usage: node scripts/check-shared-version.mjs [root]   (default: the repository root)

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isMain } from "./is-main.mjs";

const here = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The `version = "x"` line of one table of a Cargo.toml (null when the table or the line is missing). */
export function tomlVersion(text, table) {
  let inTable = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      inTable = header[1].trim() === table;
      continue;
    }
    if (inTable) {
      const m = /^version\s*=\s*"([^"]*)"/.exec(line);
      if (m) return m[1];
    }
  }
  return null;
}

/** Every place that names the shared version, as [label, version-or-null]. */
export function versions(root) {
  const read = (p) => readFileSync(join(root, p), "utf8");
  const json = (p) => JSON.parse(read(p));
  const lock = json("extension/package-lock.json");
  return [
    [".release-please-manifest.json", json(".release-please-manifest.json")["."] ?? null],
    ["Cargo.toml [workspace.package]", tomlVersion(read("Cargo.toml"), "workspace.package")],
    ["crates/ferret-server/Cargo.toml [package]", tomlVersion(read("crates/ferret-server/Cargo.toml"), "package")],
    ["extension/package.json", json("extension/package.json").version ?? null],
    ["extension/package-lock.json (version)", lock.version ?? null],
    ['extension/package-lock.json (packages[""])', lock.packages?.[""]?.version ?? null],
  ];
}

/** Problems found: a missing version, or the places that do not all name the same one. */
export function check(root) {
  const rows = versions(root);
  const problems = rows.filter(([, v]) => typeof v !== "string" || v === "").map(([l]) => `${l}: no version found`);
  const distinct = new Set(rows.map(([, v]) => v).filter((v) => typeof v === "string" && v !== ""));
  if (distinct.size > 1) {
    problems.push("the server and the extension must carry the same version, but they differ:");
    for (const [label, v] of rows) problems.push(`  ${label}: ${v}`);
  }
  return problems;
}

if (isMain(import.meta.url)) {
  const root = process.argv[2] ? resolve(process.argv[2]) : here;
  const problems = check(root);
  if (problems.length > 0) {
    for (const p of problems) console.error(p);
    console.error("Release-please bumps all of them together (extra-files in release-please-config.json); see docs/EXTENSION-FIREFOX.md.");
    process.exit(1);
  }
  console.log(`The server and the extension share version ${versions(root)[0][1]}.`);
}
