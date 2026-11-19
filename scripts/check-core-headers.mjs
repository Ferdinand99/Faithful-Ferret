#!/usr/bin/env node
// The licence guard for code that goes to the app stores: no third-party copyright or licence
// header in crates/ferret-core or in the mobile app sources.
//
// The crypto core ships to iOS and Android (UniFFI), and the store terms add restrictions that
// GPL and AGPL code owned by someone else cannot carry. Code taken from another project (Bitwarden,
// AliasVault, Vaultwarden) goes only into web/, extension/, the server crates and test fixtures,
// where it keeps its header and gets a notice (notices-extra.json). In the core and in the mobile
// sources, such code is written from scratch, after reading the source at most.
//
// This check reads every text file below the guarded folders and fails on a file that carries a
// copyright line, a licence header or an SPDX identifier of someone else. A notice that names this
// project (Faithful Ferret, Hedgerow or its author) passes. A permissive dependency is a Cargo
// dependency (checked by cargo-deny and cargo-about), not a copied file, so it does not show up here.
//
// Usage: node scripts/check-core-headers.mjs [folder ...]   (default: the guarded folders that exist)

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isMain } from "./is-main.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The folders that ship to the app stores. A mobile app folder is added here when it is created. */
export const GUARDED = Object.freeze(["crates/ferret-core", "apps/ios", "apps/android", "mobile", "bindings/uniffi"]);

/** Folders that are not source. */
const SKIP = new Set(["target", "node_modules", ".git"]);

/** The holders that are this project. */
const OURS = /faithful[ -]ferret|hedgerow|ferdinand/i;

/** What a foreign notice looks like: a copyright line, a licence header or an SPDX identifier. */
const PATTERNS = [
  /\bcopyright\b\s*(?:\(c\)|©|\d{4})/i,
  /©\s*\d{4}/,
  /\ball rights reserved\b/i,
  /\blicensed under the\b/i,
  /\bSPDX-License-Identifier\s*:/i,
  /\bpermission is hereby granted\b/i,
  /\bthis (?:file|program|library) is (?:free software|part of)\b/i,
];

/**
 * The lines of a text that carry a foreign notice.
 * @param {string} text
 * @returns {{ line: number, text: string }[]}
 */
export function foreignNotices(text) {
  const found = [];
  const lines = text.split(/\r?\n/);
  for (const [i, line] of lines.entries()) {
    if (!PATTERNS.some((p) => p.test(line))) continue;
    // The notice of this project, on the line or in the two next to it (a header spans lines).
    const near = lines.slice(Math.max(0, i - 2), i + 3).join("\n");
    if (OURS.test(near)) continue;
    found.push({ line: i + 1, text: line.trim().slice(0, 120) });
  }
  return found;
}

/** @param {string} dir @returns {string[]} */
function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

/** A file that is not text is not read. @param {Buffer} bytes */
const isText = (bytes) => !bytes.subarray(0, 8000).includes(0);

/**
 * Checks the folders (paths from the repository root) and returns the findings.
 * @param {string[]} folders
 * @param {string} [base]
 */
export function check(folders, base = root) {
  const findings = [];
  for (const folder of folders) {
    const dir = join(base, folder);
    if (!existsSync(dir)) continue;
    for (const file of walk(dir)) {
      const bytes = readFileSync(file);
      if (!isText(bytes)) continue;
      for (const f of foreignNotices(bytes.toString("utf8"))) {
        findings.push({ file: relative(base, file).split(sep).join("/"), ...f });
      }
    }
  }
  return findings;
}

if (isMain(import.meta.url)) {
  const folders = process.argv.length > 2 ? process.argv.slice(2) : [...GUARDED];
  const findings = check(folders);
  if (findings.length > 0) {
    console.error("A file in code that goes to the app stores carries a notice of another project:");
    for (const f of findings) console.error(`  ${f.file}:${f.line}: ${f.text}`);
    console.error("Third-party GPL or AGPL code may be taken into web/, extension/, the server crates and test fixtures only.");
    console.error("In the core and the mobile sources, write the code again from the idea (see notices-extra.json for what is taken).");
    process.exit(1);
  }
  console.log(`No foreign notice in ${folders.filter((f) => existsSync(join(root, f))).join(", ")}.`);
}
