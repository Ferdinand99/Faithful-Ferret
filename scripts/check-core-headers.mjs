#!/usr/bin/env node
// The licence guard for code that goes to the app stores: no third-party copyright or licence
// header in crates/ferret-core, in the code that it compiles in from outside its folder, or in the
// mobile app sources.
//
// The crypto core ships to iOS and Android (UniFFI), and the store terms add restrictions that
// GPL and AGPL code owned by someone else cannot carry. Code taken from another project (Bitwarden,
// AliasVault, Vaultwarden) goes only into web/, extension/, the server crates and test fixtures,
// where it keeps its header and gets a notice (notices-extra.json). In the core and in the mobile
// sources, such code is written from scratch, after reading the source at most.
//
// This check reads every text file below the guarded folders and fails on a file that carries a
// copyright line, a licence header or an SPDX identifier of someone else. Only a copyright line
// that itself names this project (Faithful Ferret, Hedgerow or its author) as the holder passes,
// and an SPDX line passes only next to such a line. The marker "Modified by Faithful Ferret" is
// the mark of taken code (it is what the taking rule asks for), so it is never exempt.
//
// Two more checks: every include!, include_str!, include_bytes! and #[path] target used by the
// core must lie inside a guarded folder (else code in an unguarded folder would be compiled into
// the core), and the core folder must exist and hold files (a rename must not make the check
// pass by scanning nothing).
//
// A permissive or weak-copyleft dependency is a Cargo dependency (checked by cargo-deny and
// cargo-about), not a copied file, and does not show up here. Data files that came with their own
// notice are listed one by one in ALLOWED, with the reason.
//
// Usage: node scripts/check-core-headers.mjs [folder ...]   (default: the guarded folders that exist)

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isMain } from "./is-main.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The folders that ship to the app stores: the core, the code that the core compiles in from
 * outside its folder (ct/harness), and the mobile apps. A mobile app folder is added here when it
 * is created.
 */
export const GUARDED = Object.freeze(["crates/ferret-core", "ct/harness", "apps/ios", "apps/android", "mobile", "bindings/uniffi"]);

/** The folder whose Rust sources are checked for what they include. */
const CORE = "crates/ferret-core";

/**
 * Files in a guarded folder that carry a notice of another project on purpose. The lines that match
 * `lines` are let through for that file, and nothing else in it; the reason says why.
 */
export const ALLOWED = Object.freeze({
  "crates/ferret-core/src/passkey/public_suffix_list.dat": {
    lines: /This Source Code Form is subject to/i,
    reason: "Public Suffix List data (MPL-2.0), a data file with its own header; the notice is the one the licence asks for. It is not code.",
  },
});

/** Folders that are not source. */
const SKIP = new Set(["target", "node_modules", ".git"]);

/** A copyright line that names this project as the holder. */
const OURS_COPYRIGHT = /\bcopyright\b.*(?:faithful[ -]ferret|hedgerow|ferdinand)/i;

/** The mark of taken code. Never exempt. */
const TAKEN = /\bModified by Faithful Ferret\b/i;

/** What a foreign notice looks like: a copyright line, a licence header or an SPDX identifier. */
const PATTERNS = [
  /\bcopyright\b\s*:?\s*(?:\(c\)|©|\d{4})/i,
  /^\W*[Cc]opyright\b\s*:?\s*[A-Z]/, // "Copyright Bitwarden Inc."
  /\(c\)\s*\d{4}/i,
  /©/,
  /\ball rights reserved\b/i,
  /\blicensed under\b/i,
  /\bSPDX-License-Identifier\s*:/i,
  /\bSPDX-File(?:CopyrightText|Contributor)\s*:/i,
  /\bpermission is hereby granted\b/i,
  /\bthis (?:file|program|library) is (?:free software|part of)\b/i,
  /\bThis Source Code Form is subject to\b/i,
  /\bGNU (?:Affero |Lesser |Library )?General Public License\b/i,
  /@license\b/i,
  /\bLicense\s*:\s*(?:A?L?GPL|MPL|MIT|Apache|BSD|ISC)\b/,
  TAKEN,
];

/**
 * The lines of a text that carry a foreign notice.
 * @param {string} text
 * @param {RegExp} [allowedLines] lines of this form are let through (an entry of ALLOWED)
 * @returns {{ line: number, text: string }[]}
 */
export function foreignNotices(text, allowedLines) {
  const found = [];
  const lines = text.split(/\r?\n/);
  /** The nearest line above or below that has something in it. */
  const neighbour = (/** @type {number} */ i, /** @type {number} */ step) => {
    for (let j = i + step; j >= 0 && j < lines.length; j += step) if (!/^\W*$/.test(lines[j])) return lines[j];
    return "";
  };
  for (const [i, line] of lines.entries()) {
    if (!PATTERNS.some((p) => p.test(line))) continue;
    if (allowedLines?.test(line)) continue;
    if (!TAKEN.test(line)) {
      // The project's own copyright line.
      if (OURS_COPYRIGHT.test(line)) continue;
      // An SPDX line is the project's own only when the line next to it is such a copyright line,
      // and neither neighbour is the mark of taken code.
      const above = neighbour(i, -1);
      const below = neighbour(i, 1);
      if (/SPDX-License-Identifier/i.test(line) && (OURS_COPYRIGHT.test(above) || OURS_COPYRIGHT.test(below)) && !TAKEN.test(above) && !TAKEN.test(below)) continue;
    }
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

/** @param {string} path @param {string} base */
const slash = (path, base) => relative(base, path).split(sep).join("/");

/**
 * Checks the folders (paths from the repository root) and returns the findings.
 * @param {string[]} folders
 * @param {string} [base]
 * @param {Record<string, { lines: RegExp }>} [allowed]
 * @returns {{ file: string, line: number, text: string }[]}
 */
export function check(folders, base = root, allowed = ALLOWED) {
  const findings = [];
  for (const folder of folders) {
    const dir = join(base, folder);
    if (!existsSync(dir)) continue;
    for (const file of walk(dir)) {
      const bytes = readFileSync(file);
      if (!isText(bytes)) continue;
      const name = slash(file, base);
      for (const f of foreignNotices(bytes.toString("utf8"), allowed[name]?.lines)) findings.push({ file: name, ...f });
    }
  }
  return findings;
}

/**
 * How many files the guard looks at, so that a check that read nothing is an error.
 * @param {readonly string[]} folders
 * @param {string} [base]
 */
export function scannedFiles(folders, base = root) {
  let count = 0;
  for (const folder of folders) {
    const dir = join(base, folder);
    if (existsSync(dir)) count += walk(dir).length;
  }
  return count;
}

/** include!("x"), include_str!("x"), include_bytes!("x") and #[path = "x"]; the argument is a plain string or it is not checkable. */
const INCLUDE = /\binclude(?:_str|_bytes)?!\s*\(\s*(?:"((?:[^"\\]|\\.)*)"|([^)]*))\s*\)|#\[\s*path\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\]]*))\]/g;

/**
 * Every include and #[path] target of the Rust sources of the core must be a plain path that lies
 * inside a guarded folder.
 * @param {string} [base]
 * @param {readonly string[]} [guarded]
 * @returns {{ file: string, line: number, text: string }[]}
 */
export function checkIncludes(base = root, guarded = GUARDED) {
  const findings = [];
  // The library sources are what ships; the tests of the core do not.
  const dir = join(base, CORE, "src");
  if (!existsSync(dir)) return findings;
  const inside = guarded.map((g) => resolve(base, g) + sep);
  for (const file of walk(dir).filter((f) => f.endsWith(".rs"))) {
    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    for (const [i, line] of lines.entries()) {
      for (const m of line.matchAll(INCLUDE)) {
        const literal = m[1] ?? m[3];
        const here = { file: slash(file, base), line: i + 1, text: line.trim().slice(0, 120) };
        if (literal === undefined) {
          findings.push({ ...here, text: `${here.text}  (the target is not a plain string, so it cannot be checked)` });
          continue;
        }
        const target = resolve(normalize(join(dirname(file), literal)));
        if (!inside.some((g) => target.startsWith(g))) findings.push({ ...here, text: `${here.text}  (target ${slash(target, base)} is outside the guarded folders)` });
        else if (!existsSync(target)) findings.push({ ...here, text: `${here.text}  (target does not exist)` });
      }
    }
  }
  return findings;
}

if (isMain(import.meta.url)) {
  const all = process.argv.length <= 2;
  const folders = all ? [...GUARDED] : process.argv.slice(2);
  const failures = [];
  if (all) {
    if (!existsSync(join(root, CORE))) failures.push(`${CORE} does not exist: the guard would check nothing (if it was renamed, change GUARDED)`);
    else if (scannedFiles(folders) === 0) failures.push("no file was scanned");
  }
  const findings = [...check(folders), ...(all ? checkIncludes() : [])];
  if (failures.length > 0 || findings.length > 0) {
    for (const f of failures) console.error(f);
    if (findings.length > 0) {
      console.error("Code that goes to the app stores carries a notice of another project, or compiles in code from an unguarded place:");
      for (const f of findings) console.error(`  ${f.file}:${f.line}: ${f.text}`);
      console.error("Third-party GPL or AGPL code may be taken into web/, extension/, the server crates and test fixtures only.");
      console.error("In the core and the mobile sources, write the code again from the idea (see notices-extra.json for what is taken).");
    }
    process.exit(1);
  }
  console.log(`No foreign notice in ${folders.filter((f) => existsSync(join(root, f))).join(", ")}.`);
}
