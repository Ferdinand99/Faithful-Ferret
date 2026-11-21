#!/usr/bin/env node
// Writes THIRD-PARTY-NOTICES: the licence texts of the Rust crates, npm packages and the font
// that are in the program, and fails when one of them has a licence that is not on the allowlist in about.toml.
//
// Usage:
//   node scripts/third-party-notices.mjs --rust server.json --rust wasm.json --out THIRD-PARTY-NOTICES
//   node scripts/third-party-notices.mjs --rust server.json --rust wasm.json --check
// The --rust files are the output of `cargo about generate --format json` (see
// scripts/notices.sh, which runs everything). --check does not write: it fails if the file on disk
// differs from what would be written, which is what CI uses to catch a stale file.
//
// The npm packages are the production dependencies in web/package-lock.json (there are none today:
// the web vault has dev dependencies only); their licence files are read from web/node_modules, so run
// `npm ci` in web/ first.
//
// The vendored web files are the third-party files in web/vendor (listed in web/vendor/MANIFEST.json,
// which the web build checks hash by hash). Each needs an entry under `vendored` in notices-extra.json,
// and the two lists must agree; the licence text is read from the file the entry names. A file that is
// taken from another project keeps its header, and the entry says what was changed ("Modified by
// Faithful Ferret").
//
// Source that was written from other projects (a port of a parser, a reader of another product's file
// format, test data of the same shape) is listed under `adapted`: the origin, the licence, the files,
// and what was changed. Each listed file starts with an SPDX line and "Modified by Faithful Ferret".

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isMain } from "./is-main.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The allowlist: the `accepted` array of about.toml, the single place where it is kept. */
export function acceptedLicenses(aboutToml) {
  const block = /^accepted\s*=\s*\[([^\]]*)\]/m.exec(aboutToml);
  if (!block) throw new Error("about.toml has no `accepted` list.");
  const ids = [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  if (ids.length === 0) throw new Error("The `accepted` list of about.toml is empty.");
  return ids;
}

/**
 * Is an SPDX expression covered by the allowlist? "A OR B" needs one side, "A AND B" needs both,
 * and "WITH" exceptions are part of the identifier ("Apache-2.0 WITH LLVM-exception").
 */
export function licenseAllowed(expression, accepted) {
  const allowed = new Set(accepted);
  const parse = (text) => {
    let stripped = text.trim();
    // Remove one pair of parentheses only when it encloses the whole expression.
    while (stripped.startsWith("(") && closingOf(stripped) === stripped.length - 1) {
      stripped = stripped.slice(1, -1).trim();
    }
    // Split on a top-level operator only.
    for (const operator of [" OR ", " AND "]) {
      const parts = splitTopLevel(stripped, operator);
      if (parts.length > 1) {
        return operator === " OR " ? parts.some(parse) : parts.every(parse);
      }
    }
    return allowed.has(stripped);
  };
  return parse(expression);
}

/** Index of the parenthesis that closes the one at position 0, or -1. */
function closingOf(text) {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

function splitTopLevel(text, operator) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") depth--;
    else if (depth === 0 && text.startsWith(operator, i)) {
      parts.push(text.slice(start, i));
      start = i + operator.length;
      i = start - 1;
    }
  }
  parts.push(text.slice(start));
  return parts;
}

const clean = (text) => text.replace(/\r\n/g, "\n").trim();

/**
 * The vendored web files of `extra.vendored`, checked against web/vendor/MANIFEST.json (`manifest`) and read
 * through `readText` (the licence files, relative to the repository). Throws when the two lists differ, when
 * an entry does not say what was changed, or when a licence text lacks the copyright line or still has a
 * placeholder.
 * @param {{ vendored?: any[] }} extra
 * @param {{ files?: any[] }} manifest
 * @param {(path: string) => string} readText
 */
export function vendoredEntries(extra, manifest, readText) {
  const problems = [];
  const entries = [];
  const listed = new Map((manifest.files ?? []).map((f) => [f.name, f]));
  const seen = new Set();
  for (const v of extra.vendored ?? []) {
    const label = `${v.name} ${v.version}`;
    const m = listed.get(v.name);
    seen.add(v.name);
    if (!m) {
      problems.push(`${label}: notices-extra.json lists a vendored file that web/vendor/MANIFEST.json does not`);
      continue;
    }
    if (m.version !== v.version || m.license !== v.license || m.copyright !== v.copyright || `web/vendor/${m.file}` !== v.file || `web/vendor/${m.licenseFile}` !== v.licenseFile || m.origin !== v.origin) {
      problems.push(`${label}: version, licence, copyright, origin or files differ from web/vendor/MANIFEST.json`);
      continue;
    }
    if (typeof v.note !== "string" || !v.note.includes("Modified by Faithful Ferret")) {
      problems.push(`${label}: the note must say what was changed, starting from "Modified by Faithful Ferret"`);
      continue;
    }
    const text = clean(readText(v.licenseFile));
    if (!text.includes(v.copyright) || hasPlaceholder(text)) {
      problems.push(`${label}: ${v.licenseFile} must hold the copyright line "${v.copyright}" and no licence template placeholder`);
      continue;
    }
    entries.push({ licenseId: v.license, text, packages: [{ label, url: v.origin }], file: v.file, note: v.note });
  }
  for (const name of listed.keys()) {
    if (!seen.has(name)) problems.push(`${name}: web/vendor/MANIFEST.json lists a file that notices-extra.json has no entry for`);
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return entries;
}

/** The terms of a GNU licence text without the how-to-apply appendix (which has a `<year>` template in it). */
export function licenceTerms(text) {
  const end = text.indexOf("END OF TERMS AND CONDITIONS");
  return end < 0 ? text : text.slice(0, end + "END OF TERMS AND CONDITIONS".length).trim();
}

/**
 * The adapted source of `extra.adapted`: files of this repository that were written from, or taken and changed
 * from, another project (its code, its formats, its test shapes). Each entry names the origin, the licence and
 * the files; each file must exist and start with an SPDX line and "Modified by Faithful Ferret"; the licence
 * text is read from `licenseFile`. Throws when an entry is incomplete, a file lacks its header, or the note does
 * not say what was changed.
 * @param {{ adapted?: any[] }} extra
 * @param {(path: string) => string} readText
 */
export function adaptedEntries(extra, readText) {
  const problems = [];
  const entries = [];
  for (const a of extra.adapted ?? []) {
    const label = a.name ?? "(no name)";
    const given = (key) => typeof a[key] === "string" && a[key].trim() !== "";
    if (!["name", "origin", "source", "license", "licenseFile", "copyright", "note"].every(given) || !Array.isArray(a.files) || a.files.length === 0) {
      problems.push(`${label}: an adapted entry needs name, origin, source, license, licenseFile, copyright, note and files`);
      continue;
    }
    if (!a.note.includes("Modified by Faithful Ferret")) {
      problems.push(`${label}: the note must say what was changed, starting from "Modified by Faithful Ferret"`);
      continue;
    }
    let broken = false;
    for (const file of a.files) {
      let head;
      try {
        head = readText(file).slice(0, 4000);
      } catch {
        problems.push(`${label}: ${file} is listed and does not exist`);
        broken = true;
        continue;
      }
      if (!/SPDX-License-Identifier:\s*\S+/.test(head) || !head.includes("Modified by Faithful Ferret")) {
        problems.push(`${label}: ${file} must start with an SPDX-License-Identifier line and "Modified by Faithful Ferret"`);
        broken = true;
      }
    }
    if (broken) continue;
    const terms = licenceTerms(clean(readText(a.licenseFile)));
    if (terms === "" || hasPlaceholder(terms)) {
      problems.push(`${label}: ${a.licenseFile} is empty or has a licence template placeholder`);
      continue;
    }
    entries.push({ licenseId: a.license, text: terms, label, origin: a.origin, source: a.source, copyright: a.copyright, files: a.files, note: a.note });
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return entries;
}

/**
 * A licence template that was never filled in. cargo-about writes the bare SPDX template when it
 * finds no licence file for a crate, and a template is not a copyright notice: MIT and the BSD
 * licences want the copyright notice reproduced. The Apache-2.0 appendix has its own
 * "[yyyy] [name of copyright owner]" boilerplate, which is not matched here. The templates write
 * their blanks in angle brackets (SPDX), square brackets (the GitHub MIT template: "[year]
 * [fullname]") or curly brackets.
 */
export const PLACEHOLDER = /[<[{](?:year|fullname|owner|copyright holders?|name of author|organi[sz]ation)[>\]}]/i;

export function hasPlaceholder(text) {
  return PLACEHOLDER.test(text);
}

/** Puts the copyright holder where the template has its placeholders. */
export function fillTemplate(text, holder) {
  return text.replace(/[<[{]year[>\]}]\s+[<[{](?:fullname|copyright holders?|owner|name of author)[>\]}]/gi, () => holder);
}

/** Replaces the whole line that has a placeholder by the given notice lines. */
export function fillLines(text, lines) {
  return text
    .split("\n")
    .flatMap((line) => (hasPlaceholder(line) ? lines : [line]))
    .join("\n");
}

/**
 * Reads the `licenses` of cargo-about JSON files into [{ licenseId, text, packages: [label] }].
 *
 * A licence text that still has a placeholder is filled only from `extra.copyright` (notices-extra.json),
 * for the exact crate name and version. A crate without such an entry, an entry whose crate
 * authors differ from the recorded ones, and an entry that no crate needs are all errors.
 */
export function rustEntries(reports, extra = { copyright: [] }) {
  const entries = [];
  const problems = [];
  const wanted = new Map((extra.copyright ?? []).map((c) => [`${c.name} ${c.version}`, c]));
  const used = new Set();
  const asPackage = (crate) => ({ label: `${crate.name} ${crate.version}`, url: crate.repository ?? "" });
  for (const report of reports) {
    for (const license of report.licenses) {
      const text = clean(license.text);
      if (!hasPlaceholder(text)) {
        entries.push({ licenseId: license.id, text, packages: license.used_by.map(({ crate }) => asPackage(crate)) });
        continue;
      }
      for (const { crate } of license.used_by) {
        const key = `${crate.name} ${crate.version}`;
        const entry = wanted.get(key);
        if (!entry) {
          problems.push(`${key} (${license.id}) has no copyright notice, only a licence template. Clarify it in about.toml or add it to notices-extra.json.`);
          continue;
        }
        used.add(key);
        if (entry.license !== license.id) {
          problems.push(`${key}: notices-extra.json says ${entry.license} but the licence is ${license.id}`);
          continue;
        }
        if (entry.basis === "authors") {
          const have = JSON.stringify(crate.authors ?? []);
          if (have !== JSON.stringify(entry.authors) || entry.holder !== entry.authors.join(", ") || entry.authors.length === 0) {
            problems.push(`${key}: the authors in the crate (${have}) are not the ones in notices-extra.json`);
            continue;
          }
        } else if (entry.basis !== "repository" || !(entry.holder || entry.notice?.length) || !entry.source) {
          problems.push(`${key}: an entry of notices-extra.json needs basis "authors", or basis "repository" with holder (or notice lines) and source`);
          continue;
        }
        // Lines of the notice that are taken from a file of the crate must be in that file.
        const missing = (entry.verify ?? []).filter((v) => {
          const path = join(dirname(crate.manifest_path ?? ""), v.file);
          return !crate.manifest_path || !existsSync(path) || !readFileSync(path, "utf8").includes(v.contains);
        });
        if (missing.length > 0) {
          problems.push(`${key}: ${missing.map((v) => `"${v.contains}" is not in ${v.file} of the crate`).join(", ")}`);
          continue;
        }
        if (entry.basis === "repository" && entry.authors && JSON.stringify(crate.authors ?? []) !== JSON.stringify(entry.authors)) {
          problems.push(`${key}: the authors in the crate (${JSON.stringify(crate.authors ?? [])}) are not the ones in notices-extra.json`);
          continue;
        }
        const filled = entry.notice?.length ? fillLines(text, entry.notice) : fillTemplate(text, entry.holder);
        if (hasPlaceholder(filled)) {
          problems.push(`${key}: the licence template has a placeholder that notices-extra.json can not fill`);
          continue;
        }
        entries.push({ licenseId: license.id, text: filled, packages: [asPackage(crate)] });
      }
    }
  }
  for (const key of wanted.keys()) {
    if (!used.has(key)) problems.push(`notices-extra.json has an entry for ${key} that no crate needs (the version changed, or it is clarified now). Remove or update it.`);
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return entries;
}

/**
 * The production npm packages of a package-lock.json, with licence files read from node_modules.
 * Throws for a licence that is not allowed and for a package without a licence text.
 */
export function npmEntries(lock, accepted, projectRoot) {
  const entries = [];
  const problems = [];
  for (const [path, info] of Object.entries(lock.packages ?? {})) {
    if (!path.startsWith("node_modules/") || info.dev || info.devOptional) continue;
    const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    const label = `${name} ${info.version}`;
    const expression = info.license ?? "";
    if (!licenseAllowed(expression, accepted)) {
      problems.push(`${label} has the licence "${expression || "(none)"}", which is not on the allowlist in about.toml`);
      continue;
    }
    // The lock path itself, so a package nested below another one reads its own files.
    const folder = join(projectRoot, path);
    const files = existsSync(folder)
      ? readdirSync(folder).filter((f) => /^(licen[cs]e|copying|notice)([-._].*)?$/i.test(f)).sort()
      : [];
    if (files.length === 0) {
      problems.push(`${label}: no licence file found in ${folder} (run npm ci)`);
      continue;
    }
    for (const file of files) {
      entries.push({
        licenseId: expression,
        text: clean(readFileSync(join(folder, file), "utf8")),
        packages: [{ label, url: "" }],
      });
    }
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return entries;
}

/** Groups entries with the same text, so a licence that many crates share is written once. */
export function group(entries) {
  const byText = new Map();
  for (const entry of entries) {
    const found = byText.get(entry.text) ?? { text: entry.text, ids: new Set(), packages: new Map() };
    found.ids.add(entry.licenseId);
    for (const p of entry.packages) found.packages.set(p.label, p.url);
    byText.set(entry.text, found);
  }
  return [...byText.values()]
    .map((g) => ({ text: g.text, ids: [...g.ids].sort(), packages: [...g.packages].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)) }))
    .sort((a, b) => {
      const key = (g) => `${g.ids.join(" ")}\n${g.packages[0][0]}`;
      return key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;
    });
}

const RULE = "=".repeat(78);

function section(title, groups) {
  const count = new Set(groups.flatMap((g) => g.packages.map(([label]) => label))).size;
  const lines = [RULE, `${title} (${count} packages)`, RULE, ""];
  for (const g of groups) {
    lines.push(`--- ${g.ids.join(", ")} ---`, "", "Used by:");
    for (const [label, url] of g.packages) lines.push(url ? `  ${label} (${url})` : `  ${label}`);
    lines.push("", g.text, "", "");
  }
  return lines.join("\n");
}

const block = (title, lines, text) => [RULE, title, RULE, "", ...lines, "", text, "", ""].join("\n");

/** The whole file. Same input, same text: no dates, no paths. */
export function render({ product, intro = [], rust, npm = [], vendored = [], fontLicense, adapted = [] }) {
  const head = [
    "THIRD-PARTY NOTICES",
    "",
    `${product} is free software under the GNU Affero General Public License,`,
    "version 3 (see the file LICENSE). It contains the third-party software listed below.",
    "Each section gives the licence text and the packages it applies to.",
    "",
    "This file is made by scripts/notices.sh from the dependencies of the program. Do not edit it.",
    "",
    ...intro.flatMap((paragraph) => [...paragraph, ""]),
    "",
  ].join("\n");
  const parts = [head, section("Rust crates", group(rust))];
  if (npm.length > 0) parts.push(section("npm packages", group(npm)));
  if (vendored.length > 0) {
    const lines = [RULE, `Web vault files from other projects (${vendored.length} ${vendored.length === 1 ? "file" : "files"})`, RULE, ""];
    for (const v of vendored) {
      lines.push(`--- ${v.licenseId} ---`, "", "Used by:", `  ${v.packages[0].label} (${v.packages[0].url})`, `  file: ${v.file}`, `  ${v.note}`, "", v.text, "", "");
    }
    parts.push(lines.join("\n"));
  }
  if (fontLicense) {
    parts.push(
      block(
        "Inter (font)",
        [
          "The web vault in the server image carries a Latin subset of the Inter font",
          "(web/fonts/InterVariable-Latin.woff2).",
          "Copyright (c) 2016 The Inter Project Authors (https://github.com/rsms/inter), SIL Open Font License 1.1:",
        ],
        clean(fontLicense),
      ),
    );
  }
  if (adapted.length > 0) {
    const lines = [RULE, `Source written from other projects (${adapted.length} ${adapted.length === 1 ? "entry" : "entries"})`, RULE, ""];
    for (const a of adapted) {
      lines.push(a.label, `  Origin: ${a.origin}`, `  Source: ${a.source}`, `  Licence: ${a.licenseId}`, `  Copyright: ${a.copyright}`, `  Files: ${a.files.join(", ")}`, `  ${a.note}`, "");
    }
    // Each licence text once, in the order the entries name them.
    const seen = new Set();
    for (const a of adapted) {
      if (seen.has(a.licenseId)) continue;
      seen.add(a.licenseId);
      lines.push(`--- ${a.licenseId} ---`, "", a.text, "", "");
    }
    parts.push(lines.join("\n"));
  }
  const text = parts.join("").replace(/\n+$/, "\n");
  if (hasPlaceholder(text)) throw new Error("THIRD-PARTY-NOTICES would contain an unfilled licence template (<year>, <owner> or <copyright holders>).");
  return text;
}

function parseArgs(argv) {
  const options = { rust: [], out: null, check: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--rust") options.rust.push(argv[++i]);
    else if (argv[i] === "--out") options.out = argv[++i];
    else if (argv[i] === "--check") options.check = true;
    else throw new Error(`Unknown argument ${argv[i]}`);
  }
  if (options.rust.length === 0) throw new Error("Give at least one --rust <cargo-about json>.");
  if (!options.check && !options.out) throw new Error("Give --out <file> or --check.");
  return options;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const accepted = acceptedLicenses(readFileSync(join(root, "about.toml"), "utf8"));
  const extra = JSON.parse(readFileSync(join(root, "notices-extra.json"), "utf8"));
  const reports = options.rust.map((file) => JSON.parse(readFileSync(file, "utf8")));
  const optional = (file) => (existsSync(join(root, file)) ? readFileSync(join(root, file), "utf8") : null);
  // The web vault has no runtime npm dependencies today; if one is added, its licence is checked and listed.
  const lockText = optional("web/package-lock.json");
  const fontLicense = extra.fontLicenseFile ? readFileSync(join(root, extra.fontLicenseFile), "utf8") : null;
  const text = render({
    product: extra.product,
    intro: extra.intro,
    rust: rustEntries(reports, extra),
    npm: lockText ? npmEntries(JSON.parse(lockText), accepted, join(root, "web")) : [],
    vendored: vendoredEntries(extra, JSON.parse(optional("web/vendor/MANIFEST.json") ?? '{"files":[]}'), (path) => readFileSync(join(root, path), "utf8")),
    fontLicense,
    adapted: adaptedEntries(extra, (path) => readFileSync(join(root, path), "utf8")),
  });
  const target = join(root, options.out ?? "THIRD-PARTY-NOTICES");
  if (options.check) {
    const current = existsSync(target) ? readFileSync(target, "utf8").replace(/\r\n/g, "\n") : "";
    if (current !== text) {
      console.error("THIRD-PARTY-NOTICES is out of date. Run scripts/notices.sh and commit the result.");
      process.exit(1);
    }
    console.log("THIRD-PARTY-NOTICES is up to date.");
  } else {
    writeFileSync(target, text);
    console.log(`Wrote ${target} (${text.length} characters).`);
  }
}

if (isMain(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`ERROR: ${error.message}`);
    process.exit(1);
  }
}
