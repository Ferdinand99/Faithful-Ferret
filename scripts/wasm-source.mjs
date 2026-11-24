#!/usr/bin/env node
// Which WebAssembly package CI tests the web vault and the extension against: `tree` (built from
// the commit under test, scripts/wasm-tree.sh) or `lock` (the published package named in
// web/wasm.lock.json).
//
//   node scripts/wasm-source.mjs [<repository root>]     prints tree or lock
//
// The client code (web/, extension/) calls the bindings of the core in the same tree. While the
// package that the lock names is older than the core in the tree, a build against that package
// cannot run the code under test, so CI builds the package from the tree: `tree` when the version
// of the lock is lower than the workspace version of Cargo.toml, `lock` otherwise (the lock has
// caught up: the pin pull request that follows a release). Release builds do not use this: they
// take the locked package, or the package of their own release run, and nothing else.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** @param {string} version @returns {[number, number, number]} */
function parse(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) throw new Error(`wasm-source: '${version}' is not a version like 1.2.3`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** The workspace version of a Cargo.toml. @param {string} text @returns {string} */
export function workspaceVersion(text) {
  const section = /^\[workspace\.package\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(text);
  const version = section && /^version\s*=\s*"([^"]+)"\s*$/m.exec(section[1]);
  if (!version) throw new Error("wasm-source: Cargo.toml has no [workspace.package] version");
  return version[1];
}

/**
 * `tree` when the locked package is older than the core in the tree, otherwise `lock`.
 * @param {string} lockVersion the version in web/wasm.lock.json
 * @param {string} treeVersion the workspace version
 * @returns {"tree" | "lock"}
 */
export function chooseSource(lockVersion, treeVersion) {
  const lock = parse(lockVersion);
  const tree = parse(treeVersion);
  for (let i = 0; i < 3; i++) {
    if (lock[i] !== tree[i]) return lock[i] < tree[i] ? "tree" : "lock";
  }
  return "lock";
}

/** @param {string} root the repository root @returns {"tree" | "lock"} */
export function sourceFor(root) {
  const lock = JSON.parse(readFileSync(join(root, "web", "wasm.lock.json"), "utf8"));
  return chooseSource(String(lock.version), workspaceVersion(readFileSync(join(root, "Cargo.toml"), "utf8")));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), ".."));
  try {
    console.log(sourceFor(root));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
