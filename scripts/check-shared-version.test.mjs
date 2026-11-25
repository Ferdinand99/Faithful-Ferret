import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { check, tomlVersion } from "./check-shared-version.mjs";
import { afterEach, describe, expect, it } from "./test-support.mjs";

const dirs = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

function tree({ manifest = "0.12.0", workspace = "0.12.0", server = "0.12.0", pkg = "0.12.0", lock = "0.12.0", lockRoot = "0.12.0" } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "shared-version-"));
  dirs.push(dir);
  const files = {
    ".release-please-manifest.json": JSON.stringify({ ".": manifest }),
    "Cargo.toml": `[workspace]\nmembers = []\n\n[workspace.package]\nedition = "2024"\nversion = "${workspace}"\n`,
    "crates/ferret-server/Cargo.toml": `[package]\nname = "ferret-server"\nversion = "${server}"\n\n[dependencies]\nserde = { version = "1" }\n`,
    "extension/package.json": JSON.stringify({ name: "ferret-extension", version: pkg }),
    "extension/package-lock.json": JSON.stringify({ name: "ferret-extension", version: lock, packages: { "": { version: lockRoot } } }),
  };
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  return dir;
}

describe("tomlVersion", () => {
  it("reads the version of the named table only", () => {
    const text = '[package]\nname = "a"\nversion = "1.2.3"\n\n[dependencies]\nversion = "9"\n';
    expect(tomlVersion(text, "package")).toBe("1.2.3");
    expect(tomlVersion(text, "dependencies")).toBe("9");
    expect(tomlVersion(text, "workspace.package")).toBe(null);
  });
  it("ignores a dependency's inline version", () => {
    expect(tomlVersion('[package]\nname = "a"\n[dependencies]\nx = { version = "1" }\n', "package")).toBe(null);
  });
});

describe("check", () => {
  it("passes when the server and the extension have the same version", () => {
    expect(check(tree())).toEqual([]);
  });
  it.each([["manifest"], ["workspace"], ["server"], ["pkg"], ["lock"], ["lockRoot"]])("fails when %s differs", (key) => {
    const problems = check(tree({ [key]: "0.9.1" }));
    expect(problems.length > 0).toBe(true);
    expect(problems.join("\n")).toContain("0.9.1");
  });
  it("fails on a missing version", () => {
    const dir = tree();
    writeFileSync(join(dir, "extension/package.json"), JSON.stringify({ name: "x" }));
    expect(check(dir)).toContain("extension/package.json: no version found");
  });
});
