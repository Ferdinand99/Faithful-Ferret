import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "./test-support.mjs";
import {
  acceptedLicenses,
  fillLines,
  fillTemplate,
  group,
  hasPlaceholder,
  licenseAllowed,
  npmEntries,
  render,
  rustEntries,
} from "./third-party-notices.mjs";

const accepted = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause"];
const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");

const dirs = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));
function folder(files = {}) {
  const dir = mkdtempSync(join(tmpdir(), "notices-"));
  dirs.push(dir);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  return dir;
}

describe("acceptedLicenses", () => {
  it("reads the list", () => {
    expect(acceptedLicenses('x = 1\naccepted = [\n  "MIT", # note\n  "Apache-2.0",\n]\n')).toEqual(["MIT", "Apache-2.0"]);
  });
  it("refuses a missing or empty list", () => {
    expect(() => acceptedLicenses("targets = []")).toThrow(/no `accepted`/);
    expect(() => acceptedLicenses("accepted = []")).toThrow(/empty/);
  });
});

describe("the allowlists", () => {
  // The licences of the two cargo-deny policies: the root graph (the WebAssembly binding) and the server.
  const denyAllow = (file) => {
    const block = /\[licenses\][^[]*?allow\s*=\s*\[([^\]]*)\]/s.exec(read(file));
    return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  };
  const denyFiles = ["deny.toml", "crates/ferret-server/deny.toml"];
  it("has every licence that a cargo-deny policy allows, except the one of our own crates", () => {
    const accepted = acceptedLicenses(read("about.toml"));
    for (const file of denyFiles) {
      for (const id of denyAllow(file)) {
        if (id !== "AGPL-3.0-only") expect(accepted, `${id} of ${file}`).toContain(id);
      }
    }
  });
  it("has no licence that is incompatible with the AGPL", () => {
    // OpenSSL has an advertising clause that the FSF calls incompatible with the GPL family.
    for (const id of ["OpenSSL", "OpenSSL-standalone", "SSLeay", "BUSL-1.1", "GPL-2.0-only", "SSPL-1.0"]) {
      expect(acceptedLicenses(read("about.toml"))).not.toContain(id);
      for (const file of denyFiles) expect(denyAllow(file)).not.toContain(id);
    }
  });
});

describe("licenseAllowed", () => {
  it.each([
    ["MIT", true],
    ["MIT OR Apache-2.0", true],
    ["GPL-3.0-only OR MIT", true],
    ["GPL-3.0-only OR LGPL-2.1", false],
    ["MIT AND Apache-2.0", true],
    ["MIT AND GPL-3.0-only", false],
    ["(MIT OR GPL-3.0-only) AND BSD-3-Clause", true],
    ["(GPL-3.0-only OR LGPL-2.1) AND MIT", false],
    ["MIT OR GPL-3.0-only AND LGPL-2.1", true],
    ["Apache-2.0 WITH LLVM-exception", true],
    ["Apache-2.0 WITH Other-exception", false],
    ["(MIT)", true],
    ["", false],
    ["SEE LICENSE IN LICENSE.txt", false],
  ])("%s -> %s", (expression, expected) => {
    expect(licenseAllowed(expression, accepted)).toBe(expected);
  });
});

describe("placeholders", () => {
  it.each([
    "Copyright (c) <year> <owner>.",
    "Copyright (c) <year> <copyright holders>",
    "<YEAR> <Copyright Holder>",
    "by <name of author>",
    "Copyright (c) [year] [fullname]",
    "Copyright (c) {year} {fullname}",
    "Copyright (c) {year} {owner}",
    "Copyright (c) [YEAR] [Copyright Holders]",
  ])("finds %s", (text) => expect(hasPlaceholder(text)).toBe(true));
  it("does not mind the boilerplate at the end of the Apache licence", () => {
    expect(hasPlaceholder("Copyright [yyyy] [name of copyright owner]\n\nLicensed under the Apache License")).toBe(false);
    expect(hasPlaceholder("Copyright {yyyy} {name of copyright owner}")).toBe(false);
  });
  it("fills the other forms, and a whole line with notice lines", () => {
    expect(fillTemplate("Copyright (c) [year] [fullname]\n\nx", "A B")).toBe("Copyright (c) A B\n\nx");
    expect(fillTemplate("Copyright (c) {year} {fullname}", "A B")).toBe("Copyright (c) A B");
    expect(fillLines("a\nCopyright (c) <year> <owner>\nb", ["L1", "L2"])).toBe("a\nL1\nL2\nb");
  });
  it("is filled with the holder", () => {
    expect(fillTemplate("Copyright (c) <year> <copyright holders>\n\nPermission", "A B")).toBe("Copyright (c) A B\n\nPermission");
    expect(fillTemplate("Copyright (c) <year> <owner>.", "A B")).toBe("Copyright (c) A B.");
  });
  it("is not in the notices file of the repository", () => {
    expect(hasPlaceholder(read("THIRD-PARTY-NOTICES"))).toBe(false);
  });
});

describe("rustEntries and group", () => {
  const crate = (name, version, extra = {}) => ({ name, version, repository: `https://x/${name}`, authors: [], ...extra });
  const report = (id, text, crates) => ({ licenses: [{ id, text, used_by: crates.map((c) => ({ crate: c })) }] });
  it("joins crates with the same text and keeps the order stable", () => {
    const a = report("MIT", "MIT text\r\n", [crate("zeta", "1.0.0"), crate("alpha", "2.0.0")]);
    const b = report("MIT", "MIT text", [crate("alpha", "2.0.0")]);
    const c = report("Zlib", "Zlib text", [crate("flate", "0.1.0")]);
    const groups = group(rustEntries([a, b, c]));
    expect(groups).toHaveLength(2);
    expect(groups[0].ids).toEqual(["MIT"]);
    expect(groups[0].packages.map(([label]) => label)).toEqual(["alpha 2.0.0", "zeta 1.0.0"]);
    expect(group(rustEntries([c, b, a]))).toEqual(groups);
  });

  const template = "Copyright (c) <year> <copyright holders>\n\nPermission is hereby granted";
  const entry = (extra = {}) => ({ name: "c", version: "1.0.0", license: "MIT", basis: "authors", authors: ["A <a@x>"], holder: "A <a@x>", ...extra });
  it("fails for a crate that has only a licence template", () => {
    const r = report("MIT", template, [crate("c", "1.0.0")]);
    expect(() => rustEntries([r])).toThrow(/c 1.0.0 \(MIT\) has no copyright notice, only a licence template/);
  });
  it("fills the template from notices-extra.json when the crate authors are the recorded ones", () => {
    const r = report("MIT", template, [crate("c", "1.0.0", { authors: ["A <a@x>"] })]);
    const entries = rustEntries([r], { copyright: [entry()] });
    expect(entries).toHaveLength(1);
    expect(entries[0].text).toBe("Copyright (c) A <a@x>\n\nPermission is hereby granted");
  });
  it("refuses an entry when the authors changed, the version changed or the crate does not need it", () => {
    const r = report("MIT", template, [crate("c", "1.0.0", { authors: ["B <b@x>"] })]);
    expect(() => rustEntries([r], { copyright: [entry()] })).toThrow(/authors in the crate/);
    const v2 = report("MIT", template, [crate("c", "2.0.0", { authors: ["A <a@x>"] })]);
    expect(() => rustEntries([v2], { copyright: [entry()] })).toThrow(/c 2.0.0 .* has no copyright notice/);
    const clarified = report("MIT", "Copyright (c) 2020 Real Holder", [crate("c", "1.0.0")]);
    expect(() => rustEntries([clarified], { copyright: [entry()] })).toThrow(/no crate needs/);
  });
  it("takes a repository entry only with holder and source", () => {
    const r = report("MIT", template, [crate("c", "1.0.0")]);
    const repo = { name: "c", version: "1.0.0", license: "MIT", basis: "repository", holder: "The C project" };
    expect(() => rustEntries([r], { copyright: [repo] })).toThrow(/needs basis/);
    expect(rustEntries([r], { copyright: [{ ...repo, source: "https://x/c" }] })[0].text).toContain("Copyright (c) The C project");
  });
  it("takes notice lines that are in a file of the crate, and refuses lines that are not", () => {
    const dir = folder({ "build.rs": "// Copyright 2021, X Developers\n// Copyright 2022, Y Developers\n" });
    const r = report("MIT", template, [crate("c", "1.0.0", { authors: ["A <a@x>"], manifest_path: join(dir, "Cargo.toml") })]);
    const notice = {
      name: "c",
      version: "1.0.0",
      license: "MIT",
      basis: "repository",
      authors: ["A <a@x>"],
      notice: ["Copyright 2021, X Developers", "Copyright 2022, Y Developers", "Copyright (c) A <a@x>"],
      source: "build.rs",
      verify: [{ file: "build.rs", contains: "Copyright 2021, X Developers" }],
    };
    expect(rustEntries([r], { copyright: [notice] })[0].text).toBe(
      "Copyright 2021, X Developers\nCopyright 2022, Y Developers\nCopyright (c) A <a@x>\n\nPermission is hereby granted",
    );
    const wrong = { ...notice, verify: [{ file: "build.rs", contains: "Copyright 1999, Z" }] };
    expect(() => rustEntries([r], { copyright: [wrong] })).toThrow(/is not in build.rs of the crate/);
    const otherAuthors = { ...notice, authors: ["B <b@x>"] };
    expect(() => rustEntries([r], { copyright: [otherAuthors] })).toThrow(/authors in the crate/);
  });
  it("does not touch the Apache boilerplate and real notices", () => {
    const apache = report("Apache-2.0", "Copyright [yyyy] [name of copyright owner]", [crate("d", "1.0.0")]);
    expect(rustEntries([apache])).toHaveLength(1);
  });
});

describe("the real notices-extra.json", () => {
  const extra = JSON.parse(read("notices-extra.json"));
  it("has a holder for every entry, and authors that give the holder", () => {
    for (const c of extra.copyright) {
      expect(c.holder || c.notice?.length, c.name).toBeTruthy();
      if (c.basis === "authors") expect(c.authors.join(", ")).toBe(c.holder);
      else expect(c.source, c.name).toBeTruthy();
    }
  });
  it("names the product and a font licence file that is in the repository", () => {
    expect(extra.product).toBeTruthy();
    if (extra.fontLicenseFile) expect(read(extra.fontLicenseFile)).toContain("SIL OPEN FONT LICENSE");
  });
});

describe("npmEntries", () => {
  const lock = (packages) => ({ packages: { "": {}, ...packages } });

  it("takes production packages with their licence files, and skips dev packages", () => {
    const dir = folder({ "node_modules/a/LICENSE": "A licence", "node_modules/a/package.json": "{}", "node_modules/dev/LICENSE": "x" });
    const entries = npmEntries(
      lock({
        "node_modules/a": { version: "1.0.0", license: "MIT" },
        "node_modules/dev": { version: "1.0.0", license: "GPL-3.0-only", dev: true },
      }),
      accepted,
      dir,
    );
    expect(entries).toHaveLength(1);
    expect(entries[0].packages[0].label).toBe("a 1.0.0");
  });
  it("fails for a licence that is not allowed", () => {
    const dir = folder({ "node_modules/a/LICENSE": "A licence" });
    expect(() => npmEntries(lock({ "node_modules/a": { version: "1.0.0", license: "GPL-3.0-only" } }), accepted, dir)).toThrow(
      /a 1.0.0 has the licence "GPL-3.0-only"/,
    );
  });
  it("fails for a package with no licence file", () => {
    const dir = folder({ "node_modules/a/package.json": "{}" });
    expect(() => npmEntries(lock({ "node_modules/a": { version: "1.0.0", license: "MIT" } }), accepted, dir)).toThrow(/no licence file/);
  });
  it("reads scoped packages and several licence files", () => {
    const dir = folder({
      "node_modules/@s/p/LICENSE_MIT": "mit",
      "node_modules/@s/p/LICENSE_APACHE-2.0": "apache",
      "node_modules/@s/p/README.md": "no",
    });
    const entries = npmEntries(lock({ "node_modules/@s/p": { version: "2.0.0", license: "Apache-2.0 OR MIT" } }), accepted, dir);
    expect(entries.map((e) => e.text).sort()).toEqual(["apache", "mit"]);
  });
  it("reads a nested package from its own folder, not from the top one", () => {
    const dir = folder({
      "node_modules/b/LICENSE": "top b",
      "node_modules/a/node_modules/b/LICENSE": "nested b",
    });
    const entries = npmEntries(
      lock({
        "node_modules/b": { version: "1.0.0", license: "MIT" },
        "node_modules/a/node_modules/b": { version: "2.0.0", license: "MIT" },
      }),
      accepted,
      dir,
    );
    expect(entries.find((e) => e.packages[0].label === "b 2.0.0").text).toBe("nested b");
    expect(entries.find((e) => e.packages[0].label === "b 1.0.0").text).toBe("top b");
  });
});

describe("render", () => {
  const rust = rustEntries([{ licenses: [{ id: "MIT", text: "MIT text", used_by: [{ crate: { name: "a", version: "1.0.0" } }] }] }]);
  it("is the same for the same input and ends with one newline", () => {
    const input = { product: "Faithful Ferret", rust, npm: [], fontLicense: "OFL text" };
    const text = render(input);
    expect(render(input)).toBe(text);
    expect(text.endsWith("\n")).toBe(true);
    expect(text.endsWith("\n\n")).toBe(false);
    expect(text).toContain("a 1.0.0");
    expect(text).toContain("OFL text");
    expect(text).toContain("Faithful Ferret is free software");
  });
  it("fails when any text still has a placeholder, wherever it came from", () => {
    expect(() => render({ product: "P", rust, npm: [{ licenseId: "MIT", text: "Copyright <year> <owner>", packages: [{ label: "n 1", url: "" }] }], fontLicense: "x" })).toThrow(
      /unfilled licence template/,
    );
  });
});

describe("notices.sh", () => {
  it("runs cargo-about with --fail, so a crate without a readable licence stops the build", () => {
    const script = read("scripts/notices.sh");
    const commands = script.split("cargo about generate").slice(1);
    expect(commands).toHaveLength(2);
    for (const c of commands) expect(c.split("\n")[0] + c.split("\n")[1]).toContain("--fail");
  });
});
