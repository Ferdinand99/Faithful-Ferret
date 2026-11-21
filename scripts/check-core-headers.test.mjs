import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ALLOWED, check, checkIncludes, foreignNotices, GUARDED, scannedFiles } from "./check-core-headers.mjs";
import { afterEach, describe, expect, it } from "./test-support.mjs";

const dirs = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));
function tree(files) {
  const dir = mkdtempSync(join(tmpdir(), "headers-"));
  dirs.push(dir);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  return dir;
}

describe("foreignNotices", () => {
  it("finds a copyright line, a licence header and an SPDX line of someone else", () => {
    expect(foreignNotices("// Copyright (c) 2020 Someone Else\nfn main() {}\n")).toHaveLength(1);
    expect(foreignNotices("/* Copyright 2021 Bitwarden Inc. */")).toHaveLength(1);
    expect(foreignNotices("// SPDX-License-Identifier: GPL-3.0-only\n")).toHaveLength(1);
    expect(foreignNotices("// Licensed under the Apache License, Version 2.0\n")).toHaveLength(1);
    expect(foreignNotices("// Permission is hereby granted, free of charge, to any person\n")).toHaveLength(1);
    expect(foreignNotices("// All rights reserved.\n")).toHaveLength(1);
  });
  it("finds the header form that the taking rule produces: the source's copyright, SPDX and the Modified line", () => {
    const taken = "// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (c) 2024 AliasVault\n// Modified by Faithful Ferret: ported\nfn a() {}\n";
    expect(foreignNotices(taken).map((f) => f.line)).toEqual([1, 2, 3]);
    const block = "/*\n * Copyright (C) 2023 Bitwarden Inc.\n * Modified by Faithful Ferret\n */\n";
    expect(foreignNotices(block).map((f) => f.line)).toEqual([2, 3]);
    // The marker alone is enough in a guarded folder, whoever the holder is.
    expect(foreignNotices("// Modified by Faithful Ferret: changed a line\n")).toHaveLength(1);
    // An own copyright line does not make the marker, or a foreign SPDX line next to it, pass.
    expect(foreignNotices("// Copyright (c) 2026 Faithful Ferret\n// Modified by Faithful Ferret\n").map((f) => f.line)).toEqual([2]);
    expect(foreignNotices("// SPDX-License-Identifier: GPL-3.0-only\n// Modified by Faithful Ferret\n// Copyright (c) 2026 Faithful Ferret\n").map((f) => f.line)).toEqual([1, 2]);
  });
  it("finds more header forms: no year, REUSE, GPL family, MPL, Apache and @license", () => {
    for (const header of [
      "// Copyright Bitwarden Inc.",
      "// SPDX-FileCopyrightText: 2024 Someone <a@b.example>",
      "// SPDX-License-Identifier: AGPL-3.0-or-later",
      "// SPDX-License-Identifier: LGPL-2.1-only",
      "// SPDX-License-Identifier: MPL-2.0",
      "// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.",
      "// You should have received a copy of the GNU General Public License along with this program.",
      "// GNU Affero General Public License",
      "// GNU Lesser General Public License",
      "/** @license MIT */",
      "// License: AGPL-3.0-or-later",
      "// (c) 2020 Someone",
      "// © 2021 Someone",
      "// Licensed under the Apache License",
      "// This file is part of Vaultwarden",
    ]) {
      expect(foreignNotices(`${header}\n`), header).toHaveLength(1);
    }
  });
  it("lets only a copyright line that names this project as the holder through, and an SPDX line next to one", () => {
    expect(foreignNotices("// Copyright (c) 2026 Faithful Ferret\n")).toHaveLength(0);
    expect(foreignNotices("// Copyright the Hedgerow authors\n")).toHaveLength(0);
    expect(foreignNotices("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (c) 2026 Faithful Ferret\n")).toHaveLength(0);
    expect(foreignNotices("// Copyright (c) 2026 Faithful Ferret\n//\n// SPDX-License-Identifier: AGPL-3.0-only\n")).toHaveLength(0);
    // The project name nearby does not help another holder's line.
    expect(foreignNotices("// Faithful Ferret\n// Copyright (c) 2024 AliasVault\n")).toHaveLength(1);
    // An SPDX line alone is not enough.
    expect(foreignNotices("// SPDX-License-Identifier: AGPL-3.0-only\nfn a() {}\n")).toHaveLength(1);
  });
  it("finds nothing in ordinary code, and reports the line number", () => {
    expect(foreignNotices("fn copy() {}\n// the copyright of a key is not a thing\n")).toHaveLength(0);
    expect(foreignNotices("a\nb\n// (c) text\n// Copyright (c) 2019 X\n")[0].line).toBe(4);
  });
});

describe("check", () => {
  it("fails for a file in a guarded folder and passes for the same file elsewhere", () => {
    const header = "// Copyright (c) Project Nayuki. (MIT License)\n";
    const base = tree({ "crates/ferret-core/src/a.rs": header, "web/vendor/b.mjs": header, "crates/ferret-core/src/ok.rs": "fn ok() {}\n" });
    const found = check(["crates/ferret-core"], base);
    expect(found).toHaveLength(1);
    expect(found[0].file).toBe("crates/ferret-core/src/a.rs");
    expect(check(["web"], base)).toHaveLength(1);
    expect(check(["crates/ferret-server"], base)).toHaveLength(0);
  });
  it("skips build output and binary files", () => {
    const base = tree({ "crates/ferret-core/target/x.rs": "// Copyright (c) 2020 X\n", "crates/ferret-core/a.bin": "\u0000Copyright (c) 2020 X" });
    expect(check(["crates/ferret-core"], base)).toHaveLength(0);
  });
  it("guards the core, its compiled-in harness and the mobile folders", () => {
    for (const folder of ["crates/ferret-core", "ct/harness", "apps/ios", "apps/android"]) expect(GUARDED).toContain(folder);
  });
  it("finds nothing in the real core today, and reads files", () => {
    expect(check(GUARDED)).toHaveLength(0);
    expect(scannedFiles(["crates/ferret-core"]) > 50).toBe(true);
    expect(scannedFiles(["crates/ferret-core"], tree({}))).toBe(0);
  });
});

describe("the allow-list", () => {
  const psl = "crates/ferret-core/src/passkey/public_suffix_list.dat";
  const other = "crates/ferret-core/src/other.dat";
  const header = "// This Source Code Form is subject to the terms of the Mozilla Public\n// License, v. 2.0. If a copy of the MPL was not distributed with this\n";
  it("names exactly the Public Suffix List data file, with a reason, and that file is there with its MPL header", () => {
    expect(Object.keys(ALLOWED)).toEqual([psl]);
    expect(ALLOWED[psl].reason).toContain("MPL-2.0");
    const real = readFileSync(new URL(`../${psl}`, import.meta.url), "utf8");
    expect(real).toContain("This Source Code Form is subject to the terms of the Mozilla Public");
    expect(check(["crates/ferret-core"])).toHaveLength(0);
    // Without the entry the file is a finding: the entry is what lets it through.
    expect(check(["crates/ferret-core"], undefined, {}).map((f) => f.file)).toEqual([psl]);
  });
  it("lets through the MPL header line of that file and nothing else in it, and no other file", () => {
    const base = tree({ [psl]: `${header}// Copyright (c) 2020 Someone\nac\n`, [other]: header });
    const found = check(["crates/ferret-core"], base).map((f) => `${f.file}:${f.line}`);
    expect(found.sort()).toEqual([`${other}:1`, `${psl}:3`]);
  });
});

describe("checkIncludes", () => {
  it("accepts targets inside a guarded folder and refuses the rest", () => {
    const base = tree({
      "ct/harness/ok.rs": "fn ok() {}\n",
      "crates/ferret-core/src/data.dat": "x\n",
      "crates/ferret-core/src/a.rs": 'include!("../../../ct/harness/ok.rs");\nconst S: &str = include_str!("data.dat");\n',
      "elsewhere/bad.rs": "fn bad() {}\n",
      "crates/ferret-core/src/b.rs": 'include!("../../../elsewhere/bad.rs");\n',
      "crates/ferret-core/src/c.rs": 'include_bytes!("../../../elsewhere/bad.rs");\n',
      "crates/ferret-core/src/d.rs": '#[path = "../../../elsewhere/bad.rs"]\nmod d;\n',
      "crates/ferret-core/src/e.rs": 'include!(concat!(env!("OUT_DIR"), "/x.rs"));\n',
      "crates/ferret-core/src/f.rs": 'include!("missing.rs");\n',
    });
    const found = checkIncludes(base).sort((x, y) => (x.file < y.file ? -1 : 1));
    expect(found.map((f) => f.file)).toEqual(["b.rs", "c.rs", "d.rs", "e.rs", "f.rs"].map((n) => `crates/ferret-core/src/${n}`));
    expect(found[0].text).toContain("outside the guarded folders");
    expect(found[3].text).toContain("not a plain string");
    expect(found[4].text).toContain("does not exist");
  });
  it("counts ct/harness as guarded only because it is listed", () => {
    const base = tree({ "ct/harness/ok.rs": "fn ok() {}\n", "crates/ferret-core/src/a.rs": 'include!("../../../ct/harness/ok.rs");\n' });
    expect(checkIncludes(base)).toHaveLength(0);
    expect(checkIncludes(base, ["crates/ferret-core"])).toHaveLength(1);
  });
  it("finds nothing in the real core: every include lies in a guarded folder", () => {
    expect(checkIncludes()).toHaveLength(0);
  });
});
