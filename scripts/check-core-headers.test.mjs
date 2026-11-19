import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { check, foreignNotices, GUARDED } from "./check-core-headers.mjs";
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
  it("lets the notice of this project through, also across the lines of a header", () => {
    expect(foreignNotices("// Copyright (c) 2026 Faithful Ferret\n")).toHaveLength(0);
    expect(foreignNotices("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright the Hedgerow authors\n")).toHaveLength(0);
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
  it("guards the core and the mobile folders", () => {
    expect(GUARDED).toContain("crates/ferret-core");
    expect(GUARDED).toContain("apps/ios");
    expect(GUARDED).toContain("apps/android");
  });
  it("finds nothing in the real core today", () => {
    expect(check(GUARDED)).toHaveLength(0);
  });
});
