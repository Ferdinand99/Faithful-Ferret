// What the page and the workers say to each other, and what happens to the
// workers. All of it on real module workers in the browser, through the
// client of bindings/wasm/js.
import { randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { findLeaks, findTextLeaks } from "./walker.mjs";
import { keep, openHarness } from "./support.mjs";

const place = (l) => `${l.worker}:${l.dir}:${l.method}`;

// The methods that take a code as an argument, by the code.
const CODE_ARGUMENTS = {
  "recovery key code": ["unlock_recovery", "recover"],
  "secret key code": ["login_start", "register_start"],
  "recovery key code (recovered)": [],
  "recovery key code (rekey)": [],
};

test("worker_messages_contain_no_vault_secrets", async ({ page, browserName }) => {
  test.setTimeout(240_000);
  await openHarness(page);
  const run = await page.evaluate(() => window.ferret.leakRun());
  const { messages, secrets, texts, anchored, zeroChecks } = run;

  // The watch sees both workers and both directions.
  for (const worker of ["vault", "job"]) {
    for (const dir of ["out", "in"]) {
      expect(messages.some((m) => m.worker === worker && m.dir === dir), `${worker} ${dir}`).toBe(true);
    }
  }
  expect(messages.length).toBeGreaterThan(80);
  const required = [
    "VK", "VK (new epoch)", "IK", "IK (new epoch)", "IK (passkey item)",
    "k_head (epoch 1)", "k_del (epoch 1)", "k_meta (epoch 1)", "seed_a (epoch 1)",
    "k_head (epoch 2)", "seed_a (epoch 2)",
    "KEK_pw", "KEK_pw (changed)", "KEK_pw (recovered)", "KEK_rk", "KEK_rk (rekey)", "KEK_pin", "KEK_prf",
    "passkey scalar", "passkey seed_uv", "passkey seed_nouv", "PRF output", "RK", "SK",
    "export key (create)", "export key (changed)", "export key (recovered)",
  ];
  for (const name of required) expect(Object.keys(secrets), name).toContain(name);

  // Every secret that the page derived was proven right against the vault, or
  // is read from the vault itself. Without this, a wrong derivation would be a
  // secret that is never found, and the search would pass for nothing.
  const proof = (name) => {
    let m;
    if (/^(VK|IK|passkey )/.test(name)) return "read from the worker";
    if (name === "PRF output") return "generated here and found in its arguments";
    if (/^(RK|SK)( \(.*\))?$/.test(name)) return "decoded from the code the worker revealed";
    if ((m = /^(KEK_(?:pw|rk|pin|prf)(?: \((?:changed|recovered|rekey)\))?)$/.exec(name))) return `${m[1]} opens the wrap to the vault key`;
    if ((m = /^export key \((create|changed|recovered)\)$/.exec(name))) {
      return `KEK_pw${m[1] === "create" ? "" : ` (${m[1]})`} opens the wrap to the vault key`;
    }
    if ((m = /^(k_head|k_del|k_meta|seed_a) \(epoch (\d)\)$/.exec(name))) {
      return {
        k_head: `k_head tags an item, epoch ${m[2]}`,
        k_del: `k_del opens a tombstone, epoch ${m[2]}`,
        k_meta: `k_meta opens the manifest, epoch ${m[2]}`,
        seed_a: `pk_a from seed_a, epoch ${m[2]}`,
      }[m[1]];
    }
    return null;
  };
  for (const name of Object.keys(secrets)) {
    const how = proof(name);
    expect(how, `${name} has a proof`).not.toBeNull();
    const fromSource = ["read from the worker", "generated here and found in its arguments", "decoded from the code the worker revealed"];
    expect(fromSource.includes(how) || anchored.includes(how), `${name}: ${how}`).toBe(true);
  }
  expect(anchored).toHaveLength(17);

  // The export-file key K_exp is the one secret that crosses, from the job
  // worker to the page and on to the vault worker.
  const kexp = {};
  messages
    .filter((m) => m.worker === "job" && m.dir === "in" && m.method === "argon2_export_key")
    .forEach((m, i) => {
      const bytes = m.leaves.filter((l) => l.hex?.length === 64);
      expect(bytes.length, "one 32-byte key in the reply").toBe(1);
      kexp[`K_exp #${i + 1}`] = bytes[0].hex;
    });
  expect(Object.keys(kexp)).toHaveLength(2);
  const everything = { ...secrets, ...kexp };

  const isKexp = (name) => name.startsWith("K_exp");
  const allowed = (m, name) => {
    if (isKexp(name)) {
      return (
        (m.worker === "job" && m.dir === "in" && m.method === "argon2_export_key") ||
        (m.worker === "vault" && m.dir === "out" && (m.method === "export_finish" || m.method === "import_open"))
      );
    }
    // The page gets the PRF output from the authenticator and hands it over
    // to unlock a vault or to make a wrap: it is an argument, never a reply.
    if (name === "PRF output") {
      return m.worker === "vault" && m.dir === "out" && (m.method === "wrap_prf" || m.method === "unlock_prf");
    }
    return false;
  };

  // The codes the user is shown and types back (base32 text, not bytes).
  const codeAllowed = (m, name) =>
    m.worker === "vault" &&
    ((m.dir === "in" && (m.method === "reveal_recovery_code" || m.method === "reveal_secret_key_code")) ||
      (m.dir === "out" && CODE_ARGUMENTS[name]?.includes(m.method)));
  const codeLeaks = findTextLeaks(messages, texts, codeAllowed);
  expect(codeLeaks.map((l) => `${place(l)} ${l.path} holds ${l.secret}`)).toEqual([]);
  const codePlaces = Object.fromEntries(
    Object.keys(texts).map((name) => [
      name,
      [...new Set(findTextLeaks(messages, { [name]: texts[name] }).map(place))].sort(),
    ]),
  );

  const all = findLeaks(messages, everything);
  const leaks = findLeaks(messages, everything, allowed);
  expect(leaks.map((l) => `${place(l)} ${l.path} holds ${l.secret}`)).toEqual([]);

  // And the exceptions are exactly where they should be.
  const placements = (pick) => [...new Set(all.filter((l) => pick(l.secret)).map(place))].sort();
  expect(placements(isKexp)).toEqual(["job:in:argon2_export_key", "vault:out:export_finish", "vault:out:import_open"]);
  // The file is written and opened with the same password, salt and parameters: one key, twice.
  expect(kexp["K_exp #1"]).toBe(kexp["K_exp #2"]);
  expect(placements((n) => n === "PRF output")).toEqual(["vault:out:unlock_prf", "vault:out:wrap_prf"]);
  expect(all.filter((l) => !isKexp(l.secret) && l.secret !== "PRF output")).toEqual([]);

  // K_exp is wiped on the page once it has been sent, and the job workers are ended.
  expect(zeroChecks.exportKeyAfterFinish).toBe(true);
  expect(zeroChecks.exportKeyAfterOpen).toBe(true);
  expect(run.jobWorkers).toEqual([true, true]);
  expect(run.imported).toBe(2);

  expect(codePlaces).toEqual({
    "recovery key code": ["vault:in:reveal_recovery_code", "vault:out:recover", "vault:out:unlock_recovery"],
    "secret key code": ["vault:in:reveal_secret_key_code", "vault:out:login_start", "vault:out:register_start"],
    "recovery key code (recovered)": ["vault:in:reveal_recovery_code"],
    "recovery key code (rekey)": ["vault:in:reveal_recovery_code"],
  });

  console.log(
    `[${browserName}] leak walk: ${messages.length} messages, ${Object.keys(everything).length} secrets, ${leaks.length} leaks`,
  );
  keep(browserName, "leak", {
    messages: messages.length,
    secrets: Object.keys(everything).length,
    leaks: leaks.length,
    exceptions: all.length,
  });
});

test("the_code_search_finds_a_planted_code", () => {
  const code = "FFR1-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23-4567-ABCD-EFGH-JKMN-PQRS-TVWX";
  const text = (t) => [{ worker: "vault", dir: "in", method: "x", leaves: [{ path: "", text: t }] }];
  const bytes = (t) => [{ worker: "vault", dir: "in", method: "x", leaves: [{ path: "", hex: Buffer.from(t).toString("hex") }] }];
  for (const m of [
    text(code),
    text(`before ${code} after`),
    text(code.replaceAll("-", "").toLowerCase()),
    text(code.replaceAll("-", " ")),
    bytes(code),
    bytes(`note: ${code}`),
  ]) {
    expect(findTextLeaks(m, { code }).length).toBe(1);
  }
  expect(findTextLeaks(text("FFR1-ABCD-EFGH"), { code })).toEqual([]);
  expect(findTextLeaks(text(code), { code }, () => true)).toEqual([]);
});

test("the_walk_finds_a_secret_when_one_is_there", async ({ page }) => {
  test.setTimeout(120_000);
  await openHarness(page);
  const secret = randomBytes(32).toString("hex");
  const runs = await page.evaluate((hex) => window.ferret.plantedRun(hex), secret);
  const planted = runs.filter((r) => r.group === "planted");
  const innocent = runs.filter((r) => r.group === "innocent");
  expect(planted.length).toBeGreaterThanOrEqual(25);
  for (const r of planted) {
    expect(r.out.length, `${r.form}: sent`).toBe(1);
    expect(r.in.length, `${r.form}: received`).toBe(1);
    expect(findLeaks(r.out, { key: secret }).length, `${r.form}: page to worker`).toBeGreaterThan(0);
    expect(findLeaks(r.in, { key: secret }).length, `${r.form}: worker to page`).toBeGreaterThan(0);
  }
  for (const r of innocent) {
    expect(findLeaks([...r.out, ...r.in], { key: secret }), r.form).toEqual([]);
  }
});

test("job_worker_terminated_after_use", async ({ page, browserName }) => {
  test.setTimeout(180_000);
  await openHarness(page);
  const r = await page.evaluate(() => window.ferret.jobTerminatedRun());
  expect(r.keyLengths).toEqual([32, 32, 32]);
  expect(r.jobs).toBe(3);
  expect(r.terminated).toEqual([true, true, true]);
  expect(r.endedAnswers).toEqual([false, false, false]);
  expect(r.liveAnswers).toBe(true);
  // `performance.memory` is Chromium only, and it measures the page's own
  // JavaScript heap, not the workers'. The proof is that the workers are gone.
  console.log(`[${browserName}] job workers ended: ${r.terminated.length}; page heap ${r.heapBefore} -> ${r.heapAfter}`);
  if (browserName === "chromium") expect(r.heapBefore).not.toBeNull();
});

test("lock_destroys_vault_worker_and_clears_buffers", async ({ page }) => {
  test.setTimeout(180_000);
  await openHarness(page);
  const r = await page.evaluate(() => window.ferret.lockRun());
  expect(r.passwordWiped, "the password buffer of the caller").toBe(true);
  expect(r.before).toMatch(/[1-9a-f]/);
  expect(r.before).toHaveLength(64);
  expect(r.after).toBe("0".repeat(64));
  expect(r.firstTerminated).toBe(true);
  expect(r.workers).toEqual([true, false]);
  expect(r.afterLock).toBe("vault_locked");
});

test("passkey_signature_verifies_with_webcrypto", async ({ page }) => {
  test.setTimeout(180_000);
  await openHarness(page);
  const r = await page.evaluate(() => window.ferret.passkeyRun());
  expect(r.good).toBe(true);
  expect(r.badMessage).toBe(false);
  expect(r.tampered).toBe(false);
  expect(r.clientDataType).toBe("webauthn.get");
  expect(r.challengeMatches).toBe(true);
  expect(r.signatureDerLength).toBeGreaterThanOrEqual(68);
});

// Argon2id with 256 MiB: a few seconds in Chromium and WebKit, about eight
// times that in Firefox. Pull requests run it only with the `browsers` label;
// the nightly run and scripts/lanbox-browsers.sh always do.
test("export_256mib_does_not_oom", async ({ page, browserName }) => {
  test.skip(process.env.FERRET_EXPORT_256 !== "1", "set FERRET_EXPORT_256=1 (the `browsers` label, the nightly run, the LANBox script)");
  test.setTimeout(240_000);
  await openHarness(page);
  const r = await page.evaluate(() => window.ferret.exportRun());
  expect(r.kdf).toEqual({ m_kib: 262144, t: 3, p: 1 });
  expect(r.keyLength).toBe(32);
  expect(r.keyWiped).toBe(true);
  expect(r.count).toBe(1);
  expect(r.jobWorkers).toEqual([true, true]);
  console.log(
    `[${browserName}] export 256 MiB (t=3, p=1): write ${r.writeMs} ms, open ${r.openMs} ms, file ${r.fileBytes} bytes`,
  );
  keep(browserName, "export-256mib", r);
});
