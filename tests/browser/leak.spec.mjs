// What the page and the workers say to each other, and what happens to the
// workers. All of it on real module workers in the browser, through the
// client of bindings/wasm/js.
import { randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { findLeaks } from "./walker.mjs";
import { keep, openHarness } from "./support.mjs";

const place = (l) => `${l.worker}:${l.dir}:${l.method}`;

test("worker_messages_contain_no_vault_secrets", async ({ page, browserName }) => {
  test.setTimeout(240_000);
  await openHarness(page);
  const run = await page.evaluate(() => window.ferret.leakRun());
  const { messages, secrets, zeroChecks } = run;

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
  ];
  for (const name of required) expect(Object.keys(secrets), name).toContain(name);

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

  const all = findLeaks(messages, everything);
  const leaks = findLeaks(messages, everything, allowed);
  expect(leaks.map((l) => `${place(l)} ${l.path} holds ${l.secret}`)).toEqual([]);

  // And the exceptions are exactly where they should be.
  const placements = (pick) => [...new Set(all.filter((l) => pick(l.secret)).map(place))].sort();
  expect(placements(isKexp)).toEqual(["job:in:argon2_export_key", "vault:out:export_finish", "vault:out:import_open"]);
  expect(placements((n) => n === "PRF output")).toEqual(["vault:out:unlock_prf", "vault:out:wrap_prf"]);
  expect(all.filter((l) => !isKexp(l.secret) && l.secret !== "PRF output")).toEqual([]);

  // K_exp is wiped on the page once it has been sent, and the job workers are ended.
  expect(zeroChecks.exportKeyAfterFinish).toBe(true);
  expect(zeroChecks.exportKeyAfterOpen).toBe(true);
  expect(run.jobWorkers).toEqual([true, true]);
  expect(run.imported).toBe(2);

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
