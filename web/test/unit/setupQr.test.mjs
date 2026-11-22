// The reader and the checks of the sheet's QR text (src/flows/setupQr.mjs).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SetupQrError, checkQrAfterLogin, checkQrBeforeKe3, readSetupQr } from "../../src/flows/setupQr.mjs";
import { ACCOUNT, SERVER, coded, fakeClient, scenario } from "./accountHelpers.mjs";
import { SERVER_KEY, qrHandlers, qrText } from "./setupQrHelpers.mjs";
import { web } from "./helpers.mjs";

const client = (handlers = qrHandlers) => fakeClient({ handlers });
const OTHER_ACCOUNT = "9a8b7c6d5e4f30211203f4e5d6c7b8a9";

test("reading_the_sheet_text_shows_host_and_port_before_anything_is_sent", async () => {
  const world = await scenario({ handlers: qrHandlers });
  const text = qrText({ url: "https://Vault.Example:8443" });
  const qr = await world.session.readSetupQr(`  ${text}\n`);
  // What the page shows: the host and the port, in the browser's reading of the address.
  assert.deepEqual([qr.scheme, qr.host, qr.port], ["https", "vault.example", 8443]);
  assert.equal(qr.accountId, ACCOUNT);
  assert.equal(qr.ksfProfile, 1);
  assert.equal(qr.skBit, true);
  assert.deepEqual(qr.serverPublicKey, SERVER_KEY);
  // The core is asked once, with the text trimmed; no request goes to any server, and nothing is stored.
  assert.deepEqual(world.client.calls.map((c) => c.method), ["setup_qr_parse"]);
  assert.equal(world.client.calls[0].snapshot[0], text);
  assert.equal(world.requests.length, 0);
  // No port in the address: none is shown.
  assert.equal((await readSetupQr(client(), qrText())).port, null);
  assert.equal((await readSetupQr(client(), qrText({ sk: false }))).skBit, false);
  // The answer is frozen and holds its own copy of the key.
  assert.ok(Object.isFrozen(qr));
});

test("the_reader_refuses_what_is_not_a_sheet_text", async () => {
  const bad = [
    ["", "malformed_setup_qr"],
    ["   \n", "malformed_setup_qr"],
    ["https://vault.example", "malformed_setup_qr"],
    [qrText().replace("&s=1", "&s=2"), "malformed_setup_qr"],
    [qrText().replace("ferret-setup:v1", "ferret-setup:v2"), "qr_unsupported"],
    ["x".repeat(1_701), "qr_too_large"],
    [42, "malformed_setup_qr"],
    [null, "malformed_setup_qr"],
  ];
  for (const [text, code] of bad) {
    const c = client();
    const error = await readSetupQr(c, text).catch((e) => e);
    assert.ok(error instanceof SetupQrError, String(text));
    assert.equal(error.code, code, String(text));
    // The error says the code and nothing of the text.
    assert.equal(error.message, code);
    if (typeof text === "string" && text.trim().length > 6) assert.ok(!JSON.stringify(error, Object.getOwnPropertyNames(error)).includes(text.trim()));
    // An empty or over-long text never reaches the core.
    if (code === "qr_too_large" || typeof text !== "string" || text.trim() === "") assert.equal(c.calls.length, 0);
  }
  // A failure of the core that is not about the text goes on as it is.
  const stopped = await readSetupQr(client({ setup_qr_parse: () => { throw coded("worker_failed"); } }), qrText()).catch((e) => e);
  assert.equal(stopped.code, "worker_failed");
  assert.ok(!(stopped instanceof SetupQrError));
  // The profile the core does not know keeps its own code.
  const unknown = await readSetupQr(client({ setup_qr_parse: () => { throw coded("kdf_profile_unknown"); } }), qrText()).catch((e) => e);
  assert.equal(unknown.code, "kdf_profile_unknown");
});

test("the_reader_ignores_white_space_in_the_text_as_the_pdf_wraps_it", async () => {
  const text = qrText({ url: "https://Vault.Example:8443" });
  const expectRead = async (pasted, label) => {
    const c = client();
    const qr = await readSetupQr(c, pasted);
    assert.deepEqual([qr.host, qr.port, qr.accountId, qr.skBit], ["vault.example", 8443, ACCOUNT, true], label);
    // The core is asked with the text as one piece, whatever was pasted.
    assert.deepEqual(c.calls.map((call) => call.method), ["setup_qr_parse"], label);
    assert.equal(c.calls[0].snapshot[0], text, label);
  };
  /** The text broken into lines of `size` characters, joined by `join`. */
  const wrapped = (size, join) => text.match(new RegExp(`.{1,${size}}`, "gu")).join(join);
  // The PDF prints the text with a short line width; a browser turns the line breaks into spaces (Firefox) or drops them (Chromium).
  await expectRead(wrapped(8, " "), "spaces");
  await expectRead(wrapped(8, "\n"), "line feeds");
  await expectRead(wrapped(8, ""), "line breaks dropped");
  for (const size of [8, 13, 21, 40]) await expectRead(`${wrapped(size, "\r\n")}\r\n`, `CRLF every ${size}`);
  await expectRead(wrapped(8, "\t"), "tabs");
  await expectRead(` ${wrapped(8, " ")} `, "no-break spaces");
  await expectRead(wrapped(8, "  　"), "other Unicode spaces");
  await expectRead(`﻿ ${wrapped(10, " \n ")}  `, "a mix, with a byte order mark and a line separator");
});

test("a_text_that_is_not_a_sheet_text_is_still_refused_when_white_space_is_removed", async () => {
  const text = qrText();
  const lines = (value) => value.replace(/(.{8})/g, "$1\n");
  const refused = async (pasted, code) => {
    const c = client();
    const error = await readSetupQr(c, pasted).catch((e) => e);
    assert.ok(error instanceof SetupQrError);
    assert.equal(error.code, code);
    return c;
  };
  // Removing white space does not make a wrong text right.
  await refused(lines(text.replace("&s=1", "&s=2")), "malformed_setup_qr");
  await refused(lines(`${text}x`), "malformed_setup_qr");
  await refused(lines(text.slice(0, -1)), "malformed_setup_qr");
  await refused("  \r\n\t ", "malformed_setup_qr");
  await refused(lines(text.replace("ferret-setup:v1", "ferret-setup:v2")), "qr_unsupported");
  // The limit is on the text without white space: 1700 characters reach the core, 1701 do not, and white space does not count.
  assert.equal((await refused(lines("x".repeat(1_700)), "malformed_setup_qr")).calls.length, 1);
  assert.equal((await refused(lines("x".repeat(1_701)), "qr_too_large")).calls.length, 0);
  // A raw paste of more than twice the limit is refused as too large before it is cleaned.
  assert.equal((await refused(" ".repeat(3_401), "qr_too_large")).calls.length, 0);
  assert.equal((await refused(`${text}${" ".repeat(3_400)}`, "qr_too_large")).calls.length, 0);
});

test("the_reader_checks_the_form_of_the_answer", async () => {
  const good = () => ({
    server_url: SERVER, scheme: "https", host: "vault.example", port: null,
    account_id: new Uint8Array(16).fill(1), ksf_profile: 1, sk_bit: true, server_public_key: SERVER_KEY.slice(),
  });
  assert.equal((await readSetupQr(client({ setup_qr_parse: good }), "x")).accountId, "01".repeat(16));
  const broken = [
    (a) => { a.scheme = "ftp"; },
    (a) => { a.host = ""; },
    (a) => { a.port = 0; },
    (a) => { a.port = 70_000; },
    (a) => { a.port = "443"; },
    (a) => { a.account_id = new Uint8Array(15); },
    (a) => { a.account_id = "01".repeat(16); },
    (a) => { a.ksf_profile = 256; },
    (a) => { a.ksf_profile = 1.5; },
    (a) => { a.sk_bit = "yes"; },
    (a) => { a.server_public_key = new Uint8Array(31); },
    (a) => { a.server_url = 7; },
    (a) => { delete a.server_public_key; },
  ];
  for (const [index, damage] of broken.entries()) {
    const answer = good();
    damage(answer);
    await assert.rejects(readSetupQr(client({ setup_qr_parse: () => answer }), "x"), { code: "malformed_setup_qr" }, `case ${index}`);
  }
  await assert.rejects(readSetupQr(client({ setup_qr_parse: () => null }), "x"), { code: "malformed_setup_qr" });
  // The key in the result is a copy: changing the core's array afterwards changes nothing.
  const answer = good();
  const qr = await readSetupQr(client({ setup_qr_parse: () => answer }), "x");
  answer.server_public_key.fill(0);
  assert.deepEqual(qr.serverPublicKey, SERVER_KEY);
});

test("the_checks_before_ke3_name_the_address_the_profile_and_the_key", async () => {
  const qr = await readSetupQr(client(), qrText({ profile: 2 }));
  const seen = { serverUrl: SERVER, serverProfile: 2, serverPublicKey: SERVER_KEY };
  assert.doesNotThrow(() => checkQrBeforeKe3(qr, seen));
  // A profile above the sheet's is an upgrade, not a downgrade.
  assert.doesNotThrow(() => checkQrBeforeKe3(qr, { ...seen, serverProfile: 3 }));
  const refused = (change, code) => assert.throws(() => checkQrBeforeKe3(qr, { ...seen, ...change }), { code, name: "SetupQrError" });
  refused({ serverUrl: "https://other.example" }, "qr_server_url");
  refused({ serverUrl: "http://vault.example" }, "qr_server_url");
  refused({ serverProfile: 1 }, "qr_profile");
  refused({ serverProfile: 1.5 }, "qr_profile");
  refused({ serverPublicKey: new Uint8Array(32).fill(8) }, "qr_server_key");
  refused({ serverPublicKey: new Uint8Array(31).fill(9) }, "qr_server_key");
  refused({ serverPublicKey: new Uint8Array(32) }, "qr_server_key");
  // The same server written another way is the same server: a path, capital letters in the host, the default port.
  for (const url of [`${SERVER}/`, `${SERVER}/some/path?x=1`, "https://Vault.EXAMPLE", "https://vault.example:443/"]) {
    const other = await readSetupQr(client(), qrText({ url, profile: 2 }));
    assert.doesNotThrow(() => checkQrBeforeKe3(other, seen), url);
  }
  // A page address that is no address is never "the same".
  assert.throws(() => checkQrBeforeKe3(qr, { ...seen, serverUrl: "not a url" }), { code: "qr_server_url" });
  assert.throws(() => checkQrBeforeKe3(qr, { ...seen, serverUrl: "ftp://vault.example" }), { code: "qr_server_url" });
  // A value that is not known yet is not checked; the address always is.
  assert.doesNotThrow(() => checkQrBeforeKe3(qr, { serverUrl: SERVER }));
  assert.doesNotThrow(() => checkQrBeforeKe3(qr, { serverUrl: SERVER, serverProfile: 2 }));
  assert.throws(() => checkQrBeforeKe3(qr, /** @type {any} */ ({})), { code: "qr_server_url" });
  // Only a read sheet text is checked.
  assert.throws(() => checkQrBeforeKe3(/** @type {any} */ ({ serverUrl: SERVER }), seen), TypeError);
});

test("the_check_after_login_names_the_account", async () => {
  const qr = await readSetupQr(client(), qrText());
  assert.doesNotThrow(() => checkQrAfterLogin(qr, { accountId: ACCOUNT }));
  assert.throws(() => checkQrAfterLogin(qr, { accountId: OTHER_ACCOUNT }), { code: "qr_account" });
  assert.throws(() => checkQrAfterLogin(qr, { accountId: ACCOUNT.toUpperCase() }), { code: "qr_account" });
  assert.throws(() => checkQrAfterLogin(qr, /** @type {any} */ ({ accountId: undefined })), { code: "qr_account" });
});

test("setup_qr_module_imports_no_dom_and_no_store", () => {
  const source = readFileSync(join(web, "src", "flows", "setupQr.mjs"), "utf8");
  const code = source.split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*") && !line.trim().startsWith("/**")).join("\n");
  const imports = [...code.matchAll(/^\s*import\b[^;]*?from\s+"([^"]+)"/gm)].map((m) => m[1]);
  // Only the byte and id codec: no store, no API client, no view or DOM helper.
  assert.deepEqual(imports, ["../b64.mjs"]);
  assert.ok(!/\bimport\s*\(/.test(code), "no dynamic import");
  for (const word of ["document", "window", "globalThis", "navigator", "localStorage", "sessionStorage", "indexedDB", "location", "history", "console", "fetch", "postMessage"]) {
    assert.ok(!new RegExp(`\\b${word}\\b`).test(code), `no ${word}`);
  }
  // And b64.mjs, the one thing it imports, has no DOM either.
  const codec = readFileSync(join(web, "src", "b64.mjs"), "utf8");
  assert.ok(!/^\s*import\b/m.test(codec));
  assert.ok(!/\bdocument\b|\bwindow\b/.test(codec.replace(/\/\/.*$/gm, "")));
});
