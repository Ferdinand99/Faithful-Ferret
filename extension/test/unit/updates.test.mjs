import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { packZip, sha256 } from "../../scripts/lib/archive.mjs";
import {
  appendUpdate, assetName, compareVersions, entryProblem, formatUpdates, parseUpdates, RELEASE_ID, releaseTag,
  UPDATE_URL, updateLink,
} from "../../scripts/lib/updates.mjs";
import { writeUpdates } from "../../scripts/updates-json.mjs";
import { extensionRoot } from "./buildHelpers.mjs";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

/** @param {string} version @param {string} hash */
const entry = (version, hash) => ({ version, update_link: updateLink(version), update_hash: `sha256:${hash}` });

/** @param {unknown[]} updates */
const fileWith = (updates) => `${JSON.stringify({ addons: { [RELEASE_ID]: { updates } } }, null, 2)}\n`;

/**
 * A signed-looking package: manifest.json and a META-INF/ signature file.
 * @param {Record<string, unknown>} [gecko] @param {string} [version] @param {boolean} [signed]
 */
function fakeXpi(gecko = { id: RELEASE_ID, update_url: UPDATE_URL }, version = "0.7.1", signed = true) {
  /** @type {Map<string, Buffer>} */
  const files = new Map([["manifest.json", Buffer.from(JSON.stringify({ name: "Faithful Ferret", version, browser_specific_settings: { gecko } }))]]);
  if (signed) files.set("META-INF/mozilla.rsa", Buffer.from("signature"));
  return packZip(files);
}

test("the_update_url_and_the_links_are_stable_https_release_urls_outside_the_core_tags", () => {
  assert.equal(UPDATE_URL, "https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-updates/updates.json");
  assert.equal(updateLink("0.7.1"), "https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-v0.7.1/ferret-firefox-mv2-release-0.7.1-signed.xpi");
  // release-please owns v*: the extension's tags never start with it.
  assert.equal(releaseTag("0.7.1"), "extension-v0.7.1");
  assert.equal(/^v/.test(releaseTag("0.7.1")), false);
  // The asset is named as the sign job names it.
  assert.equal(assetName("0.7.1"), "ferret-firefox-mv2-release-0.7.1-signed.xpi");
  for (const bad of ["", "v0.7.1", "0.7.1-beta", "01.2", "1.2.3.4.5", "1..2", " 1.2", "1.2/../x"]) {
    assert.throws(() => releaseTag(bad), /not a plain dotted version/, bad);
    assert.throws(() => updateLink(bad), /not a plain dotted version/, bad);
  }
});

test("versions_compare_as_numbers", () => {
  assert.ok(compareVersions("0.7.10", "0.7.9") > 0);
  assert.ok(compareVersions("0.8", "0.7.99") > 0);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
  assert.ok(compareVersions("0.7.1", "0.7.2") < 0);
});

test("the_first_publication_writes_one_entry_in_the_mozilla_format", () => {
  const { text, changed } = appendUpdate(null, { version: "0.7.1", sha256: HASH_A });
  assert.equal(changed, true);
  assert.equal(text, fileWith([entry("0.7.1", HASH_A)]));
  assert.deepEqual(JSON.parse(text), {
    addons: {
      "ferret@hedgerow.tools": {
        updates: [{
          version: "0.7.1",
          update_link: "https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-v0.7.1/ferret-firefox-mv2-release-0.7.1-signed.xpi",
          update_hash: `sha256:${HASH_A}`,
        }],
      },
    },
  });
});

test("a_new_version_is_appended_and_every_older_entry_is_kept", () => {
  const first = appendUpdate(null, { version: "0.7.1", sha256: HASH_A }).text;
  const second = appendUpdate(first, { version: "0.7.2", sha256: HASH_B });
  assert.equal(second.changed, true);
  assert.deepEqual(parseUpdates(second.text), [entry("0.7.1", HASH_A), entry("0.7.2", HASH_B)]);
  const third = appendUpdate(second.text, { version: "0.8", sha256: HASH_A });
  assert.deepEqual(parseUpdates(third.text).map((e) => e.version), ["0.7.1", "0.7.2", "0.8"]);
  // The older entries are byte for byte what they were.
  assert.equal(third.text, formatUpdates([entry("0.7.1", HASH_A), entry("0.7.2", HASH_B), entry("0.8", HASH_A)]));
});

test("the_same_entry_again_is_a_no_op_and_a_version_is_never_published_twice", () => {
  const first = appendUpdate(null, { version: "0.7.1", sha256: HASH_A }).text;
  const again = appendUpdate(first, { version: "0.7.1", sha256: HASH_A });
  assert.equal(again.changed, false);
  assert.equal(again.text, first);
  assert.throws(() => appendUpdate(first, { version: "0.7.1", sha256: HASH_B }), /already lists 0\.7\.1 with another file/);
  // 0.7.1.0 is the same version to Firefox.
  assert.throws(() => appendUpdate(first, { version: "0.7.1.0", sha256: HASH_A }), /already lists 0\.7\.1/);
  // Older than the newest: refused.
  const two = appendUpdate(first, { version: "0.7.3", sha256: HASH_B }).text;
  assert.throws(() => appendUpdate(two, { version: "0.7.2", sha256: HASH_A }), /0\.7\.2 is older than 0\.7\.3/);
});

test("the_writer_refuses_a_malformed_hash_or_version", () => {
  for (const hash of ["", "A".repeat(64), "a".repeat(63), "a".repeat(65), `sha256:${HASH_A}`, "z".repeat(64)]) {
    assert.throws(() => appendUpdate(null, { version: "0.7.1", sha256: hash }), /64 lower-case hex/, hash);
  }
  for (const version of ["", "v1", "1.2.3-beta", "1.2.3.4.5"]) {
    assert.throws(() => appendUpdate(null, { version, sha256: HASH_A }), /not a plain dotted version/, version);
  }
});

test("a_current_file_with_a_non_https_or_foreign_link_or_another_shape_is_refused", () => {
  const good = entry("0.7.1", HASH_A);
  /** @type {[unknown, RegExp][]} */
  const cases = [
    [{ ...good, update_link: good.update_link.replace("https:", "http:") }, /is not an HTTPS link/],
    [{ ...good, update_link: "https://example.com/ferret-firefox-mv2-release-0.7.1-signed.xpi" }, /update_link of 0\.7\.1 is not https:\/\/github\.com/],
    [{ ...good, update_link: updateLink("0.7.2") }, /update_link of 0\.7\.1 is not/],
    [{ ...good, update_hash: `sha512:${HASH_A}` }, /update_hash of 0\.7\.1 is not sha256/],
    [{ ...good, update_hash: HASH_A }, /update_hash of 0\.7\.1 is not sha256/],
    [{ ...good, update_info_url: "https://example.com/" }, /exactly version, update_link and update_hash/],
    [{ ...good, applications: { gecko: { strict_min_version: "1" } } }, /exactly version, update_link and update_hash/],
    [{ version: "0.7.1", update_link: good.update_link }, /exactly version, update_link and update_hash/],
    ["0.7.1", /exactly version, update_link and update_hash/],
  ];
  for (const [bad, expected] of cases) {
    assert.throws(() => appendUpdate(fileWith([bad]), { version: "0.7.2", sha256: HASH_B }), expected, JSON.stringify(bad));
    assert.notEqual(entryProblem(bad), "");
  }
  assert.equal(entryProblem(good), "");
  // Another add-on, another top-level key, no list, versions out of order or twice, not JSON.
  /** @type {[string, RegExp][]} */
  const files = [
    [JSON.stringify({ addons: { "other@example.com": { updates: [] } } }), /expected \{ "addons"/],
    [JSON.stringify({ addons: { [RELEASE_ID]: { updates: [] }, "other@example.com": { updates: [] } } }), /expected \{ "addons"/],
    [JSON.stringify({ addons: { [RELEASE_ID]: { updates: [] } }, extra: 1 }), /expected \{ "addons"/],
    [JSON.stringify({ addons: { [RELEASE_ID]: {} } }), /exactly an updates list/],
    [JSON.stringify({ addons: { [RELEASE_ID]: { updates: {} } } }), /exactly an updates list/],
    [fileWith([entry("0.7.2", HASH_A), entry("0.7.1", HASH_B)]), /0\.7\.1 comes after 0\.7\.2/],
    [fileWith([entry("0.7.1", HASH_A), entry("0.7.1", HASH_B)]), /0\.7\.1 comes after 0\.7\.1/],
    ["{", /not valid JSON/],
    ["", /not valid JSON/],
  ];
  for (const [text, expected] of files) {
    assert.throws(() => appendUpdate(text, { version: "0.7.3", sha256: HASH_B }), expected, text);
  }
  // An empty list is a valid current file.
  assert.equal(appendUpdate(fileWith([]), { version: "0.7.1", sha256: HASH_A }).text, fileWith([entry("0.7.1", HASH_A)]));
});

test("the_update_hash_is_the_hash_of_the_signed_file_and_a_wrong_one_is_refused", () => {
  const xpi = fakeXpi();
  const name = assetName("0.7.1");
  const ok = writeUpdates({ xpi, name, sha256: sha256(xpi), version: "0.7.1", previous: null });
  assert.equal(parseUpdates(ok.text)[0].update_hash, `sha256:${sha256(xpi)}`);
  // The signing job reported another hash: the file is not the one that was signed.
  assert.throws(() => writeUpdates({ xpi, name, sha256: HASH_A, version: "0.7.1", previous: null }), /the signing job reported/);
  const changed = Buffer.from(xpi);
  changed[changed.length - 1] ^= 1;
  assert.throws(() => writeUpdates({ xpi: changed, name, sha256: sha256(xpi), version: "0.7.1", previous: null }), /the signing job reported/);
});

test("the_writer_checks_the_signed_package_it_announces", () => {
  const name = assetName("0.7.1");
  /** @type {[Buffer, string, string, RegExp][]} */
  const cases = [
    [fakeXpi(undefined, undefined, false), name, "0.7.1", /no signature/],
    [fakeXpi({ id: "ferret-test@hedgerow.tools", update_url: UPDATE_URL }), name, "0.7.1", /add-on id of the package/],
    [fakeXpi({ id: RELEASE_ID }), name, "0.7.1", /update_url is undefined/],
    [fakeXpi({ id: RELEASE_ID, update_url: "https://example.com/updates.json" }), name, "0.7.1", /update_url is "https:\/\/example\.com/],
    [fakeXpi(undefined, "0.7.2"), name, "0.7.1", /has version "0\.7\.2", not 0\.7\.1/],
    [fakeXpi(), "ferret-firefox-mv2-release-0.7.1.xpi", "0.7.1", /expected ferret-firefox-mv2-release-0\.7\.1-signed\.xpi/],
    [packZip(new Map([["META-INF/mozilla.rsa", Buffer.from("x")]])), name, "0.7.1", /no manifest\.json/],
  ];
  for (const [xpi, file, version, expected] of cases) {
    assert.throws(() => writeUpdates({ xpi, name: file, sha256: sha256(xpi), version, previous: null }), expected, String(expected));
  }
});

test("the_writer_cli_appends_to_the_current_file_and_fails_closed", () => {
  const dir = mkdtempSync(join(tmpdir(), "ferret-updates-"));
  try {
    const xpiPath = join(dir, assetName("0.7.2"));
    const xpi = fakeXpi(undefined, "0.7.2");
    writeFileSync(xpiPath, xpi);
    const previous = join(dir, "current.json");
    writeFileSync(previous, appendUpdate(null, { version: "0.7.1", sha256: HASH_A }).text);
    const out = join(dir, "updates.json");
    const run = (/** @type {string[]} */ args) => spawnSync("node", [join(extensionRoot, "scripts", "updates-json.mjs"), ...args], { encoding: "utf8" });
    const ok = run(["--xpi", xpiPath, "--sha256", sha256(xpi), "--version", "0.7.2", "--previous", previous, "--out", out]);
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(parseUpdates(readFileSync(out, "utf8")), [entry("0.7.1", HASH_A), entry("0.7.2", sha256(xpi))]);
    // A wrong hash writes nothing.
    rmSync(out);
    const wrong = run(["--xpi", xpiPath, "--sha256", HASH_B, "--version", "0.7.2", "--previous", previous, "--out", out]);
    assert.notEqual(wrong.status, 0);
    assert.match(wrong.stderr, /the signing job reported/);
    assert.throws(() => readFileSync(out));
    // A missing current file is an error, not a new start (only leaving out --previous starts one).
    const missing = run(["--xpi", xpiPath, "--sha256", sha256(xpi), "--version", "0.7.2", "--previous", join(dir, "nope.json"), "--out", out]);
    assert.notEqual(missing.status, 0);
    for (const args of [[], ["--xpi", xpiPath], ["--bogus", "1"], ["--xpi", xpiPath, "--xpi", xpiPath, "--sha256", sha256(xpi), "--version", "0.7.2", "--out", out]]) {
      assert.notEqual(run(args).status, 0, args.join(" "));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
