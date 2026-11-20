// The page "Devices": the list of browsers and devices, revoking one, forgetting old ones, revoking all of them
// after the master password again, what the page says revoking does and does not do, and that no token or key
// ever reaches the page.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { devicesErrorText, devicesView } from "../../src/views/devices.mjs";
import { menuRoutes } from "../../src/views/account.mjs";
import route from "../../src/routes/devices.route.mjs";
import { checkStep, readWire } from "../../src/wire.mjs";
import { web } from "./helpers.mjs";
import { all, click, find, settle, t as keyT, textOf, walk, withDom } from "./vaultHelpers.mjs";

const read = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "devices.json"), "utf8"));
const i18n = (lang) => createI18n({ en: read("en"), nb: read("nb") }, lang);

const BROWSER_ID = "d0010000000000000000000000000000";
const EXTENSION_ID = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
const LAPTOP_ID = "d0020000000000000000000000000000";
const AT = 1_793_491_200;

/** The list as the server sends it: this browser, the extension and another browser. */
function serverList() {
  return {
    devices: [
      { id: BROWSER_ID, kind: "web", name: "Test browser", created_at: AT - 600, last_seen: AT, current: true },
      { id: EXTENSION_ID, kind: "device", name: "Ferret for Firefox (Windows)", platform: "windows", created_at: AT - 3600, last_seen: AT - 60, current: false },
      { id: LAPTOP_ID, kind: "web", name: "", created_at: AT - 86_400, last_seen: AT - 7200, current: false },
    ],
  };
}

/** A page over fake calls that record what they were asked. */
function page({ t = keyT, list = serverList(), reauthAnswer = "ok", calls = [], overrides = {} } = {}) {
  const view = devicesView({
    t,
    locale: "en",
    load: async () => {
      calls.push("load");
      return list;
    },
    revoke: async (id) => {
      calls.push(`revoke ${id}`);
    },
    revokeAll: async () => {
      calls.push("revokeAll");
      return { revoked: 3 };
    },
    forgetOld: async () => {
      calls.push("forgetOld");
      return { revoked: 1 };
    },
    reauth: async () => {
      calls.push("reauth");
      return reauthAnswer;
    },
    ...overrides,
  });
  return { view, calls };
}

test("devices_page_lists_the_extension_with_its_name", async () => {
  await withDom(async () => {
    const { view } = page({ t: i18n("en").t });
    await settle();
    const rows = all(view, "devices-row");
    assert.equal(rows.length, 3);
    // This browser first, marked, with no button to revoke it.
    assert.equal(rows[0].getAttribute("data-current"), "true");
    assert.ok(find(rows[0], "devices-current"));
    assert.equal(find(rows[0], "devices-revoke"), null);
    assert.ok(find(rows[0], "devices-current-help"));
    // The extension by its name, kind and platform, with a button.
    const extension = rows[1];
    assert.equal(textOf(find(extension, "devices-name")).trim(), "Ferret for Firefox (Windows)");
    assert.equal(extension.getAttribute("data-kind"), "device");
    assert.match(textOf(find(extension, "devices-facts")), /App or extension · Windows/);
    assert.match(textOf(find(extension, "devices-seen")), /Last seen/);
    assert.ok(find(extension, "devices-revoke"));
    // A browser that never gave a name has a placeholder, not an empty row.
    assert.equal(textOf(find(rows[2], "devices-name")).trim(), "Unnamed browser");
    assert.match(textOf(find(rows[2], "devices-facts")), /Browser \(web vault\)/);
    // The list is complete: no note about rows left out.
    assert.equal(find(view, "devices-more").hidden, true);
  });
});

test("a_long_list_says_how_many_were_left_out", async () => {
  await withDom(async () => {
    const { view } = page({ list: { ...serverList(), more: 7 } });
    await settle();
    const more = find(view, "devices-more");
    assert.equal(more.hidden, false);
    assert.match(textOf(more), /devices\.more \{"count":7\}/);
  });
});

test("revoking_one_asks_first_and_revokes_that_row_only", async () => {
  await withDom(async () => {
    const calls = [];
    const { view } = page({ calls });
    await settle();
    const button = find(all(view, "devices-row")[1], "devices-revoke");
    // Cancel: nothing is revoked.
    let pending = click(button);
    await settle();
    await click(find(view, "dialog-cancel"));
    await pending;
    assert.deepEqual(calls, ["load"]);
    // Confirm: the extension's id, and the list is read again.
    pending = click(button);
    await settle();
    assert.match(textOf(find(view, "dialog")), /devices\.revoke\.body/);
    await click(find(view, "dialog-confirm"));
    await pending;
    await settle();
    assert.deepEqual(calls, ["load", `revoke ${EXTENSION_ID}`, "load"]);
    assert.equal(find(view, "devices-done").hidden, false);
  });
});

test("revoke_all_asks_for_the_password_first", async () => {
  await withDom(async () => {
    // The dialog is cancelled: nothing is revoked.
    const cancelled = page({ reauthAnswer: "cancelled" });
    await settle();
    await click(find(cancelled.view, "devices-revoke-all"));
    await settle();
    assert.deepEqual(cancelled.calls, ["load", "reauth"]);
    assert.equal(find(cancelled.view, "devices-revoke-all").disabled, false);

    // The password was confirmed: then, and only then, every device is revoked.
    const confirmed = page();
    await settle();
    await click(find(confirmed.view, "devices-revoke-all"));
    await settle();
    assert.deepEqual(confirmed.calls, ["load", "reauth", "revokeAll", "load"]);
    assert.match(textOf(find(confirmed.view, "devices-done")), /devices\.revoke_all\.done \{"count":3\}/);

    // The server still wants the password (or a second factor): the page says so and keeps the list.
    for (const code of ["reauth_required", "second_factor_required"]) {
      const refused = page({
        overrides: {
          revokeAll: async () => {
            throw Object.assign(new Error("403 refused"), { code });
          },
        },
      });
      await settle();
      await click(find(refused.view, "devices-revoke-all"));
      await settle();
      const error = find(refused.view, "devices-error");
      assert.equal(error.hidden, false);
      assert.equal(textOf(error).trim(), `devices.error.${code}`);
      assert.equal(all(refused.view, "devices-row").length, 3);
    }
  });
});

test("forget_old_devices_reports_how_many", async () => {
  await withDom(async () => {
    const { view, calls } = page();
    await settle();
    await click(find(view, "devices-forget-old"));
    await settle();
    assert.deepEqual(calls, ["load", "forgetOld", "load"]);
    assert.match(textOf(find(view, "devices-done")), /devices\.forget_old\.done \{"count":1\}/);
  });
});

test("the_page_says_what_revoking_does_and_does_not", async () => {
  await withDom(async () => {
    const { view } = page();
    await settle();
    for (const role of ["devices-what-does", "devices-what-not", "devices-what-stolen"]) assert.ok(find(view, role), role);
    assert.equal(textOf(find(view, "devices-what-does")).trim(), "devices.what.does");
    assert.equal(textOf(find(view, "devices-what-not")).trim(), "devices.what.does_not");
  });
  // In words: access to the server ends at once; what the device holds stays; a full key rotation comes later.
  const en = read("en");
  assert.match(en["devices.what.does"], /access to the server/);
  assert.match(en["devices.what.does"], /at once/);
  assert.match(en["devices.what.does_not"], /does not erase/);
  assert.match(en["devices.what.does_not"], /rotation of the vault's keys/);
  const nb = read("nb");
  assert.match(nb["devices.what.does"], /tilgangen til serveren/);
  assert.match(nb["devices.what.does_not"], /sletter ikke/);
  // The confirmation and "revoke all" say it as well.
  assert.match(en["devices.revoke.body"], /stays on it/);
  assert.match(en["devices.revoke_all.body"], /master password first/);
});

test("devices_texts_exist_in_both_languages", async () => {
  const en = read("en");
  const nb = read("nb");
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort());
  for (const [key, text] of Object.entries(en)) {
    assert.ok(key.startsWith("devices."), key);
    assert.ok(text.trim() !== "" && nb[key].trim() !== "", key);
    // The same placeholders in both.
    const holes = (s) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();
    assert.deepEqual(holes(nb[key]), holes(text), key);
  }
  // Every key the page and its route can ask for is in the catalog: render every state in both languages and record
  // what is asked for.
  for (const lang of ["en", "nb"]) {
    const { t, missing } = i18n(lang);
    await withDom(async () => {
      const { view } = page({ t, list: { ...serverList(), more: 2 } });
      await settle();
      const pending = click(find(all(view, "devices-row")[1], "devices-revoke"));
      await settle();
      await click(find(view, "dialog-cancel"));
      await pending;
      await click(find(view, "devices-forget-old"));
      await click(find(view, "devices-revoke-all"));
      await settle();
    });
    for (const code of ["bad_request", "busy", "forbidden", "network", "not_found", "reauth_required", "second_factor_required", "throttled", "unauthorized", "something_else"]) {
      devicesErrorText(t, { code });
    }
    for (const platform of ["windows", "macos", "linux", "android", "ios", "chromeos", "other"]) t(`devices.platform.${platform}`);
    t(route.title);
    assert.deepEqual(missing, [], lang);
  }
  // The page is on the account menu.
  assert.equal(route.menu, "account");
  assert.deepEqual(menuRoutes([route]).map((r) => r.path), ["/devices"]);
});

test("no_token_or_key_reaches_the_dom", async () => {
  // The wire shape refuses any field it does not know, so a token or a key in a row never gets to the page.
  const row = serverList().devices[1];
  for (const extra of [{ access_token: "a".repeat(43) }, { refresh_token: "b".repeat(43) }, { jkt: "c".repeat(43) }, { jwk: { kty: "EC" } }]) {
    const text = JSON.stringify({ devices: [{ ...row, ...extra }] });
    assert.throws(() => readWire("devices_res", text));
  }
  // A device with tokens must have a name and a platform; a browser has no platform.
  assert.throws(() => checkStep("devices_res", { devices: [{ ...row, platform: undefined }] }));
  assert.throws(() => checkStep("devices_res", { devices: [{ ...serverList().devices[0], platform: "linux" }] }));
  const good = readWire("devices_res", JSON.stringify(serverList()));
  checkStep("devices_res", good);

  await withDom(async () => {
    const { view } = page({ list: good });
    await settle();
    // Not even the ids are shown: the page holds names, kinds, platforms and times, set as text.
    for (const node of walk(view)) {
      const strings = [node.data ?? "", ...(node.attributes ? [...node.attributes.values()] : [])];
      for (const text of strings) {
        for (const id of [BROWSER_ID, EXTENSION_ID, LAPTOP_ID]) assert.ok(!String(text).includes(id), "an id reached the page");
      }
    }
    // A name that looks like markup is text.
    const marked = page({ list: { devices: [{ ...row, name: "<img src=x onerror=alert(1)>" }] } });
    await settle();
    const name = find(marked.view, "devices-name");
    assert.equal(textOf(name).trim(), "<img src=x onerror=alert(1)>");
    assert.ok(![...walk(marked.view)].some((n) => n.tagName === "img"));
  });
});

test("revoking_one_is_a_delete_of_the_web_vault_with_its_cookie", async () => {
  /** @type {Array<[string, any]>} */
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push([url, init]);
    return new Response(null, { status: 204 });
  };
  const api = createApi({ fetchImpl });
  assert.equal(await api.del(`/api/auth/devices/${EXTENSION_ID}`), null);
  const [[url, init]] = seen;
  assert.equal(url, `/api/auth/devices/${EXTENSION_ID}`);
  assert.equal(init.method, "DELETE");
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.redirect, "error");
  assert.equal(init.headers["Ferret-Protocol"], "1");
  assert.equal(init.body, undefined);
  assert.equal(Object.hasOwn(init.headers, "Authorization"), false);
  // A path that would leave the origin is refused before anything is sent.
  await assert.rejects(api.del("//evil.example/x"), TypeError);
  assert.equal(seen.length, 1);
});
