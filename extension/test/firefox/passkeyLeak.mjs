// The leak scan of the passkey tests (U4-13, `no_sentinel_key_leaves_the_core`): a sentinel private key (a test key of the
// fixture relying party, extension/test/fixtures/passkey-sentinel.json) goes into the vault through the core's import, signs, and
// none of its forms may then be found outside the core:
//   - in a file of the browser's profile (storage, IndexedDB, caches, the session store);
//   - in the browser's console: every console line of the pages, the extension's pages and its background, which the browser writes
//     to its output (CONSOLE_PREFS) and the driver keeps, and the messages of the console service;
//   - in a message an extension page receives (`runtime.onMessage`: what the content scripts and pages send each other);
//   - in the network: the body and address of every request the browser sends (chrome context, `http-on-modify-request`);
//   - in what the page saw (its reports at the relying party);
//   - in a log of the stack's containers (scripts/lanbox-ext.sh greps the needles after the run).
// The needles are the private scalar and the PKCS #8 bytes, raw and as hex, base64 and base64url. Not a spec.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** The preferences that make the browser write every console line of content, extension pages and chrome to its output. */
export const CONSOLE_PREFS = Object.freeze({ "devtools.console.stdout.content": true, "devtools.console.stdout.chrome": true, "browser.dom.window.dump.enabled": true });

/** The sentinel: its PKCS #8 (base64url), the text needles and the raw byte needles. */
export function sentinel() {
  const file = JSON.parse(readFileSync(resolve(here, "..", "fixtures", "passkey-sentinel.json"), "utf8"));
  const pkcs8 = Buffer.from(file.pkcs8, "base64url");
  // The private scalar of a P-256 PKCS #8 (RFC 5915 inside RFC 5208): the 32 bytes after the OCTET STRING header 04 20.
  const at = pkcs8.indexOf(Buffer.from([0x04, 0x20]), 30);
  const d = pkcs8.subarray(at + 2, at + 34);
  const forms = (/** @type {Buffer} */ b) => [b.toString("hex"), b.toString("base64"), b.toString("base64url")];
  const needles = [...forms(d), ...forms(pkcs8)];
  if (JSON.stringify(needles) !== JSON.stringify(file.needles)) throw new Error("passkey-sentinel.json: the needles do not match the key");
  return { pkcs8: /** @type {string} */ (file.pkcs8), needles, bytes: [new Uint8Array(d), new Uint8Array(pkcs8)] };
}

/**
 * Watches every request the browser sends from now on (chrome context): its address and, when the body can be read again, its
 * body, for the needles (as text, and the raw bytes as Latin-1). Only counts and hits are kept, never a body.
 * @param {import("./driver.mjs").Session} session @param {string[]} needles @param {Uint8Array[]} raw
 */
export async function watchNetwork(session, needles, raw) {
  await session.chrome((/** @type {string[]} */ texts, /** @type {number[][]} */ bytes) => {
    const w = /** @type {any} */ (globalThis);
    // A chrome script runs in a sandbox of its own: what must outlive it is kept on the shared global of the Services module.
    const g = w.Components.utils.getGlobalForObject(w.Services);
    const Ci = w.Components.interfaces;
    const { NetUtil } = w.ChromeUtils.importESModule("resource://gre/modules/NetUtil.sys.mjs");
    const latin = bytes.map((b) => String.fromCharCode(...b));
    const all = [...texts, ...latin];
    g.__ferretNet = { requests: 0, bodies: 0, hits: /** @type {string[]} */ ([]) };
    g.__ferretNetObserver = {
      observe(/** @type {any} */ subject) {
        const net = g.__ferretNet;
        net.requests += 1;
        try {
          const channel = subject.QueryInterface(Ci.nsIHttpChannel);
          const url = channel.URI.spec;
          if (all.some((n) => url.includes(n))) net.hits.push(`address of a request to ${channel.URI.host}`);
          let stream = null;
          try {
            stream = channel.QueryInterface(Ci.nsIUploadChannel).uploadStream;
          } catch {
            stream = null;
          }
          if (stream) {
            const seekable = stream.QueryInterface(Ci.nsISeekableStream);
            seekable.seek(0, 0);
            const body = NetUtil.readInputStreamToString(stream, stream.available());
            seekable.seek(0, 0);
            net.bodies += 1;
            if (all.some((n) => body.includes(n))) net.hits.push(`body of a request to ${channel.URI.host}`);
          }
        } catch {
          // A request whose body cannot be read again is counted without one.
        }
      },
    };
    w.Services.obs.addObserver(g.__ferretNetObserver, "http-on-modify-request");
  }, needles, raw.map((b) => [...b]));
}

/** What the network watch saw: how many requests and bodies, and where a needle was. @param {import("./driver.mjs").Session} session */
export async function networkFindings(session) {
  return /** @type {{ requests: number, bodies: number, hits: string[] }} */ (await session.chrome(() => {
    const w = /** @type {any} */ (globalThis);
    const g = w.Components.utils.getGlobalForObject(w.Services);
    w.Services.obs.removeObserver(g.__ferretNetObserver, "http-on-modify-request");
    return { ...g.__ferretNet, hits: [...g.__ferretNet.hits] };
  }));
}

/**
 * The console messages of the whole browser that hold a needle (chrome context, the console service), and how many were read.
 * @param {import("./driver.mjs").Session} session @param {string[]} needles
 */
export async function consoleFindings(session, needles) {
  const service = /** @type {string[]} */ (await session.chrome(() => {
    const w = /** @type {any} */ (globalThis);
    return (w.Services.console.getMessageArray() ?? []).map((/** @type {any} */ m) => String(m.message ?? m.errorMessage ?? ""));
  }));
  // The browser's own output, as the driver keeps it (the console lines of every process, with CONSOLE_PREFS).
  const output = String(/** @type {any} */ (session).log ?? "");
  const all = [...service, ...output.split(/\r?\n/)];
  const hits = all.filter((text) => needles.some((n) => text.includes(n))).map((text) => text.slice(0, 80));
  return { messages: all.length, hits, control: all.some((text) => text.includes("ferret-leak-control")) };
}

/**
 * Listens in the current extension page (the test bridge) to every runtime message the extension's pages and content scripts send
 * from now on, and keeps how many there were and which held a needle.
 * @param {import("./driver.mjs").Session} session @param {string[]} needles
 */
export async function watchMessages(session, needles) {
  await session.content((/** @type {string[]} */ texts) => {
    const w = /** @type {any} */ (window);
    w.__leak = { messages: 0, hits: [] };
    browser.runtime.onMessage.addListener((/** @type {unknown} */ message) => {
      w.__leak.messages += 1;
      let text = "";
      try {
        text = typeof message === "string" ? message : JSON.stringify(message);
      } catch {
        text = String(message);
      }
      if (texts.some((n) => text.includes(n))) w.__leak.hits.push(text.slice(0, 80));
      return undefined;
    });
  }, needles);
}

/** What the message watch saw. @param {import("./driver.mjs").Session} session */
export async function messageFindings(session) {
  return /** @type {{ messages: number, hits: string[] }} */ (await session.content(() => ({ .../** @type {any} */ (window).__leak })));
}
