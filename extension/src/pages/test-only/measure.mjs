// The measure page (test build only): starts one scenario of the lifetime
// measurement and shows the log that the background page has written.
//
// To measure, start a scenario here, then CLOSE this page and about:debugging, and
// wait. A page that stays open can keep the background alive and give a wrong
// answer. Later, open this page again: it reads the log straight from storage
// (reading does not wake the background) and shows how the background page lived.
import { el, mount } from "../el.mjs";
import { LOG_KEY, SCENARIO_KEY, summarize } from "../../shared/test-only/measureSummary.mjs";

const PORT = "ferret-test-measure";
const SCENARIOS = [
  ["idle", "Vault open, no page, no network"],
  ["sse", "Vault open, with an open fetch stream (https URL of a server-sent events stream)"],
  ["popup", "Vault open, with the popup page open as a tab (open it yourself, then close this page)"],
  ["argon", "Vault open, with a long Argon2id job (runs again and again)"],
];

/**
 * Sends one command to the background page and waits for the answer. The port is
 * closed at once: an open port could keep the background page alive.
 * @param {Record<string, unknown>} command
 * @returns {Promise<any>}
 */
function send(command) {
  return new Promise((resolve, reject) => {
    const port = browser.runtime.connect({ name: PORT });
    const timer = setTimeout(() => {
      port.disconnect();
      reject(new Error("no answer"));
    }, 120_000);
    port.onMessage.addListener((/** @type {any} */ reply) => {
      clearTimeout(timer);
      port.disconnect();
      if (reply?.ok) resolve(reply.value);
      else reject(new Error(String(reply?.code ?? "failed")));
    });
    port.onDisconnect.addListener(() => {
      clearTimeout(timer);
      reject(new Error("the background page closed the port"));
    });
    port.postMessage({ id: "1", ...command });
  });
}

/** @param {number | null} ms */
const seconds = (ms) => (ms === null ? "never" : `${Math.round(ms / 1000)} s`);

async function show() {
  const stored = await browser.storage.local.get([LOG_KEY, SCENARIO_KEY]);
  const entries = Array.isArray(stored[LOG_KEY]) ? stored[LOG_KEY] : [];
  const scenario = stored[SCENARIO_KEY] ?? null;
  const summary = summarize(entries);
  const text = JSON.stringify({ scenario, summary, entries });
  const target = document.getElementById("report");
  if (!target) return;
  const rows = entries.slice(-40).map((e) => el("li", null, `${new Date(e.at).toISOString().slice(11, 19)}  ${e.kind}  boot ${e.boot}  ${e.core ?? ""}`));
  mount(
    target,
    el("p", { id: "summary" },
      `Scenario ${scenario?.name ?? "none"}. Starts of the page: ${summary.boots}. Heartbeats: ${summary.heartbeats}. ` +
      `The browser first announced the end of the page after ${seconds(summary.firstSuspendAfterMs)}; ` +
      `the page started again after ${seconds(summary.restartAfterMs)}.`),
    el("ul", { id: "entries" }, ...rows),
    el("pre", { id: "log" }, text),
  );
  document.documentElement.dataset.log = "1";
}

/** @param {string} message */
function say(message) {
  const status = document.getElementById("status");
  if (status) mount(status, document.createTextNode(message));
  document.documentElement.dataset.status = message;
}

function main() {
  const root = document.getElementById("root");
  if (!root) return;
  const select = /** @type {HTMLSelectElement} */ (el("select", { id: "scenario" }, ...SCENARIOS.map(([value, label]) => el("option", { value }, label))));
  const url = /** @type {HTMLInputElement} */ (el("input", { id: "url", type: "text", placeholder: "https://example.org/sse (only for the stream scenario)" }));
  const run = async (/** @type {() => Promise<unknown>} */ action) => {
    try {
      say("working...");
      await action();
    } catch (error) {
      say(`failed: ${/** @type {Error} */ (error).message}`);
    }
  };
  mount(
    root,
    el("h1", null, "Ferret lifetime measurement (test build)"),
    el("p", null, "Start a scenario, then close this page and about:debugging and wait. Open this page again later to read the log."),
    el("label", { for: "scenario" }, "Scenario "),
    select,
    el("label", { for: "url" }, " Stream URL "),
    url,
    el("p", null,
      el("button", {
        id: "grant",
        type: "button",
        onclick: () => run(async () => {
          const origin = new URL(url.value).origin;
          const granted = await browser.permissions.request({ origins: [`${origin}/*`] });
          say(granted ? `permission for ${origin} granted` : `permission for ${origin} refused`);
          document.documentElement.dataset.granted = granted ? "1" : "0";
        }),
      }, "Allow the stream's server"),
      " ",
      el("button", {
        id: "start",
        type: "button",
        onclick: () => run(async () => {
          /** @type {Record<string, unknown>} */
          const command = { cmd: "start", scenario: select.value };
          if (select.value === "sse") command.url = url.value;
          await send(command);
          say(`started ${select.value}: close this page now`);
          document.documentElement.dataset.started = "1";
        }),
      }, "Start"),
      " ",
      el("button", { id: "stop", type: "button", onclick: () => run(async () => { await send({ cmd: "stop" }); say("stopped"); }) }, "Stop"),
      " ",
      el("button", { id: "clear", type: "button", onclick: () => run(async () => { await send({ cmd: "clear" }); await show(); say("log cleared"); }) }, "Clear log"),
      " ",
      el("button", { id: "refresh", type: "button", onclick: () => run(async () => { await show(); say("log read"); }) }, "Read log"),
    ),
    el("p", { id: "status" }),
    el("div", { id: "report" }),
  );
  show().then(() => { document.documentElement.dataset.ready = "1"; }, (error) => say(`failed: ${error.message}`));
}

main();
