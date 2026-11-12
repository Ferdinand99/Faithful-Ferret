// The options page of the test build. It exists to answer one question: when the
// browser opens an options page (inside about:addons, or in a tab), does the
// router's check accept the page as a top-level extension page? The page asks the
// test build's whoami port, which answers with the verdict of `isUiPort` and the
// facts the browser gave about the sender, and shows the answer.
import { el, mount } from "../../shared/dom.mjs";

const root = document.getElementById("root");
const port = browser.runtime.connect({ name: "ferret-test-whoami" });
port.onMessage.addListener((answer) => {
  port.disconnect();
  if (!root) return;
  const text = JSON.stringify(answer);
  mount(
    root,
    el("h1", null, "Ferret options (test build)"),
    // The way to the measurement page without looking up the extension's address.
    el("p", null, el("a", { id: "measure-link", href: "/pages/test-only/measure.html" }, "Open the lifetime measurement page")),
    el("pre", { id: "whoami" }, text),
  );
  document.documentElement.dataset.whoami = text;
  // An options page inside about:addons is not reachable from the test driver: it leaves the answer where the test can read it.
  browser.storage.local.set({ probe_whoami_options: answer }).catch(() => {});
  document.documentElement.dataset.ready = "1";
});
