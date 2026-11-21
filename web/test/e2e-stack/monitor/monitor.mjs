// A stand-in for the push monitor that the server tells after every good backup set.
//
// It records every call to /api/push/<token> (the method, the path, the query and the few headers that say who called) and
// answers 200. The scenarios read the record from /__recorded and empty it with /__reset. Nothing else is served, and the
// record lives in memory only. The port is on the network of the stack, never published.
import { createServer } from "node:http";

const PORT = 9100;
/** @type {{ at: number, method: string, path: string, query: string, headers: Record<string, string> }[]} */
let calls = [];

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://stand-in");
  const send = (/** @type {number} */ status, /** @type {unknown} */ body) => {
    response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(JSON.stringify(body));
  };
  if (url.pathname === "/health") return send(200, { ok: true });
  if (url.pathname === "/__recorded") return send(200, { calls });
  if (url.pathname === "/__reset") {
    calls = [];
    return send(200, { ok: true });
  }
  if (url.pathname.startsWith("/api/push/")) {
    const keep = ["user-agent", "referer", "authorization", "cookie", "content-length"];
    calls.push({
      at: Date.now(),
      method: request.method ?? "",
      path: url.pathname,
      query: url.search,
      headers: Object.fromEntries(keep.filter((name) => request.headers[name] !== undefined).map((name) => [name, String(request.headers[name])])),
    });
    return send(200, { ok: true });
  }
  return send(404, { ok: false });
});
server.listen(PORT, "0.0.0.0");
