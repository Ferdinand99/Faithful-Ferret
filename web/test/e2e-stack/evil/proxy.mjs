// The malicious server of the end-to-end stack: a proxy that sits between the
// TLS terminator and the real server and lies on request. It has three
// listeners, and the real server believes it (it is the server's only trusted
// proxy; it passes the forwarding headers of the terminator on untouched):
//
//   vault listener    -> the vault listener of the real server. `/api/sync/*`
//                        is read, recorded and, in a lying mode, reshaped
//                        (modes.mjs). The event stream `/api/sync/events` and
//                        everything else passes through unbuffered.
//   admin listener    -> the admin listener of the real server, never touched.
//   control listener  -> only here: GET /health, GET /mode, POST /mode
//                        {mode, ...params}, POST /reset, GET /recorded. It is
//                        on the network of the stack and published nowhere.
//
// In the mode `honest` (the default) every request and answer is forwarded byte
// for byte; the proxy only keeps a record of what the real server said.
//
// Test rig only: it lives in the end-to-end stack and in no production image.
import http from "node:http";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createRecorder } from "./recorder.mjs";
import { ModeError, activate, honest, parseMode, preempt, shape } from "./modes.mjs";

/** Headers that belong to one connection and are not passed on. */
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);
const SID_COOKIE = "__Host-ferret_sid";
const MAX_BODY = 8 * 1024 * 1024;

/** One connection per request: a restart of the real server must not leave a dead socket in a pool. */
const agent = new http.Agent({ keepAlive: false });

/** @param {string[]} raw rawHeaders @param {(name: string) => boolean} [skip] */
function pairs(raw, skip = () => false) {
  /** @type {string[]} */
  const out = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i].toLowerCase();
    if (HOP_BY_HOP.has(name) || skip(name)) continue;
    out.push(raw[i], raw[i + 1]);
  }
  return out;
}

/** The session cookie of a request, or null. @param {http.IncomingMessage} req */
function sessionOf(req) {
  for (const line of [req.headers.cookie ?? ""]) {
    for (const part of line.split(";")) {
      const eq = part.indexOf("=");
      if (eq > 0 && part.slice(0, eq).trim() === SID_COOKIE) return part.slice(eq + 1).trim() || null;
    }
  }
  return null;
}

/**
 * What a request to the vault listener is.
 * @param {string} method @param {string} pathname
 * @returns {"events" | "changes" | "items" | "checkpoint" | "put_item" | "batch" | "put_checkpoint" | "other" | null} null: not the sync API
 */
function classify(method, pathname) {
  if (pathname !== "/api/sync" && !pathname.startsWith("/api/sync/")) return null;
  if (pathname === "/api/sync/events") return "events";
  if (method === "GET" && pathname === "/api/sync/changes") return "changes";
  if (method === "GET" && pathname === "/api/sync/items") return "items";
  if (method === "GET" && pathname === "/api/sync/checkpoint") return "checkpoint";
  if (method === "PUT" && pathname === "/api/sync/checkpoint") return "put_checkpoint";
  if (method === "PUT" && /^\/api\/sync\/items\/[0-9a-f]{32}$/.test(pathname)) return "put_item";
  if (method === "POST" && pathname === "/api/sync/batch") return "batch";
  return "other";
}

/** @param {http.ServerResponse} res @param {number} status @param {unknown} json */
function sendJson(res, status, json) {
  const body = Buffer.from(JSON.stringify(json));
  res.writeHead(status, { "content-type": "application/json", "content-length": body.length, "cache-control": "no-store" });
  res.end(body);
}

/** @param {http.IncomingMessage} req @param {number} limit @returns {Promise<Buffer>} */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new ModeError("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** @param {Buffer} buf */
function parseJson(buf) {
  try {
    return JSON.parse(buf.toString("utf8"));
  } catch {
    return undefined;
  }
}

/**
 * @param {{ upstreamVault: string, upstreamAdmin: string, now?: () => number, random?: (n: number) => Uint8Array, log?: (line: string) => void }} options
 */
export function createProxy({ upstreamVault, upstreamAdmin, now = Date.now, random = randomBytes, log = () => {} }) {
  const recorder = createRecorder({ now });
  let active = honest(recorder);

  /**
   * Sends the request on to `upstream`. `onResponse` gets the real answer and
   * decides what the client gets.
   * @param {string} upstream
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   * @param {Buffer | null} body the request body when it was read (else it is streamed)
   * @param {(up: http.IncomingMessage) => void} onResponse
   * @param {(name: string) => boolean} [skip] request headers not to pass on
   */
  function forward(upstream, req, res, body, onResponse, skip) {
    const target = new URL(upstream);
    const up = http.request(
      { agent, host: target.hostname, port: target.port, method: req.method, path: req.url, headers: pairs(req.rawHeaders, skip) },
      onResponse,
    );
    up.on("error", () => {
      if (!res.headersSent) sendJson(res, 502, { error: "upstream_unreachable" });
      else res.destroy();
    });
    res.on("close", () => {
      if (!res.writableFinished) up.destroy();
    });
    if (body !== null) up.end(body);
    else req.pipe(up);
  }

  /** Passes an answer through as it is, as a stream. @param {http.ServerResponse} res @param {http.IncomingMessage} answer @param {boolean} [flush] */
  function stream(res, answer, flush = false) {
    res.writeHead(answer.statusCode ?? 502, pairs(answer.rawHeaders));
    if (flush) {
      res.flushHeaders();
      res.socket?.setNoDelay(true);
    }
    answer.pipe(res);
    res.on("close", () => answer.destroy());
  }

  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  function passThrough(upstream, req, res) {
    forward(upstream, req, res, null, (answer) => stream(res, answer));
  }

  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  async function vault(req, res) {
    const url = new URL(req.url ?? "/", "http://proxy.invalid");
    const kind = classify(req.method ?? "GET", url.pathname);
    if (kind === null) return passThrough(upstreamVault, req, res);
    if (kind === "events") {
      // The event stream: unbuffered, in both directions.
      return forward(upstreamVault, req, res, null, (answer) => stream(res, answer, true));
    }
    const sid = sessionOf(req);
    const shaped = kind === "changes" || kind === "items" || kind === "checkpoint";
    if (shaped) {
      const early = preempt(active, { route: kind, query: url.searchParams }, recorder);
      if (early) return sendJson(res, early.status, early.json);
    }
    /** @type {Buffer} */
    let body;
    try {
      body = await readBody(req, MAX_BODY);
    } catch {
      if (!res.headersSent) sendJson(res, 413, { error: "too_large" });
      return;
    }
    // The answers that are read are not compressed, so that they can be parsed.
    forward(upstreamVault, req, res, body, (answer) => bufferedAnswer(kind, url, sid, body, res, answer), shaped ? (name) => name === "accept-encoding" : undefined);
  }

  /**
   * @param {string} kind @param {URL} url @param {string | null} sid @param {Buffer} sent
   * @param {http.ServerResponse} res @param {http.IncomingMessage} answer
   */
  function bufferedAnswer(kind, url, sid, sent, res, answer) {
    /** @type {Buffer[]} */
    const chunks = [];
    answer.on("data", (c) => chunks.push(c));
    answer.on("error", () => res.destroy());
    answer.on("end", () => {
      const raw = Buffer.concat(chunks);
      const headers = pairs(answer.rawHeaders, (name) => name === "content-length");
      /** @type {Buffer} */
      let out = raw;
      const readable = answer.statusCode === 200 && !answer.headers["content-encoding"];
      const json = readable ? parseJson(raw) : undefined;
      if (json !== undefined) {
        record(kind, url, sid, sent, json);
        if (kind === "changes" || kind === "items" || kind === "checkpoint") {
          const lie = shape(active, recorder, { route: kind, query: url.searchParams, sid }, json, random);
          if (lie !== null) {
            out = Buffer.from(JSON.stringify(lie));
            log(`mode ${active.mode}: reshaped ${kind}`);
            for (let i = headers.length - 2; i >= 0; i -= 2) if (["etag", "content-md5"].includes(headers[i].toLowerCase())) headers.splice(i, 2);
          }
        }
      }
      res.writeHead(answer.statusCode ?? 502, [...headers, "content-length", String(out.length)]);
      res.end(out);
    });
  }

  /** What the real server said or stored, into the record. @param {string} kind @param {URL} url @param {string | null} sid @param {Buffer} sent @param {any} json */
  function record(kind, url, sid, sent, json) {
    switch (kind) {
      case "changes":
        return recorder.observeChanges(json, sid);
      case "items":
        return recorder.observeItems(json, sid);
      case "checkpoint":
        return recorder.observeCheckpoint(json, sid);
      case "put_item":
        return recorder.observePut(url.pathname.slice(url.pathname.lastIndexOf("/") + 1), parseJson(sent), json, sid);
      case "batch":
        return recorder.observeBatch(parseJson(sent), json, sid);
      case "put_checkpoint":
        return recorder.observePutCheckpoint(parseJson(sent), sid);
      default:
    }
  }

  /** The admin listener: nothing but a pipe. @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  function admin(req, res) {
    passThrough(upstreamAdmin, req, res);
  }

  /** The control listener. @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  async function control(req, res) {
    // A page in a browser must not be able to switch the lies on.
    if (req.headers.origin !== undefined || req.headers["sec-fetch-site"] !== undefined) return sendJson(res, 403, { error: "forbidden" });
    const { pathname } = new URL(req.url ?? "/", "http://control.invalid");
    try {
      if (req.method === "GET" && pathname === "/health") return sendJson(res, 200, { ok: true });
      if (req.method === "GET" && pathname === "/mode") return sendJson(res, 200, { mode: active.mode, params: active.params, since: active.since });
      if (req.method === "GET" && pathname === "/recorded") return sendJson(res, 200, recorder.summary());
      if (req.method === "POST" && pathname === "/mode") {
        const parsed = parseMode(parseJson(await readBody(req, 64 * 1024)));
        active = activate(parsed, recorder);
        log(`mode ${active.mode}`);
        return sendJson(res, 200, { mode: active.mode, params: active.params, since: active.since });
      }
      if (req.method === "POST" && pathname === "/reset") {
        await readBody(req, 64 * 1024);
        recorder.clear();
        active = honest(recorder);
        log("reset");
        return sendJson(res, 200, { mode: active.mode, params: active.params, since: active.since });
      }
      return sendJson(res, 404, { error: "not_found" });
    } catch (e) {
      return sendJson(res, e instanceof ModeError ? 400 : 500, { error: e instanceof ModeError ? e.message : "internal" });
    }
  }

  /** @param {(req: http.IncomingMessage, res: http.ServerResponse) => unknown} handler */
  const make = (handler) => {
    const server = http.createServer((req, res) => {
      Promise.resolve(handler(req, res)).catch(() => {
        if (!res.headersSent) sendJson(res, 500, { error: "internal" });
        else res.destroy();
      });
    });
    // The terminator keeps connections open; do not close them from under it.
    server.keepAliveTimeout = 60_000;
    return server;
  };

  const servers = { vault: make(vault), admin: make(admin), control: make(control) };

  return {
    recorder,
    servers,
    /** The mode that is active now. */
    mode: () => ({ mode: active.mode, params: active.params }),
    /**
     * Starts the three listeners; a port of 0 picks a free one.
     * @param {{ host: string, vaultPort: number, adminPort: number, controlPort: number }} where
     * @returns {Promise<{ vault: number, admin: number, control: number }>}
     */
    async listen({ host, vaultPort, adminPort, controlPort }) {
      /** @type {Record<string, number>} */
      const ports = {};
      for (const [name, port] of /** @type {const} */ ([["vault", vaultPort], ["admin", adminPort], ["control", controlPort]])) {
        await new Promise((resolve, reject) => {
          servers[name].once("error", reject);
          servers[name].listen(port, host, () => resolve(undefined));
        });
        ports[name] = /** @type {import("node:net").AddressInfo} */ (servers[name].address()).port;
      }
      return /** @type {{ vault: number, admin: number, control: number }} */ (ports);
    },
    async close() {
      await Promise.all(Object.values(servers).map((s) => new Promise((resolve) => { s.close(() => resolve(undefined)); s.closeAllConnections(); })));
    },
  };
}

// Run as the container's program: the addresses come from the environment.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const env = process.env;
  const proxy = createProxy({
    upstreamVault: env.EVIL_UPSTREAM_VAULT ?? "http://ferret-e2e-app:3041",
    upstreamAdmin: env.EVIL_UPSTREAM_ADMIN ?? "http://ferret-e2e-app:3040",
    log: (line) => console.log(`evil: ${line}`),
  });
  const ports = await proxy.listen({
    host: env.EVIL_HOST ?? "0.0.0.0",
    vaultPort: Number(env.EVIL_VAULT_PORT ?? 8041),
    adminPort: Number(env.EVIL_ADMIN_PORT ?? 8040),
    controlPort: Number(env.EVIL_CONTROL_PORT ?? 9000),
  });
  console.log(`evil: vault ${ports.vault}, admin ${ports.admin}, control ${ports.control}`);
  for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => proxy.close().then(() => process.exit(0)));
}
