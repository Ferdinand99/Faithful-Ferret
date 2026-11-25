// Pipes ports 80 and 443 of localhost (this container's own loopback, where a test browser looks
// for http://localhost and https://localhost) to the fixture container, so that the pages of the
// fixture are also served at localhost. The bytes are not touched (TLS runs end to end: the
// browser asks for "localhost" and the certificate of the fixture has that name).
//
//   node forward.mjs <fixture host name> [http port] [https port]     e.g. node forward.mjs rp-a.test
//
// Listening on 80 and 443 needs root or net.ipv4.ip_unprivileged_port_start=0 in the container.
import net from "node:net";

const [target, httpPort = "80", httpsPort = "443"] = process.argv.slice(2);
if (!target) {
  console.error("usage: node forward.mjs <fixture host name> [http port] [https port]");
  process.exit(2);
}

/** @param {number} port @param {string} address */
function forward(port, address) {
  const server = net.createServer((client) => {
    const upstream = net.connect(port, target);
    client.pipe(upstream).pipe(client);
    const close = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on("error", close);
    upstream.on("error", close);
  });
  server.on("error", (e) => {
    // ::1 may not exist in the container; 127.0.0.1 is the one that must.
    if (address === "::1") return;
    console.error(`forward: ${address}:${port}: ${e.message}`);
    process.exit(1);
  });
  server.listen(port, address, () => console.log(`forward: ${address}:${port} -> ${target}:${port}`));
}

for (const port of [Number(httpPort), Number(httpsPort)]) {
  forward(port, "127.0.0.1");
  forward(port, "::1");
}
