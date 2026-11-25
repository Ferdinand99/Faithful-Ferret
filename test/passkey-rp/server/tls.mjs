// The test certificate authority of the passkey fixtures: made when the container starts,
// with the openssl program. The CA key is deleted as soon as the one server certificate is
// signed, so nothing can mint more certificates later. The CA is limited by name
// constraints to the fixture's own names (permitted: the listed hosts and localhost; every
// other name is refused by the browser even if the CA were trusted for the whole web),
// and lives two days. Only the test profile of the matrix runner trusts it.
import { execFileSync } from "node:child_process";
import { chmodSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The openssl extension lines of the CA: constrained to `hosts` and the localhost names.
 * @param {string[]} hosts
 * @param {string[]} localhostNames
 * @returns {string[]}
 */
export function caExtensions(hosts, localhostNames) {
  const permitted = [...hosts, ...localhostNames].map((h) => `permitted;DNS:${h}`).join(",");
  return [
    "basicConstraints=critical,CA:TRUE,pathlen:0",
    "keyUsage=critical,keyCertSign,cRLSign",
    `nameConstraints=critical,${permitted}`,
  ];
}

/**
 * @param {string} dir  where ca.pem, server.pem and server.key go
 * @param {string[]} hosts
 * @param {string[]} localhostNames
 * @returns {{ caPem: string, keyPem: string, certPem: string }}
 */
export function makeCertificates(dir, hosts, localhostNames) {
  const names = [...hosts, ...localhostNames];
  if (names.length === 0) throw new Error("tls: no host names");
  const run = (/** @type {string[]} */ ...args) => execFileSync("openssl", args, { cwd: dir, stdio: ["ignore", "ignore", "pipe"] });
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  const exts = caExtensions(hosts, localhostNames).flatMap((line) => ["-addext", line]);
  run("req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Ferret passkey fixtures CA (test only)", ...exts);
  run("req", "-new", ...ec, "-keyout", "server.key", "-out", "server.csr", "-subj", `/CN=${names[0]}`);
  writeFileSync(
    join(dir, "server.ext"),
    [`subjectAltName=${names.map((h) => `DNS:${h}`).join(",")}`, "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", "extendedKeyUsage=serverAuth", ""].join("\n"),
  );
  run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2", "-out", "server.pem", "-extfile", "server.ext");
  rmSync(join(dir, "ca.key"));
  chmodSync(join(dir, "server.key"), 0o600);
  return {
    caPem: readFileSync(join(dir, "ca.pem"), "utf8"),
    keyPem: readFileSync(join(dir, "server.key"), "utf8"),
    certPem: readFileSync(join(dir, "server.pem"), "utf8"),
  };
}
