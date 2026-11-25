// The test certificate authority of the passkey fixtures: made when the container starts,
// with the openssl program. The CA key is deleted as soon as the one server certificate is
// signed, so nothing can mint more certificates later. The CA is limited by name
// constraints to the fixture's own names (permitted: the listed hosts and localhost; every
// other name is refused by the browser even if the CA were trusted for the whole web),
// and lives thirty days (kept in a volume, so a restart keeps it). Only the test profile of the matrix runner trusts it.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** How long the CA and the certificate live, and how much of that must be left for them to be reused when the container restarts. */
const DAYS = 30;
const REUSE_MIN_SECONDS = 3 * 24 * 3600;

/**
 * The openssl extension lines of the CA: constrained to `hosts` and the localhost names, and no IP address at all.
 * @param {string[]} hosts
 * @param {string[]} localhostNames
 * @returns {string[]}
 */
export function caExtensions(hosts, localhostNames) {
  const permitted = [...hosts, ...localhostNames].map((h) => `permitted;DNS:${h}`).join(",");
  return [
    "basicConstraints=critical,CA:TRUE,pathlen:0",
    "keyUsage=critical,keyCertSign,cRLSign",
    `nameConstraints=critical,${permitted},excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0`,
  ];
}

/**
 * Makes the CA and the certificate, or, when `dir` (a volume that outlives the container) already holds ones for the same
 * names with more than three days left, takes those: a restart of the container then keeps the CA that a test browser trusts.
 * @param {string} dir  where ca.pem, server.pem and server.key go
 * @param {string[]} hosts
 * @param {string[]} localhostNames
 * @returns {{ caPem: string, keyPem: string, certPem: string }}
 */
export function makeCertificates(dir, hosts, localhostNames) {
  const names = [...hosts, ...localhostNames];
  if (names.length === 0) throw new Error("tls: no host names");
  const fingerprint = createHash("sha256").update(JSON.stringify(caExtensions(hosts, localhostNames)) + names.join(",")).digest("hex");
  const stamp = join(dir, "names.sha256");
  if (existsSync(stamp) && readFileSync(stamp, "utf8").trim() === fingerprint && ["ca.pem", "server.pem", "server.key"].every((f) => existsSync(join(dir, f)))) {
    try {
      // openssl exits 0 when the certificate is still valid that many seconds from now.
      execFileSync("openssl", ["x509", "-in", join(dir, "ca.pem"), "-noout", "-checkend", String(REUSE_MIN_SECONDS)], { stdio: "ignore" });
      execFileSync("openssl", ["x509", "-in", join(dir, "server.pem"), "-noout", "-checkend", String(REUSE_MIN_SECONDS)], { stdio: "ignore" });
      return { caPem: readFileSync(join(dir, "ca.pem"), "utf8"), keyPem: readFileSync(join(dir, "server.key"), "utf8"), certPem: readFileSync(join(dir, "server.pem"), "utf8") };
    } catch {
      // expired or about to: make new ones
    }
  }
  const run = (/** @type {string[]} */ ...args) => execFileSync("openssl", args, { cwd: dir, stdio: ["ignore", "ignore", "pipe"] });
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  const exts = caExtensions(hosts, localhostNames).flatMap((line) => ["-addext", line]);
  run("req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", String(DAYS), "-subj", "/CN=Ferret passkey fixtures CA (test only)", ...exts);
  run("req", "-new", ...ec, "-keyout", "server.key", "-out", "server.csr", "-subj", `/CN=${names[0]}`);
  writeFileSync(
    join(dir, "server.ext"),
    [`subjectAltName=${names.map((h) => `DNS:${h}`).join(",")}`, "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", "extendedKeyUsage=serverAuth", ""].join("\n"),
  );
  run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", String(DAYS), "-out", "server.pem", "-extfile", "server.ext");
  rmSync(join(dir, "ca.key"));
  chmodSync(join(dir, "server.key"), 0o600);
  writeFileSync(stamp, `${fingerprint}\n`);
  return {
    caPem: readFileSync(join(dir, "ca.pem"), "utf8"),
    keyPem: readFileSync(join(dir, "server.key"), "utf8"),
    certPem: readFileSync(join(dir, "server.pem"), "utf8"),
  };
}
