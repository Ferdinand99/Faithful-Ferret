// Asks the stack whether a session is still good: GET /api/auth/session on an
// origin with a cookie header. Prints the status code and nothing else. Used by
// scripts/lanbox-ferret-e2e-gate.sh between moves of the server clock; no browser.
// usage: node probe.mjs <origin> <cookie header>
const [origin, cookie] = process.argv.slice(2);
if (!origin || !cookie) {
  console.error("usage: node probe.mjs <origin> <cookie header>");
  process.exit(2);
}
const response = await fetch(`${origin}/api/auth/session`, { headers: { cookie, accept: "application/json" }, redirect: "manual" });
console.log(response.status);
