// Run by `scripts/lanbox-ext.sh e2e`, in a container on the end-to-end stack's
// network: Firefox trusts the stack's certificate authority (policies.json) and
// the stack's host names load over https. Later specs of the extension use the
// same setup to sign in against the stack.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { channels, launch, readHosts, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

test("the_e2e_ca_is_trusted_and_the_stack_hosts_load_over_https", async () => {
  assert.ok(process.env.FERRET_E2E_CA_PEM, "FERRET_E2E_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e)");
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      for (const host of readHosts().e2e) {
        await session.navigate(`https://${host}/`);
        const where = await session.content(() => document.documentURI);
        assert.ok(where.startsWith(`https://${host}/`), `${channel}: ${host} loaded, not an error page (${where})`);
      }
    } finally {
      await session.quit();
    }
  }
});
