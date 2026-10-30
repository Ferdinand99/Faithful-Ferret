// The end-to-end stack itself: both origins answer over https with the stack's
// test CA, the security headers arrive through the TLS terminator, the proxy's
// forwarding headers are believed from the terminator and from nobody else. The
// scenarios of the milestone build on this.
import { expect, test } from "@playwright/test";

const vault = process.env.FERRET_E2E_VAULT_URL ?? "";
const admin = process.env.FERRET_E2E_ADMIN_URL ?? "";

test("both_origins_answer_over_https_with_the_test_ca", async ({ page }) => {
  for (const origin of [vault, admin]) {
    const response = await page.goto(`${origin}/healthz`);
    expect(response?.status(), origin).toBe(200);
    expect(await page.textContent("body"), origin).toBe("ok");
  }
});

test("the_vault_page_carries_the_security_headers_through_the_terminator", async ({ page }) => {
  const response = await page.goto(`${vault}/`);
  expect(response?.status()).toBe(200);
  const headers = response?.headers() ?? {};
  for (const name of [
    "content-security-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
  ]) {
    expect(headers[name], name).toBeTruthy();
  }
  expect(headers["server"]).toBeUndefined();
});

test("the_wasm_package_is_served_as_application_wasm", async ({ request }) => {
  const page = await request.get(`${vault}/`);
  const match = /\/[A-Za-z0-9_./-]*\.wasm/.exec(await page.text());
  const path = match ? match[0] : "/pkg-web/ferret_core_wasm_bg.wasm";
  const response = await request.get(`${vault}${path}`);
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("application/wasm");
});

// The headers every mutating API request needs besides the body.
const apiHeaders = { "ferret-protocol": "1", origin: vault };
// A well-formed first step of the registration with a setup token that is wrong:
// it is refused with 403 once the transport has passed, and with 400
// insecure_transport when it has not.
const registerStart = {
  setup_token: "not-the-setup-token",
  email: "e2e@example.test",
  request: "A".repeat(43),
};

// Setup over https is accepted as far as the transport goes: the terminator is a
// trusted proxy, so its X-Forwarded-Proto is believed. (The request itself is
// refused, because its setup token is wrong.)
test("the_terminator_is_trusted_so_https_setup_is_not_an_insecure_transport", async ({ request }) => {
  const response = await request.post(`${vault}/api/auth/opaque/register/start`, {
    data: registerStart,
    headers: apiHeaders,
  });
  expect(response.status()).toBe(403);
  expect(await response.text()).toContain("forbidden");
});

// A peer that is not the terminator cannot claim https: this test container
// reaches the app directly, and its forged header is ignored.
test("a_forged_forwarded_proto_from_another_peer_is_ignored", async ({ request }) => {
  const response = await request.post("http://ferret-e2e-app:3041/api/auth/opaque/register/start", {
    data: registerStart,
    headers: { ...apiHeaders, "x-forwarded-proto": "https", "x-forwarded-for": "203.0.113.9" },
  });
  expect(response.status()).toBe(400);
  expect(await response.text()).toContain("insecure_transport");
});
