// A registration and a sign-in with the page's own host as the RP ID, and the outcome of each call as a short record.
// Used by the pages of this folder and by pk-adversary.
window.ceremony = async function ceremony() {
  const rpId = location.hostname;
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));
  const out = {};
  const record = async (name, run) => {
    try {
      const value = await run();
      out[name] = value === null || value === undefined ? String(value) : {
        type: value.type,
        native: value instanceof PublicKeyCredential && Object.getPrototypeOf(value) === PublicKeyCredential.prototype,
      };
      return value;
    } catch (error) {
      out[name] = { error: error && error.name };
      return null;
    }
  };
  const created = await record("create", () => navigator.credentials.create({ publicKey: {
    challenge: random(32),
    rp: { id: rpId, name: "Fixture" },
    user: { id: random(16), name: "alice", displayName: "Alice" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
  } }));
  await record("get", () => navigator.credentials.get({ publicKey: {
    challenge: random(32),
    rpId,
    allowCredentials: created ? [{ type: "public-key", id: created.rawId }] : [],
    userVerification: "preferred",
  } }));
  return out;
};

// The calls that are not Ferret's to take, and their outcome.
window.otherCalls = async function otherCalls() {
  const out = {};
  for (const [name, run] of [
    ["password", () => navigator.credentials.get({ password: true })],
    ["federated", () => navigator.credentials.get({ federated: { providers: ["https://idp.example"] } })],
    ["no_options", () => navigator.credentials.get()],
    ["silent", () => navigator.credentials.get({ mediation: "silent", publicKey: { challenge: new Uint8Array(16) } })],
  ]) {
    try {
      const value = await run();
      out[name] = { value: value === null ? "null" : typeof value };
    } catch (error) {
      out[name] = { error: error && error.name };
    }
  }
  return out;
};
