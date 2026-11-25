// The answer objects of the passkey script against the browser's own, field for field. The spec puts the objects' builder on
// window.__credentialFrom (the script content/passkeyResponse.mjs, joined); this page makes a registration and a sign-in with
// the browser's own WebAuthn (a virtual authenticator), builds the same answer again from the same bytes with the builder, and
// lists every difference a page script can see. A difference that cannot be removed (a script's object is not a platform
// object) is listed under `known`; the spec asserts that `differences` is empty and that `known` is what it expects.
window.compareAnswers = async function compareAnswers() {
  const build = window.__credentialFrom;
  if (typeof build !== "function") throw new Error("the builder is not in the page");
  const rpId = location.hostname;
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));
  const hex = (ab) => Array.from(new Uint8Array(ab), (x) => x.toString(16).padStart(2, "0")).join("");
  // A value as text: bytes as hex, so two values compare by what they hold, and the order of keys stays.
  const norm = (v) => JSON.stringify(v, (key, x) => (x instanceof ArrayBuffer ? "bytes:" + hex(x) : ArrayBuffer.isView(x) ? "view:" + hex(x.buffer) : x === undefined ? "undefined" : x));

  // What a script can see of an object's shape: keys, for...in, tag and, for each member, its kind and flags.
  const shape = (o) => {
    const forIn = [];
    for (const k in o) forIn.push(k);
    const members = {};
    for (const k of forIn) {
      let p = o;
      while (p !== null && !Object.prototype.hasOwnProperty.call(p, k)) p = Object.getPrototypeOf(p);
      const d = Object.getOwnPropertyDescriptor(p, k);
      members[k] = {
        enumerable: d.enumerable, configurable: d.configurable, writable: d.writable === undefined ? null : d.writable,
        getter: typeof d.get === "function" ? d.get.name + "/" + d.get.length : null, setter: d.set === undefined ? null : "set",
        method: typeof d.value === "function" ? d.value.name + "/" + d.value.length : null,
      };
    }
    return { keys: Object.keys(o), own: Reflect.ownKeys(o).length, forIn, tag: Object.prototype.toString.call(o), members };
  };
  const chain = (o) => {
    const out = [];
    for (let p = Object.getPrototypeOf(o); p !== null; p = Object.getPrototypeOf(p)) out.push(p);
    return out;
  };
  const called = (f, self) => {
    try {
      return norm(f.call(self));
    } catch (e) {
      return "throws " + e.name;
    }
  };
  const cloned = (o) => {
    try {
      structuredClone(o);
      return "clones";
    } catch (e) {
      return "throws " + e.name;
    }
  };

  // Compares one pair (the browser's object, ours) and lists what differs.
  const compare = (name, theirs, ours, differences, known) => {
    const a = shape(theirs);
    const b = shape(ours);
    for (const field of ["keys", "own", "forIn", "tag", "members"]) {
      if (norm(a[field]) !== norm(b[field])) differences.push(name + ": " + field + ": browser " + norm(a[field]) + " / ours " + norm(b[field]));
    }
    // The prototypes behind the object's own are the browser's: the very same objects.
    const ca = chain(theirs);
    const cb = chain(ours);
    if (cb.length !== ca.length + 1 || !ca.every((p, i) => p === cb[i + 1])) differences.push(name + ": the prototype chain does not continue as the browser's");
    for (const [constructorName, ctor] of [["PublicKeyCredential", window.PublicKeyCredential], ["Credential", window.Credential], ["AuthenticatorResponse", window.AuthenticatorResponse], ["AuthenticatorAttestationResponse", window.AuthenticatorAttestationResponse], ["AuthenticatorAssertionResponse", window.AuthenticatorAssertionResponse]]) {
      if ((theirs instanceof ctor) !== (ours instanceof ctor)) differences.push(name + ": instanceof " + constructorName + ": browser " + (theirs instanceof ctor) + " / ours " + (ours instanceof ctor));
    }
    // Every member: the value (a method: what it gives).
    for (const k of a.forIn) {
      if (typeof theirs[k] !== typeof ours[k]) {
        differences.push(name + "." + k + ": typeof " + typeof theirs[k] + " / " + typeof ours[k]);
        continue;
      }
      if (typeof theirs[k] === "function") {
        const x = called(theirs[k], theirs);
        const y = called(ours[k], ours);
        if (x !== y) differences.push(name + "." + k + "(): browser " + x + " / ours " + y);
      } else if (k !== "response") {
        if (norm(theirs[k]) !== norm(ours[k])) differences.push(name + "." + k + ": browser " + norm(theirs[k]) + " / ours " + norm(ours[k]));
      }
    }
    // A buffer an attribute holds is the same object at every read.
    for (const k of a.forIn) {
      if (theirs[k] instanceof ArrayBuffer && ((theirs[k] === theirs[k]) !== (ours[k] === ours[k]))) differences.push(name + "." + k + ": same object at each read: differs");
    }
    // What a script is not given: the browser's brand. Kept as what it is, not asserted away.
    const proto = Object.getPrototypeOf(theirs);
    for (const k of ["toJSON", "getClientExtensionResults", "getTransports", "getAuthenticatorData", "getPublicKey", "getPublicKeyAlgorithm"]) {
      if (typeof proto[k] === "function") known[name + ": the browser's " + k + " on ours"] = called(proto[k], ours);
    }
    known[name + ": the object's own prototype is the browser's"] = Object.getPrototypeOf(ours) === proto;
    known[name + ": structuredClone: browser"] = cloned(theirs);
    known[name + ": structuredClone: ours"] = cloned(ours);
    known[name + ": then in object"] = "then" in ours;
  };

  const out = {};
  for (const kind of ["create", "get"]) {
    const differences = [];
    const known = {};
    let theirs;
    let fields;
    if (kind === "create") {
      theirs = await navigator.credentials.create({ publicKey: {
        challenge: random(32), rp: { id: rpId, name: "Fixture" }, user: { id: random(16), name: "alice", displayName: "Alice" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
        extensions: { credProps: true, prf: {} },
      } });
      window.__created = theirs;
      const r = theirs.response;
      fields = {
        id: theirs.rawId, clientDataJSON: r.clientDataJSON, authenticatorData: r.getAuthenticatorData(), authenticatorAttachment: theirs.authenticatorAttachment,
        attestationObject: r.attestationObject, publicKey: r.getPublicKey(), publicKeyAlgorithm: r.getPublicKeyAlgorithm(), transports: r.getTransports(),
        clientExtensionResults: theirs.getClientExtensionResults(),
      };
    } else {
      theirs = await navigator.credentials.get({ publicKey: {
        challenge: random(32), rpId, allowCredentials: [{ type: "public-key", id: window.__created.rawId }], userVerification: "preferred",
        extensions: { prf: { eval: { first: new Uint8Array(32).fill(5), second: new Uint8Array(32).fill(6) } } },
      } });
      const r = theirs.response;
      fields = {
        id: theirs.rawId, clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, authenticatorAttachment: theirs.authenticatorAttachment,
        signature: r.signature, userHandle: r.userHandle, clientExtensionResults: theirs.getClientExtensionResults(),
      };
    }
    const ours = build(kind, fields);
    if (ours === null) {
      differences.push(kind + ": the builder gave null");
      out[kind] = { differences, known };
      continue;
    }
    compare(kind + " credential", theirs, ours, differences, known);
    compare(kind + " response", theirs.response, ours.response, differences, known);
    if (JSON.stringify(theirs) !== JSON.stringify(ours)) differences.push(kind + ": JSON.stringify: browser " + JSON.stringify(theirs) + " / ours " + JSON.stringify(ours));
    if (norm(theirs.toJSON()) !== norm(ours.toJSON())) differences.push(kind + ": toJSON()");
    out[kind] = {
      differences, known,
      seen: {
        attachment: theirs.authenticatorAttachment, transports: kind === "create" ? theirs.response.getTransports() : null, ext: norm(theirs.getClientExtensionResults()),
        json: JSON.stringify(theirs.toJSON()), forIn: shape(theirs).forIn, responseForIn: shape(theirs.response).forIn,
      },
    };
  }
  return out;
};
