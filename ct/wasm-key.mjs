// The functions of the WebAssembly build in which a hit is a hit in code that
// handles key material, passwords, codes, tags, or may hold such code that
// wasm-opt inlined: the named functions of the binding, every export shim and
// every function without a name. Used by ct/wasm-allow-gen.mjs (which refuses
// to bless a change there) and ct/wasm-allow-baseline.mjs (which checks a pull
// request against the base branch).

export const KEY =
  /^ferret_core::(wrap|secret|codes|integrity|envelope|keys|account|opaque|prim|text|totp|item::pad|pinning|ids|tlv|sheet)::|^ferret_core::passkey::prf|^ferret_core::export::(?!plain)|^ferret_core_wasm::|shim$|^unnamed$/;

/** The path of a function from the `function` regular expression of an allow entry. */
export function pathOfEntry(functionRegex) {
  return functionRegex.replace(/^\^/, "").replace(/\$$/, "").replace(/\\(.)/g, "$1");
}
