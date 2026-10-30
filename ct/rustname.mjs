// A rough demangling of Rust symbols (the legacy `_ZN...E` and the v0 `_R...`
// schemes): the identifiers, joined with `::`. Good enough to say which crate
// and module a function belongs to; not a full demangler.

export function normalize(mangled) {
  let s = mangled.replace(/^\$/, "");
  if (s.startsWith("_ZN")) s = s.slice(3);
  else if (s.startsWith("_R")) s = s.slice(2).replace(/C[sd][0-9A-Za-z]*_/g, "~");
  const parts = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] >= "0" && s[i] <= "9") {
      let j = i;
      while (s[j] >= "0" && s[j] <= "9") j++;
      const n = Number(s.slice(i, j));
      let k = j;
      if (s[k] === "_") k++;
      const part = s.slice(k, k + n);
      // The hash of a legacy symbol is not a name.
      if (!/^h[0-9a-f]{16}$/.test(part)) parts.push(part);
      i = k + n;
    } else {
      i++;
    }
  }
  return parts.length ? parts.join("::") : mangled;
}

/**
 * The path of a function without the markers in front of it that this rough
 * demangling leaves (`N::`, `Nt~::`): it starts at the first identifier of
 * three or more lower-case letters, digits and underscores.
 */
export function pathOf(mangled) {
  const parts = normalize(mangled).split("::");
  const at = parts.findIndex((part) => /^[a-z_][a-z0-9_]{2,}$/.test(part));
  return at < 0 ? parts.join("::") : parts.slice(at).join("::");
}

/**
 * The path of a function from the name section of a module that went through
 * wasm-bindgen, which demangles the names: `"<ferret_core[8bc9]::wrap::Method
 * as core::clone::Clone>::clone"`. The crate disambiguators `[8bc9]`, the
 * leading `<` and the generic arguments after `::<` are removed, so that the
 * same function has the same path in every build; a name without a path (an
 * export such as `vault_encrypt_item`) stays as it is. Names of the mangled
 * kinds go through `pathOf`.
 */
export function cleanPath(raw) {
  let s = raw.replace(/^\$/, "");
  if (s.startsWith('"')) s = s.replace(/^"/, "").replace(/"$/, "");
  if (/^_ZN|^_R/.test(s)) return pathOf(raw);
  s = s.replace(/\[[0-9a-f]{4,}\]/g, "").replace(/^[<(&*]+/, "");
  const generic = s.indexOf("::<");
  if (generic >= 0) s = s.slice(0, generic);
  return s.slice(0, 160);
}
