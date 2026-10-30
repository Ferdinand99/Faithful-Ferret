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
