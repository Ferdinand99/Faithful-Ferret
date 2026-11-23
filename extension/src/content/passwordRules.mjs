// The character rules a new-password field states for itself, as far as they can be read: which of the four classes of the
// generator (lower case, upper case, digits, symbols) the field refuses. Read from the field's `passwordrules` attribute
// (Apple's rule language: `allowed:` and `required:` lists of `upper`, `lower`, `digit`, `special`, `ascii-printable`,
// `unicode` and `[...]` sets) and from its `pattern`. The answer is only ever a list of classes to leave out of a password
// the core generates: nothing here makes, changes or shortens a value, and a rule that cannot be read (an invalid pattern, a
// pattern that no probe string satisfies, a list that is not understood) gives no class, as if the page had stated nothing.
//
// A class is refused when the page does not accept every character the generator uses for it: a field that allows only some of
// the symbols gets none, because the core cannot be told which symbols to use.

/** @type {ReadonlyArray<"lower" | "upper" | "digit" | "symbol">} */
export const CLASSES = Object.freeze(["lower", "upper", "digit", "symbol"]);

/** The characters of each class as the core's generator uses them (crates/ferret-core/src/generator/password.rs). */
const ALPHABET = Object.freeze({
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digit: "0123456789",
  symbol: "!#$%&*+-.:=?@^_~",
});

/** The longest `pattern` or `passwordrules` that is read. */
const MAX_RULE_TEXT = 1000;
/** The units a probe string is made of: lower case, upper case and digits in every mix a pattern may ask for. */
const BASES = Object.freeze(["aB3", "a3", "aB", "a", "B3", "B"]);
/** The longest probe string: a pattern is tried on strings of this length at most. */
const MAX_PROBE = 64;

/** @param {any} element @param {string} name */
const attr = (element, name) => {
  const value = element.getAttribute(name);
  return typeof value === "string" ? value : "";
};

/** @param {string} value @returns {number | null} */
const wholeNumber = (value) => (/^\d{1,6}$/.test(value.trim()) ? Number(value.trim()) : null);

/**
 * The classes a `passwordrules` value allows, or null when it names none of them (it does not restrict, or is not understood).
 * `allowed` and `required` lists both count; a custom set (`[...]`) allows a class only when it holds every character of it.
 * @param {string} text
 * @returns {Set<string> | null}
 */
export function classesAllowedBy(text) {
  if (text === "" || text.length > MAX_RULE_TEXT) return null;
  /** @type {Set<string>} */
  const allowed = new Set();
  let restricts = false;
  // Rules are separated by `;`, and a custom set may hold one, so the sets are taken out first.
  const sets = /** @type {string[]} */ ([]);
  const plain = text.replace(/\[[^\]]*\]/g, (set) => {
    sets.push(set.slice(1, -1));
    return `<${sets.length - 1}>`;
  });
  for (const rule of plain.split(";")) {
    const at = rule.indexOf(":");
    if (at < 0) continue;
    const name = rule.slice(0, at).trim().toLowerCase();
    if (name !== "allowed" && name !== "required") continue;
    if (name === "allowed") restricts = true;
    for (const raw of rule.slice(at + 1).split(",")) {
      const word = raw.trim().toLowerCase();
      if (word === "upper") allowed.add("upper");
      else if (word === "lower") allowed.add("lower");
      else if (word === "digit") allowed.add("digit");
      else if (word === "special") allowed.add("symbol");
      else if (word === "ascii-printable" || word === "unicode") CLASSES.forEach((c) => allowed.add(c));
      else {
        const set = /^<(\d+)>$/.exec(word);
        if (!set) continue;
        const chars = sets[Number(set[1])] ?? "";
        for (const c of CLASSES) if ([...ALPHABET[c]].every((ch) => chars.includes(ch))) allowed.add(c);
      }
    }
  }
  return restricts ? allowed : null;
}

/**
 * The classes a pattern refuses, found by trying it on strings. A base string without symbols (of lower case, upper case and
 * digits, or of some of them) that the pattern accepts is changed at one place into each character of a class: when any of them
 * is refused, the class is. Without a base the pattern accepts (a pattern that asks for a symbol, say), nothing is said.
 * @param {string} pattern @param {number | null} min @param {number | null} max
 * @returns {Set<string>}
 */
export function classesRefusedByPattern(pattern, min, max) {
  /** @type {Set<string>} */
  const refused = new Set();
  if (pattern === "" || pattern.length > MAX_RULE_TEXT) return refused;
  /** @type {RegExp} */
  let regex;
  try {
    regex = new RegExp(`^(?:${pattern})$`, "v");
  } catch {
    try {
      regex = new RegExp(`^(?:${pattern})$`, "u");
    } catch {
      return refused;
    }
  }
  const lengths = [...new Set([max ?? 20, min ?? 12, 20, 16, 12, 10, 8])].filter((n) => n >= 6 && n <= MAX_PROBE && (min === null || n >= min) && (max === null || n <= max));
  try {
    for (const n of lengths) {
      for (const unit of BASES) {
        const base = Array.from({ length: n }, (_, i) => unit[i % unit.length]).join("");
        if (!regex.test(base)) continue;
        for (const c of CLASSES) {
          const position = c === "symbol" ? n - 1 : 1;
          for (const ch of ALPHABET[c]) {
            if (!regex.test(`${base.slice(0, position)}${ch}${base.slice(position + 1)}`)) refused.add(c);
          }
        }
        return refused;
      }
    }
  } catch {
    return new Set();
  }
  return refused;
}

/**
 * The classes of characters a new-password field refuses (see the head of the file), in the order of CLASSES. Not all four: a
 * field that refuses every class gives none (the rules cannot be read).
 * @param {any} element a password input
 * @returns {string[]}
 */
export function refusedClasses(element) {
  /** @type {Set<string>} */
  const refused = new Set();
  try {
    const allowed = classesAllowedBy(attr(element, "passwordrules"));
    if (allowed !== null) for (const c of CLASSES) if (!allowed.has(c)) refused.add(c);
    for (const c of classesRefusedByPattern(attr(element, "pattern"), wholeNumber(attr(element, "minlength")), wholeNumber(attr(element, "maxlength")))) refused.add(c);
  } catch {
    return [];
  }
  const list = CLASSES.filter((c) => refused.has(c));
  return list.length >= CLASSES.length ? [] : list;
}
