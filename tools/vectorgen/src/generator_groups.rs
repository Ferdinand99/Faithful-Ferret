//! The vector group for the password and passphrase generator
//! (`generator.json`).
//!
//! The expected values are made apart from the core: a reference generator
//! here draws from a recording RNG, reduces with `%`, picks characters and
//! words by plain indexing and shuffles with `swap`, in the order of draws
//! that the core documents (`ferret_core::generator`). The core, which
//! reduces with a multiplication and selects in constant time, must give the
//! same values from the same draws. Only `bits` comes from the core's own
//! log2 (`testing::generator::log2_of`), so that the number is the same bit
//! for bit; the tests of the core check that log2 against the float one.
//!
//! Some cases start with draws that are refused (at or above
//! `n * floor(2^32 / n)`), so the vectors pin the rejection as well.

use crate::groups::{generator, invalid_case, valid_case};
use crate::{Error, render};
use ferret_core::SecureRng;
use ferret_core::testing::generator::{embedded_words, log2_of};
use ferret_core::testing::vector::{Case, VectorFile};
use ferret_core::testing::{TestRng, hex_encode};
use serde_json::{Value, json};
use std::collections::VecDeque;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&*+-.:=?@^_~";
const AMBIGUOUS: &[u8] = b"Il1|O0o";

/// Draws of four bytes: first the forced ones, then those of a test RNG.
/// Every draw is recorded for the case.
struct Draws {
    forced: VecDeque<u32>,
    inner: TestRng,
    recorded: Vec<String>,
}

impl Draws {
    fn new(seed: &str, forced: &[u32]) -> Self {
        Self {
            forced: forced.iter().copied().collect(),
            inner: TestRng::new(format!("generator/{seed}").as_bytes()),
            recorded: Vec::new(),
        }
    }

    fn next(&mut self) -> u32 {
        let bytes = match self.forced.pop_front() {
            Some(x) => x.to_le_bytes(),
            None => {
                let mut b = [0u8; 4];
                self.inner.fill(&mut b);
                b
            }
        };
        self.recorded.push(hex_encode(&bytes));
        u32::from_le_bytes(bytes)
    }

    /// Uniform in `0..n` by rejection, the plain way.
    fn index(&mut self, n: u32) -> u32 {
        let limit = u64::from(n) * ((1u64 << 32) / u64::from(n));
        loop {
            let x = self.next();
            if u64::from(x) < limit {
                return x % n;
            }
        }
    }
}

/// The largest draw that `n` accepts plus one: the first refused value.
fn first_refused(n: u32) -> u32 {
    u32::try_from(u64::from(n) * ((1u64 << 32) / u64::from(n))).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy)]
struct Pw {
    length: u16,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    min_each: u8,
    avoid_ambiguous: bool,
}

impl Pw {
    fn input(&self) -> Value {
        json!({
            "length": self.length,
            "lower": self.lower,
            "upper": self.upper,
            "digits": self.digits,
            "symbols": self.symbols,
            "min_each": self.min_each,
            "avoid_ambiguous": self.avoid_ambiguous,
        })
    }

    fn classes(&self) -> Vec<Vec<u8>> {
        [
            (self.lower, LOWER),
            (self.upper, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, c)| {
            c.iter()
                .copied()
                .filter(|x| !(self.avoid_ambiguous && AMBIGUOUS.contains(x)))
                .collect()
        })
        .collect()
    }

    /// The reference: min_each of each class, the rest of the alphabet,
    /// then Fisher–Yates from the end.
    fn make(&self, draws: &mut Draws) -> (String, f64) {
        let classes = self.classes();
        let alphabet: Vec<u8> = classes.concat();
        let mut chars = Vec::new();
        for class in &classes {
            for _ in 0..self.min_each {
                let i = draws.index(u32::try_from(class.len()).unwrap());
                chars.push(class[usize::try_from(i).unwrap()]);
            }
        }
        while chars.len() < usize::from(self.length) {
            let i = draws.index(u32::try_from(alphabet.len()).unwrap());
            chars.push(alphabet[usize::try_from(i).unwrap()]);
        }
        for i in (1..chars.len()).rev() {
            let j = draws.index(u32::try_from(i + 1).unwrap());
            chars.swap(i, usize::try_from(j).unwrap());
        }
        let bits = f64::from(self.length) * log2_of(u32::try_from(alphabet.len()).unwrap());
        (String::from_utf8(chars).unwrap(), bits)
    }
}

const fn pw(length: u16, classes: [bool; 4], min_each: u8, avoid_ambiguous: bool) -> Pw {
    Pw {
        length,
        lower: classes[0],
        upper: classes[1],
        digits: classes[2],
        symbols: classes[3],
        min_each,
        avoid_ambiguous,
    }
}

const ALL: [bool; 4] = [true, true, true, true];

/// `(name, options, forced first draws)`.
fn password_rows() -> Vec<(&'static str, Pw, Vec<u32>)> {
    vec![
        ("default", pw(20, ALL, 1, false), vec![]),
        ("default-2", pw(20, ALL, 1, false), vec![]),
        ("default-3", pw(20, ALL, 1, false), vec![]),
        ("shortest", pw(4, ALL, 1, false), vec![]),
        ("shortest-no-min", pw(4, ALL, 0, false), vec![]),
        ("longest", pw(128, ALL, 1, false), vec![]),
        ("longest-min-8", pw(128, ALL, 8, true), vec![]),
        (
            "lower-only",
            pw(16, [true, false, false, false], 0, false),
            vec![],
        ),
        (
            "upper-only",
            pw(16, [false, true, false, false], 2, false),
            vec![],
        ),
        (
            "digits-only-pin",
            pw(6, [false, false, true, false], 0, false),
            vec![],
        ),
        (
            "symbols-only",
            pw(12, [false, false, false, true], 3, false),
            vec![],
        ),
        (
            "letters",
            pw(24, [true, true, false, false], 4, false),
            vec![],
        ),
        (
            "letters-digits",
            pw(15, [true, true, true, false], 1, false),
            vec![],
        ),
        (
            "no-symbols-ambiguous",
            pw(30, [true, true, true, false], 2, true),
            vec![],
        ),
        ("ambiguous-all", pw(40, ALL, 0, true), vec![]),
        (
            "ambiguous-digits",
            pw(10, [false, false, true, false], 1, true),
            vec![],
        ),
        ("min-fills-length", pw(32, ALL, 8, false), vec![]),
        ("min-fills-length-short", pw(4, ALL, 1, true), vec![]),
        (
            "lower-digits",
            pw(8, [true, false, true, false], 3, false),
            vec![],
        ),
        (
            "upper-symbols",
            pw(9, [false, true, false, true], 1, true),
            vec![],
        ),
        ("length-64", pw(64, ALL, 2, false), vec![]),
        (
            "length-100",
            pw(100, [true, true, true, false], 0, false),
            vec![],
        ),
        // Refused draws first: the first choice is of the lower-case class
        // (26 letters), so its first refused value and the largest draw are
        // thrown away before the case's own draws.
        (
            "refused-first-draws",
            pw(8, ALL, 1, false),
            vec![first_refused(26), u32::MAX],
        ),
        // With no min_each the first choice is of the whole alphabet (78).
        (
            "refused-alphabet-draw",
            pw(10, ALL, 0, false),
            vec![first_refused(78), first_refused(78) - 1],
        ),
    ]
}

#[derive(Clone, Copy)]
struct Pp {
    words: u8,
    separator: char,
    capitalize: bool,
    number: bool,
}

impl Pp {
    fn input(&self) -> Value {
        json!({
            "words": self.words,
            "separator": self.separator.to_string(),
            "capitalize": self.capitalize,
            "number": self.number,
        })
    }

    /// The reference: a word per draw, then the digit and its word.
    fn make(&self, draws: &mut Draws) -> (String, f64) {
        let list: Vec<&str> = embedded_words().lines().collect();
        let n = u32::try_from(list.len()).unwrap();
        let mut words: Vec<String> = (0..self.words)
            .map(|_| {
                let w = list[usize::try_from(draws.index(n)).unwrap()];
                if self.capitalize {
                    let mut c = w.chars();
                    let first = c.next().unwrap().to_ascii_uppercase();
                    format!("{first}{}", c.as_str())
                } else {
                    w.to_owned()
                }
            })
            .collect();
        let mut bits = f64::from(self.words) * log2_of(n);
        if self.number {
            let digit = draws.index(10);
            let at = draws.index(u32::from(self.words));
            words[usize::try_from(at).unwrap()].push_str(&digit.to_string());
            bits += log2_of(10) + log2_of(u32::from(self.words));
        }
        (words.join(&self.separator.to_string()), bits)
    }
}

const fn pp(words: u8, separator: char, capitalize: bool, number: bool) -> Pp {
    Pp {
        words,
        separator,
        capitalize,
        number,
    }
}

fn passphrase_rows() -> Vec<(&'static str, Pp, Vec<u32>)> {
    vec![
        ("default", pp(5, '-', true, false), vec![]),
        ("default-2", pp(5, '-', true, false), vec![]),
        ("fewest", pp(3, '-', false, false), vec![]),
        ("most", pp(20, '.', false, false), vec![]),
        ("dot", pp(6, '.', false, false), vec![]),
        ("underscore", pp(6, '_', true, false), vec![]),
        ("space", pp(7, ' ', false, false), vec![]),
        ("number", pp(5, '-', false, true), vec![]),
        ("number-capitalized", pp(4, '-', true, true), vec![]),
        ("number-most", pp(20, ' ', true, true), vec![]),
        ("number-fewest", pp(3, '_', false, true), vec![]),
        // The first word's draw is refused once (7776 * 552336 is the first
        // refused value).
        (
            "refused-first-draw",
            pp(4, '-', false, false),
            vec![first_refused(7_776)],
        ),
        // The digit's draw is refused once: words first, then the refused
        // draw for 10, then the rest.
        ("refused-digit-draw", pp(3, '-', true, true), vec![]),
    ]
}

/// `uniform_index` on its own: `(name, n, forced draws)`.
fn index_rows() -> Vec<(&'static str, u32, Vec<u32>)> {
    vec![
        ("n-1", 1, vec![]),
        ("n-1-largest-draw", 1, vec![u32::MAX]),
        ("n-3-refuses-the-top", 3, vec![u32::MAX, 7]),
        ("n-3-last-accepted", 3, vec![u32::MAX - 1]),
        (
            "n-10-refused-twice",
            10,
            vec![first_refused(10), u32::MAX, 12_345],
        ),
        ("n-26", 26, vec![]),
        ("n-78-refused", 78, vec![first_refused(78), 77]),
        ("n-7776-refused", 7_776, vec![first_refused(7_776), 7_775]),
        (
            "n-7776-last-accepted",
            7_776,
            vec![first_refused(7_776) - 1],
        ),
        ("n-2-31-plus-1", (1 << 31) + 1, vec![(1 << 31) + 1, 5]),
        ("n-max", u32::MAX, vec![u32::MAX, u32::MAX - 1]),
    ]
}

fn password_cases(cases: &mut Vec<Case>) {
    for (name, o, forced) in password_rows() {
        let mut draws = Draws::new(&format!("password/{name}"), &forced);
        let (value, bits) = o.make(&mut draws);
        let mut c = valid_case(
            &format!("generator/password/{name}"),
            &format!(
                "a password of {} characters, min_each {}{}",
                o.length,
                o.min_each,
                if forced.is_empty() {
                    ""
                } else {
                    ", after refused draws"
                }
            ),
            "generator.password",
            vec![],
            o.input(),
            json!({ "value": value, "bits": bits }),
        );
        c.rng = draws.recorded;
        cases.push(c);
    }
    let refused: [(&str, Pw); 9] = [
        ("length-3", pw(3, ALL, 0, false)),
        ("length-129", pw(129, ALL, 0, false)),
        ("length-0", pw(0, ALL, 0, false)),
        ("no-class", pw(20, [false; 4], 0, false)),
        ("min-each-9", pw(80, ALL, 9, false)),
        ("min-each-over-length", pw(7, ALL, 2, false)),
        (
            "min-each-over-length-one-class",
            pw(4, [false, false, true, false], 5, false),
        ),
        ("min-each-over-length-ambiguous", pw(4, ALL, 2, true)),
        ("length-max-u16", pw(u16::MAX, ALL, 0, false)),
    ];
    for (name, o) in refused {
        cases.push(invalid_case(
            &format!("generator/password/refused-{name}"),
            &format!("options {name} are refused, nothing is drawn"),
            "generator.password",
            vec![],
            o.input(),
            "generator_options",
        ));
    }
}

fn passphrase_cases(cases: &mut Vec<Case>) {
    for (name, o, forced) in passphrase_rows() {
        let mut draws = if name == "refused-digit-draw" {
            // Three word draws of the test RNG, then a refused draw for the
            // digit: made by drawing the words first and forcing the rest.
            let mut probe = Draws::new(&format!("passphrase/{name}"), &[]);
            let words: Vec<u32> = (0..3).map(|_| probe.next()).collect();
            let mut forced = words;
            forced.push(first_refused(10));
            forced.extend([4, 2]);
            Draws::new(&format!("passphrase/{name}"), &forced)
        } else {
            Draws::new(&format!("passphrase/{name}"), &forced)
        };
        let (value, bits) = o.make(&mut draws);
        let mut c = valid_case(
            &format!("generator/passphrase/{name}"),
            &format!(
                "a passphrase of {} words, separator {:?}{}{}",
                o.words,
                o.separator,
                if o.capitalize { ", capitalized" } else { "" },
                if o.number { ", with a number" } else { "" }
            ),
            "generator.passphrase",
            vec![],
            o.input(),
            json!({ "value": value, "bits": bits }),
        );
        c.rng = draws.recorded;
        cases.push(c);
    }
    let refused = [
        ("words-2", pp(2, '-', false, false)),
        ("words-21", pp(21, '-', false, false)),
        ("words-0", pp(0, '-', false, false)),
        ("separator-comma", pp(5, ',', false, false)),
        ("separator-letter", pp(5, 'a', false, false)),
        ("separator-tab", pp(5, '\t', false, false)),
    ];
    for (name, o) in refused {
        cases.push(invalid_case(
            &format!("generator/passphrase/refused-{name}"),
            &format!("options {name} are refused, nothing is drawn"),
            "generator.passphrase",
            vec![],
            o.input(),
            "generator_options",
        ));
    }
}

fn index_cases(cases: &mut Vec<Case>) {
    for (name, n, forced) in index_rows() {
        let mut draws = Draws::new(&format!("index/{name}"), &forced);
        let index = draws.index(n);
        let mut c = valid_case(
            &format!("generator/uniform_index/{name}"),
            &format!("uniform_index({n}) is {index}"),
            "generator.uniform_index",
            vec![],
            json!({ "n": n }),
            json!({ "index": index }),
        );
        c.rng = draws.recorded;
        cases.push(c);
    }
    cases.push(invalid_case(
        "generator/uniform_index/n-0",
        "uniform_index(0) is refused, nothing is drawn",
        "generator.uniform_index",
        vec![],
        json!({ "n": 0 }),
        "generator_options",
    ));
}

pub(crate) fn generator_file() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    password_cases(&mut cases);
    passphrase_cases(&mut cases);
    index_cases(&mut cases);
    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "generator".into(),
        suite: 1,
        spec: "ferret_core::generator (module documentation); EFF large word list".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
