//! Plaintext exports for migration: JSON and CSV.
//!
//! Spec: Fase 1 § 6.4 ("Ukryptert eksport"). The caller has
//! already asked for the master password again, shown the warnings and let
//! the user choose the path; this module only formats.
//!
//! **JSON.** The same structure as the body of the encrypted export, as
//! compact JSON:
//! `{"v":1,"items":[{"id":"<32 hex>","body":{...}}]}`. The body keys are in
//! the order of the schema, then the unknown ones as they were read. Byte
//! strings are lowercase hex. A float that is NaN or infinite, which JSON
//! cannot hold, is `null`. A passkey object has no `priv`, `prf_seed_uv` or
//! `prf_seed_nouv` unless [`PlainExportOptions::include_passkeys`] is set.
//!
//! **CSV.** RFC 4180: comma-separated, `CRLF` after every row (also the
//! last), a cell is quoted when it holds a comma, a double quote, `CR` or
//! `LF`, and a double quote inside is doubled. One row per item, with the
//! columns
//! `id,type,name,url,notes,totp,favorite,created,modified,passkey_rp_id,passkey_user_name`
//! followed by `field_N_label,field_N_kind,field_N_value` for N from 1 to
//! the highest number of custom fields in any item. `url` holds all the
//! item's addresses separated by one space. The CSV never contains a passkey
//! private key or PRF seed, whatever the options say. It refuses an item whose
//! body has a newer `schema` (`unsupported`), because the columns are those of
//! schema 1 and the rest of such a body would be left out silently.
//!
//! **Formula injection.** A spreadsheet reads a cell that starts with `=`,
//! `+`, `-`, `@`, tab or CR as a formula, and some importers skip leading
//! spaces first. Every CSV cell whose first character after any leading
//! spaces is one of these gets `'` at the very start of the cell (before
//! quoting), so `" =x"` becomes `"' =x"`. The header cells
//! are fixed text and are not changed.

use super::ExportItem;
use crate::cbor::Value;
use crate::error::Error;
use zeroize::Zeroizing;

/// Where the formatting code writes. It runs twice: once to count the bytes,
/// then into a buffer reserved at exactly that size, so the buffer never
/// grows and no smaller copy of the secrets is freed unwiped.
enum Sink {
    Count(usize),
    Buf(Zeroizing<String>),
}

impl Sink {
    fn s(&mut self, s: &str) {
        match self {
            Sink::Count(n) => *n = n.saturating_add(s.len()),
            Sink::Buf(b) => b.push_str(s),
        }
    }

    fn c(&mut self, c: char) {
        match self {
            Sink::Count(n) => *n = n.saturating_add(c.len_utf8()),
            Sink::Buf(b) => b.push(c),
        }
    }
}

/// Runs `write` to count, and again into a buffer of that size.
fn two_pass(write: impl Fn(&mut Sink)) -> String {
    let mut count = Sink::Count(0);
    write(&mut count);
    let n = match count {
        Sink::Count(n) => n,
        Sink::Buf(_) => 0,
    };
    let mut out = Sink::Buf(Zeroizing::new(String::with_capacity(n)));
    write(&mut out);
    match out {
        Sink::Buf(mut b) => core::mem::take(&mut *b),
        Sink::Count(_) => String::new(),
    }
}

/// What the plaintext exports include.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PlainExportOptions {
    /// Include passkey private keys and PRF seeds in the JSON. Off by
    /// default. It does not affect the CSV, which never has them.
    pub include_passkeys: bool,
}

/// The keys of a passkey that are secret.
const PASSKEY_SECRETS: [&str; 3] = ["priv", "prf_seed_uv", "prf_seed_nouv"];

/// Exports `items` as JSON (see the module documentation).
///
/// The text holds every secret in clear; the caller must treat it so.
pub fn export_plain_json(items: &[ExportItem], o: &PlainExportOptions) -> Result<String, Error> {
    Ok(two_pass(|out| {
        out.s("{\"v\":1,\"items\":[");
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.c(',');
            }
            out.s("{\"id\":\"");
            push_hex(out, item.item_id.as_bytes());
            out.s("\",\"body\":");
            let mut body = item.body.to_value();
            if !o.include_passkeys {
                strip_passkey_secrets(&mut body);
            }
            push_json(out, &body);
            out.c('}');
        }
        out.s("]}");
    }))
}

/// Removes the secret keys from the passkey object of a body. A `passkey`
/// that is not a map (only a body of a newer schema can have one) cannot be
/// told apart from its secrets, so it is left out.
fn strip_passkey_secrets(body: &mut Value) {
    if let Value::Map(entries) = body {
        entries.retain(|(key, value)| key != "passkey" || matches!(value, Value::Map(_)));
        for (key, value) in entries.iter_mut() {
            if key == "passkey"
                && let Value::Map(passkey) = value
            {
                passkey.retain(|(k, _)| !PASSKEY_SECRETS.contains(&k.as_str()));
            }
        }
    }
}

/// One hex digit, lowercase.
fn hex_digit(n: u8) -> char {
    char::from_digit(u32::from(n & 15), 16).unwrap_or('0')
}

fn push_hex(out: &mut Sink, bytes: &[u8]) {
    for b in bytes {
        out.c(hex_digit(b >> 4));
        out.c(hex_digit(*b));
    }
}

/// A JSON string: `"`, `\` and the control characters below U+0020 escaped
/// (RFC 8259 § 7); everything else as it is.
fn push_json_string(out: &mut Sink, s: &str) {
    out.c('"');
    for c in s.chars() {
        match c {
            '"' => out.s("\\\""),
            '\\' => out.s("\\\\"),
            '\n' => out.s("\\n"),
            '\r' => out.s("\\r"),
            '\t' => out.s("\\t"),
            '\u{8}' => out.s("\\b"),
            '\u{c}' => out.s("\\f"),
            c if u32::from(c) < 0x20 => {
                out.s("\\u00");
                push_hex(out, &[u8::try_from(u32::from(c)).unwrap_or(0)]);
            }
            c => out.c(c),
        }
    }
    out.c('"');
}

/// A float as a JSON number, or `null` when it has none.
fn push_float(out: &mut Sink, x: f64) {
    if x.is_finite() {
        out.s(&x.to_string());
    } else {
        out.s("null");
    }
}

/// An IEEE 754 half-precision float as `f64`.
fn half_to_f64(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = i32::from((bits >> 10) & 0x1f);
    let frac = f64::from(bits & 0x03ff);
    match exp {
        0 => sign * frac * 2f64.powi(-24),
        0x1f if bits & 0x03ff == 0 => sign * f64::INFINITY,
        0x1f => f64::NAN,
        _ => sign * (1.0 + frac / 1024.0) * 2f64.powi(exp.saturating_sub(15)),
    }
}

fn push_json(out: &mut Sink, value: &Value) {
    match value {
        Value::Null => out.s("null"),
        Value::Bool(true) => out.s("true"),
        Value::Bool(false) => out.s("false"),
        Value::Int(n) => out.s(&n.to_string()),
        Value::Float(bits) => push_float(out, f64::from_bits(*bits)),
        Value::Float32(bits) => push_float(out, f64::from(f32::from_bits(*bits))),
        Value::Float16(bits) => push_float(out, half_to_f64(*bits)),
        Value::Bytes(b) => {
            out.c('"');
            push_hex(out, b);
            out.c('"');
        }
        Value::Text(s) => push_json_string(out, s),
        Value::Array(items) => {
            out.c('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.c(',');
                }
                push_json(out, item);
            }
            out.c(']');
        }
        Value::Map(entries) => {
            out.c('{');
            for (i, (key, item)) in entries.iter().enumerate() {
                if i > 0 {
                    out.c(',');
                }
                push_json_string(out, key);
                out.c(':');
                push_json(out, item);
            }
            out.c('}');
        }
    }
}

// --------------------------------------------------------------------- csv

/// The first characters that make a spreadsheet read a cell as a formula.
/// Spec: Fase 1 § 6.4.
const FORMULA_STARTS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Whether a spreadsheet may read the cell as a formula: it starts with one of
/// [`FORMULA_STARTS`], also after leading spaces (some importers trim before
/// they look).
fn is_formula(text: &str) -> bool {
    text.trim_start_matches(' ').starts_with(FORMULA_STARTS)
}

/// The fixed columns, before the custom fields.
const FIXED_COLUMNS: [&str; 11] = [
    "id",
    "type",
    "name",
    "url",
    "notes",
    "totp",
    "favorite",
    "created",
    "modified",
    "passkey_rp_id",
    "passkey_user_name",
];

/// Writes one cell: neutralised first, then quoted if it needs to be.
/// Written straight into `out`: no copy of the text is made.
fn push_cell(out: &mut Sink, text: &str) {
    let quote = text.contains([',', '"', '\r', '\n']);
    if quote {
        out.c('"');
    }
    if is_formula(text) {
        out.c('\'');
    }
    for c in text.chars() {
        if quote && c == '"' {
            out.c('"');
        }
        out.c(c);
    }
    if quote {
        out.c('"');
    }
}

fn push_row<'a>(out: &mut Sink, cells: impl IntoIterator<Item = &'a str>) {
    for (i, cell) in cells.into_iter().enumerate() {
        if i > 0 {
            out.c(',');
        }
        push_cell(out, cell);
    }
    out.s("\r\n");
}

/// The row of one item. The only copy of item text made on the way is the
/// joined address cell, which is wiped.
fn push_item_row(out: &mut Sink, item: &ExportItem, width: usize) {
    let b = &item.body;
    let id: String = item
        .item_id
        .as_bytes()
        .iter()
        .flat_map(|b| [hex_digit(b >> 4), hex_digit(*b)])
        .collect();
    let urls = Zeroizing::new(
        b.urls
            .iter()
            .map(|u| u.url.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );
    let favorite = b.favorite.to_string();
    let created = b.created.to_string();
    let modified = b.modified.to_string();
    let (rp_id, user_name) = b
        .passkey
        .as_ref()
        .map_or(("", ""), |p| (p.rp_id.as_str(), p.user_name.as_str()));
    let mut cells: Vec<&str> = vec![
        &id,
        b.item_type.as_str(),
        &b.name,
        &urls,
        b.notes.as_deref().unwrap_or(""),
        b.totp.as_ref().map_or("", |t| t.uri.as_str()),
        &favorite,
        &created,
        &modified,
        rp_id,
        user_name,
    ];
    for f in &b.fields {
        cells.extend([f.label.as_str(), f.kind.as_str(), f.value.as_str()]);
    }
    // Every row has as many cells as the header.
    cells.resize(
        FIXED_COLUMNS.len().saturating_add(width.saturating_mul(3)),
        "",
    );
    push_row(out, cells);
}

/// Exports `items` as CSV (see the module documentation). The options do not
/// change the CSV: it never holds a passkey private key or PRF seed.
///
/// The text holds every secret in clear; the caller must treat it so.
///
/// A body with a newer `schema` (read-only) is refused with
/// [`Error::Unsupported`]: the CSV columns are those of schema 1, and a key
/// this version cannot place would be dropped from the file without a word.
/// The JSON export holds such a body whole.
pub fn export_plain_csv(items: &[ExportItem], _o: &PlainExportOptions) -> Result<String, Error> {
    if items.iter().any(|i| i.body.is_read_only()) {
        return Err(Error::Unsupported);
    }
    let width = items.iter().map(|i| i.body.fields.len()).max().unwrap_or(0);
    let mut header: Vec<String> = FIXED_COLUMNS.iter().map(|c| (*c).to_owned()).collect();
    for n in 1..=width {
        header.push(format!("field_{n}_label"));
        header.push(format!("field_{n}_kind"));
        header.push(format!("field_{n}_value"));
    }
    Ok(two_pass(|out| {
        push_row(out, header.iter().map(String::as_str));
        for item in items {
            push_item_row(out, item, width);
        }
    }))
}
