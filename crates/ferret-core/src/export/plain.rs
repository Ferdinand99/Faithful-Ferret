//! Plaintext exports for migration: JSON and CSV.
//!
//! Spec: Fase 1 § 6.4 ("Ukryptert eksport") and plan E4. The caller has
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
//! private key or PRF seed, whatever the options say.
//!
//! **Formula injection.** A spreadsheet reads a cell that starts with `=`,
//! `+`, `-`, `@`, tab or CR as a formula. Every CSV cell that starts with
//! one of these gets `'` in front of it (before quoting). The header cells
//! are fixed text and are not changed.

use super::ExportItem;
use crate::cbor::Value;
use crate::error::Error;
use zeroize::Zeroizing;

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
    let mut out = String::new();
    out.push_str("{\"v\":1,\"items\":[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"id\":\"");
        push_hex(&mut out, item.item_id.as_bytes());
        out.push_str("\",\"body\":");
        let mut body = item.body.to_value();
        if !o.include_passkeys {
            strip_passkey_secrets(&mut body);
        }
        push_json(&mut out, &body);
        out.push('}');
    }
    out.push_str("]}");
    Ok(out)
}

/// Removes the secret keys from the passkey object of a body.
fn strip_passkey_secrets(body: &mut Value) {
    if let Value::Map(entries) = body {
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

fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(*b));
    }
}

/// A JSON string: `"`, `\` and the control characters below U+0020 escaped
/// (RFC 8259 § 7); everything else as it is.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                out.push_str("\\u00");
                push_hex(out, &[u8::try_from(u32::from(c)).unwrap_or(0)]);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A float as a JSON number, or `null` when it has none.
fn push_float(out: &mut String, x: f64) {
    if x.is_finite() {
        out.push_str(&x.to_string());
    } else {
        out.push_str("null");
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

fn push_json(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Float(bits) => push_float(out, f64::from_bits(*bits)),
        Value::Float32(bits) => push_float(out, f64::from(f32::from_bits(*bits))),
        Value::Float16(bits) => push_float(out, half_to_f64(*bits)),
        Value::Bytes(b) => {
            out.push('"');
            push_hex(out, b);
            out.push('"');
        }
        Value::Text(s) => push_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_json(out, item);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for (i, (key, item)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_json_string(out, key);
                out.push(':');
                push_json(out, item);
            }
            out.push('}');
        }
    }
}

// --------------------------------------------------------------------- csv

/// The first characters that make a spreadsheet read a cell as a formula.
/// Spec: Fase 1 § 6.4.
const FORMULA_STARTS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

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
/// Written straight into `out`, so that no copy of the text is made.
fn push_cell(out: &mut String, text: &str) {
    let quote = text.contains([',', '"', '\r', '\n']);
    if quote {
        out.push('"');
    }
    if text.starts_with(FORMULA_STARTS) {
        out.push('\'');
    }
    for c in text.chars() {
        if quote && c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    if quote {
        out.push('"');
    }
}

fn push_row<'a>(out: &mut String, cells: impl IntoIterator<Item = &'a str>) {
    for (i, cell) in cells.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_cell(out, cell);
    }
    out.push_str("\r\n");
}

/// The row of one item. The only copy of item text made on the way is the
/// joined address cell, which is wiped.
fn push_item_row(out: &mut String, item: &ExportItem, width: usize) {
    let b = &item.body;
    let mut id = String::new();
    push_hex(&mut id, item.item_id.as_bytes());
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
pub fn export_plain_csv(items: &[ExportItem], _o: &PlainExportOptions) -> Result<String, Error> {
    let width = items.iter().map(|i| i.body.fields.len()).max().unwrap_or(0);
    let mut header: Vec<String> = FIXED_COLUMNS.iter().map(|c| (*c).to_owned()).collect();
    for n in 1..=width {
        header.push(format!("field_{n}_label"));
        header.push(format!("field_{n}_kind"));
        header.push(format!("field_{n}_value"));
    }
    let mut out = String::new();
    push_row(&mut out, header.iter().map(String::as_str));
    for item in items {
        push_item_row(&mut out, item, width);
    }
    Ok(out)
}
