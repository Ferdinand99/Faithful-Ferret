//! Earlier passwords of an item (Fase 1 § 5.2 and Appendix B, the
//! `password_history` key): moving the old password into the history inside
//! the core, at most five, newest first, no entry for an unchanged password,
//! the lenient read, unknown keys around and inside the key, older readers,
//! read-only bodies, the redacted view and the exports. Also the comparison of
//! one field with a candidate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::cbor::{self, Value};
use ferret_core::item::{MAX_PASSWORD_HISTORY, PASSWORD_FIELD_ID, PASSWORD_HISTORY_KEY};
use ferret_core::{
    Error, ExportItem, Field, FieldKind, ItemBody, ItemId, ItemType, PlainExportOptions,
    export_plain_csv, export_plain_json,
};

const NOW: u64 = 1_700_000_000_000;

fn field(id: &str, kind: FieldKind, value: &str) -> Field {
    Field {
        id: id.to_owned(),
        label: id.to_owned(),
        kind,
        value: value.to_owned(),
        extra: Vec::new(),
    }
}

fn login(password: &str) -> ItemBody {
    let mut b = ItemBody::new(ItemType::Login, "Example", NOW);
    b.fields = vec![
        field("username", FieldKind::Text, "anna@example.net"),
        field(PASSWORD_FIELD_ID, FieldKind::Password, password),
    ];
    b
}

/// The body after an edit that sets the password to `new`: a copy with the
/// value changed, as the binding makes it.
fn edited(before: &ItemBody, new: &str) -> ItemBody {
    let mut after = before.clone();
    for f in &mut after.fields {
        if f.id == PASSWORD_FIELD_ID {
            f.value = new.to_owned();
        }
    }
    after
}

fn reread(body: &ItemBody) -> ItemBody {
    ItemBody::from_cbor(&body.to_cbor().unwrap()).unwrap().body
}

fn values(body: &ItemBody) -> Vec<(String, u64)> {
    body.password_history()
        .iter()
        .map(|e| (e.value.clone(), e.until))
        .collect()
}

fn entry(value: &str, until: u64) -> Value {
    Value::Map(vec![
        ("value".into(), Value::text(value)),
        ("until".into(), Value::uint(until)),
    ])
}

#[test]
fn update_with_keep_history_moves_the_old_password_inside_the_core() {
    let before = login("old-secret");
    let mut after = edited(&before, "new-secret");
    assert!(after.keep_replaced_password(&before, NOW + 5).unwrap());
    assert_eq!(values(&after), vec![("old-secret".to_owned(), NOW + 5)]);
    // The password field holds the new value; nothing else changed.
    assert!(after.field_value_equals(PASSWORD_FIELD_ID, b"new-secret"));
    assert_eq!(after.fields[0].value, "anna@example.net");
    // It is in the body that is sealed, under its key, after the known keys.
    let again = reread(&after);
    assert_eq!(values(&again), vec![("old-secret".to_owned(), NOW + 5)]);
    assert_eq!(again.extra.last().unwrap().0, PASSWORD_HISTORY_KEY);
    // A field that is gone counts as a change; an empty old value does not.
    let mut gone = before.clone();
    gone.fields.retain(|f| f.id != PASSWORD_FIELD_ID);
    assert!(gone.keep_replaced_password(&before, NOW).unwrap());
    assert_eq!(values(&gone), vec![("old-secret".to_owned(), NOW)]);
    let empty = login("");
    let mut set = edited(&empty, "first");
    assert!(!set.keep_replaced_password(&empty, NOW).unwrap());
    assert!(set.password_history().is_empty());
    // An item with no password field has nothing to keep.
    let mut note = ItemBody::new(ItemType::Note, "Note", NOW);
    let plain = note.clone();
    assert!(!note.keep_replaced_password(&plain, NOW).unwrap());
    assert!(note.extra.is_empty());
    // Only the field with the id `password` counts, not `password-2`.
    let mut two = login("a");
    two.fields
        .push(field("password-2", FieldKind::Password, "second"));
    let mut changed = two.clone();
    changed.fields[2].value = "other".into();
    assert!(!changed.keep_replaced_password(&two, NOW).unwrap());
}

#[test]
fn history_keeps_at_most_five_newest_first() {
    let mut body = login("p0");
    for i in 1..=8u64 {
        let before = body.clone();
        body = edited(&before, &format!("p{i}"));
        assert!(body.keep_replaced_password(&before, NOW + i).unwrap());
        body = reread(&body);
    }
    assert_eq!(MAX_PASSWORD_HISTORY, 5);
    assert_eq!(
        values(&body),
        vec![
            ("p7".to_owned(), NOW + 8),
            ("p6".to_owned(), NOW + 7),
            ("p5".to_owned(), NOW + 6),
            ("p4".to_owned(), NOW + 5),
            ("p3".to_owned(), NOW + 4),
        ]
    );
    assert!(body.field_value_equals(PASSWORD_FIELD_ID, b"p8"));
    // push_password_history itself: newest first, five at most.
    let mut b = login("x");
    for i in 0..7u64 {
        b.push_password_history(&format!("h{i}"), i).unwrap();
    }
    let got: Vec<u64> = b.password_history().iter().map(|e| e.until).collect();
    assert_eq!(got, vec![6, 5, 4, 3, 2]);
}

#[test]
fn an_unchanged_password_adds_no_history() {
    let before = login("same-secret");
    let mut after = edited(&before, "same-secret");
    after.name = "Renamed".into();
    assert!(!after.keep_replaced_password(&before, NOW).unwrap());
    assert!(after.password_history().is_empty());
    assert!(
        !after.extra.iter().any(|(k, _)| k == PASSWORD_HISTORY_KEY),
        "no key is added"
    );
    // A body without history is written byte for byte as before.
    assert_eq!(
        after.to_cbor().unwrap().as_slice(),
        reread(&after).to_cbor().unwrap().as_slice()
    );
    // Equal is byte for byte: a value that differs only in case or form is a
    // change.
    let mut case = edited(&before, "Same-secret");
    assert!(case.keep_replaced_password(&before, NOW).unwrap());
    let composed = login("caf\u{e9}");
    let mut decomposed = edited(&composed, "cafe\u{301}");
    assert!(decomposed.keep_replaced_password(&composed, NOW).unwrap());
}

/// A schema 1 body as a version that does not know the history writes it
/// back: the typed keys from its own struct, the rest as it read them.
fn older_reader_round_trip(bytes: &[u8]) -> Vec<u8> {
    // An older version reads the same keys into `extra`: decoding and
    // encoding the CBOR tree unchanged is what its `to_value` does.
    let value = cbor::decode(bytes).unwrap();
    cbor::encode(&value).unwrap()
}

#[test]
fn history_is_kept_by_a_reader_that_does_not_know_it() {
    let before = login("old");
    let mut after = edited(&before, "new");
    after
        .extra
        .push(("zeta".into(), Value::text("unknown before")));
    after.keep_replaced_password(&before, NOW).unwrap();
    after
        .extra
        .push(("omega".into(), Value::text("unknown after")));
    let bytes = after.to_cbor().unwrap();
    // The key sits among the unknown keys, in the order they were written.
    let keys: Vec<&str> = after.extra.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["zeta", PASSWORD_HISTORY_KEY, "omega"]);
    // An older reader keeps it byte for byte.
    assert_eq!(older_reader_round_trip(&bytes), bytes.as_slice());
    // This version reads it back, and a later push keeps its place.
    let mut again = reread(&after);
    again.push_password_history("newer", NOW + 1).unwrap();
    let keys: Vec<&str> = again.extra.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["zeta", PASSWORD_HISTORY_KEY, "omega"]);
    assert_eq!(
        values(&again),
        vec![("newer".to_owned(), NOW + 1), ("old".to_owned(), NOW)]
    );
    // An entry with a key of its own (from a later version) keeps it.
    let mut b = login("x");
    b.extra.push((
        PASSWORD_HISTORY_KEY.into(),
        Value::Array(vec![Value::Map(vec![
            ("value".into(), Value::text("kept")),
            ("until".into(), Value::uint(3)),
            ("device".into(), Value::text("laptop")),
        ])]),
    ));
    b.push_password_history("front", 9).unwrap();
    let Value::Array(list) = &b.extra[0].1 else {
        panic!("a list")
    };
    assert_eq!(list[1].get("device").unwrap().as_text(), Some("laptop"));
}

#[test]
fn a_stored_history_is_read_leniently_and_the_body_is_not_changed() {
    let mut b = login("x");
    b.extra.push((
        PASSWORD_HISTORY_KEY.into(),
        Value::Array(vec![
            entry("one", 1),
            Value::text("not a map"),
            Value::Map(vec![("value".into(), Value::text("no date"))]),
            Value::Map(vec![
                ("value".into(), Value::uint(5)),
                ("until".into(), Value::uint(5)),
            ]),
            entry("two", 2),
            entry("three", 3),
            entry("four", 4),
            entry("five", 5),
            entry("six", 6),
        ]),
    ));
    let before = b.to_cbor().unwrap();
    let got: Vec<String> = b
        .password_history()
        .iter()
        .map(|e| e.value.clone())
        .collect();
    assert_eq!(got, vec!["one", "two", "three", "four", "five"]);
    assert_eq!(b.to_cbor().unwrap().as_slice(), before.as_slice());
    // A push keeps what the read returns and drops the rest.
    b.push_password_history("zero", 0).unwrap();
    let got: Vec<String> = b
        .password_history()
        .iter()
        .map(|e| e.value.clone())
        .collect();
    assert_eq!(got, vec!["zero", "one", "two", "three", "four"]);
    let Value::Array(list) = &b.extra[0].1 else {
        panic!("a list")
    };
    assert_eq!(list.len(), 5, "the entries of the wrong form are gone");
    // A value that is not a list is read as none and replaced by a push.
    let mut c = login("x");
    c.extra
        .push((PASSWORD_HISTORY_KEY.into(), Value::text("broken")));
    assert!(c.password_history().is_empty());
    assert!(c.view().password_history.is_empty());
    c.push_password_history("first", 1).unwrap();
    assert_eq!(values(&c), vec![("first".to_owned(), 1)]);
    assert_eq!(c.extra.len(), 1);
}

#[test]
fn a_read_only_body_refuses_a_push() {
    let value = Value::Map(vec![
        ("schema".into(), Value::uint(2)),
        ("type".into(), Value::text("login")),
        ("name".into(), Value::text("Future")),
        ("fields".into(), Value::Array(vec![])),
        ("urls".into(), Value::Array(vec![])),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(2)),
        ("favorite".into(), Value::Bool(false)),
        (
            PASSWORD_HISTORY_KEY.into(),
            Value::Array(vec![entry("kept", 1)]),
        ),
    ]);
    let mut body = ItemBody::from_value(value).unwrap().body;
    assert!(body.is_read_only());
    let before = body.to_cbor().unwrap();
    assert_eq!(
        body.push_password_history("x", 2),
        Err(Error::ReadOnlySchema)
    );
    let previous = login("old");
    assert_eq!(
        body.keep_replaced_password(&previous, 2),
        Err(Error::ReadOnlySchema)
    );
    assert_eq!(body.to_cbor().unwrap().as_slice(), before.as_slice());
    // It is still shown.
    assert_eq!(values(&body), vec![("kept".to_owned(), 1)]);
}

#[test]
fn item_view_shows_history_dates_and_never_values() {
    let mut body = login("current-secret");
    body.push_password_history("older-secret-1", 11).unwrap();
    body.push_password_history("older-secret-2", 22).unwrap();
    let view = body.view();
    let dates: Vec<u64> = view.password_history.iter().map(|h| h.until).collect();
    assert_eq!(dates, vec![22, 11]);
    let text = format!("{view:?}");
    for secret in ["older-secret-1", "older-secret-2", "current-secret"] {
        assert!(!text.contains(secret), "{secret} is in the view");
    }
    // Neither the entries nor the body show a value in `Debug`.
    for e in body.password_history() {
        assert!(!format!("{e:?}").contains("older"));
    }
    assert!(!format!("{body:?}").contains("older"));
    // An item without history has an empty list.
    assert!(login("x").view().password_history.is_empty());
}

#[test]
fn plain_export_includes_the_history() {
    let mut body = login("current");
    body.push_password_history("earlier", 42).unwrap();
    let items = [ExportItem {
        item_id: ItemId::from_bytes([7; 16]),
        body,
    }];
    let json = export_plain_json(&items, &PlainExportOptions::default()).unwrap();
    assert!(
        json.contains(r#""password_history":[{"value":"earlier","until":42}]"#),
        "{json}"
    );
    // The CSV has no column for it, as for folders.
    let csv = export_plain_csv(&items, &PlainExportOptions::default()).unwrap();
    assert!(!csv.contains("earlier"));
    assert!(csv.contains("current"));
}

#[test]
fn field_value_equals_compares_one_field_byte_for_byte() {
    let mut body = login("hunter2");
    body.fields.push(field("pin", FieldKind::Hidden, "1234"));
    assert!(body.field_value_equals(PASSWORD_FIELD_ID, b"hunter2"));
    assert!(!body.field_value_equals(PASSWORD_FIELD_ID, b"hunter"));
    assert!(!body.field_value_equals(PASSWORD_FIELD_ID, b"hunter22"));
    assert!(!body.field_value_equals(PASSWORD_FIELD_ID, b"Hunter2"));
    assert!(!body.field_value_equals(PASSWORD_FIELD_ID, b""));
    // Another field's value does not count for this one.
    assert!(!body.field_value_equals(PASSWORD_FIELD_ID, b"anna@example.net"));
    assert!(!body.field_value_equals(PASSWORD_FIELD_ID, b"1234"));
    assert!(body.field_value_equals("pin", b"1234"));
    assert!(body.field_value_equals("username", b"anna@example.net"));
    // No field with the id: false. No normalisation of the candidate.
    assert!(!body.field_value_equals("missing", b""));
    let nfc = login("caf\u{e9}");
    assert!(!nfc.field_value_equals(PASSWORD_FIELD_ID, "cafe\u{301}".as_bytes()));
    assert!(nfc.field_value_equals(PASSWORD_FIELD_ID, "caf\u{e9}".as_bytes()));
    // The first field with the id counts, as everywhere else.
    let mut twice = login("first");
    twice
        .fields
        .push(field(PASSWORD_FIELD_ID, FieldKind::Password, "second"));
    assert!(twice.field_value_equals(PASSWORD_FIELD_ID, b"first"));
    assert!(!twice.field_value_equals(PASSWORD_FIELD_ID, b"second"));
}
