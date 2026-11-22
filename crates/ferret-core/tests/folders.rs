//! Folder names of an item (Fase 1 § 5.2, the `folders` key): the rules for
//! a write, the lenient read, unknown keys around the key, bodies from
//! before folders existed, read-only bodies, and the exports.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::cbor::{self, Value};
use ferret_core::item::folders::{FOLDERS_KEY, MAX_FOLDER_CHARS, MAX_FOLDERS, normalize_folders};
use ferret_core::testing::TestRng;
use ferret_core::testing::export::{export_encrypt_unchecked, import_decrypt_unchecked};
use ferret_core::{
    Error, ExportItem, ExportPassword, FolderError, ItemBody, ItemId, ItemType, KdfParams,
    PlainExportOptions, export_plain_json,
};

const NOW: u64 = 1_700_000_000_000;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn login() -> ItemBody {
    ItemBody::new(ItemType::Login, "Example", NOW)
}

fn reread(body: &ItemBody) -> ItemBody {
    ItemBody::from_cbor(&body.to_cbor().unwrap()).unwrap().body
}

fn folder_err(kind: FolderError) -> Error {
    Error::Folder(kind)
}

/// The body map of a schema 1 item as an older version wrote it: no
/// `folders` key, one unknown key.
fn old_body_value() -> Value {
    Value::Map(vec![
        ("schema".into(), Value::uint(1)),
        ("type".into(), Value::text("login")),
        ("name".into(), Value::text("Old")),
        ("fields".into(), Value::Array(vec![])),
        ("urls".into(), Value::Array(vec![])),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(2)),
        ("favorite".into(), Value::Bool(false)),
        ("zeta".into(), Value::text("kept")),
    ])
}

fn with_key(mut base: Value, key: &str, value: Value) -> Value {
    if let Value::Map(entries) = &mut base {
        entries.push((key.to_owned(), value));
    }
    base
}

fn keys_of(body: &ItemBody) -> Vec<String> {
    body.extra.iter().map(|(k, _)| k.clone()).collect()
}

// ------------------------------------------------------------ round trip

#[test]
fn folders_round_trip_through_the_body() {
    let mut body = login();
    body.set_folders(&names(&[" Work ", "Personal", "Æsj"]))
        .unwrap();
    assert_eq!(body.folders(), names(&["Work", "Personal", "Æsj"]));
    let back = reread(&body);
    assert_eq!(back.folders(), names(&["Work", "Personal", "Æsj"]));
    assert_eq!(back.view().folders, names(&["Work", "Personal", "Æsj"]));
    // Stored as the top-level key `folders`, a list of text, trimmed, in the
    // order given (sorting is for display only).
    let value = cbor::decode(&body.to_cbor().unwrap()).unwrap();
    assert_eq!(
        value.get(FOLDERS_KEY),
        Some(&Value::Array(vec![
            Value::text("Work"),
            Value::text("Personal"),
            Value::text("Æsj"),
        ]))
    );
}

#[test]
fn a_new_body_has_no_folders_and_no_key() {
    let body = login();
    assert!(body.folders().is_empty());
    assert!(body.view().folders.is_empty());
    let value = cbor::decode(&body.to_cbor().unwrap()).unwrap();
    assert!(value.get(FOLDERS_KEY).is_none());
}

#[test]
fn a_body_written_before_folders_opens_with_none() {
    let bytes = cbor::encode(&old_body_value()).unwrap();
    let decoded = ItemBody::from_cbor(&bytes).unwrap();
    assert!(!decoded.read_only);
    assert!(decoded.body.folders().is_empty());
    assert!(decoded.body.view().folders.is_empty());
    // Clearing folders it does not have changes nothing: the body is written
    // byte for byte as it was read.
    let mut body = decoded.body;
    body.set_folders(&[]).unwrap();
    assert_eq!(body.to_cbor().unwrap().as_slice(), bytes.as_slice());
}

#[test]
fn an_empty_list_removes_the_key() {
    let mut body = login();
    body.set_folders(&names(&["Work"])).unwrap();
    body.set_folders(&[]).unwrap();
    assert!(body.folders().is_empty());
    assert!(body.extra.is_empty());
    assert_eq!(reread(&body), login());
}

// ----------------------------------------------------------------- rules

#[test]
fn names_are_trimmed() {
    assert_eq!(
        normalize_folders(&names(&["  Work\t", "\u{3000}Home\n"])).unwrap(),
        names(&["Work", "Home"])
    );
}

#[test]
fn an_empty_name_is_folder_empty() {
    for bad in ["", " ", "\t\n", "\u{3000}"] {
        assert_eq!(
            normalize_folders(&names(&["Work", bad])),
            Err(folder_err(FolderError::Empty)),
            "{bad:?}"
        );
    }
}

#[test]
fn a_name_over_64_characters_is_folder_too_long() {
    // 64 characters is the limit, counted in characters, not bytes, and
    // after trimming.
    let at_limit = "ø".repeat(MAX_FOLDER_CHARS);
    assert_eq!(at_limit.len(), 128);
    assert_eq!(
        normalize_folders(&[format!("  {at_limit}  ")]).unwrap(),
        vec![at_limit.clone()]
    );
    assert_eq!(
        normalize_folders(&[format!("{at_limit}x")]),
        Err(folder_err(FolderError::TooLong))
    );
    assert_eq!(
        normalize_folders(&["a".repeat(MAX_FOLDER_CHARS + 1)]),
        Err(folder_err(FolderError::TooLong))
    );
}

#[test]
fn more_than_20_names_is_folder_too_many() {
    let twenty: Vec<String> = (0..MAX_FOLDERS).map(|i| format!("F{i}")).collect();
    assert_eq!(normalize_folders(&twenty).unwrap(), twenty);
    let mut twenty_one = twenty.clone();
    twenty_one.push("F20".into());
    assert_eq!(
        normalize_folders(&twenty_one),
        Err(folder_err(FolderError::TooMany))
    );
}

#[test]
fn names_equal_without_case_are_folder_duplicate() {
    for pair in [
        ["Work", "work"],
        ["Work", " WORK "],
        ["Ærlig", "ærlig"],
        ["ΣΊΣΥΦΟΣ", "σίσυφοσ"],
        ["Same", "Same"],
    ] {
        assert_eq!(
            normalize_folders(&names(&pair)),
            Err(folder_err(FolderError::Duplicate)),
            "{pair:?}"
        );
    }
    // Different names stay apart, also ones that differ only in a mark.
    assert_eq!(
        normalize_folders(&names(&["Work", "Works", "Café", "Cafe"])).unwrap(),
        names(&["Work", "Works", "Café", "Cafe"])
    );
}

#[test]
fn a_refused_list_leaves_the_body_as_it_was() {
    let mut body = login();
    body.set_folders(&names(&["Work"])).unwrap();
    let before = body.clone();
    for bad in [
        names(&["Home", ""]),
        names(&["Home", "home"]),
        vec!["x".repeat(65)],
        (0..21).map(|i| format!("F{i}")).collect(),
    ] {
        assert!(body.set_folders(&bad).is_err());
        assert_eq!(body, before);
    }
}

#[test]
fn the_codes_are_stable() {
    assert_eq!(folder_err(FolderError::Empty).code(), "folder_empty");
    assert_eq!(folder_err(FolderError::TooLong).code(), "folder_too_long");
    assert_eq!(folder_err(FolderError::TooMany).code(), "folder_too_many");
    assert_eq!(
        folder_err(FolderError::Duplicate).code(),
        "folder_duplicate"
    );
}

// ---------------------------------------------------------- unknown keys

#[test]
fn unknown_keys_survive_setting_and_clearing_folders() {
    let value = with_key(old_body_value(), "omega", Value::uint(9));
    let mut body = ItemBody::from_value(value).unwrap().body;
    assert_eq!(keys_of(&body), ["zeta", "omega"]);
    // A new key goes after the unknown ones.
    body.set_folders(&names(&["Work"])).unwrap();
    assert_eq!(keys_of(&body), ["zeta", "omega", "folders"]);
    let mut back = reread(&body);
    assert_eq!(keys_of(&back), ["zeta", "omega", "folders"]);
    assert_eq!(back.extra[0].1, Value::text("kept"));
    // A key that is there keeps its place when it is replaced.
    let mut entries = old_body_value().into_map().unwrap();
    entries.insert(8, ("folders".into(), Value::Array(vec![Value::text("A")])));
    let value = Value::Map(entries);
    let mut placed = ItemBody::from_value(value).unwrap().body;
    assert_eq!(keys_of(&placed), ["folders", "zeta"]);
    placed.set_folders(&names(&["B", "C"])).unwrap();
    assert_eq!(keys_of(&placed), ["folders", "zeta"]);
    assert_eq!(placed.folders(), names(&["B", "C"]));
    // Clearing takes away the folders and nothing else.
    back.set_folders(&[]).unwrap();
    assert_eq!(keys_of(&back), ["zeta", "omega"]);
}

#[test]
fn an_edit_of_other_fields_keeps_the_folders() {
    let mut body = login();
    body.set_folders(&names(&["Work", "Home"])).unwrap();
    let mut back = reread(&body);
    back.name = "Renamed".into();
    back.favorite = true;
    back.notes = Some("n".into());
    assert_eq!(reread(&back).folders(), names(&["Work", "Home"]));
}

// ---------------------------------------------------------- lenient read

#[test]
fn a_stored_value_against_the_rules_is_read_leniently_and_kept() {
    let long = "y".repeat(65);
    let stored = Value::Array(vec![
        Value::uint(1),
        Value::text(""),
        Value::text(" A "),
        Value::text("a"),
        Value::text(long.as_str()),
        Value::Null,
        Value::text("B"),
    ]);
    let value = with_key(old_body_value(), FOLDERS_KEY, stored.clone());
    let bytes = cbor::encode(&value).unwrap();
    let body = ItemBody::from_cbor(&bytes).unwrap().body;
    assert_eq!(body.folders(), names(&["A", "B"]));
    assert_eq!(body.view().folders, names(&["A", "B"]));
    // Reading changed nothing: the body is written as it was read.
    assert_eq!(body.to_cbor().unwrap().as_slice(), bytes.as_slice());
    // An edit that does not set folders keeps the stored value as it is.
    let mut edited = body.clone();
    edited.name = "Edited".into();
    let reread_value = cbor::decode(&edited.to_cbor().unwrap()).unwrap();
    assert_eq!(reread_value.get(FOLDERS_KEY), Some(&stored));
}

#[test]
fn a_stored_value_that_is_not_a_list_reads_as_no_folders() {
    for stored in [
        Value::text("Work"),
        Value::uint(3),
        Value::Map(vec![("a".into(), Value::text("b"))]),
    ] {
        let value = with_key(old_body_value(), FOLDERS_KEY, stored);
        let body = ItemBody::from_value(value).unwrap().body;
        assert!(body.folders().is_empty());
    }
}

#[test]
fn only_the_first_20_stored_names_are_read() {
    let stored = Value::Array((0..25).map(|i| Value::text(format!("F{i}"))).collect());
    let body = ItemBody::from_value(with_key(old_body_value(), FOLDERS_KEY, stored))
        .unwrap()
        .body;
    let expected: Vec<String> = (0..20).map(|i| format!("F{i}")).collect();
    assert_eq!(body.folders(), expected);
}

// ------------------------------------------------------------- read-only

#[test]
fn a_body_of_a_newer_schema_shows_folders_and_refuses_a_write() {
    let mut value = with_key(
        old_body_value(),
        FOLDERS_KEY,
        Value::Array(vec![Value::text("Future")]),
    );
    if let Value::Map(entries) = &mut value {
        entries[0].1 = Value::uint(2);
    }
    let decoded = ItemBody::from_value(value.clone()).unwrap();
    assert!(decoded.read_only);
    let mut body = decoded.body;
    assert_eq!(body.folders(), names(&["Future"]));
    assert_eq!(
        body.set_folders(&names(&["Now"])),
        Err(Error::ReadOnlySchema)
    );
    assert_eq!(body.set_folders(&[]), Err(Error::ReadOnlySchema));
    assert_eq!(body.to_value(), value);
}

// --------------------------------------------------------------- exports

fn foldered_items() -> Vec<ExportItem> {
    let mut a = login();
    a.set_folders(&names(&["Work", "Personal"])).unwrap();
    let b = ItemBody::new(ItemType::Note, "No folder", NOW);
    vec![
        ExportItem {
            item_id: ItemId::from_bytes([1; 16]),
            body: a,
        },
        ExportItem {
            item_id: ItemId::from_bytes([2; 16]),
            body: b,
        },
    ]
}

#[test]
fn the_encrypted_export_keeps_folders() {
    let pw = ExportPassword::for_open(b"correct horse battery").unwrap();
    let small = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    let items = foldered_items();
    let file = export_encrypt_unchecked(
        &mut TestRng::new(b"folders-export"),
        &pw,
        small,
        NOW,
        &items,
    )
    .unwrap();
    let back = import_decrypt_unchecked(&pw, &file).unwrap();
    assert_eq!(back, items);
    assert_eq!(back[0].body.folders(), names(&["Work", "Personal"]));
    assert!(back[1].body.folders().is_empty());
    // An imported body is written into the vault as it is, folders included.
    assert_eq!(
        reread(&back[0].body).folders(),
        names(&["Work", "Personal"])
    );
}

#[test]
fn the_json_export_holds_folders() {
    let json = export_plain_json(&foldered_items(), &PlainExportOptions::default()).unwrap();
    assert!(
        json.contains(r#""favorite":false,"folders":["Work","Personal"]}"#),
        "{json}"
    );
    assert_eq!(json.matches("\"folders\"").count(), 1);
}
