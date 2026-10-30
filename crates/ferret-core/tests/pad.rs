//! ISO/IEC 7816-4 padding (Fase 1 § 5.2): the classes, the limit, the
//! removal, and `vectors/internal/padding.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::Error;
use ferret_core::item::pad::{
    MAX_PADDED, MAX_PLAINTEXT, is_padded_len, pad, padded_len, scan::unpad_scan, unpad,
};
use ferret_core::testing::hex_encode;
use ferret_core::testing::vector::{self, Outcome};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn pad_class_boundaries() {
    for (len, want) in [
        (0, 256),
        (1, 256),
        (254, 256),
        (255, 256),
        (256, 512),
        (510, 512),
        (511, 512),
        (512, 1_024),
        (1_023, 1_024),
        (1_024, 2_048),
        (2_047, 2_048),
        (2_048, 4_096),
        (4_094, 4_096),
        (4_095, 4_096),
        (4_096, 8_192),
        (8_190, 8_192),
        (8_191, 8_192),
        (8_192, 12_288),
        (61_438, 61_440),
        (61_439, 61_440),
    ] {
        assert_eq!(padded_len(len).unwrap(), want, "plaintext of {len} bytes");
        assert_eq!(pad(&vec![7u8; len]).unwrap().len(), want);
    }
    assert_eq!(padded_len(61_440), Err(Error::TooLarge));
    assert_eq!(padded_len(65_535), Err(Error::TooLarge));
    assert_eq!(padded_len(usize::MAX), Err(Error::TooLarge));
    assert_eq!(pad(&vec![0u8; 61_440]).unwrap_err(), Error::TooLarge);
    assert_eq!(MAX_PADDED, 61_440);
    assert_eq!(MAX_PLAINTEXT, 61_439);
}

#[test]
fn the_padded_length_is_never_below_len_plus_one() {
    for len in 0..=MAX_PLAINTEXT {
        let padded = padded_len(len).unwrap();
        assert!(padded > len, "{len} -> {padded}");
        assert!(is_padded_len(padded));
    }
}

#[test]
fn only_the_classes_are_padded_lengths() {
    let classes: Vec<usize> = (0..=70_000).filter(|n| is_padded_len(*n)).collect();
    let mut want = vec![256, 512, 1_024, 2_048];
    want.extend((1..=15).map(|k| k * 4_096));
    assert_eq!(classes, want);
}

#[test]
fn pad_layout_is_the_plaintext_marker_and_zeros() {
    let padded = pad(b"abc").unwrap();
    assert_eq!(&padded[..3], b"abc");
    assert_eq!(padded[3], 0x80);
    assert!(padded[4..].iter().all(|b| *b == 0));
    assert_eq!(padded.len(), 256);
    // A plaintext that fills the class but one byte.
    let padded = pad(&[1u8; 255]).unwrap();
    assert_eq!(padded[255], 0x80);
    assert_eq!(padded.len(), 256);
}

#[test]
fn pad_roundtrip_all_lengths_0_to_5000() {
    for len in 0..=5_000usize {
        let plain: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let padded = pad(&plain).unwrap();
        let n = unpad(&padded).unwrap();
        assert_eq!(&padded[..n], plain.as_slice(), "length {len}");
    }
}

#[test]
fn plaintext_may_end_in_the_marker_byte_or_zeros() {
    for plain in [
        vec![0x80],
        vec![0x00],
        vec![0x80, 0x00, 0x80],
        vec![0u8; 40],
    ] {
        let padded = pad(&plain).unwrap();
        let n = unpad(&padded).unwrap();
        assert_eq!(&padded[..n], plain.as_slice());
    }
}

#[test]
fn unpad_rejects_missing_marker_and_nonzero_tail() {
    // No marker at all.
    assert_eq!(unpad(&[0u8; 256]), Err(Error::Decrypt));
    assert_eq!(unpad(&[]), Err(Error::Decrypt));
    assert_eq!(unpad(&[1, 2, 3]), Err(Error::Decrypt));
    // A byte other than zero after the marker.
    let mut padded = pad(b"hello").unwrap().to_vec();
    padded[200] = 1;
    assert_eq!(unpad(&padded), Err(Error::Decrypt));
    // The marker as the very last byte is a valid empty tail.
    let mut full = vec![9u8; 255];
    full.push(0x80);
    assert_eq!(unpad(&full), Ok(255));
    // A marker alone.
    assert_eq!(unpad(&[0x80]), Ok(0));
}

#[test]
fn the_scan_agrees_with_a_plain_reference_on_many_buffers() {
    fn reference(buf: &[u8]) -> Option<usize> {
        let at = buf.iter().rposition(|b| *b != 0)?;
        (buf[at] == 0x80).then_some(at)
    }
    let mut state = 0x1234_5678u32;
    let mut next = move || {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        state >> 24
    };
    for _ in 0..20_000 {
        let len = usize::try_from(next() % 12).unwrap();
        let buf: Vec<u8> = (0..len)
            .map(|_| match next() % 4 {
                0 => 0x00,
                1 => 0x80,
                2 => 0x01,
                _ => u8::try_from(next()).unwrap(),
            })
            .collect();
        let (ok, at) = unpad_scan(&buf);
        match reference(&buf) {
            Some(want) => assert_eq!((ok, at), (1, want), "{buf:?}"),
            None => assert_eq!(ok, 0, "{buf:?}"),
        }
    }
}

#[test]
fn the_scan_reads_the_whole_buffer_whatever_it_holds() {
    // The result is the same for a buffer with the marker in front or at the
    // back; the loop has no exit. This only checks the answers, the timing
    // is the business of the constant-time analysis.
    let mut a = vec![0u8; 4_096];
    a[0] = 0x80;
    let mut b = vec![0u8; 4_096];
    b[4_095] = 0x80;
    assert_eq!(unpad_scan(&a), (1, 0));
    assert_eq!(unpad_scan(&b), (1, 4_095));
}

// -------------------------------------------------------------- vectors

#[test]
fn padding_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/padding.json")).unwrap();
    assert!(file.cases.len() >= 20, "{} cases", file.cases.len());
    let report = vector::run_all(&file, |case, _rng| match case.op.as_str() {
        "pad.apply" => {
            let plain = segments(&case.input["plain"]);
            let padded = pad(&plain)?;
            Ok(Outcome {
                output: json!({
                    "padded_len": padded.len(),
                    "padded_sha256": hex_encode(&Sha256::digest(&*padded)),
                }),
                intermediate: None,
            })
        }
        "pad.remove" => {
            let padded = segments(&case.input["padded"]);
            let n = unpad(&padded)?;
            Ok(Outcome {
                output: json!({
                    "plain_len": n,
                    "plain_sha256": hex_encode(&Sha256::digest(&padded[..n])),
                }),
                intermediate: None,
            })
        }
        other => panic!("unknown op {other}"),
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());
}

// ------------------------------------------------------- the single file

fn compile(source: &std::path::Path, name: &str) {
    use std::process::Command;
    let out = std::env::temp_dir().join(format!("ferret-ct-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let result = Command::new(rustc)
        .args([
            "--crate-type=lib",
            "--edition=2024",
            "--emit=metadata",
            "-D",
            "warnings",
        ])
        .arg("--crate-name")
        .arg(name)
        .arg("--out-dir")
        .arg(&out)
        .arg(source)
        .output()
        .expect("rustc must be on the PATH to compile the constant-time harness");
    let _ = std::fs::remove_dir_all(&out);
    assert!(
        result.status.success(),
        "rustc failed on {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn unpad_harness_is_one_file_with_core_only_and_no_tables() {
    // The analyzer run (x86_64 and arm64, O0 to O3) is a separate check. Here: the file
    // compiles on its own with rustc, with `core` only, and it is the file
    // the core includes.
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ct/harness/unpad.rs");
    compile(&source, "unpad_single_file");
    let dir = std::env::temp_dir().join(format!("ferret-ct-unpad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wrapper = dir.join("no_std_wrapper.rs");
    std::fs::write(
        &wrapper,
        format!(
            "#![no_std]\ninclude!(r\"{}\");\n",
            source.canonicalize().unwrap().display()
        ),
    )
    .unwrap();
    compile(&wrapper, "unpad_no_std");
    let _ = std::fs::remove_dir_all(&dir);

    let pad_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/item/pad.rs"),
    )
    .unwrap();
    assert!(pad_rs.contains("include!(\"../../../../ct/harness/unpad.rs\")"));

    // No table, no early exit: the loop has no `break`, `return` or `?`, and
    // there is no `if`, `match` or `while` on a byte of the buffer.
    let text = std::fs::read_to_string(&source).unwrap();
    for line in text.lines() {
        let code = line.split("//").next().unwrap();
        for forbidden in [
            "const ", "static ", "break", "return", "match ", "if ", "while ",
        ] {
            assert!(
                !code.contains(forbidden),
                "{forbidden:?} in the harness: {line}"
            );
        }
    }
}
