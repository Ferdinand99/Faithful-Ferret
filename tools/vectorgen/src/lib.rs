//! Generates and checks the Ferret Core test vectors under `vectors/`.
//!
//! * The files in `vectors/internal/` are made here, by the registered
//!   groups, and are never edited by hand.
//! * `VERSION`, `OPS.md`, `ERRORS.md`, `schema/` and `external/` are written
//!   by hand (or copied from third parties) and are only checked.
//! * `MANIFEST.json` lists the SHA-256 of every file under `vectors/` except
//!   itself.
//!
//! Generation is deterministic: the same inputs give the same bytes.

#![forbid(unsafe_code)]

mod groups;
mod text_groups;

use ferret_core::testing::{hex_encode, vector::VectorFile};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Name of the manifest, relative to the vectors root.
pub const MANIFEST_FILE: &str = "MANIFEST.json";

/// Hand-written files that must exist.
pub const REQUIRED_FILES: &[&str] = &[
    "VERSION",
    "OPS.md",
    "ERRORS.md",
    "schema/vector-file.schema.json",
];

/// Files by path relative to the vectors root, with `/` separators.
pub type Files = BTreeMap<String, Vec<u8>>;

/// Errors from the generator.
pub type Error = Box<dyn std::error::Error>;

/// One generated file: its path under `vectors/` and a function making it.
type Group = (&'static str, fn() -> Result<Vec<u8>, Error>);

/// The registered groups. Each task that adds a vector file adds one line.
const GROUPS: &[Group] = &[
    ("internal/kdf.json", groups::kdf),
    ("internal/tlv.json", groups::tlv),
    ("internal/unicode.json", text_groups::unicode),
    ("internal/codes.json", text_groups::codes),
];

/// Serializes a vector file the way every generated file is written:
/// pretty JSON, two-space indent, trailing newline.
pub fn render(file: &VectorFile) -> Result<Vec<u8>, Error> {
    let mut bytes = serde_json::to_vec_pretty(file)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Makes every generated file in memory.
pub fn generated_files() -> Result<Files, Error> {
    let mut files = Files::new();
    for (path, make) in GROUPS {
        files.insert((*path).to_string(), make()?);
    }
    Ok(files)
}

/// Reads every file under `root` (except the manifest) into memory.
pub fn collect_dir(root: &Path) -> Result<Files, Error> {
    fn walk(dir: &Path, prefix: &str, out: &mut Files) -> Result<(), Error> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type()?.is_dir() {
                walk(&entry.path(), &rel, out)?;
            } else if rel != MANIFEST_FILE {
                out.insert(rel, fs::read(entry.path())?);
            }
        }
        Ok(())
    }
    let mut files = Files::new();
    walk(root, "", &mut files)?;
    Ok(files)
}

/// The bytes of `MANIFEST.json` for the given files.
pub fn manifest_bytes(files: &Files) -> Result<Vec<u8>, Error> {
    let version: u64 = files
        .get("VERSION")
        .map(|v| String::from_utf8_lossy(v).trim().parse())
        .transpose()?
        .ok_or("vectors/VERSION is missing")?;
    let mut hashes = Map::new();
    for (path, bytes) in files {
        hashes.insert(
            path.clone(),
            Value::from(hex_encode(&Sha256::digest(bytes))),
        );
    }
    let manifest = json!({
        "format": "ferret-vectors-manifest/1",
        "version": version,
        "files": hashes,
    });
    let mut out = serde_json::to_vec_pretty(&manifest)?;
    out.push(b'\n');
    Ok(out)
}

/// Writes the generated files and `MANIFEST.json` under `root`. Files in
/// `internal/` that no group makes any more are removed.
pub fn generate(root: &Path) -> Result<(), Error> {
    let generated = generated_files()?;
    let internal = root.join("internal");
    fs::create_dir_all(&internal)?;
    for path in collect_dir(&internal)?.keys() {
        let rel = format!("internal/{path}");
        if !generated.contains_key(&rel) {
            fs::remove_file(root.join(&rel))?;
        }
    }
    for (path, bytes) in &generated {
        let target = root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, bytes)?;
    }
    let on_disk = collect_dir(root)?;
    fs::write(root.join(MANIFEST_FILE), manifest_bytes(&on_disk)?)?;
    Ok(())
}

/// Regenerates in memory and compares with `root` byte for byte; also checks
/// the required hand-written files and `MANIFEST.json`. Returns all problems.
pub fn check(root: &Path) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let generated = match generated_files() {
        Ok(files) => files,
        Err(e) => return Err(vec![format!("generation failed: {e}")]),
    };
    let on_disk = match collect_dir(root) {
        Ok(files) => files,
        Err(e) => return Err(vec![format!("cannot read {}: {e}", root.display())]),
    };
    for required in REQUIRED_FILES {
        if !on_disk.contains_key(*required) {
            problems.push(format!("missing required file {required}"));
        }
    }
    for (path, bytes) in &generated {
        match on_disk.get(path) {
            None => problems.push(format!("{path} is not on disk")),
            Some(disk) if disk != bytes => problems.push(format!("{path} differs from generated")),
            Some(_) => {}
        }
    }
    for path in on_disk.keys() {
        if path.starts_with("internal/") && !generated.contains_key(path) {
            problems.push(format!("{path} is not made by any group"));
        }
    }
    if on_disk.contains_key("VERSION") {
        match manifest_bytes(&on_disk) {
            Err(e) => problems.push(format!("cannot build manifest: {e}")),
            Ok(expected) => match fs::read(root.join(MANIFEST_FILE)) {
                Err(_) => problems.push(format!("{MANIFEST_FILE} is missing")),
                Ok(disk) if disk != expected => {
                    problems.push(format!("{MANIFEST_FILE} does not match the files"));
                }
                Ok(_) => {}
            },
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}
