//! Where the WebAssembly package inside the web vault came from.
//!
//! The web build (`web/scripts/build.mjs`) writes `web/dist/wasm-source.json`:
//!
//! ```text
//! { "source": "lock",    "version": "0.8.0", "sha256": "…" }   the published package named in web/wasm.lock.json
//! { "source": "release", "sha256": "…" }                        the package of this release run
//! { "source": "tree",    "commit": "…", "sha256": "…" }         built from the commit, for test builds only
//! ```
//!
//! `build.rs` reads it, puts the source and the SHA-256 into the binary (`ferret --build-info`
//! prints them), and refuses a release image whose vault was built with a package from the
//! tree. `tests/build_info.rs` includes this file, so the tests run the same code.

/// The source of the package and its SHA-256, as the web build recorded them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSource {
    pub source: String,
    pub sha256: String,
}

/// The value of a string field in the record: `"key": "value"`, where the value is plain
/// (letters, digits, dot, dash and underscore). `None` when the key is not there or its value
/// is anything else.
fn field(text: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let rest = text.split_once(&marker)?.1.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (value, _) = rest.split_once('"')?;
    let plain = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    plain.then(|| value.to_string())
}

/// Reads the record. The source must be `lock`, `release` or `tree`, and the SHA-256 64
/// lower-case hex digits; anything else is an error.
pub fn parse(text: &str) -> Result<WasmSource, String> {
    let source = field(text, "source").ok_or("wasm-source.json has no source")?;
    if !matches!(source.as_str(), "lock" | "release" | "tree") {
        return Err(format!(
            "wasm-source.json: the source is {source}, expected lock, release or tree"
        ));
    }
    let sha256 = field(text, "sha256").ok_or("wasm-source.json has no sha256")?;
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("wasm-source.json: the sha256 is not 64 lower-case hex digits".to_string());
    }
    Ok(WasmSource { source, sha256 })
}

/// What a release image may carry: the locked package or the package of its own release run,
/// never one built from the tree.
pub fn check_release(wasm: &WasmSource) -> Result<(), String> {
    match wasm.source.as_str() {
        "lock" | "release" => Ok(()),
        other => Err(format!(
            "a release image cannot carry a WebAssembly package from the source {other}: the web vault must be built from the locked package or from the package of its own release run"
        )),
    }
}

/// What the build script puts into the binary: the source and the SHA-256 (`none` and an empty
/// digest without a record).
///
/// * `record`: the text of `web/dist/wasm-source.json`, if the file is there;
/// * `release_build`: the build is a release image (`FERRET_RELEASE_BUILD` is set);
/// * `release_profile`: cargo's release profile;
/// * `dev_no_web`: the feature that lets a release build go ahead without a web vault.
///
/// A record that cannot be read is an error, and so is a tree package in a release image, and a
/// release-profile build with a vault but no record.
pub fn decide(
    record: Option<&str>,
    release_build: bool,
    release_profile: bool,
    dev_no_web: bool,
) -> Result<(String, String), String> {
    match record {
        Some(text) => {
            let wasm = parse(text)?;
            if release_build {
                check_release(&wasm)?;
            }
            Ok((wasm.source, wasm.sha256))
        }
        None if release_profile && !dev_no_web => Err(
            "web/dist/wasm-source.json is missing: build the web vault with web/scripts/build.mjs, which writes it"
                .to_string(),
        ),
        None => Ok(("none".to_string(), String::new())),
    }
}
