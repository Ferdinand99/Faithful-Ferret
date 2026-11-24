//! Generates the list of migrations from the files in `migrations/`, so a new
//! migration is a new file and no edited line (and no two tasks edit the same
//! list). The files are `NNNN_name.sql`, applied in name order after the kit's
//! core migrations.
//!
//! It also refuses a release build without the built web vault (`web/dist`),
//! unless the feature `dev-no-web` is on.
//!
//! It also reads `web/dist/wasm-source.json` (where the web vault's WebAssembly package came from)
//! into the binary, for `ferret --build-info`, and refuses a release image (`FERRET_RELEASE_BUILD`
//! set, which the server Dockerfile does when it gets a revision) whose vault was built with a
//! package from the tree.
//!
//! It also copies the kit's templates to `templates/kit/` (git ignores the copy), so the
//! admin pages' askama templates can extend the kit's layouts.

use std::path::PathBuf;

#[path = "build_support/registry.rs"]
mod registry;
#[path = "build_support/wasm_source.rs"]
mod wasm_source;

fn main() {
    vole_kit_build::templates();
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let migrations = manifest_dir.join("migrations");
    // Re-run when a file is added or removed, and (cargo watches the directory
    // recursively) when one changes.
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=build_support/registry.rs");
    println!("cargo:rerun-if-changed=build_support/wasm_source.rs");
    let source = match registry::render(&migrations) {
        Ok(source) => source,
        Err(message) => {
            println!("cargo:warning={message}");
            panic!("{message}");
        }
    };
    std::fs::write(out_dir.join("migrations.rs"), source).expect("write migrations.rs");

    // The web vault is built into the binary (`http::static_files::Embedded`).
    // A release build without it would serve no vault at all.
    let dist = manifest_dir.join("../../web/dist");
    println!("cargo:rerun-if-changed=../../web/dist");
    println!("cargo:rerun-if-env-changed=PROFILE");
    let release = std::env::var("PROFILE").is_ok_and(|p| p == "release");
    let allowed = std::env::var_os("CARGO_FEATURE_DEV_NO_WEB").is_some();
    if release && !allowed && !dist.join("index.html").is_file() {
        let message = "web/dist/index.html is missing: build the web vault first (web/scripts/build.mjs), or build with --features dev-no-web";
        println!("cargo:warning={message}");
        panic!("{message}");
    }

    // Where the vault's WebAssembly package came from. A release image says so in its
    // `--build-info`; without the record (a build with `dev-no-web`, or a debug build without a
    // built vault) the binary says `none`.
    println!("cargo:rerun-if-env-changed=FERRET_RELEASE_BUILD");
    let record = dist.join("wasm-source.json");
    println!("cargo:rerun-if-changed=../../web/dist/wasm-source.json");
    let (wasm_kind, wasm_sha) = match std::fs::read_to_string(&record) {
        Ok(text) => {
            let wasm = wasm_source::parse(&text).unwrap_or_else(|message| fail(&message));
            if std::env::var_os("FERRET_RELEASE_BUILD").is_some_and(|v| !v.is_empty()) {
                wasm_source::check_release(&wasm).unwrap_or_else(|message| fail(&message));
            }
            (wasm.source, wasm.sha256)
        }
        Err(_) if release && !allowed => fail(
            "web/dist/wasm-source.json is missing: build the web vault with web/scripts/build.mjs, which writes it",
        ),
        Err(_) => ("none".to_string(), String::new()),
    };
    println!("cargo:rustc-env=FERRET_WASM_SOURCE={wasm_kind}");
    println!("cargo:rustc-env=FERRET_WASM_SHA256={wasm_sha}");
}

/// Stops the build with a message cargo shows as a warning too.
fn fail(message: &str) -> ! {
    println!("cargo:warning={message}");
    panic!("{message}");
}
