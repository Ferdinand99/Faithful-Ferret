//! Generates the list of migrations from the files in `migrations/`, so a new
//! migration is a new file and no edited line (and no two tasks edit the same
//! list). The files are `NNNN_name.sql`, applied in name order after the kit's
//! core migrations.
//!
//! It also refuses a release build without the built web vault (`web/dist`),
//! unless the feature `dev-no-web` is on.
//!
//! Later this script also copies the kit's templates for the admin pages.

use std::path::PathBuf;

#[path = "build_support/registry.rs"]
mod registry;

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let migrations = manifest_dir.join("migrations");
    // Re-run when a file is added or removed, and (cargo watches the directory
    // recursively) when one changes.
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=build_support/registry.rs");
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
}
