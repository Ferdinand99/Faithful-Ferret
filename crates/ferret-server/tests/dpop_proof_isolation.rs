//! The file that reads a DPoP proof (`src/auth/dpop/proof.rs`) stands alone, so
//! the fuzz target can take it in as it is and run the code of the release
//! build: it names no item of the server, includes no other file, and has
//! `use` lines for the crates the fuzz target has only. (A path in code that
//! names another crate without a `use` is not scanned for; the fuzz crate would
//! not compile with it, and CI builds the fuzz crate.) The fuzz crate itself
//! has no dependency on the server, so nothing else of the server is in its
//! lock.
//! Spec: Fase 1 § 7.6 (the one reader of a proof).

use std::path::PathBuf;

use syn::UseTree;
use syn::visit::{self, Visit};

/// The crates the reader may use, besides the standard library.
const ALLOWED_ROOTS: &[&str] = &[
    "std",
    "core",
    "alloc",
    "serde",
    "serde_json",
    "base64",
    "sha2",
];

/// The macros that pull in a file the scan does not read.
const INCLUDE_MACROS: &[&str] = &["include", "include_str", "include_bytes"];

fn ident_name(ident: &syn::Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_string()
}

/// Whether `text` (the tokens of a macro or an attribute, written out) has the
/// word `word` followed by `::` (a path) or by `!` (a macro call).
fn names_word(text: &str, word: &str, then: &str) -> bool {
    let mut rest = text;
    while let Some(at) = rest.find(word) {
        let before = rest[..at].chars().last();
        let after = &rest[at + word.len()..];
        let whole = !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.starts_with(|c: char| c.is_alphanumeric() || c == '_');
        if whole && after.trim_start().starts_with(then) {
            return true;
        }
        rest = after;
    }
    false
}

/// What the scan finds in one file of source text.
#[derive(Default)]
struct Isolation {
    problems: Vec<String>,
}

impl Isolation {
    fn hit(&mut self, what: impl Into<String>) {
        self.problems.push(what.into());
    }

    /// A word of an item that leaves the file: `crate` or `super` anywhere in
    /// a path (`self` stays in the file and is allowed).
    fn check_segment(&mut self, name: &str) {
        if name == "crate" || name == "super" {
            self.hit(format!("names `{name}::`"));
        }
    }

    fn check_tokens(&mut self, text: &str) {
        for word in ["crate", "super"] {
            if names_word(text, word, "::") {
                self.hit(format!("names `{word}::` in a macro or an attribute"));
            }
        }
        for name in INCLUDE_MACROS {
            if names_word(text, name, "!") {
                self.hit(format!("`{name}!` pulls in a file"));
            }
        }
    }

    fn check_use(&mut self, tree: &UseTree, first: bool) {
        match tree {
            UseTree::Path(p) => {
                let name = ident_name(&p.ident);
                self.check_segment(&name);
                if first && !ALLOWED_ROOTS.contains(&name.as_str()) && name != "self" {
                    self.hit(format!(
                        "`use {name}::..` is not one of the crates of the reader"
                    ));
                }
                self.check_use(&p.tree, false);
            }
            UseTree::Name(n) => {
                let name = ident_name(&n.ident);
                self.check_segment(&name);
                if first && !ALLOWED_ROOTS.contains(&name.as_str()) {
                    self.hit(format!(
                        "`use {name}` is not one of the crates of the reader"
                    ));
                }
            }
            UseTree::Rename(r) => {
                let name = ident_name(&r.ident);
                self.check_segment(&name);
                if first && !ALLOWED_ROOTS.contains(&name.as_str()) {
                    self.hit(format!(
                        "`use {name} as ..` is not one of the crates of the reader"
                    ));
                }
            }
            UseTree::Glob(_) => {}
            UseTree::Group(g) => {
                for item in &g.items {
                    self.check_use(item, first);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for Isolation {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        for segment in &path.segments {
            self.check_segment(&ident_name(&segment.ident));
        }
        visit::visit_path(self, path);
    }

    fn visit_visibility(&mut self, _: &'ast syn::Visibility) {
        // `pub(crate)` names no item of the crate; it is not a path to one.
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.check_use(&item.tree, true);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        self.hit(format!("`extern crate {}`", item.ident));
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.content.is_none() {
            self.hit(format!("`mod {};` loads another file", item.ident));
        }
        visit::visit_item_mod(self, item);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(last) = mac.path.segments.last()
            && INCLUDE_MACROS.contains(&ident_name(&last.ident).as_str())
        {
            self.hit(format!("`{}!` pulls in a file", last.ident));
        }
        self.check_tokens(&mac.tokens.to_string());
        visit::visit_macro(self, mac);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if attr.path().is_ident("path") {
            self.hit("`#[path]` pulls in a file");
        }
        // Doc comments are prose; one that is not a string is looked at like
        // any other expression (`#[doc = include_str!(..)]`).
        let prose = attr.path().is_ident("doc")
            && matches!(&attr.meta, syn::Meta::NameValue(nv) if matches!(nv.value, syn::Expr::Lit(_)));
        if prose {
            return;
        }
        if let syn::Meta::List(list) = &attr.meta {
            let text = list.tokens.to_string();
            let has_path = text
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|word| word == "path");
            if attr.path().is_ident("cfg_attr") && has_path {
                self.hit("`#[cfg_attr(.., path = ..)]` pulls in a file");
            }
            self.check_tokens(&text);
        }
        visit::visit_attribute(self, attr);
    }
}

/// The problems of one source text, or why it does not parse.
fn problems_in(source: &str) -> Vec<String> {
    match syn::parse_file(source) {
        Ok(file) => {
            let mut scan = Isolation::default();
            scan.visit_file(&file);
            scan.problems
        }
        Err(e) => vec![format!("does not parse: {e}")],
    }
}

/// Whether a line of a manifest names the package `ferret-server`, as a key
/// (`ferret-server = ..`, `ferret-server.workspace = ..`, `[dependencies.ferret-server]`)
/// or as a renamed package (`package = "ferret-server"`). `ferret-server-auth`
/// is another package and does not count.
fn names_server_dependency(line: &str) -> bool {
    let line = line.trim();
    if line.contains("\"ferret-server\"") {
        return true;
    }
    let key = line.trim_start_matches('[');
    let key = key
        .rsplit_once("dependencies.")
        .map_or(key, |(_, name)| name);
    key.strip_prefix("ferret-server").is_some_and(|rest| {
        matches!(
            rest.trim_start().chars().next(),
            None | Some('=' | '.' | ']')
        )
    })
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn proof_rs_names_no_crate_item_and_includes_nothing() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/auth/dpop/proof.rs");
    let source = std::fs::read_to_string(&path).expect("the proof reader");
    let problems = problems_in(&source);
    assert!(
        problems.is_empty(),
        "src/auth/dpop/proof.rs is not stand-alone: {problems:?}"
    );

    // The scan sees every way out of the file, and nothing that stays in.
    for planted in [
        "fn f() { crate::auth::dpop::verify(); }",
        "fn f() -> super::Thing { todo!() }",
        "use crate::error::ApiError;",
        "use super::Thing;",
        "use {serde::Deserialize, crate::state::FerretState};",
        "use std::{fmt, super::x};",
        "use crate;",
        "use axum::http::HeaderMap;",
        "use ferret_core::Thing as Other;",
        "extern crate other;",
        "mod more;",
        "#[path = \"x.rs\"] mod more {}",
        "#[cfg_attr(test, path = \"x.rs\")] mod more {}",
        "const S: &str = include_str!(\"x.txt\");",
        "const B: &[u8] = include_bytes!(\"x.bin\");",
        "include!(\"x.rs\");",
        "fn f() { let s = format!(\"{}\", include_str!(\"x\")); }",
        "fn f() { println!(\"{}\", crate::x::y); }",
        "#[doc = include_str!(\"x.md\")] fn f() {}",
        "struct S { f: <T as super::Tr>::Out }",
        "impl crate::Tr for S {}",
    ] {
        assert!(!problems_in(planted).is_empty(), "not caught: {planted}");
    }
    for clean in [
        "//! The crate and the super module are only prose here.\nuse std::fmt;",
        "use base64::Engine as _;\nuse base64::engine::general_purpose::URL_SAFE_NO_PAD;",
        "use serde::de::{self, Deserializer};\nuse sha2::{Digest as _, Sha256};",
        "use serde_json::Value;\nuse core::marker::PhantomData;",
        "pub(crate) fn f() {}",
        "/// Uses crate::x in a doc comment, and include!(\"x\").\nfn f() {}",
        "mod inline { pub fn f() {} }",
        "fn f() { let crate_name = \"crate\"; let _ = (crate_name, \"include!(x)\"); }",
        "fn f() { let _ = std::str::from_utf8(b\"\"); }",
        "#[derive(Debug)] #[serde(deny_unknown_fields)] struct S;",
    ] {
        let found = problems_in(clean);
        assert!(found.is_empty(), "wrongly refused: {clean}: {found:?}");
    }
}

#[test]
fn the_fuzz_target_takes_in_proof_rs_and_nothing_else_of_the_server() {
    let root = repo_root();
    let target = std::fs::read_to_string(root.join("fuzz/fuzz_targets/fuzz_dpop_proof.rs"))
        .expect("the fuzz target");

    // The one `#[path]` of the target is the reader, and it names no crate of
    // the server in code.
    let file = syn::parse_file(&target).expect("the fuzz target parses");
    let mut paths = Vec::new();
    for item in &file.items {
        if let syn::Item::Mod(m) = item {
            for attr in &m.attrs {
                if attr.path().is_ident("path")
                    && let syn::Meta::NameValue(nv) = &attr.meta
                    && let syn::Expr::Lit(lit) = &nv.value
                    && let syn::Lit::Str(s) = &lit.lit
                {
                    paths.push(s.value());
                }
            }
        }
    }
    assert_eq!(paths, ["../../crates/ferret-server/src/auth/dpop/proof.rs"]);
    assert!(
        root.join("fuzz/fuzz_targets")
            .join(&paths[0])
            .canonicalize()
            .expect("the path of the target points to a file")
            .ends_with("crates/ferret-server/src/auth/dpop/proof.rs")
    );
    let code: String = target
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    assert!(
        !code.contains("ferret_server::"),
        "the target names the server crate"
    );
    assert!(
        !code.contains("ferret_server_auth"),
        "the target is about the reader, not the library"
    );

    // The fuzz crate does not depend on the server, so its lock has none of it.
    let manifest =
        std::fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("the fuzz manifest");
    for line in manifest
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
    {
        assert!(
            !names_server_dependency(line) && !line.contains("crates/ferret-server\""),
            "the fuzz crate depends on the server: {line}"
        );
    }
    let lock = std::fs::read_to_string(root.join("fuzz/Cargo.lock")).expect("the fuzz lock");
    assert!(
        !lock.lines().any(|l| l == "name = \"ferret-server\""),
        "the server is in the lock of the fuzz crate"
    );
}

#[test]
fn the_manifest_scan_sees_every_way_to_name_the_server() {
    for planted in [
        "ferret-server = { path = \"../crates/ferret-server\" }",
        "ferret-server={ path = \"x\" }",
        "ferret-server.workspace = true",
        "[dependencies.ferret-server]",
        "server = { package = \"ferret-server\", path = \"x\" }",
        "  ferret-server = \"1\"",
    ] {
        assert!(names_server_dependency(planted), "not caught: {planted}");
    }
    for clean in [
        "ferret-server-auth = { path = \"../crates/ferret-server-auth\", features = [\"test-support\"] }",
        "[dependencies.ferret-server-auth]",
        "ferret-core = { path = \"../crates/ferret-core\" }",
        "name = \"fuzz_dpop_proof\"",
    ] {
        assert!(!names_server_dependency(clean), "wrongly caught: {clean}");
    }
}
