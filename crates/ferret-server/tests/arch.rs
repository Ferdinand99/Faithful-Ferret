//! The architecture tests. They read the source files with `syn` and fail when
//! the boundaries of the design are crossed:
//!
//! * the vault modules (`src/vault/**`) never name the application state, the
//!   kit's core state, its cookie key or its crypto, nor the server's secrets,
//!   and take their state only through `FromRef` (a deny-list of names, not an
//!   allow-list of crates);
//! * the vault routes are generic over the state and never apply one;
//! * the types that carry ciphertext, tags, messages or proofs have no derived
//!   `Debug`, so a stray `{:?}` cannot print them.
//!
//! Doc comments are prose and are not scanned.

use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{GenericArgument, PathArguments, ReturnType, Type, UseTree};

/// Identifiers the vault modules must not use.
const FORBIDDEN_IDENTS: &[&str] = &[
    "FerretState",
    "Core",
    "session_key",
    "Key",
    "SignedCookieJar",
    "PrivateCookieJar",
    "aws_lc_rs",
    "Secrets",
    "ServerKeys",
    "StateSealKey",
];

/// Text the vault modules must not have in a string.
const FORBIDDEN_LITERALS: &[&str] = &["session.key", "session_key"];

/// Types with a byte field that are not secret and may derive `Debug`: a device
/// id, and the hash that keys a session row.
const DERIVED_DEBUG_ALLOWED: &[&str] = &["DeviceId", "SidHash"];

/// Types that must not derive `Debug` besides those the wire module lists in
/// `redacted_debug!`.
const ALSO_REDACTED: &[&str] = &["SessionSecret", "Secrets"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `dir`, sorted.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let entries = std::fs::read_dir(&next).unwrap_or_else(|e| panic!("{next:?}: {e}"));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn parse(path: &Path) -> Result<syn::File, String> {
    let source = std::fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
    syn::parse_file(&source).map_err(|e| format!("{path:?}: does not parse: {e}"))
}

// ---------------------------------------------------------------------------
// The deny-list
// ---------------------------------------------------------------------------

struct Names {
    file: String,
    found: Vec<String>,
}

impl Names {
    fn hit(&mut self, what: String) {
        self.found.push(format!("{}: {what}", self.file));
    }

    /// A path as segments: `crate::state::VaultDb` is `["crate", "state", "VaultDb"]`.
    fn check_path(&mut self, segments: &[String]) {
        let at = |i: usize| segments.get(i).map(String::as_str);
        let joined = segments.join("::");
        match (at(0), at(1)) {
            (Some("vole_kit"), Some("crypto" | "state")) => {
                self.hit(format!("names `{joined}`"));
            }
            (Some("crate"), Some("state")) if at(2) != Some("VaultDb") => {
                self.hit(format!(
                    "names `{joined}` (only `crate::state::VaultDb` is allowed)"
                ));
            }
            (Some("crate"), Some("auth")) if at(2) == Some("secrets") => {
                self.hit(format!("names `{joined}`"));
            }
            (Some("super"), Some("state")) => self.hit(format!("names `{joined}`")),
            _ => {}
        }
    }

    /// Looks through text that is not parsed (macro arguments, attribute lists).
    fn check_text(&mut self, text: &str) {
        for word in text.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if FORBIDDEN_IDENTS.contains(&word) {
                self.hit(format!("names `{word}` (in a macro or attribute)"));
            }
        }
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        for path in [
            "vole_kit::crypto",
            "vole_kit::state",
            "crate::auth::secrets",
            "super::state",
        ] {
            if compact.contains(path) {
                self.hit(format!("names `{path}` (in a macro or attribute)"));
            }
        }
        let mut rest = compact.as_str();
        while let Some(at) = rest.find("crate::state") {
            rest = &rest[at + "crate::state".len()..];
            if !rest.starts_with("::VaultDb") {
                self.hit("names `crate::state` other than `VaultDb` (in a macro)".to_string());
            }
        }
        for literal in FORBIDDEN_LITERALS {
            if text.contains(literal) {
                self.hit(format!(
                    "has the text `{literal}` (in a macro or attribute)"
                ));
            }
        }
    }
}

fn flatten(tree: &UseTree, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten(&p.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(n) => {
            if n.ident == "self" {
                out.push(prefix.clone());
            } else {
                prefix.push(n.ident.to_string());
                out.push(prefix.clone());
                prefix.pop();
            }
        }
        UseTree::Rename(r) => {
            if r.ident == "self" {
                out.push(prefix.clone());
            } else {
                prefix.push(r.ident.to_string());
                out.push(prefix.clone());
                prefix.pop();
            }
        }
        UseTree::Glob(_) => {
            prefix.push("*".to_string());
            out.push(prefix.clone());
            prefix.pop();
        }
        UseTree::Group(g) => {
            for item in &g.items {
                flatten(item, prefix, out);
            }
        }
    }
}

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let name = ident.to_string();
        if FORBIDDEN_IDENTS.contains(&name.as_str()) {
            self.hit(format!("names `{name}`"));
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.check_path(&segments);
        visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        flatten(&item.tree, &mut Vec::new(), &mut paths);
        for path in paths {
            match path.as_slice() {
                [root] if root == "crate" || root == "vole_kit" => {
                    self.hit(format!("`use {root}` gives the root a name of its own"));
                }
                [root, star] if root == "crate" && star == "*" => {
                    self.hit("glob import of the crate root".to_string());
                }
                _ => self.check_path(&path),
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        let value = lit.value();
        for literal in FORBIDDEN_LITERALS {
            if value.contains(literal) {
                self.hit(format!("has the string `{literal}`"));
            }
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.check_text(&mac.tokens.to_string());
        visit::visit_macro(self, mac);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        // Doc comments are prose.
        if attr.path().is_ident("doc") {
            return;
        }
        if let syn::Meta::List(list) = &attr.meta {
            self.check_text(&list.tokens.to_string());
        }
        visit::visit_attribute(self, attr);
    }
}

/// The violations in one source text.
fn scan_names(file: &str, source: &str) -> Vec<String> {
    match syn::parse_file(source) {
        Ok(syntax) => {
            let mut names = Names {
                file: file.to_string(),
                found: Vec::new(),
            };
            names.visit_file(&syntax);
            names.found
        }
        Err(e) => vec![format!("{file}: does not parse: {e}")],
    }
}

fn scan_dir_names(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for path in rust_files(dir) {
        let source = std::fs::read_to_string(&path).expect("a source file");
        found.extend(scan_names(&path.display().to_string(), &source));
    }
    found
}

#[test]
fn vault_modules_do_not_name_forbidden_identifiers() {
    let dir = manifest_dir().join("src/vault");
    assert!(
        rust_files(&dir).len() >= 10,
        "the vault modules are where the test expects them"
    );
    let found = scan_dir_names(&dir);
    assert!(
        found.is_empty(),
        "the vault modules cross the boundary:\n{}",
        found.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Generic routes
// ---------------------------------------------------------------------------

struct Shapes {
    file: String,
    found: Vec<String>,
    checked: usize,
}

impl Shapes {
    fn check_signature(&mut self, sig: &syn::Signature) {
        let ReturnType::Type(_, ty) = &sig.output else {
            return;
        };
        let Type::Path(path) = &**ty else {
            return;
        };
        let Some(last) = path.path.segments.last() else {
            return;
        };
        if last.ident != "Router" {
            return;
        }
        self.checked += 1;
        let params: Vec<String> = sig
            .generics
            .type_params()
            .map(|p| p.ident.to_string())
            .collect();
        let state = match &last.arguments {
            PathArguments::AngleBracketed(args) => args.args.first().and_then(|a| match a {
                GenericArgument::Type(Type::Path(p)) if p.path.segments.len() == 1 => {
                    p.path.segments.first().map(|s| s.ident.to_string())
                }
                _ => None,
            }),
            _ => None,
        };
        if !state.is_some_and(|s| params.contains(&s)) {
            self.found.push(format!(
                "{}: `{}` returns a Router that is not generic over its own state parameter",
                self.file, sig.ident
            ));
        }
    }
}

impl<'ast> Visit<'ast> for Shapes {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.check_signature(&item.sig);
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.check_signature(&item.sig);
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "with_state" {
            self.found.push(format!(
                "{}: applies a state with `with_state`; only the server's routers do",
                self.file
            ));
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn scan_shapes(file: &str, source: &str) -> (Vec<String>, usize) {
    match syn::parse_file(source) {
        Ok(syntax) => {
            let mut shapes = Shapes {
                file: file.to_string(),
                found: Vec::new(),
                checked: 0,
            };
            shapes.visit_file(&syntax);
            (shapes.found, shapes.checked)
        }
        Err(e) => (vec![format!("{file}: does not parse: {e}")], 0),
    }
}

#[test]
fn vault_routes_are_generic_over_the_state_and_use_from_ref() {
    let mut found = Vec::new();
    let mut checked = 0;
    for path in rust_files(&manifest_dir().join("src/vault")) {
        let source = std::fs::read_to_string(&path).expect("a source file");
        let (hits, count) = scan_shapes(&path.display().to_string(), &source);
        found.extend(hits);
        checked += count;
    }
    assert!(
        found.is_empty(),
        "vault routes must be `fn routes<S>() -> Router<S>`:\n{}",
        found.join("\n")
    );
    assert!(checked >= 4, "the route functions were found ({checked})");

    // The narrow state comes through `FromRef`, and the session extractors ask
    // for nothing but the narrow `SessionAuth`.
    let state = std::fs::read_to_string(manifest_dir().join("src/state.rs")).expect("state.rs");
    assert!(state.contains("impl FromRef<FerretState> for VaultDb"));
    assert!(state.contains("impl FromRef<FerretState> for SessionAuth"));
    let extract =
        std::fs::read_to_string(manifest_dir().join("src/http/extract.rs")).expect("extract.rs");
    assert!(
        extract.matches("SessionAuth: FromRef<S>").count() >= 2,
        "both extractors are generic over the state"
    );
}

// ---------------------------------------------------------------------------
// No derived Debug on types that carry secrets or ciphertext
// ---------------------------------------------------------------------------

struct Declared {
    name: String,
    derives_debug: bool,
    holds_bytes: bool,
    file: String,
}

struct Types {
    file: String,
    declared: Vec<Declared>,
    redacted: Vec<String>,
}

fn derives_debug(attrs: &[syn::Attribute]) -> bool {
    let mut debug = false;
    for attr in attrs {
        if attr.path().is_ident("derive") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "Debug")
                {
                    debug = true;
                }
                Ok(())
            });
        }
    }
    debug
}

/// Whether the type is, or contains, `u8` bytes in a `Vec`, a boxed slice or an
/// array.
fn holds_bytes(ty: &Type) -> bool {
    let is_u8 = |t: &Type| matches!(t, Type::Path(p) if p.path.is_ident("u8"));
    match ty {
        Type::Array(a) => is_u8(&a.elem) || holds_bytes(&a.elem),
        Type::Slice(s) => is_u8(&s.elem) || holds_bytes(&s.elem),
        Type::Reference(r) => holds_bytes(&r.elem),
        Type::Tuple(t) => t.elems.iter().any(holds_bytes),
        Type::Path(p) => p.path.segments.iter().any(|segment| {
            let PathArguments::AngleBracketed(args) = &segment.arguments else {
                return false;
            };
            args.args.iter().any(|arg| match arg {
                GenericArgument::Type(t) => (segment.ident == "Vec" && is_u8(t)) || holds_bytes(t),
                _ => false,
            })
        }),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for Types {
    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.declared.push(Declared {
            name: item.ident.to_string(),
            derives_debug: derives_debug(&item.attrs),
            holds_bytes: item.fields.iter().any(|f| holds_bytes(&f.ty)),
            file: self.file.clone(),
        });
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.declared.push(Declared {
            name: item.ident.to_string(),
            derives_debug: derives_debug(&item.attrs),
            holds_bytes: item
                .variants
                .iter()
                .any(|v| v.fields.iter().any(|f| holds_bytes(&f.ty))),
            file: self.file.clone(),
        });
        visit::visit_item_enum(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if item.mac.path.is_ident("redacted_debug") {
            let text = item.mac.tokens.to_string();
            self.redacted.extend(
                text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .filter(|w| !w.is_empty())
                    .map(str::to_string),
            );
        }
        visit::visit_item_macro(self, item);
    }
}

fn scan_types(root: &Path) -> Types {
    let mut all = Types {
        file: String::new(),
        declared: Vec::new(),
        redacted: Vec::new(),
    };
    for path in rust_files(root) {
        all.file = path.display().to_string();
        let syntax = parse(&path).unwrap_or_else(|e| panic!("{e}"));
        all.visit_file(&syntax);
    }
    all
}

#[test]
fn no_derive_debug_on_request_types() {
    let types = scan_types(&manifest_dir().join("src"));

    // The wire module lists its request and response types in one macro that
    // writes `Type([redacted])`.
    assert!(
        types.redacted.iter().any(|n| n == "PutItemReq")
            && types.redacted.iter().any(|n| n == "RegisterFinishReq"),
        "the redacted types of the wire module were found: {:?}",
        types.redacted
    );
    let named: Vec<&str> = types
        .redacted
        .iter()
        .map(String::as_str)
        .chain(ALSO_REDACTED.iter().copied())
        .collect();

    let mut problems = Vec::new();
    for name in &named {
        let declarations: Vec<&Declared> =
            types.declared.iter().filter(|d| d.name == *name).collect();
        if declarations.is_empty() {
            problems.push(format!("`{name}` is listed as redacted but not declared"));
        }
        for declared in declarations {
            if declared.derives_debug {
                problems.push(format!(
                    "{}: `{name}` derives Debug; write it by hand and print `[redacted]`",
                    declared.file
                ));
            }
        }
    }
    // Any other type that holds bytes must write its Debug by hand too, unless
    // the bytes are known not to be secret.
    for declared in &types.declared {
        if declared.derives_debug
            && declared.holds_bytes
            && !DERIVED_DEBUG_ALLOWED.contains(&declared.name.as_str())
        {
            problems.push(format!(
                "{}: `{}` holds bytes and derives Debug",
                declared.file, declared.name
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ---------------------------------------------------------------------------
// The check on the checks
// ---------------------------------------------------------------------------

#[test]
fn arch_test_detects_a_planted_violation() {
    // A module in a temporary directory, as a developer would add one.
    let dir = std::env::temp_dir().join(format!("ferret-test-arch-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("vault")).expect("a temporary directory");
    std::fs::write(
        dir.join("vault/planted.rs"),
        "use vole_kit::state::Core;\npub fn f(_: Core) {}\n",
    )
    .expect("a planted module");
    std::fs::write(dir.join("vault/clean.rs"), "use crate::state::VaultDb;\n").expect("clean");
    let found = scan_dir_names(&dir.join("vault"));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        found
            .iter()
            .any(|f| f.contains("planted.rs") && f.contains("vole_kit::state")),
        "{found:?}"
    );
    assert!(found.iter().any(|f| f.contains("`Core`")), "{found:?}");
    assert!(!found.iter().any(|f| f.contains("clean.rs")), "{found:?}");

    // Each way of getting round the list, one by one.
    let violations = [
        "use vole_kit::state::Core;",
        "use vole_kit::{crypto::seal, auth};",
        "use vole_kit::crypto;",
        "use crate::state::FerretState;",
        "use crate::state::*;",
        "use crate::state::{VaultDb, Other};",
        "use crate::state as s;",
        "use crate::{state, other};",
        "use crate as root;",
        "use crate::*;",
        "use crate::auth::secrets::Secrets;",
        "fn f() { let _ = vole_kit::crypto::seal(); }",
        "fn f() { let _ = crate::state::Other::new(); }",
        "fn f() { let _ = \"session.key\"; }",
        "fn f() { let _ = \"the session_key file\"; }",
        "fn f() { println!(\"{}\", crate::state::Other); }",
        "fn f() { println!(\"{}\", \"session.key\"); }",
        "fn f() { format!(\"{}\", vole_kit::crypto::x); }",
        "struct S { k: Key }",
        "fn f(_: SignedCookieJar) {}",
        "fn f(_: PrivateCookieJar) {}",
        "fn f(_: axum::extract::State<FerretState>) {}",
        "type T = aws_lc_rs::Foo;",
        "use crate::auth::secrets;",
        "fn f(_: ServerKeys, _: StateSealKey) {}",
        "#[some(Core)] fn f() {}",
        "this does not parse",
    ];
    for source in violations {
        assert!(
            !scan_names("planted.rs", source).is_empty(),
            "not detected: {source}"
        );
    }

    // What is allowed.
    let clean = [
        "use crate::state::VaultDb;",
        "use crate::{state::VaultDb, store::Store};",
        "use ferret_core::AccountId;",
        "fn f(db: crate::state::VaultDb) { let _ = crate::state::VaultDb::clone(&db); }",
        "/// Core, Key and session.key in the docs are prose.\nfn f() {}",
        "//! The module docs: crate::state::FerretState.\nfn f() {}",
        "fn f() { let _ = \"hello\"; println!(\"{}\", crate::state::VaultDb::new); }",
    ];
    for source in clean {
        let found = scan_names("clean.rs", source);
        assert!(found.is_empty(), "false alarm for {source}: {found:?}");
    }

    // The shape check has its own plants.
    for source in [
        "pub fn routes() -> Router<FerretState> { Router::new() }",
        "pub fn routes() -> Router { Router::new() }",
        "pub fn routes<S>() -> Router<()> { Router::new() }",
        "pub fn routes<S>() -> Router<S> { Router::new().with_state(1) }",
    ] {
        assert!(
            !scan_shapes("planted.rs", source).0.is_empty(),
            "not detected: {source}"
        );
    }
    let (found, checked) = scan_shapes(
        "clean.rs",
        "pub fn routes<S>() -> Router<S> where S: Clone { Router::new() }",
    );
    assert!(found.is_empty() && checked == 1, "{found:?}");
}
