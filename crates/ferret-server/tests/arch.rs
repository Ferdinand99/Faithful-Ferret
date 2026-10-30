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
//!
//! The vault modules also may not reach code that this scan cannot see:
//! `#[path]`, `include!`, `include_str!`, `include_bytes!`, `extern crate`, glob
//! imports from `vole_kit`, `crate`, `crate::auth` and `crate::http`, and
//! relative paths that climb (`super::super::state`) are all refused.
//! `SessionAuth` is the handle that holds the cookie key. Its name may appear
//! in one place only: the bound `SessionAuth: FromRef<S>` that a route needs to
//! take a `VaultSession` (and in the `use` that names it). Taking it as state
//! or calling anything on it is refused, as is every item of
//! `crate::http::extract` other than `VaultSession`.
//!
//! What a syntactic deny-list cannot see, and this one does not claim to:
//! strings built at compile time (`concat!`), macros defined outside `vault/`,
//! type aliases defined outside `vault/`, and a type that wraps bytes in a
//! foreign type or a `String`.

use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{GenericArgument, PathArguments, ReturnType, Type, UseTree, WherePredicate};

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
    "SessionAuth",
];

/// Macros that pull in a file the scan does not read.
const INCLUDE_MACROS: &[&str] = &["include", "include_str", "include_bytes"];

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

    /// A path of an expression, a type or a pattern, as segments:
    /// `crate::state::VaultDb` is `["crate", "state", "VaultDb"]`. A path that
    /// starts with `super` is checked as if it started at the crate root, since
    /// it may climb out of `vault/`.
    fn check_path(&mut self, segments: &[String]) {
        let supers = segments.iter().take_while(|s| *s == "super").count();
        if supers > 0 {
            let mut rooted = vec!["crate".to_string()];
            rooted.extend_from_slice(&segments[supers..]);
            self.check_rooted(&rooted, &segments.join("::"));
        } else {
            self.check_rooted(segments, &segments.join("::"));
        }
    }

    fn check_rooted(&mut self, segments: &[String], joined: &str) {
        let at = |i: usize| segments.get(i).map(String::as_str);
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
            (Some("crate"), Some("http"))
                if at(2) == Some("extract") && at(3) != Some("VaultSession") =>
            {
                self.hit(format!(
                    "names `{joined}` (only `crate::http::extract::VaultSession` is allowed)"
                ));
            }
            _ => {}
        }
    }

    /// A path of a `use`. `alias` is the name after `as`.
    fn check_use_path(&mut self, segments: &[String], alias: Option<&str>) {
        let joined = segments.join("::");
        let last = segments.last().map(String::as_str);
        let is_glob = last == Some("*");
        let root = segments.first().map(String::as_str);
        let second = segments.get(1).map(String::as_str);
        let is_root_alone = matches!(root, Some("crate" | "vole_kit")) && segments.len() == 1;
        if let Some(alias) = alias {
            if FORBIDDEN_IDENTS.contains(&alias) {
                self.hit(format!("names `{alias}` (as an alias)"));
            }
            if is_root_alone {
                self.hit(format!(
                    "`use {joined} as {alias}` gives the root a name of its own"
                ));
            }
            if last == Some("SessionAuth") {
                self.hit("renames `SessionAuth`".to_string());
            }
        } else if is_root_alone {
            self.hit(format!("`use {joined}` gives the root a name of its own"));
        }
        if is_glob
            && (root == Some("vole_kit")
                || (root == Some("crate")
                    && (segments.len() == 2 || matches!(second, Some("auth" | "http")))))
        {
            self.hit(format!("glob import `{joined}`"));
        }
        self.check_path(segments);
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
            "super::auth::secrets",
            "super::http::extract",
        ] {
            if compact.contains(path) {
                self.hit(format!("names `{path}` (in a macro or attribute)"));
            }
        }
        for (path, allowed) in [
            ("crate::state", "::VaultDb"),
            ("crate::http::extract", "::VaultSession"),
        ] {
            let mut rest = compact.as_str();
            while let Some(at) = rest.find(path) {
                rest = &rest[at + path.len()..];
                if !rest.starts_with(allowed) {
                    self.hit(format!(
                        "names `{path}` other than `{}` (in a macro)",
                        allowed.trim_start_matches(':')
                    ));
                }
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

/// A `use` path with the name after `as`, if there is one.
struct UsePath {
    segments: Vec<String>,
    alias: Option<String>,
}

fn flatten(tree: &UseTree, prefix: &mut Vec<String>, out: &mut Vec<UsePath>) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten(&p.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(n) => {
            let mut segments = prefix.clone();
            if n.ident != "self" {
                segments.push(n.ident.to_string());
            }
            out.push(UsePath {
                segments,
                alias: None,
            });
        }
        UseTree::Rename(r) => {
            let mut segments = prefix.clone();
            if r.ident != "self" {
                segments.push(r.ident.to_string());
            }
            out.push(UsePath {
                segments,
                alias: Some(r.rename.to_string()),
            });
        }
        UseTree::Glob(_) => {
            let mut segments = prefix.clone();
            segments.push("*".to_string());
            out.push(UsePath {
                segments,
                alias: None,
            });
        }
        UseTree::Group(g) => {
            for item in &g.items {
                flatten(item, prefix, out);
            }
        }
    }
}

/// The one `use` of the cookie-key handle that is allowed: it names the type
/// that the `FromRef` bound of a route needs.
fn is_session_auth_import(path: &UsePath) -> bool {
    path.alias.is_none() && path.segments == ["crate", "http", "extract", "SessionAuth"]
}

/// `SessionAuth: FromRef<..>` (and nothing else about `SessionAuth`).
fn is_session_auth_from_ref(predicate: &WherePredicate) -> bool {
    let WherePredicate::Type(predicate) = predicate else {
        return false;
    };
    let Type::Path(bounded) = &predicate.bounded_ty else {
        return false;
    };
    let names: Vec<String> = bounded
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let session_auth =
        names == ["SessionAuth"] || names == ["crate", "http", "extract", "SessionAuth"];
    session_auth
        && bounded.qself.is_none()
        && !predicate.bounds.is_empty()
        && predicate.bounds.iter().all(|bound| {
            matches!(bound, syn::TypeParamBound::Trait(t)
                if t.path.segments.last().is_some_and(|s| s.ident == "FromRef"))
        })
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

    fn visit_where_predicate(&mut self, predicate: &'ast WherePredicate) {
        if is_session_auth_from_ref(predicate)
            && let WherePredicate::Type(predicate) = predicate
        {
            // The bound is how a route says it can take a `VaultSession`; only
            // the trait it asks for is looked at.
            for bound in &predicate.bounds {
                self.visit_type_param_bound(bound);
            }
            return;
        }
        visit::visit_where_predicate(self, predicate);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        flatten(&item.tree, &mut Vec::new(), &mut paths);
        for path in &paths {
            if is_session_auth_import(path) {
                continue;
            }
            for segment in &path.segments {
                if FORBIDDEN_IDENTS.contains(&segment.as_str()) {
                    self.hit(format!("names `{segment}`"));
                }
            }
            self.check_use_path(&path.segments, path.alias.as_deref());
        }
        // The idents of the tree were looked at above.
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        self.hit(format!("`extern crate {}` is not allowed", item.ident));
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
        if let Some(last) = mac.path.segments.last()
            && INCLUDE_MACROS.contains(&last.ident.to_string().as_str())
        {
            self.hit(format!(
                "`{}!` pulls in a file the scan does not read",
                last.ident
            ));
        }
        self.check_text(&mac.tokens.to_string());
        visit::visit_macro(self, mac);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if attr.path().is_ident("path") {
            self.hit("`#[path]` pulls in a file the scan does not read".to_string());
        }
        // Doc comments are prose; a doc attribute that is not a string (an
        // `include_str!`) is looked at like any other expression.
        let is_prose = attr.path().is_ident("doc")
            && matches!(
                &attr.meta,
                syn::Meta::NameValue(nv) if matches!(nv.value, syn::Expr::Lit(_))
            );
        if is_prose {
            return;
        }
        if let syn::Meta::List(list) = &attr.meta {
            let text = list.tokens.to_string();
            let has_path = text
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|word| word == "path");
            if attr.path().is_ident("cfg_attr") && has_path {
                self.hit(
                    "`#[cfg_attr(.., path = ..)]` pulls in a file the scan does not read"
                        .to_string(),
                );
            }
            self.check_text(&text);
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
        } else if attr.path().is_ident("cfg_attr")
            && let syn::Meta::List(list) = &attr.meta
        {
            // `#[cfg_attr(feature, derive(.., Debug))]`
            let text = list.tokens.to_string();
            let words: Vec<&str> = text
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .collect();
            if words.contains(&"derive") && words.contains(&"Debug") {
                debug = true;
            }
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
        // The cookie-key handle.
        "fn f(_: axum::extract::State<SessionAuth>) {}",
        "fn f(_: axum::extract::State<crate::http::extract::SessionAuth>) {}",
        "fn f<S>(s: &S) { let _ = crate::http::extract::SessionAuth::from_ref(s); }",
        "use crate::http::extract::SessionAuth as Handle;",
        "use crate::http::extract::{SessionAuth as Handle};",
        "fn f<S>() where crate::http::extract::SessionAuth: Clone {}",
        "fn f<S>() where SessionAuth: FromRef<S> + Clone {}",
        "use crate::http::extract::AdminSession;",
        "use crate::http::extract::*;",
        "use crate::http::extract::{self};",
        "use crate::http::*;",
        "fn f() { let _ = crate::http::extract::AdminSession; }",
        "fn f() { format!(\"{}\", crate::http::extract::SessionAuth); }",
        // Ways to reach code the scan does not read.
        "#[path = \"../x.rs\"] mod x;",
        "#[cfg_attr(test, path = \"../x.rs\")] mod x;",
        "include!(\"../x.rs\");",
        "fn f() { let _ = include_str!(\"../a.txt\"); }",
        "fn f() { let _ = include_bytes!(\"../a.bin\"); }",
        "#[doc = include_str!(\"../README.md\")] fn f() {}",
        "extern crate vole_kit as vk;",
        "extern crate vole_kit;",
        "use vole_kit::*;",
        "use vole_kit::{auth::*, other};",
        "use crate::auth::*;",
        "use crate::auth::session::*;",
        "use super::super::state::Other;",
        "use super::state::Other;",
        "fn f() { let _ = super::super::state::Other; }",
        "fn f() { let _ = super::super::super::auth::secrets::Other; }",
        "fn f() { let _ = super::super::http::extract::AdminSession; }",
        "use crate::state::VaultDb as Core;",
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
        // The one place `SessionAuth` may appear: the bound a route needs to
        // take a `VaultSession`.
        "use crate::http::extract::{SessionAuth, VaultSession};\npub fn routes<S>() -> Router<S> where S: Clone + Send + Sync + 'static, SessionAuth: FromRef<S> { Router::new() }",
        "pub fn routes<S>() -> Router<S> where S: Clone, crate::http::extract::SessionAuth: FromRef<S> { Router::new() }",
        "use crate::http::extract::VaultSession;",
        "use super::*;",
        "use super::{Store, quota::Limits};",
        "#[cfg(test)] mod tests { use super::*; }",
        "#[derive(Clone)] struct S;\n#[allow(clippy::too_many_arguments)] fn f() {}",
        "fn f() { let _ = super::helper(); }",
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
