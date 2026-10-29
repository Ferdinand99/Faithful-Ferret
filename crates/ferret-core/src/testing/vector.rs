//! Test-vector files (`ferret-vectors/1`), their loader and a table-driven
//! runner. The JSON Schema is `vectors/schema/vector-file.schema.json`; the
//! types here mirror it, and `validate` enforces what the schema states.

use super::{ReplayRng, hex_decode};
use crate::error::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

/// The `format` value of every vector file.
pub const FORMAT: &str = "ferret-vectors/1";

/// One vector file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorFile {
    /// Always [`FORMAT`].
    pub format: String,
    /// Group name; the file is `<group>.json` and case ids start with it.
    pub group: String,
    /// Suite number the vectors belong to.
    pub suite: u32,
    /// Where the specification defines the operations.
    pub spec: String,
    /// Which tool made the file.
    pub generator: Generator,
    /// The cases.
    pub cases: Vec<Case>,
}

/// Provenance of a generated file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generator {
    /// Tool name, `ferret-vectorgen`.
    pub tool: String,
    /// Core version.
    pub core: String,
    /// Commit of the generator.
    pub commit: String,
    /// Unicode version used.
    pub unicode: String,
    /// RNG used to make the draws, `hmac-sha256-ctr(seed)`.
    pub rng: String,
}

/// Expected outcome of a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The operation succeeds and returns `expect`.
    Valid,
    /// The operation fails with `expect_error`.
    Invalid,
}

/// Case tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tag {
    /// Argon2id at profile 1 or higher: run once per browser.
    #[serde(rename = "slow")]
    Slow,
    /// Not run by bindings; needs `skip_reason`.
    #[serde(rename = "native-only")]
    NativeOnly,
    /// From a third party.
    #[serde(rename = "external")]
    External,
}

/// One test case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Unique id, `<group>/<name>/<number>`.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Operation name from `vectors/OPS.md`.
    pub op: String,
    /// Expected outcome.
    pub status: Status,
    /// Tags.
    pub tags: Vec<Tag>,
    /// Always `true`: no real secrets in vectors.
    pub synthetic: bool,
    /// Why a `native-only` case is skipped by bindings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// The draws the core makes, in order (lowercase hex).
    pub rng: Vec<String>,
    /// Operation input; its shape is defined per `op`.
    pub input: Value,
    /// Intermediate results; checked only where the API reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate: Option<Value>,
    /// Expected output of a `valid` case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Value>,
    /// Expected error code of an `invalid` case, `null` otherwise.
    pub expect_error: Option<String>,
}

/// Why a file could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// Reading the file failed.
    Io(String),
    /// Not valid JSON for the vector format.
    Json(String),
    /// Valid JSON that breaks the format's rules.
    Invalid(Vec<String>),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "cannot read vector file: {e}"),
            LoadError::Json(e) => write!(f, "cannot parse vector file: {e}"),
            LoadError::Invalid(problems) => {
                write!(f, "vector file breaks the format: {}", problems.join("; "))
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Reads, parses and validates one vector file.
pub fn load(path: &Path) -> Result<VectorFile, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|e| LoadError::Io(e.to_string()))?;
    load_str(&text)
}

/// Parses and validates a vector file from text.
pub fn load_str(text: &str) -> Result<VectorFile, LoadError> {
    let file: VectorFile =
        serde_json::from_str(text).map_err(|e| LoadError::Json(e.to_string()))?;
    file.validate().map_err(LoadError::Invalid)?;
    Ok(file)
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
}

impl VectorFile {
    /// Checks the rules of `vector-file.schema.json`. Returns every problem.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        if self.format != FORMAT {
            problems.push(format!("format must be {FORMAT}"));
        }
        if self.group.is_empty() || !self.group.chars().all(is_name_char) {
            problems.push("group must be lowercase name characters".into());
        }
        if self.suite == 0 {
            problems.push("suite must be at least 1".into());
        }
        if self.cases.is_empty() {
            problems.push("cases must not be empty".into());
        }
        let mut seen = BTreeSet::new();
        for case in &self.cases {
            case.validate(&self.group, &mut problems);
            if !seen.insert(case.id.as_str()) {
                problems.push(format!("duplicate case id {}", case.id));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

impl Case {
    fn validate(&self, group: &str, problems: &mut Vec<String>) {
        let id = &self.id;
        let segments: Vec<&str> = id.split('/').collect();
        if segments.len() < 2
            || segments.first() != Some(&group)
            || segments
                .iter()
                .any(|s| s.is_empty() || !s.chars().all(is_name_char))
        {
            problems.push(format!(
                "{id}: id must be <group>/<name>/... in name characters"
            ));
        }
        if self.title.is_empty() || self.op.is_empty() {
            problems.push(format!("{id}: title and op must not be empty"));
        }
        if !self.synthetic {
            problems.push(format!("{id}: synthetic must be true"));
        }
        for (i, draw) in self.rng.iter().enumerate() {
            if hex_decode(draw).is_err() {
                problems.push(format!("{id}: rng[{i}] is not lowercase hex"));
            }
        }
        match (self.status, &self.expect, &self.expect_error) {
            (Status::Valid, Some(_), None) => {}
            (Status::Valid, _, _) => {
                problems.push(format!("{id}: valid needs expect and expect_error null"));
            }
            (Status::Invalid, None, Some(code))
                if !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') => {}
            (Status::Invalid, _, _) => {
                problems.push(format!("{id}: invalid needs expect_error and no expect"));
            }
        }
        if self.tags.contains(&Tag::NativeOnly)
            && self.skip_reason.as_deref().is_none_or(str::is_empty)
        {
            problems.push(format!("{id}: native-only needs skip_reason"));
        }
    }
}

/// What a handler returns for a successful operation.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The operation's output, in the shape of `expect`.
    pub output: Value,
    /// Intermediate results, where the API reports them.
    pub intermediate: Option<Value>,
}

/// A case that did not behave as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The case id.
    pub id: String,
    /// What differed (never contains key material from the case).
    pub reason: String,
}

/// Result of [`run_all`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunReport {
    /// Cases that matched.
    pub passed: usize,
    /// Cases that did not.
    pub failures: Vec<Failure>,
}

/// Runs every case of `file` through `handler`.
///
/// For each case the handler gets a [`ReplayRng`] loaded with the case's
/// `rng` draws. A case passes when
/// * `valid`: the handler returns `Ok` with output equal to `expect` (and
///   intermediate equal to the recorded one when both exist);
/// * `invalid`: the handler returns `Err` whose code equals `expect_error`;
///
/// and in both cases every recorded draw was consumed, with no panic. A
/// panic in the handler, including a draw of the wrong length, is a failed
/// case, not a crash of the runner.
pub fn run_all<F>(file: &VectorFile, mut handler: F) -> RunReport
where
    F: FnMut(&Case, &mut ReplayRng) -> Result<Outcome, Error>,
{
    let mut report = RunReport::default();
    for case in &file.cases {
        match run_case(case, &mut handler) {
            Ok(()) => report.passed += 1,
            Err(reason) => report.failures.push(Failure {
                id: case.id.clone(),
                reason,
            }),
        }
    }
    report
}

fn run_case<F>(case: &Case, handler: &mut F) -> Result<(), String>
where
    F: FnMut(&Case, &mut ReplayRng) -> Result<Outcome, Error>,
{
    let draws = case
        .rng
        .iter()
        .map(|d| hex_decode(d).map_err(|_| "rng draw is not hex".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut rng = ReplayRng::new(draws);
    let result = catch_unwind(AssertUnwindSafe(|| handler(case, &mut rng)))
        .map_err(|_| "handler panicked (for example a draw of the wrong length)".to_string())?;
    match (case.status, result) {
        (Status::Valid, Ok(outcome)) => {
            if case.expect.as_ref() != Some(&outcome.output) {
                // The path of the first difference, never the values.
                let at = case
                    .expect
                    .as_ref()
                    .map_or_else(String::new, |want| first_difference(want, &outcome.output));
                return Err(format!("output differs from expect at {at}"));
            }
            if let (Some(want), Some(got)) = (&case.intermediate, &outcome.intermediate)
                && want != got
            {
                return Err("intermediate differs".into());
            }
        }
        (Status::Valid, Err(e)) => {
            return Err(format!("expected success, got error {}", e.code()));
        }
        (Status::Invalid, Ok(_)) => return Err("expected an error, got success".into()),
        (Status::Invalid, Err(e)) => {
            if case.expect_error.as_deref() != Some(e.code()) {
                return Err(format!(
                    "expected error {}, got {}",
                    case.expect_error.as_deref().unwrap_or("none"),
                    e.code()
                ));
            }
        }
    }
    rng.finish()
        .map_err(|e| format!("recorded draws not all consumed: {e:?}"))
}

/// The JSON pointers of the places where two values differ (at most eight),
/// never the values.
fn first_difference(want: &Value, got: &Value) -> String {
    let mut found = Vec::new();
    differences(want, got, String::new(), &mut found);
    found.truncate(8);
    found.join(", ")
}

fn differences(want: &Value, got: &Value, path: String, found: &mut Vec<String>) {
    match (want, got) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in a {
                match b.get(k) {
                    Some(w) => differences(v, w, format!("{path}/{k}"), found),
                    None => found.push(format!("{path}/{k} (missing)")),
                }
            }
            for k in b.keys().filter(|k| !a.contains_key(*k)) {
                found.push(format!("{path}/{k} (unexpected)"));
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for (i, (v, w)) in a.iter().zip(b).enumerate() {
                differences(v, w, format!("{path}/{i}"), found);
            }
            if a.len() != b.len() {
                found.push(format!("{path} (length {} against {})", a.len(), b.len()));
            }
        }
        _ if want != got => found.push(path),
        _ => {}
    }
}
