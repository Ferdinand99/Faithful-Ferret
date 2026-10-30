//! Errors at the JavaScript boundary.
//!
//! An error is a JavaScript `Error` whose `message` and `code` are the same
//! stable code and nothing else: no value, no length and no position from the
//! input ever goes into it. The codes of the core are those of
//! `vectors/ERRORS.md` (`Error::code`). The glue adds three of its own, for
//! mistakes in how the binding is called:
//!
//! * `invalid_input`: an argument has the wrong type, a wrong length or a
//!   value out of range (a time that is not finite, a number above 2^53, an
//!   unknown key in an object, a missing pin state);
//! * `vault_locked`: the vault has been locked or has no such state;
//! * `invalid_handle`: an item handle that is not open.
//!
//! Nothing in this crate formats data into text.

use ferret_core::Error;
use wasm_bindgen::JsValue;

/// Why a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// An error of the core.
    Core(Error),
    /// The arguments are not what the binding accepts.
    Input,
    /// The vault is locked.
    Locked,
    /// No such open item.
    Handle,
}

impl Fail {
    /// The stable code.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Fail::Core(e) => e.code(),
            Fail::Input => "invalid_input",
            Fail::Locked => "vault_locked",
            Fail::Handle => "invalid_handle",
        }
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Fail::Core(e)
    }
}

/// The result type inside the binding.
pub(crate) type Res<T> = Result<T, Fail>;

impl From<Fail> for JsValue {
    fn from(f: Fail) -> JsValue {
        let code = f.code();
        let e = js_sys::Error::new(code);
        e.set_name("FerretError");
        // `Reflect::set` on a plain error object cannot fail; nothing to do
        // if it did, the message already holds the code.
        let _ = js_sys::Reflect::set(&e, &JsValue::from_str("code"), &JsValue::from_str(code));
        e.into()
    }
}

/// Runs a body that works on `Res` and turns its failure into the JavaScript
/// error. Every exported function goes through this, so a failure can only
/// ever be a code.
pub(crate) fn run<T>(body: impl FnOnce() -> Res<T>) -> Result<T, JsValue> {
    body().map_err(JsValue::from)
}
