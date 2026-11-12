//! Checks of request content that more than one route needs.

use ferret_core::Error as CoreError;
use ferret_core::envelope::{KIND_ITEM, parse_envelope};

use crate::error::ApiError;

/// An envelope of an item, in a version and suite this server stores. The
/// structure is checked without any key; whether it opens is for the client.
pub fn check_envelope(blob: &[u8]) -> Result<(), ApiError> {
    match parse_envelope(blob) {
        Ok(view) if view.kind == KIND_ITEM && view.ik_wrap.is_some() => Ok(()),
        Err(CoreError::TooLarge) => Err(ApiError::coded("too_large")),
        // A version, suite or kind that is not an item, or a structure that is
        // no envelope: one answer, so the server tells nothing about which.
        _ => Err(ApiError::coded("unsupported_envelope")),
    }
}
