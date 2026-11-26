//! ARC (Authenticated Received Chain, RFC 8617) sealing for the gateway.
//!
//! Sealing (first ARC set, i=1) uses the byte-level DKIM relaxed
//! canonicalization; the string helpers in `canon` remain for callers that
//! already hold decoded text.

pub mod canon;
pub mod seal;

pub use canon::{relaxed_body, relaxed_header};
pub use seal::Sealer;
