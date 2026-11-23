//! ARC (Authenticated Received Chain, RFC 8617) sealing for the gateway.
//!
//! Port in progress: the relaxed canonicalization (shared with DKIM, RFC 6376)
//! is complete. The signing side (ARC-Message-Signature / ARC-Seal) is added in
//! a later step together with the RSA key handling.

pub mod canon;
pub mod seal;

pub use canon::{relaxed_body, relaxed_header};
pub use seal::Sealer;
