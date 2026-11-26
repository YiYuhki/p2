//! ARC (Authenticated Received Chain, RFC 8617) sealing for the gateway.
//!
//! [`validate`] checks an existing chain (RFC 8617 §5.2) with the DKIM key
//! lookup and canonicalization; [`Sealer`] then adds set i=n+1 asserting the
//! resulting cv. Both use the byte-level DKIM relaxed canonicalization; the
//! string helpers in `canon` remain for callers that already hold decoded
//! text.

pub mod canon;
pub mod seal;
pub mod validate;

pub use canon::{relaxed_body, relaxed_header};
pub use seal::Sealer;
pub use validate::{ChainStatus, Cv};
