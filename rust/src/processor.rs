//! The inbound message processor wired into the SMTP proxy. This is the port's
//! current inbound pipeline: optional ARC sealing of the relayed message. The
//! attachment-quarantine and banner-insertion stages land with the mimeproc
//! port; the hook points are already here.

use std::sync::Arc;

use async_trait::async_trait;

use crate::arc::Sealer;
use crate::gateway::{Envelope, MessageProcessor, ProcessError};

/// Inbound processor. For now it relays unchanged, optionally ARC-sealing.
pub struct InboundProcessor {
    arc: Option<Arc<Sealer>>,
}

impl InboundProcessor {
    pub fn new(arc: Option<Arc<Sealer>>) -> Self {
        InboundProcessor { arc }
    }
}

#[async_trait]
impl MessageProcessor for InboundProcessor {
    async fn process(&self, _env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        if let Some(sealer) = &self.arc {
            // Authentication results will be supplied by the auth stage once the
            // SPF/DKIM/DMARC verifiers land; seal with "none" until then.
            match sealer.seal(raw, "none") {
                Ok(out) => return Ok(out),
                Err(_) => return Ok(raw.to_vec()), // sealing is advisory
            }
        }
        Ok(raw.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passthrough_without_arc() {
        let p = InboundProcessor::new(None);
        let out = p.process(&Envelope::default(), b"hi").await.unwrap();
        assert_eq!(out, b"hi");
    }
}
