//! The inbound message processor wired into the SMTP proxy: attachment
//! quarantine (replacing attachments with download links) followed by optional
//! ARC sealing of the relayed message.

use std::sync::Arc;

use async_trait::async_trait;

use crate::arc::Sealer;
use crate::gateway::{Envelope, MessageProcessor, ProcessError};
use crate::service::Service;

/// Inbound processor: quarantine (when configured) then optional ARC seal.
pub struct InboundProcessor {
    service: Option<Arc<Service>>,
    arc: Option<Arc<Sealer>>,
}

impl InboundProcessor {
    pub fn new(service: Option<Arc<Service>>, arc: Option<Arc<Sealer>>) -> Self {
        InboundProcessor { service, arc }
    }
}

#[async_trait]
impl MessageProcessor for InboundProcessor {
    async fn process(&self, env: &Envelope, raw: &[u8]) -> Result<Vec<u8>, ProcessError> {
        let quarantined = match &self.service {
            Some(s) => s.quarantine(env, raw).await?,
            None => raw.to_vec(),
        };
        if let Some(sealer) = &self.arc {
            // The auth stage (SPF/DKIM/DMARC) will supply real results; seal with
            // "none" until then. Sealing is advisory, so a failure is non-fatal.
            if let Ok(out) = sealer.seal(&quarantined, "none") {
                return Ok(out);
            }
        }
        Ok(quarantined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passthrough_without_service_or_arc() {
        let p = InboundProcessor::new(None, None);
        let out = p.process(&Envelope::default(), b"hi").await.unwrap();
        assert_eq!(out, b"hi");
    }
}
