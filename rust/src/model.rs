//! Domain types shared across the gateway. Port of the Go `internal/model`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Attachment / analysis status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    #[serde(rename = "PENDING")]
    Pending,
    #[serde(rename = "CLEAN")]
    Clean,
    #[serde(rename = "MALICIOUS")]
    Malicious,
    #[serde(rename = "ERROR")]
    Error,
    #[serde(rename = "EXPIRED")]
    Expired,
}

impl Status {
    /// Reports whether this is a terminal analyzer verdict.
    pub fn final_(self) -> bool {
        matches!(self, Status::Clean | Status::Malicious | Status::Error)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "PENDING",
            Status::Clean => "CLEAN",
            Status::Malicious => "MALICIOUS",
            Status::Error => "ERROR",
            Status::Expired => "EXPIRED",
        }
    }
}

/// Envelope/metadata record of a processed mail.
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub id: String,
    pub message_id: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub subject: String,
    pub remote_addr: String,
    pub received_at: Option<DateTime<Utc>>,
    pub attachment_count: i64,
}

/// An attachment removed from a message and held in quarantine.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub id: String,
    pub message_id: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub sha256: String,
    pub storage_key: String,
    pub token_hash: String,

    pub status: Status,
    pub threat_name: String,
    pub verdict_detail: Option<Json>,
    pub attempts: i32,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub queued_at: DateTime<Utc>,
    pub analyzed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub download_count: i32,
    pub last_downloaded_at: Option<DateTime<Utc>>,
}

/// Audit record of a completed download.
#[derive(Clone, Debug)]
pub struct DownloadEvent {
    pub attachment_id: String,
    pub user: String,
    pub remote_ip: String,
    pub user_agent: String,
    pub at: DateTime<Utc>,
}

/// What the external analyzer reports back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verdict {
    pub attachment_id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub threat_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Json>,
}

/// Unit of work published to the analysis queue (analyzer contract).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub version: i32,
    pub attachment_id: String,
    pub message_id: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub sha256: String,
    pub storage: JobObject,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verdict_url: String,
    pub attempt: i32,
    pub enqueued_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobObject {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bucket: String,
    pub key: String,
}

/// Outbound DLP hold status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldStatus {
    #[serde(rename = "HELD")]
    Held,
    #[serde(rename = "RELEASED")]
    Released,
    #[serde(rename = "REJECTED")]
    Rejected,
    #[serde(rename = "EXPIRED")]
    Expired,
}

impl HoldStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HoldStatus::Held => "HELD",
            HoldStatus::Released => "RELEASED",
            HoldStatus::Rejected => "REJECTED",
            HoldStatus::Expired => "EXPIRED",
        }
    }
}

/// An outgoing message withheld by DLP policy pending review.
#[derive(Clone, Debug)]
pub struct Hold {
    pub id: String,
    pub token_hash: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub subject: String,
    pub storage_key: String,
    pub size: i64,
    pub findings: Option<Json>,
    pub status: HoldStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: String,
    pub reason: String,
}

/// Audit record of an outbound message with findings.
#[derive(Clone, Debug)]
pub struct DlpEvent {
    pub id: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub subject: String,
    pub action: String,
    pub severity: String,
    pub findings: Option<Json>,
    pub hold_id: String,
    pub at: DateTime<Utc>,
}

/// Append-only audit record of a privileged admin action.
#[derive(Clone, Debug)]
pub struct AdminAction {
    pub id: String,
    pub at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub source: String,
    pub result: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_serde_and_final() {
        assert_eq!(
            serde_json::to_string(&Status::Malicious).unwrap(),
            "\"MALICIOUS\""
        );
        let s: Status = serde_json::from_str("\"CLEAN\"").unwrap();
        assert_eq!(s, Status::Clean);
        assert!(Status::Clean.final_());
        assert!(!Status::Pending.final_());
    }

    #[test]
    fn verdict_roundtrip() {
        let v = Verdict {
            attachment_id: "a1".into(),
            status: Status::Clean,
            threat_name: String::new(),
            detail: None,
        };
        let j = serde_json::to_string(&v).unwrap();
        // omitempty-equivalent: threat_name/detail skipped when empty.
        assert!(!j.contains("threat_name"));
        assert!(!j.contains("detail"));
        let back: Verdict = serde_json::from_str(&j).unwrap();
        assert_eq!(back.attachment_id, "a1");
    }
}
