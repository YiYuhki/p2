//! Data Loss Prevention: finds personal data and credentials in outgoing mail
//! bodies and attachments. Port of the Go `internal/dlp` text-detection core.
//!
//! The file-extraction side (OCR, archive/convert, PDF image decoding) is the
//! analysis project's territory and lands with the mimeproc port; this module
//! is the detectors + text scanner + report.

pub mod detectors;
pub mod scan;

pub use detectors::{Detector, Severity};
pub use scan::{test_rule, Finding, Options, Report, Rule, Scanner};
