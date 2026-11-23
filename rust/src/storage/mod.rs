//! Object storage: the quarantine/hold object store and its at-rest encryption
//! wrapper. Port of the Go `internal/storage`.
//!
//! The backends (filesystem, S3/MinIO) land with the async I/O layer; the
//! self-contained AES-256-GCM encryption framing is ported here first.

pub mod encrypt;

pub use encrypt::Encryptor;
