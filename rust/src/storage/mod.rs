//! Object storage for quarantined attachments and held messages. Port of the Go
//! `internal/storage`: an async `Storage` trait, a filesystem backend, and an
//! at-rest AES-256-GCM encryption wrapper. (S3/MinIO lands with the object-store
//! client wiring.)

use std::sync::Arc;

use async_trait::async_trait;

pub mod encrypt;
pub mod fs;

pub use encrypt::Encryptor;
pub use fs::Fs;

#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    NotFound,
    Invalid(String),
    Io(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "storage: not found"),
            StorageError::Invalid(k) => write!(f, "storage: invalid key {k:?}"),
            StorageError::Io(e) => write!(f, "storage: {e}"),
        }
    }
}
impl std::error::Error for StorageError {}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Object store. Attachments are bounded, so bodies are passed as byte slices
/// rather than streams.
#[async_trait]
pub trait Storage: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    /// Backend type ("fs"/"s3"), published in analysis jobs.
    fn kind(&self) -> &str;
    fn bucket(&self) -> &str;
    async fn ping(&self) -> Result<()>;
}

/// Wraps a [`Storage`] so object bodies are encrypted at rest with AES-256-GCM,
/// using the same framing as the Go `storage.Encrypted`.
pub struct Encrypted {
    inner: Arc<dyn Storage>,
    enc: Encryptor,
}

impl Encrypted {
    /// Wraps `inner`; `key` must be exactly 32 bytes.
    pub fn new(inner: Arc<dyn Storage>, key: &[u8]) -> Result<Self> {
        let enc = Encryptor::new(key).map_err(|e| StorageError::Invalid(e.to_string()))?;
        Ok(Encrypted { inner, enc })
    }
}

#[async_trait]
impl Storage for Encrypted {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        self.inner.put(key, &self.enc.encrypt(data)).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let ct = self.inner.get(key).await?;
        self.enc
            .decrypt(&ct)
            .map_err(|e| StorageError::Io(e.to_string()))
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    fn kind(&self) -> &str {
        self.inner.kind()
    }
    fn bucket(&self) -> &str {
        self.inner.bucket()
    }
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encrypted_wrapper_roundtrips_and_stores_ciphertext() {
        let dir = std::env::temp_dir().join(format!("secmail-enc-{}", uuid::Uuid::new_v4()));
        let fs: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        let enc = Encrypted::new(fs.clone(), &[7u8; 32]).unwrap();
        let plain = b"top secret attachment bytes".repeat(5);
        enc.put("a/b.bin", &plain).await.unwrap();
        // Through the wrapper: plaintext back.
        assert_eq!(enc.get("a/b.bin").await.unwrap(), plain);
        // Directly on disk via the inner FS: ciphertext, not plaintext.
        let raw = fs.get("a/b.bin").await.unwrap();
        assert_ne!(raw, plain);
        std::fs::remove_dir_all(&dir).ok();
    }
}
