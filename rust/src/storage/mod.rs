//! Object storage for quarantined attachments and held messages. Port of the Go
//! `internal/storage`: an async `Storage` trait, a filesystem backend, and an
//! at-rest AES-256-GCM encryption wrapper. (S3/MinIO lands with the object-store
//! client wiring.)

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use futures_util::stream::{self, Stream, StreamExt};

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

/// A streamed object body. An `Err` item aborts the stream (e.g. a truncated
/// or tampered encrypted object); consumers must not treat what came before
/// it as a complete object.
pub type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

/// Read size used by the streaming paths.
pub const STREAM_CHUNK: usize = 64 * 1024;

/// Object store. Writes take whole byte slices (attachments are bounded);
/// reads can be streamed with [`Storage::get_stream`] so large downloads are
/// not buffered in memory.
#[async_trait]
pub trait Storage: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    /// Streams an object. The default buffers [`Storage::get`]; backends
    /// override it to read incrementally. Lookup errors (not found, invalid
    /// key) are returned here, not as stream items.
    async fn get_stream(&self, key: &str) -> Result<ByteStream> {
        let data = self.get(key).await?;
        Ok(Box::pin(stream::once(async move { Ok(Bytes::from(data)) })))
    }
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
    async fn get_stream(&self, key: &str) -> Result<ByteStream> {
        let inner = self.inner.get_stream(key).await?;
        Ok(decrypt_stream(inner, self.enc.stream_decryptor()))
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

/// Decrypts a framed ciphertext stream frame by frame. Ends with an error
/// item when the input stops before the final frame or fails authentication.
fn decrypt_stream(inner: ByteStream, dec: encrypt::StreamDecryptor) -> ByteStream {
    let io_err = |e: encrypt::Error| std::io::Error::other(e.to_string());
    Box::pin(stream::unfold(
        Some((inner, dec)),
        move |state| async move {
            let (mut inner, mut dec) = state?;
            loop {
                match dec.next_frame() {
                    Err(e) => return Some((Err(io_err(e)), None)),
                    Ok(Some(pt)) => {
                        if dec.is_done() {
                            // Final frame: emit it and stop (trailing bytes ignored).
                            return Some((Ok(Bytes::from(pt)), None));
                        }
                        if pt.is_empty() {
                            continue;
                        }
                        return Some((Ok(Bytes::from(pt)), Some((inner, dec))));
                    }
                    Ok(None) => {}
                }
                match inner.next().await {
                    Some(Ok(b)) => dec.push(&b),
                    Some(Err(e)) => return Some((Err(e), None)),
                    None => {
                        let e = dec.finish().err().unwrap_or(encrypt::Error::Truncated);
                        return Some((Err(io_err(e)), None));
                    }
                }
            }
        },
    ))
}

/// Collects a stream (tests and small objects).
pub async fn collect_stream(mut s: ByteStream) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(c) = s.next().await {
        out.extend_from_slice(&c?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn streams_plain_and_encrypted_and_detects_truncation() {
        let dir = std::env::temp_dir().join(format!("secmail-encs-{}", uuid::Uuid::new_v4()));
        let fs: Arc<dyn Storage> = Arc::new(Fs::new(dir.to_str().unwrap()).await.unwrap());
        let enc = Encrypted::new(fs.clone(), &[7u8; 32]).unwrap();
        let plain: Vec<u8> = (0..(3 * STREAM_CHUNK + 123))
            .map(|i| (i % 253) as u8)
            .collect();
        enc.put("big", &plain).await.unwrap();
        fs.put("plain", &plain).await.unwrap();
        // Fs streams in bounded chunks.
        let mut s = fs.get_stream("plain").await.unwrap();
        let mut n = 0;
        let mut got = Vec::new();
        while let Some(c) = s.next().await {
            let c = c.unwrap();
            assert!(c.len() <= STREAM_CHUNK);
            got.extend_from_slice(&c);
            n += 1;
        }
        assert!(n >= 4);
        assert_eq!(got, plain);
        // Encrypted streams decrypt frame by frame.
        let s = enc.get_stream("big").await.unwrap();
        assert_eq!(collect_stream(s).await.unwrap(), plain);
        assert!(matches!(
            enc.get_stream("missing").await.err(),
            Some(StorageError::NotFound)
        ));
        // Truncate the ciphertext on disk: the stream yields data, then errors.
        let ct = fs.get("big").await.unwrap();
        fs.put("big", &ct[..ct.len() - 10]).await.unwrap();
        let s = enc.get_stream("big").await.unwrap();
        assert!(collect_stream(s).await.is_err(), "truncation must surface");
        // Drop the final frame entirely (cut on a frame boundary).
        let frame = 5 + STREAM_CHUNK + 16;
        fs.put("big", &ct[..8 + 3 * frame]).await.unwrap();
        let s = enc.get_stream("big").await.unwrap();
        assert!(collect_stream(s).await.is_err(), "missing final frame");
        std::fs::remove_dir_all(&dir).ok();
    }

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
