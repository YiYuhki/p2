//! Filesystem object store. Port of the Go `storage.FS`: atomic writes via a
//! temp file + rename, and path-traversal-safe keys.

use async_trait::async_trait;

use super::{Result, Storage, StorageError};

/// Filesystem-backed object store rooted at `dir`.
pub struct Fs {
    dir: std::path::PathBuf,
}

impl Fs {
    /// Creates the root directory if needed.
    pub async fn new(dir: &str) -> Result<Self> {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(Fs { dir: dir.into() })
    }

    /// Resolves a key to a path under `dir`, rejecting traversal.
    fn path(&self, key: &str) -> Result<std::path::PathBuf> {
        if key.contains("..") || key.is_empty() || key == "/" {
            return Err(StorageError::Invalid(key.to_string()));
        }
        // Reject absolute keys and normalize separators.
        let clean = key.trim_start_matches('/');
        if clean.is_empty() {
            return Err(StorageError::Invalid(key.to_string()));
        }
        Ok(self.dir.join(clean))
    }
}

#[async_trait]
impl Storage for Fs {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let p = self.path(key)?;
        if let Some(parent) = p.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }
        // Atomic write: temp file + rename.
        let tmp = p.with_extension(format!("upload-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&tmp, data)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))?;
        tokio::fs::rename(&tmp, &p).await.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            StorageError::Io(e.to_string())
        })?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let p = self.path(key)?;
        match tokio::fs::read(&p).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound),
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let p = self.path(key)?;
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    fn kind(&self) -> &str {
        "fs"
    }

    fn bucket(&self) -> &str {
        ""
    }

    async fn ping(&self) -> Result<()> {
        tokio::fs::metadata(&self.dir)
            .await
            .map(|_| ())
            .map_err(|e| StorageError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_delete_and_traversal() {
        let dir = std::env::temp_dir().join(format!("secmail-fs-{}", uuid::Uuid::new_v4()));
        let fs = Fs::new(dir.to_str().unwrap()).await.unwrap();
        fs.put("msg/1/att.bin", b"hello").await.unwrap();
        assert_eq!(fs.get("msg/1/att.bin").await.unwrap(), b"hello");
        assert_eq!(fs.get("nope").await, Err(StorageError::NotFound));
        fs.delete("msg/1/att.bin").await.unwrap();
        assert_eq!(fs.get("msg/1/att.bin").await, Err(StorageError::NotFound));
        fs.delete("already-gone").await.unwrap(); // idempotent
        assert!(matches!(
            fs.put("../escape", b"x").await,
            Err(StorageError::Invalid(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
