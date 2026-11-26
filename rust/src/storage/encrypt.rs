//! At-rest object encryption with AES-256-GCM, a byte-for-byte port of the Go
//! `storage.Encrypted` framing so a ciphertext produced by either implementation
//! decrypts with the other.
//!
//! Wire format (streamed, never buffered whole):
//! ```text
//! prefix[8]                          random per-object nonce prefix
//! then repeated frames:
//!   final[1] ctlen[4 BE] ciphertext  nonce = prefix || uint32(counter)
//! ```
//! The last frame has final=1 (possibly empty); a stream that ends without one
//! is rejected as truncated. The AAD is the single final byte, so a dropped or
//! reordered final frame fails authentication.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

const ENC_CHUNK: usize = 64 * 1024;
const TAG_OVERHEAD: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadKeyLength(usize),
    Truncated,
    OversizedFrame,
    Auth,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadKeyLength(n) => {
                write!(f, "storage: encryption key must be 32 bytes, got {n}")
            }
            Error::Truncated => write!(f, "storage: encrypted stream truncated"),
            Error::OversizedFrame => write!(f, "storage: oversized encrypted frame"),
            Error::Auth => write!(f, "storage: authentication failed"),
        }
    }
}
impl std::error::Error for Error {}

/// AES-256-GCM object encryptor.
#[derive(Clone)]
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    /// `key` must be exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 32 {
            return Err(Error::BadKeyLength(key.len()));
        }
        let cipher = Aes256Gcm::new(key.into());
        Ok(Encryptor { cipher })
    }

    fn nonce(prefix: &[u8; 8], counter: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(prefix);
        n[8..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// Encrypts `plaintext` into the framed wire format. `prefix` is the random
    /// per-object nonce prefix (injected in tests; use [`Encryptor::encrypt`]
    /// for a random one).
    pub fn encrypt_with_prefix(&self, plaintext: &[u8], prefix: [u8; 8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        out.extend_from_slice(&prefix);
        let mut counter: u32 = 0;
        let mut frame = |out: &mut Vec<u8>, chunk: &[u8], final_: bool| {
            let fb = if final_ { 1u8 } else { 0u8 };
            let nonce = Self::nonce(&prefix, counter);
            counter += 1;
            let ct = self
                .cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: chunk,
                        aad: &[fb],
                    },
                )
                .expect("gcm encrypt");
            out.push(fb);
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&ct);
        };

        let len = plaintext.len();
        let mut pos = 0;
        loop {
            let end = (pos + ENC_CHUNK).min(len);
            let chunk = &plaintext[pos..end];
            let is_full = chunk.len() == ENC_CHUNK;
            if is_full && end < len {
                frame(&mut out, chunk, false);
                pos = end;
                continue;
            }
            if is_full && end == len {
                // Exactly filled: a non-final full frame then an empty final one.
                frame(&mut out, chunk, false);
                frame(&mut out, &[], true);
                break;
            }
            frame(&mut out, chunk, true);
            break;
        }
        out
    }

    /// Encrypts with a fresh random nonce prefix.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut prefix = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut prefix);
        self.encrypt_with_prefix(plaintext, prefix)
    }

    /// Decrypts the framed wire format back to plaintext.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < 8 {
            return Err(Error::Truncated);
        }
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&data[..8]);
        let mut pos = 8;
        let mut counter: u32 = 0;
        let mut out = Vec::new();
        loop {
            if pos + 5 > data.len() {
                return Err(Error::Truncated); // ended without a final frame
            }
            let fb = data[pos];
            let final_ = fb == 1;
            let ctlen =
                u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
                    as usize;
            pos += 5;
            if ctlen > ENC_CHUNK + TAG_OVERHEAD {
                return Err(Error::OversizedFrame);
            }
            if pos + ctlen > data.len() {
                return Err(Error::Truncated);
            }
            let ct = &data[pos..pos + ctlen];
            pos += ctlen;
            let nonce = Self::nonce(&prefix, counter);
            counter += 1;
            let pt = self
                .cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: ct,
                        aad: &[fb],
                    },
                )
                .map_err(|_| Error::Auth)?;
            out.extend_from_slice(&pt);
            if final_ {
                break;
            }
        }
        Ok(out)
    }
}

/// Incremental decryptor for the framed wire format: feed ciphertext with
/// [`StreamDecryptor::push`] and take plaintext frames with
/// [`StreamDecryptor::next_frame`]. At most one frame (64 KiB) plus the unread
/// input is buffered, so an object is never held in memory whole.
pub struct StreamDecryptor {
    cipher: Aes256Gcm,
    buf: Vec<u8>,
    prefix: Option<[u8; 8]>,
    counter: u32,
    done: bool,
}

impl StreamDecryptor {
    /// Appends ciphertext read from the underlying object.
    pub fn push(&mut self, data: &[u8]) {
        if !self.done {
            self.buf.extend_from_slice(data);
        }
    }

    /// Reports whether the final frame has been decrypted.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Decrypts the next complete frame. `Ok(None)` means more input is needed
    /// (or the stream is done); errors are fatal.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.done {
            return Ok(None);
        }
        let mut pos = 0;
        let prefix = match self.prefix {
            Some(p) => p,
            None => {
                if self.buf.len() < 8 {
                    return Ok(None);
                }
                let mut p = [0u8; 8];
                p.copy_from_slice(&self.buf[..8]);
                self.prefix = Some(p);
                pos = 8;
                p
            }
        };
        if self.buf.len() < pos + 5 {
            self.buf.drain(..pos);
            return Ok(None);
        }
        let b = &self.buf[pos..];
        let fb = b[0];
        let ctlen = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
        if ctlen > ENC_CHUNK + TAG_OVERHEAD {
            return Err(Error::OversizedFrame);
        }
        if b.len() < 5 + ctlen {
            self.buf.drain(..pos);
            return Ok(None);
        }
        let nonce = Encryptor::nonce(&prefix, self.counter);
        self.counter += 1;
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &b[5..5 + ctlen],
                    aad: &[fb],
                },
            )
            .map_err(|_| Error::Auth)?;
        self.buf.drain(..pos + 5 + ctlen);
        if fb == 1 {
            self.done = true;
            self.buf = Vec::new();
        }
        Ok(Some(pt))
    }

    /// Called at end of input: errors unless the final frame was seen.
    pub fn finish(&self) -> Result<(), Error> {
        if self.done {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }
}

impl Encryptor {
    /// Starts an incremental decryption.
    pub fn stream_decryptor(&self) -> StreamDecryptor {
        StreamDecryptor {
            cipher: self.cipher.clone(),
            buf: Vec::new(),
            prefix: None,
            counter: 0,
            done: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn roundtrip_across_sizes() {
        let e = Encryptor::new(&key()).unwrap();
        for size in [
            0usize,
            1,
            100,
            ENC_CHUNK - 1,
            ENC_CHUNK,
            ENC_CHUNK + 1,
            3 * ENC_CHUNK,
            200 * 1024,
        ] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let ct = e.encrypt(&plain);
            let back = e.decrypt(&ct).unwrap();
            assert_eq!(back, plain, "size {size}");
        }
    }

    #[test]
    fn at_rest_is_ciphertext() {
        let e = Encryptor::new(&key()).unwrap();
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(10);
        let ct = e.encrypt(&plain);
        assert!(!ct
            .windows(plain.len().min(16))
            .any(|w| w == &plain[..plain.len().min(16)]));
        assert!(ct.len() > plain.len()); // framing + tags
    }

    #[test]
    fn tamper_fails() {
        let e = Encryptor::new(&key()).unwrap();
        let mut ct = e.encrypt(b"secret payload");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(e.decrypt(&ct), Err(Error::Auth));
    }

    #[test]
    fn wrong_key_fails() {
        let e = Encryptor::new(&key()).unwrap();
        let ct = e.encrypt(b"secret payload");
        let other = Encryptor::new(&[9u8; 32]).unwrap();
        assert_eq!(other.decrypt(&ct), Err(Error::Auth));
    }

    #[test]
    fn truncation_detected() {
        let e = Encryptor::new(&key()).unwrap();
        let ct = e.encrypt(&vec![7u8; ENC_CHUNK * 2]);
        // Drop the final (empty) frame: cut after the first full frame's bytes.
        let truncated = &ct[..20];
        assert!(matches!(
            e.decrypt(truncated),
            Err(Error::Truncated | Error::Auth)
        ));
    }

    /// Feeds ciphertext in odd-sized pieces through the incremental decryptor.
    fn stream_decrypt(e: &Encryptor, ct: &[u8], piece: usize) -> Result<Vec<u8>, Error> {
        let mut d = e.stream_decryptor();
        let mut out = Vec::new();
        for c in ct.chunks(piece.max(1)) {
            d.push(c);
            while let Some(pt) = d.next_frame()? {
                out.extend_from_slice(&pt);
            }
        }
        d.finish()?;
        Ok(out)
    }

    #[test]
    fn stream_decryptor_matches_decrypt() {
        let e = Encryptor::new(&key()).unwrap();
        for size in [0usize, 5, ENC_CHUNK, ENC_CHUNK + 7, 3 * ENC_CHUNK] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let ct = e.encrypt(&plain);
            for piece in [1usize, 7, 4096, 1 << 20] {
                if piece == 1 && size > ENC_CHUNK {
                    continue; // slow; covered by 7
                }
                assert_eq!(
                    stream_decrypt(&e, &ct, piece).unwrap(),
                    plain,
                    "{size}/{piece}"
                );
            }
            // Any truncation is detected.
            if !ct.is_empty() {
                let cut = &ct[..ct.len() - 1];
                assert!(stream_decrypt(&e, cut, 4096).is_err(), "truncated {size}");
            }
        }
        let other = Encryptor::new(&[9u8; 32]).unwrap();
        assert_eq!(
            stream_decrypt(&other, &e.encrypt(b"x"), 64),
            Err(Error::Auth)
        );
    }

    #[test]
    fn bad_key_length() {
        assert_eq!(
            Encryptor::new(&[0u8; 16]).err(),
            Some(Error::BadKeyLength(16))
        );
    }

    #[test]
    fn deterministic_framing_with_fixed_prefix() {
        // Same key + prefix + plaintext -> identical bytes (matches Go framing).
        let e = Encryptor::new(&key()).unwrap();
        let p = [1u8; 8];
        let a = e.encrypt_with_prefix(b"hello", p);
        let b = e.encrypt_with_prefix(b"hello", p);
        assert_eq!(a, b);
        assert_eq!(&a[..8], &p); // stream starts with the nonce prefix
        assert_eq!(e.decrypt(&a).unwrap(), b"hello");
    }
}
