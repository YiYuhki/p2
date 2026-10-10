package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Encrypted wraps a Storage so object bodies are encrypted at rest with
// AES-256-GCM. The ciphertext is a stream of authenticated frames, so arbitrary
// sizes stream without buffering the whole object:
//
//	prefix[8]                         random per-object nonce prefix
//	then repeated frames:
//	  final[1] ctlen[4 BE] ciphertext  nonce = prefix || uint32(counter)
//
// The last frame has final=1 (and may be empty); a stream that ends without one
// is rejected as truncated. The AAD is the final byte, so a dropped or
// reordered final frame fails authentication.
//
// Note: objects are only readable through this wrapper. An analyzer that reads
// the object store directly (via the job's storage pointer) would see
// ciphertext, so with encryption enabled analyzers must use the content API.
type Encrypted struct {
	Storage
	aead cipher.AEAD
}

const encChunk = 64 * 1024

// NewEncrypted wraps inner with AES-256-GCM. key must be exactly 32 bytes.
func NewEncrypted(inner Storage, key []byte) (*Encrypted, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("storage: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encrypted{Storage: inner, aead: aead}, nil
}

func (e *Encrypted) Put(ctx context.Context, key string, r io.Reader, _ int64) error {
	er, err := newEncReader(e.aead, r)
	if err != nil {
		return err
	}
	// Size is unknown after framing; pass -1 so the backend streams.
	return e.Storage.Put(ctx, key, er, -1)
}

func (e *Encrypted) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := e.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return &decReadCloser{src: rc, dec: newDecReader(e.aead, rc)}, nil
}

// ---- encrypting reader ----

type encReader struct {
	aead    cipher.AEAD
	src     io.Reader
	prefix  [8]byte
	counter uint32
	out     []byte // pending ciphertext bytes to emit
	plain   []byte // reusable plaintext chunk buffer
	done    bool   // final frame emitted
	started bool
}

func newEncReader(aead cipher.AEAD, src io.Reader) (*encReader, error) {
	e := &encReader{aead: aead, src: src, plain: make([]byte, encChunk)}
	if _, err := rand.Read(e.prefix[:]); err != nil {
		return nil, err
	}
	e.out = append(e.out, e.prefix[:]...) // stream starts with the nonce prefix
	e.started = true
	return e, nil
}

func (e *encReader) nonce() []byte {
	var n [12]byte
	copy(n[:8], e.prefix[:])
	binary.BigEndian.PutUint32(n[8:], e.counter)
	e.counter++
	return n[:]
}

func (e *encReader) Read(p []byte) (int, error) {
	for len(e.out) == 0 && !e.done {
		n, rerr := io.ReadFull(e.src, e.plain)
		switch {
		case rerr == nil:
			e.frame(e.plain[:n], false)
		case rerr == io.ErrUnexpectedEOF || rerr == io.EOF:
			e.frame(e.plain[:n], true) // last frame (possibly empty)
			e.done = true
		default:
			return 0, rerr
		}
	}
	if len(e.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, e.out)
	e.out = e.out[n:]
	return n, nil
}

func (e *encReader) frame(plain []byte, final bool) {
	fb := byte(0)
	if final {
		fb = 1
	}
	ct := e.aead.Seal(nil, e.nonce(), plain, []byte{fb})
	var hdr [5]byte
	hdr[0] = fb
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(ct)))
	e.out = append(e.out, hdr[:]...)
	e.out = append(e.out, ct...)
}

// ---- decrypting reader ----

type decReader struct {
	aead    cipher.AEAD
	src     io.Reader
	prefix  [8]byte
	counter uint32
	havePfx bool
	out     []byte
	done    bool
}

func newDecReader(aead cipher.AEAD, src io.Reader) *decReader {
	return &decReader{aead: aead, src: src}
}

func (d *decReader) nonce() []byte {
	var n [12]byte
	copy(n[:8], d.prefix[:])
	binary.BigEndian.PutUint32(n[8:], d.counter)
	d.counter++
	return n[:]
}

var errTruncated = errors.New("storage: encrypted stream truncated")

func (d *decReader) Read(p []byte) (int, error) {
	if !d.havePfx {
		if _, err := io.ReadFull(d.src, d.prefix[:]); err != nil {
			return 0, err
		}
		d.havePfx = true
	}
	for len(d.out) == 0 && !d.done {
		var hdr [5]byte
		if _, err := io.ReadFull(d.src, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return 0, errTruncated // ended without a final frame
			}
			return 0, err
		}
		final := hdr[0] == 1
		ctlen := binary.BigEndian.Uint32(hdr[1:])
		if ctlen > encChunk+uint32(d.aead.Overhead()) {
			return 0, errors.New("storage: oversized encrypted frame")
		}
		ct := make([]byte, ctlen)
		if _, err := io.ReadFull(d.src, ct); err != nil {
			return 0, errTruncated
		}
		pt, err := d.aead.Open(nil, d.nonce(), ct, []byte{hdr[0]})
		if err != nil {
			return 0, err
		}
		d.out = append(d.out, pt...)
		if final {
			d.done = true
		}
	}
	if len(d.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.out)
	d.out = d.out[n:]
	return n, nil
}

type decReadCloser struct {
	src io.ReadCloser
	dec *decReader
}

func (d *decReadCloser) Read(p []byte) (int, error) { return d.dec.Read(p) }
func (d *decReadCloser) Close() error               { return d.src.Close() }
