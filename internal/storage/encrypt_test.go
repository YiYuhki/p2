package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
)

func encStore(t *testing.T) *Encrypted {
	t.Helper()
	fs, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	e, err := NewEncrypted(fs, key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEncryptedRoundTrip(t *testing.T) {
	e := encStore(t)
	ctx := context.Background()
	sizes := []int{0, 1, 100, encChunk - 1, encChunk, encChunk + 1, 3*encChunk + 7, 200000}
	for _, n := range sizes {
		data := make([]byte, n)
		rand.Read(data)
		key := "obj/" + string(rune('a'+n%26)) + string(rune('0'+n%10)) + itoa(n)
		if err := e.Put(ctx, key, bytes.NewReader(data), int64(n)); err != nil {
			t.Fatalf("put %d: %v", n, err)
		}
		rc, err := e.Get(ctx, key)
		if err != nil {
			t.Fatalf("get %d: %v", n, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch at size %d (got %d bytes)", n, len(got))
		}
	}
}

func TestEncryptedAtRestIsCiphertext(t *testing.T) {
	fs, _ := NewFS(t.TempDir())
	key := make([]byte, 32)
	rand.Read(key)
	e, _ := NewEncrypted(fs, key)
	ctx := context.Background()
	plaintext := []byte("고객 주민번호 900101-1234567 민감정보")
	e.Put(ctx, "k", bytes.NewReader(plaintext), int64(len(plaintext)))
	// Read the raw stored object (bypassing decryption) — must not contain the plaintext.
	raw, err := fs.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := io.ReadAll(raw)
	raw.Close()
	if bytes.Contains(stored, []byte("900101-1234567")) {
		t.Fatal("plaintext leaked to the object store")
	}
}

func TestEncryptedTamperDetected(t *testing.T) {
	fs, _ := NewFS(t.TempDir())
	key := make([]byte, 32)
	rand.Read(key)
	e, _ := NewEncrypted(fs, key)
	ctx := context.Background()
	e.Put(ctx, "k", bytes.NewReader(bytes.Repeat([]byte("A"), 1000)), 1000)
	raw, _ := fs.Get(ctx, "k")
	b, _ := io.ReadAll(raw)
	raw.Close()
	b[len(b)-1] ^= 0xff // flip a ciphertext byte
	fs.Put(ctx, "k", bytes.NewReader(b), int64(len(b)))
	rc, _ := e.Get(ctx, "k")
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("tampered ciphertext should fail authentication")
	}
	rc.Close()
}

func TestWrongKeyFails(t *testing.T) {
	fs, _ := NewFS(t.TempDir())
	k1 := make([]byte, 32)
	rand.Read(k1)
	e1, _ := NewEncrypted(fs, k1)
	e1.Put(context.Background(), "k", bytes.NewReader([]byte("secret data here, padded out")), 28)
	k2 := make([]byte, 32)
	rand.Read(k2)
	e2, _ := NewEncrypted(fs, k2)
	rc, _ := e2.Get(context.Background(), "k")
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("wrong key should fail to decrypt")
	}
	rc.Close()
}

func TestBadKeyLen(t *testing.T) {
	fs, _ := NewFS(t.TempDir())
	if _, err := NewEncrypted(fs, make([]byte, 16)); err == nil {
		t.Fatal("16-byte key should be rejected")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
