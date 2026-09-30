package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/yiyuhki/p2/internal/config"
)

func conformance(t *testing.T, s Storage) {
	ctx := context.Background()
	key := "attachments/test/" + uuid.NewString()
	data := bytes.Repeat([]byte("secmail"), 1000)
	if err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch")
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("deleting a missing object must succeed: %v", err)
	}
}

func TestFSConformance(t *testing.T) {
	fs, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	conformance(t, fs)
	if err := fs.Put(context.Background(), "../escape", bytes.NewReader(nil), 0); err == nil {
		t.Fatal("path traversal accepted")
	}
}

// TestS3Conformance runs against an S3-compatible endpoint (MinIO, RustFS,
// AWS) when SECMAIL_TEST_S3_ENDPOINT is set.
func TestS3Conformance(t *testing.T) {
	ep := os.Getenv("SECMAIL_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("SECMAIL_TEST_S3_ENDPOINT not set")
	}
	s, err := NewS3(context.Background(), config.S3Config{
		Endpoint:  ep,
		Region:    "us-east-1",
		Bucket:    "secmail-test-" + uuid.NewString()[:8],
		AccessKey: os.Getenv("SECMAIL_TEST_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("SECMAIL_TEST_S3_SECRET_KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	conformance(t, s)
}
