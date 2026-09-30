// Package storage abstracts the object store holding quarantined attachments.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/yiyuhki/p2/internal/config"
)

var ErrNotFound = errors.New("storage: object not found")

type Storage interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	// Type and Bucket are published in analysis jobs so an analyzer may read
	// the object directly instead of going through the internal API.
	Type() string
	Bucket() string
	// Ping is a cheap readiness check.
	Ping(ctx context.Context) error
}

func New(ctx context.Context, cfg config.StorageConfig) (Storage, error) {
	switch cfg.Type {
	case "fs":
		return NewFS(cfg.FS.Dir)
	case "s3":
		return NewS3(ctx, cfg.S3)
	default:
		return nil, fmt.Errorf("storage: unknown type %q", cfg.Type)
	}
}

// ---- filesystem ----

type FS struct{ dir string }

func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FS{dir: dir}, nil
}

func (f *FS) path(key string) (string, error) {
	clean := filepath.Clean("/" + key)
	if strings.Contains(key, "..") || clean == "/" {
		return "", fmt.Errorf("storage: invalid key %q", key)
	}
	return filepath.Join(f.dir, clean), nil
}

func (f *FS) Put(_ context.Context, key string, r io.Reader, _ int64) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (f *FS) Get(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := f.path(key)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return fh, err
}

func (f *FS) Delete(_ context.Context, key string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f *FS) Ping(context.Context) error {
	_, err := os.Stat(f.dir)
	return err
}

func (f *FS) Type() string   { return "fs" }
func (f *FS) Bucket() string { return "" }

// ---- S3 / MinIO ----

type S3 struct {
	client *minio.Client
	bucket string
}

func NewS3(ctx context.Context, cfg config.S3Config) (*S3, error) {
	var creds *credentials.Credentials
	if cfg.AccessKey != "" {
		creds = credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	} else {
		creds = credentials.NewIAM("")
	}
	cl, err := minio.New(cfg.Endpoint, &minio.Options{Creds: creds, Secure: cfg.UseSSL, Region: cfg.Region})
	if err != nil {
		return nil, err
	}
	exists, err := cl.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("s3: check bucket: %w", err)
	}
	if !exists {
		if err := cl.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, fmt.Errorf("s3: create bucket: %w", err)
		}
	}
	return &S3{client: cl, bucket: cfg.Bucket}, nil
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	return err
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	// GetObject is lazy; Stat surfaces missing objects before streaming.
	if _, err := obj.Stat(); err != nil {
		obj.Close()
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return obj, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

func (s *S3) Ping(ctx context.Context) error {
	_, err := s.client.BucketExists(ctx, s.bucket)
	return err
}

func (s *S3) Type() string   { return "s3" }
func (s *S3) Bucket() string { return s.bucket }
