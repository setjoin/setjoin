package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// dbDumpObjectKey is the canonical object key the operator DB dump is stored
// under in the backup bucket; the restore path downloads exactly this key.
const dbDumpObjectKey = "db-dump.dump"

// s3Config holds the connection parameters for the backup bucket. It is shared
// by backup-db (upload) and restore (download), and mirrors the S3 fields of the
// gateway's restoreRequest so the same flags round-trip both paths.
type s3Config struct {
	Provider  string
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
}

// validate checks the required S3 fields.
func (c s3Config) validate() error {
	if c.Bucket == "" {
		return fmt.Errorf("--bucket is required")
	}
	if c.AccessKey == "" {
		return fmt.Errorf("--access-key is required")
	}
	if c.SecretKey == "" {
		return fmt.Errorf("--secret-key is required")
	}
	return nil
}

// newMinioClient builds a minio-go client from the config. The endpoint may
// carry a scheme (https://host); we strip it and derive secure accordingly. A
// bare host defaults to secure (https).
func newMinioClient(c s3Config) (*minio.Client, error) {
	endpoint := c.Endpoint
	secure := true
	if endpoint == "" {
		// AWS-style: derive from region.
		endpoint = "s3.amazonaws.com"
		if c.Region != "" {
			endpoint = fmt.Sprintf("s3.%s.amazonaws.com", c.Region)
		}
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse endpoint %q: %w", endpoint, err)
		}
		secure = u.Scheme == "https"
		endpoint = u.Host
	}
	cl, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(c.AccessKey, c.SecretKey, ""),
		Secure: secure,
		Region: c.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("init S3 client: %w", err)
	}
	return cl, nil
}

// uploadFile streams a local file to objectKey in the backup bucket.
func uploadFile(ctx context.Context, c s3Config, localPath, objectKey string) (retErr error) {
	cl, err := newMinioClient(c)
	if err != nil {
		return err
	}
	f, err := os.Open(localPath) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer func() { retErr = errors.Join(retErr, f.Close()) }()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", localPath, err)
	}
	_, err = cl.PutObject(ctx, c.Bucket, objectKey, f, info.Size(), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("upload to s3://%s/%s: %w", c.Bucket, objectKey, err)
	}
	return nil
}

// downloadFile streams objectKey from the backup bucket to a local path.
func downloadFile(ctx context.Context, c s3Config, objectKey, localPath string) (retErr error) {
	cl, err := newMinioClient(c)
	if err != nil {
		return err
	}
	obj, err := cl.GetObject(ctx, c.Bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("get s3://%s/%s: %w", c.Bucket, objectKey, err)
	}
	defer func() { retErr = errors.Join(retErr, obj.Close()) }()

	out, err := os.OpenFile(localPath, os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // internally-created temp path
	if err != nil {
		return fmt.Errorf("create %s: %w", localPath, err)
	}
	if _, err := io.Copy(out, obj); err != nil {
		_ = out.Close()
		return fmt.Errorf("download to %s: %w", localPath, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("sync %s: %w", localPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", localPath, err)
	}
	return nil
}
