package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// s3HotDriver implements Driver using minio-go/v7.
// Optimized for the hot path (JMAP, SMTP, admin). Fast, lightweight.
// WORM/Object Lock is supported via S3 standard Object Lock API.
type s3HotDriver struct {
	client   *minio.Client
	bucket   string
	endpoint string // original endpoint (scheme-ful when given) for ProviderName/Endpoint
	ssl      bool   // resolved transport-TLS posture (tls.go)
}

// NewS3HotDriver creates a minio-go based S3 driver.
// endpoint may be any S3-compatible service (SeaweedFS, MinIO, AWS, B2, R2, 华为OBS).
//
// TLS posture (D-MAILSERVER-INTERNAL-STORAGE-F-001): the scheme is no longer
// silently stripped — it drives the posture via ResolveEndpointTLS. The useSSL
// argument is a TLS ASSERTION: true forces TLS; false means "not asserted",
// which derives the posture from the endpoint scheme with the shared
// fail-closed rules (scheme-less non-loopback endpoints are rejected; explicit
// loopback HTTP remains supported). Direct callers must therefore pass a
// scheme-ful endpoint (e.g. minio.Client.EndpointURL()) or a loopback host.
// Prefer NewDriver(DriverConfig{...}), whose tri-state Secure field can also
// express an explicit plaintext request and detect scheme conflicts.
func NewS3HotDriver(endpoint, accessKey, secretKey, bucket string, useSSL bool) (Driver, error) {
	var secure *bool
	if useSSL {
		secure = &useSSL
	}
	hostPort, useTLS, err := ResolveEndpointTLS(endpoint, secure)
	if err != nil {
		return nil, err
	}
	if hostPort == "" {
		return nil, fmt.Errorf("s3: endpoint is required")
	}
	return newS3HotDriver(endpoint, accessKey, secretKey, bucket, hostPort, useTLS)
}

// newS3HotDriver is the resolved-posture constructor: hostPort is scheme-less,
// useTLS is final. minio-go builds the URL scheme itself from Secure, so the
// scheme must never reach it embedded in the host.
func newS3HotDriver(origEndpoint, accessKey, secretKey, bucket, hostPort string, useTLS bool) (Driver, error) {
	client, err := minio.New(hostPort, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useTLS,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: create client: %w", err)
	}
	return &s3HotDriver{client: client, bucket: bucket, endpoint: origEndpoint, ssl: useTLS}, nil
}

func (d *s3HotDriver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	_, err := d.client.PutObject(ctx, d.bucket, key, data, size, minio.PutObjectOptions{})
	return err
}

func (d *s3HotDriver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := d.client.GetObject(ctx, d.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (d *s3HotDriver) DeleteObject(ctx context.Context, key string) error {
	return d.client.RemoveObject(ctx, d.bucket, key, minio.RemoveObjectOptions{})
}

func (d *s3HotDriver) CopyObject(ctx context.Context, _, srcKey, _, dstKey string) error {
	src := minio.CopySrcOptions{Bucket: d.bucket, Object: srcKey}
	dst := minio.CopyDestOptions{Bucket: d.bucket, Object: dstKey}
	_, err := d.client.CopyObject(ctx, dst, src)
	return err
}

func (d *s3HotDriver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return d.HeadObject(ctx, key)
}

func (d *s3HotDriver) HeadObject(ctx context.Context, key string) (*ObjectInfo, error) {
	info, err := d.client.StatObject(ctx, d.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		Key:          key,
		Size:         info.Size,
		LastModified: info.LastModified,
	}, nil
}

func (d *s3HotDriver) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var result []ObjectInfo
	for obj := range d.client.ListObjects(ctx, d.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		result = append(result, ObjectInfo{
			Key:          obj.Key,
			Size:         obj.Size,
			LastModified: obj.LastModified,
		})
	}
	return result, nil
}

func (d *s3HotDriver) EnsureBucket(ctx context.Context) error {
	exists, err := d.client.BucketExists(ctx, d.bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return d.client.MakeBucket(ctx, d.bucket, minio.MakeBucketOptions{})
}

func (d *s3HotDriver) BucketExists(ctx context.Context) (bool, error) {
	return d.client.BucketExists(ctx, d.bucket)
}

func (d *s3HotDriver) ProviderName() string { return "s3" }

func (d *s3HotDriver) Endpoint() string { return d.endpoint }

func (d *s3HotDriver) Ping(ctx context.Context) error {
	_, err := d.client.BucketExists(ctx, d.bucket)
	return err
}

// ── WORM via S3 Object Lock ──

// minioRetentionMode maps the driver's lowercase domain vocabulary
// ("governance"/"compliance", see worm.go's validWORMModes) to minio-go's
// RetentionMode, which is only valid uppercase (RetentionMode.IsValid()
// checks against "GOVERNANCE"/"COMPLIANCE" in api-object-lock.go). Passing
// the lowercase value straight through makes minio-go reject it
// client-side before any I/O, so retention silently never applies (B1).
func minioRetentionMode(mode string) minio.RetentionMode {
	return minio.RetentionMode(strings.ToUpper(mode))
}

func (d *s3HotDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	retMode := minioRetentionMode(mode)
	return d.client.PutObjectRetention(ctx, d.bucket, key, minio.PutObjectRetentionOptions{
		Mode:            &retMode,
		RetainUntilDate: &retainUntil,
	})
}

func (d *s3HotDriver) GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error) {
	mode, retainUntil, err := d.client.GetObjectRetention(ctx, d.bucket, key, "")
	if err != nil {
		return nil, err
	}
	status := &RetentionStatus{}
	if mode != nil {
		status.Mode = string(*mode)
	}
	if retainUntil != nil {
		status.RetainUntil = *retainUntil
	}
	return status, nil
}

func (d *s3HotDriver) PutObjectLegalHold(ctx context.Context, key, status string) error {
	return d.client.PutObjectLegalHold(ctx, d.bucket, key, minio.PutObjectLegalHoldOptions{
		Status: (*minio.LegalHoldStatus)(&status),
	})
}

func (d *s3HotDriver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	status, err := d.client.GetObjectLegalHold(ctx, d.bucket, key, minio.GetObjectLegalHoldOptions{})
	if err != nil {
		return "", err
	}
	if status != nil {
		return string(*status), nil
	}
	return "OFF", nil
}

func (d *s3HotDriver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	retMode := minioRetentionMode(mode)
	validity := uint(retentionDays)
	unit := minio.Days
	return d.client.SetObjectLockConfig(ctx, d.bucket, &retMode, &validity, &unit)
}

func (d *s3HotDriver) GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error) {
	_, mode, validity, _, err := d.client.GetObjectLockConfig(ctx, d.bucket)
	if err != nil {
		return nil, err
	}
	cfg := &BucketLockConfig{}
	if mode != nil {
		cfg.Enabled = true
		cfg.Mode = string(*mode)
	}
	if validity != nil {
		cfg.RetentionPeriodDays = int(*validity)
	}
	return cfg, nil
}
