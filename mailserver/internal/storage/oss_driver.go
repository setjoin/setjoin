package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

type ossDriver struct {
	client     *oss.Client
	bucketName string
	endpoint   string
	useTLS     bool // resolved transport-TLS posture (tls.go)
}

// NewOSDriver creates an Aliyun OSS storage driver using the v2 SDK.
//
// TLS posture (D-MAILSERVER-INTERNAL-STORAGE-F-001): resolved through
// ResolveEndpointTLS and made EXPLICIT to the SDK — the endpoint is normalized
// to carry the resolved scheme and DisableSSL is pinned to the resolved
// posture, so the SDK's scheme-defaulting can never silently downgrade a
// configuration. Scheme-less non-loopback endpoints are rejected fail-closed;
// explicit loopback HTTP remains the supported local compatibility case.
func NewOSDriver(cfg DriverConfig) (Driver, error) {
	endpoint := cfg.Endpoint
	disableSSL := false
	useTLS := true
	if endpoint != "" {
		hostPort, resolvedTLS, err := ResolveEndpointTLS(endpoint, cfg.Secure)
		if err != nil {
			return nil, err
		}
		useTLS = resolvedTLS
		endpoint = TLSScheme(useTLS) + "://" + hostPort
		disableSSL = !useTLS
	} else if cfg.Secure != nil && !*cfg.Secure {
		// No endpoint: the SDK derives one from the region, and DisableSSL=true
		// would make that derivation PLAINTEXT (http://oss-<region>.aliyuncs.com)
		// — plaintext to a remote peer, exactly the downgrade this package
		// rejects. There is no loopback peer to justify it, so refuse before the
		// SDK client exists, consistent with NewBackupS3Driver (fail-closed).
		return nil, fmt.Errorf("storage: explicit plaintext (Secure=false) requires an explicit endpoint; " +
			"the region-derived OSS default endpoint is always TLS (fail-closed)")
	}

	ossCfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, cfg.SessionToken)).
		WithRegion(cfg.Region).
		WithEndpoint(endpoint).
		WithDisableSSL(disableSSL)

	client := oss.NewClient(ossCfg)

	// OSS object lock: the v2 SDK (v1.5.1) does not expose a PutBucketWorm API.
	// True WORM (governance/compliance mode) must be configured via the OSS
	// console or CLI. Expiration-based retention is available via
	// PutBucketLifecycle (see OSS docs for lifecycle rules).

	return &ossDriver{
		client:     client,
		bucketName: cfg.Bucket,
		endpoint:   cfg.Endpoint,
		useTLS:     useTLS,
	}, nil
}

func (d *ossDriver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	// Stream the reader straight to OSS with a known Content-Length; parity with
	// posix/s3hot (no io.ReadAll buffering). Callers always pass a real size.
	// ponytail: no seekable body means the SDK can't auto-retry a mid-stream
	// network error — same tradeoff s3hot/minio accept.
	_, err := d.client.PutObject(ctx, &oss.PutObjectRequest{
		Bucket:        oss.Ptr(d.bucketName),
		Key:           oss.Ptr(key),
		Body:          data,
		ContentLength: oss.Ptr(size),
	})
	return err
}

func (d *ossDriver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := d.client.GetObject(ctx, &oss.GetObjectRequest{
		Bucket: oss.Ptr(d.bucketName),
		Key:    oss.Ptr(key),
	})
	if err != nil {
		return nil, err
	}
	return result.Body, nil
}

func (d *ossDriver) DeleteObject(ctx context.Context, key string) error {
	_, err := d.client.DeleteObject(ctx, &oss.DeleteObjectRequest{
		Bucket: oss.Ptr(d.bucketName),
		Key:    oss.Ptr(key),
	})
	return err
}

func (d *ossDriver) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var result []ObjectInfo
	p := d.client.NewListObjectsV2Paginator(&oss.ListObjectsV2Request{
		Bucket: oss.Ptr(d.bucketName),
		Prefix: oss.Ptr(prefix),
	})
	for p.HasNext() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			result = append(result, ObjectInfo{
				Key:          oss.ToString(obj.Key),
				Size:         obj.Size,
				LastModified: oss.ToTime(obj.LastModified),
			})
		}
	}
	return result, nil
}

func (d *ossDriver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return d.HeadObject(ctx, key)
}

func (d *ossDriver) HeadObject(ctx context.Context, key string) (*ObjectInfo, error) {
	out, err := d.client.HeadObject(ctx, &oss.HeadObjectRequest{
		Bucket: oss.Ptr(d.bucketName),
		Key:    oss.Ptr(key),
	})
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		Key:  key,
		Size: out.ContentLength,
	}, nil
}

func (d *ossDriver) EnsureBucket(ctx context.Context) error {
	exists, err := d.BucketExists(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = d.client.PutBucket(ctx, &oss.PutBucketRequest{
		Bucket: oss.Ptr(d.bucketName),
	})
	return err
}

func (d *ossDriver) BucketExists(ctx context.Context) (bool, error) {
	exists, err := d.client.IsBucketExist(ctx, d.bucketName)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (d *ossDriver) ProviderName() string { return "oss" }
func (d *ossDriver) Endpoint() string     { return d.endpoint }

func (d *ossDriver) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	// Server-side copy — no download+reupload. Single-bucket store: both keys
	// live in d.bucketName (callers pass it for src and dst), matching s3hot.
	_, err := d.client.CopyObject(ctx, &oss.CopyObjectRequest{
		Bucket:       oss.Ptr(d.bucketName),
		Key:          oss.Ptr(dstKey),
		SourceBucket: oss.Ptr(d.bucketName),
		SourceKey:    oss.Ptr(srcKey),
	})
	if err != nil {
		return fmt.Errorf("oss copy: %w", err)
	}
	return nil
}

func (d *ossDriver) Ping(ctx context.Context) error {
	ok, err := d.BucketExists(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("oss: bucket %q does not exist", d.bucketName)
	}
	return nil
}

// ── Retention / Object Lock methods (storage.Retention) ──────────────────
// OSS WORM must be configured via the Aliyun console. The gateway detects and
// logs the gap at startup. ossDriver advertises the Retention capability
// structurally but every method refuses at runtime with ErrRetentionNotSupported
// (the second line of defense once a caller has obtained it via RetentionOf).

func (d *ossDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	return ErrRetentionNotSupported
}
func (d *ossDriver) GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error) {
	return nil, ErrRetentionNotSupported
}
func (d *ossDriver) PutObjectLegalHold(ctx context.Context, key, status string) error {
	return ErrRetentionNotSupported
}
func (d *ossDriver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	return "", ErrRetentionNotSupported
}
func (d *ossDriver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	return ErrRetentionNotSupported
}
func (d *ossDriver) GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error) {
	return nil, ErrRetentionNotSupported
}
