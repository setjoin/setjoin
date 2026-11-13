package storage

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"time"
)

type backupS3Driver struct {
	client         *s3.Client
	bucket         string
	endpoint       string
	useTLS         bool // resolved transport-TLS posture (tls.go)
	objectLockDays int
	lockMode       string
}

// NewS3Driver creates an S3-compatible storage driver.
// Supports AWS S3 and any S3-compatible endpoint (Backblaze B2, Cloudflare R2,
// Wasabi, MinIO, SeaweedFS, etc.).
//
// TLS posture (D-MAILSERVER-INTERNAL-STORAGE-F-001): the endpoint is resolved
// through ResolveEndpointTLS and normalized to carry the resolved scheme, so
// BaseEndpoint always states the posture explicitly (aws-sdk-go-v2 is
// TLS-by-default, but a plaintext http:// endpoint used to be accepted without
// the loopback-only restriction). Scheme-less non-loopback endpoints are
// rejected fail-closed; explicit loopback HTTP remains supported. The empty
// endpoint keeps its AWS-default meaning (TLS-by-default AWS resolution); an
// explicit Secure=false with no endpoint is rejected as contradictory.
func NewBackupS3Driver(cfg DriverConfig) (Driver, error) {
	rawEndpoint := cfg.Endpoint
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	endpoint := rawEndpoint
	useTLS := true
	if endpoint != "" {
		hostPort, resolvedTLS, err := ResolveEndpointTLS(rawEndpoint, cfg.Secure)
		if err != nil {
			return nil, err
		}
		useTLS = resolvedTLS
		endpoint = TLSScheme(useTLS) + "://" + hostPort
	} else if cfg.Secure != nil && !*cfg.Secure {
		return nil, fmt.Errorf("storage: explicit plaintext (Secure=false) requires an explicit endpoint; " +
			"the AWS default endpoint is always TLS (fail-closed)")
	}

	isAWS := strings.Contains(rawEndpoint, "amazonaws.com") || rawEndpoint == ""

	cfgAWS, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKey, cfg.SecretKey, cfg.SessionToken,
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("storage: aws config: %w", err)
	}

	client := s3.NewFromConfig(cfgAWS, func(o *s3.Options) {
		if endpoint != "" && !isAWS {
			resolved, err := url.Parse(endpoint)
			if err == nil {
				o.BaseEndpoint = aws.String(resolved.String())
			}
		}
		o.UsePathStyle = !isAWS
	})

	return &backupS3Driver{
		client:         client,
		bucket:         cfg.Bucket,
		endpoint:       rawEndpoint,
		useTLS:         useTLS,
		objectLockDays: cfg.ObjectLockRetentionDays,
		lockMode:       cfg.ObjectLockMode,
	}, nil
}

func (d *backupS3Driver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	input := &s3.PutObjectInput{
		Bucket:        aws.String(d.bucket),
		Key:           aws.String(key),
		Body:          data,
		ContentLength: aws.Int64(size),
	}
	if d.objectLockDays > 0 && d.lockMode != "" {
		retainUntil := time.Now().AddDate(0, 0, d.objectLockDays)
		mode := types.ObjectLockMode(d.lockMode)
		input.ObjectLockMode = mode
		input.ObjectLockRetainUntilDate = aws.Time(retainUntil)
	}
	_, err := d.client.PutObject(ctx, input)
	return err
}

func (d *backupS3Driver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func (d *backupS3Driver) DeleteObject(ctx context.Context, key string) error {
	_, err := d.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	})
	return err
}

func (d *backupS3Driver) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var result []ObjectInfo
	paginator := s3.NewListObjectsV2Paginator(d.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(d.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			result = append(result, ObjectInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
			})
		}
	}
	return result, nil
}

func (d *backupS3Driver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return d.HeadObject(ctx, key)
}

func (d *backupS3Driver) HeadObject(ctx context.Context, key string) (*ObjectInfo, error) {
	out, err := d.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		Key:          key,
		Size:         aws.ToInt64(out.ContentLength),
		LastModified: aws.ToTime(out.LastModified),
	}, nil
}

func (d *backupS3Driver) EnsureBucket(ctx context.Context) error {
	exists, err := d.BucketExists(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = d.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(d.bucket),
	})
	return err
}

func (d *backupS3Driver) BucketExists(ctx context.Context) (bool, error) {
	_, err := d.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(d.bucket),
	})
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (d *backupS3Driver) ProviderName() string { return "s3" }
func (d *backupS3Driver) Endpoint() string     { return d.endpoint }

func (d *backupS3Driver) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	_, err := d.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(dstBucket),
		CopySource: aws.String(fmt.Sprintf("%s/%s", srcBucket, srcKey)),
		Key:        aws.String(dstKey),
	})
	return err
}

func (d *backupS3Driver) Ping(ctx context.Context) error {
	_, err := d.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(d.bucket)})
	return err
}

// ── Retention / Object Lock methods ──────────────────────────────────────

func (d *backupS3Driver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	input := &s3.PutObjectRetentionInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
		Retention: &types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(mode),
			RetainUntilDate: aws.Time(retainUntil),
		},
	}
	if mode == "governance" {
		input.BypassGovernanceRetention = aws.Bool(true)
	}
	_, err := d.client.PutObjectRetention(ctx, input)
	return err
}

func (d *backupS3Driver) GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error) {
	out, err := d.client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	status := &RetentionStatus{}
	if out.Retention != nil {
		status.Mode = string(out.Retention.Mode)
		if out.Retention.RetainUntilDate != nil {
			status.RetainUntil = *out.Retention.RetainUntilDate
		}
	}
	return status, nil
}

func (d *backupS3Driver) PutObjectLegalHold(ctx context.Context, key, status string) error {
	_, err := d.client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
		LegalHold: &types.ObjectLockLegalHold{
			Status: types.ObjectLockLegalHoldStatus(status),
		},
	})
	return err
}

func (d *backupS3Driver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	out, err := d.client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", err
	}
	if out.LegalHold != nil {
		return string(out.LegalHold.Status), nil
	}
	return "OFF", nil
}

func (d *backupS3Driver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	// Check if bucket exists and already has Object Lock configured.
	existing, err := d.GetBucketObjectLockConfig(ctx)
	if err == nil && existing != nil && existing.Enabled {
		if existing.Mode != mode {
			return fmt.Errorf("storage: bucket Object Lock mode mismatch: config=%s, bucket=%s", mode, existing.Mode)
		}
		return nil
	}

	// Bucket does not exist — create it with Object Lock enabled.
	exists, _ := d.BucketExists(ctx)
	if !exists {
		_, err := d.client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket:                     aws.String(d.bucket),
			ObjectLockEnabledForBucket: aws.Bool(true),
		})
		if err != nil {
			return fmt.Errorf("storage: create bucket with Object Lock: %w", err)
		}
	}

	// Apply the default retention configuration.
	if retentionDays < 1 || retentionDays > math.MaxInt32 {
		return fmt.Errorf("storage: WORM retention days %d out of range [1, %d]", retentionDays, math.MaxInt32)
	}
	_, err = d.client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket: aws.String(d.bucket),
		ObjectLockConfiguration: &types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule: &types.ObjectLockRule{
				DefaultRetention: &types.DefaultRetention{
					Mode: types.ObjectLockRetentionMode(mode),
					Days: aws.Int32(int32(retentionDays)), //nolint:gosec // G115: range-checked to [1, math.MaxInt32] immediately above
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("storage: put object lock configuration: %w", err)
	}
	return nil
}

func (d *backupS3Driver) GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error) {
	out, err := d.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(d.bucket),
	})
	if err != nil {
		return nil, err
	}
	cfg := &BucketLockConfig{
		Enabled: string(out.ObjectLockConfiguration.ObjectLockEnabled) == "Enabled",
	}
	if out.ObjectLockConfiguration.Rule != nil && out.ObjectLockConfiguration.Rule.DefaultRetention != nil {
		cfg.Mode = string(out.ObjectLockConfiguration.Rule.DefaultRetention.Mode)
		cfg.RetentionPeriodDays = int(aws.ToInt32(out.ObjectLockConfiguration.Rule.DefaultRetention.Days))
	}
	return cfg, nil
}
