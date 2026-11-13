package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// Driver is the FACTORY + OBJECT-I/O interface — the return type of NewDriver
// and the surface every storage path constructs and consumes for plain object
// storage (Put/Get/Delete/List/Head/Stat/Copy/Ping + bucket existence).
//
// WORM/immutability is NO LONGER part of Driver. It is a separate, optional
// capability — the Retention interface — that only object-lock-capable backends
// implement. Callers that need immutability take a Retention (or detect its
// absence explicitly via RetentionOf) instead of seeing ErrRetentionNotSupported
// leak through a Driver method. This is the segregation step: object I/O is the
// universal contract; retention is a capability a subset of backends advertise
// by also satisfying Retention.
//
// Driver is also NOT a fat consumer interface. The data-mover consumers each
// declare their own narrow, consumer-defined interface (Interface Segregation)
// and accept that instead of Driver:
//   - backup.BackupStore   (Head/Get/Put/ProviderName + the Retention WORM ops)
//   - restore.RestoreStore (Head/Get/Put)
//   - migration.MigrationStore (Head/Get/Put/ProviderName — declared-contract-only)
//   - storage.blobMover    (ProviderName/Head/Get/Put — the in-package Migration orchestrator)
//
// Each consumer interface is a subset of Driver (or, for backup, Driver + a
// Retention sub-interface), so NewDriver(...) results are assignable to them at
// the call boundary with zero caller edits. This is COMPLEMENTARY to (not a
// revert of) storage-driver-consolidation: that work unified the implementations
// behind these driver types; ISP narrows the consumers. The two are orthogonal.
type Driver interface {
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	DeleteObject(ctx context.Context, key string) error
	ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error)
	HeadObject(ctx context.Context, key string) (*ObjectInfo, error)
	EnsureBucket(ctx context.Context) error
	BucketExists(ctx context.Context) (bool, error)
	ProviderName() string
	Endpoint() string

	// CopyObject performs a server-side copy from srcKey to dstKey within
	// the same bucket or across buckets. Used by JMAP blob upload to atomically
	// move from temp key to final SHA-256 key.
	// S3/OSS drivers use native server-side copy. POSIX uses local rename.
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error

	// Ping verifies the storage backend is reachable. Drivers perform a
	// lightweight health check (HEAD on a known key, stat the bucket
	// directory, or equivalent). Returns nil if healthy.
	Ping(ctx context.Context) error

	// StatObject returns object metadata including ContentType.
	// Provided for minio-go API compatibility; delegates to HeadObject.
	StatObject(ctx context.Context, key string) (*ObjectInfo, error)
}

// Retention is the optional WORM/immutability capability, segregated out of
// Driver. NOTE: today EVERY concrete driver implements the Retention method set
// (s3HotDriver, backupS3Driver, posixDriver on Linux via chattr+i, AND ossDriver
// + posixDriver on non-Linux as runtime stubs), so the capability is distinguished
// at RUNTIME (Aliyun OSS / non-Linux POSIX return ErrRetentionNotSupported from
// every method), NOT at the type level — see RetentionOf, whose ok==false branch
// is currently unreachable. The type-level split is structural intent for a future
// backend that omits these methods entirely.
//
// The methods mirror the S3 Object Lock API: per-object retention + legal hold,
// and the bucket-level Object Lock configuration the startup WORM check reads.
type Retention interface {
	// PutObjectRetention sets a retention lock on an object until retainUntil.
	PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error
	// GetObjectRetention reports an object's current retention state.
	GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error)
	// PutObjectLegalHold sets ("ON") or clears ("OFF") a legal hold on an object.
	PutObjectLegalHold(ctx context.Context, key, status string) error
	// GetObjectLegalHold returns "ON" or "OFF" for an object's legal hold.
	GetObjectLegalHold(ctx context.Context, key string) (string, error)
	// EnsureBucketObjectLock ensures the bucket has Object Lock enabled in the
	// given mode with the given default retention period.
	EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error
	// GetBucketObjectLockConfig reads the bucket's Object Lock configuration.
	GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error)
}

// RetentionOf reports whether the driver supports WORM/immutability and, if so,
// returns it as a Retention. Callers that require immutability use this to
// detect an unsupported backend EXPLICITLY (ok == false) instead of relying on
// an ErrRetentionNotSupported leak through a Driver method.
//
// CURRENT REALITY — the type-level gate is INERT: every concrete driver NewDriver
// can return (s3HotDriver, backupS3Driver, ossDriver, posixDriver) implements the
// full Retention method set, so the type assertion below ALWAYS succeeds and ok is
// always true for any NewDriver output. The ok == false branch is therefore
// unreachable today; it exists for a future backend that omits the Retention
// methods entirely. The REAL "unsupported backend" signal is the RUNTIME error:
// Aliyun OSS returns ErrRetentionNotSupported from every Retention method, and
// POSIX on non-Linux likewise — those backends advertise the methods only as
// stubs. So RetentionOf is the (currently always-passing) type-boundary gate; the
// runtime errors are the actual line of defense.
func RetentionOf(d Driver) (Retention, bool) {
	r, ok := d.(Retention)
	return r, ok
}

// ── Retention sentinel errors ────────────────────────────────────────────

var (
	ErrRetentionNotSupported = errors.New("storage: retention not supported by this driver")
	ErrObjectLocked          = errors.New("storage: object is locked by retention policy")
	ErrLegalHoldActive       = errors.New("storage: object is under legal hold")
)

// ── Retention types ──────────────────────────────────────────────────────

// RetentionStatus describes the current retention state of an object.
type RetentionStatus struct {
	Mode        string    // "compliance", "governance", or empty if none
	RetainUntil time.Time // zero if no retention period
	LegalHold   bool      // true if a legal hold is active
}

// BucketLockConfig describes a bucket's Object Lock configuration.
type BucketLockConfig struct {
	Enabled             bool
	Mode                string // "compliance" or "governance"
	RetentionPeriodDays int
}

// ObjectInfo describes a stored object.
type ObjectInfo struct {
	Key          string
	Size         int64
	ContentType  string
	LastModified time.Time
}

// DriverConfig holds the configuration for creating a storage driver.
type DriverConfig struct {
	Provider     string // "s3", "oss", "posix", or "backup_s3" ("" = s3)
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string // optional STS token

	// Secure controls transport TLS (see tls.go ResolveEndpointTLS for the full
	// caller/provider/operation matrix). nil derives the posture from the
	// endpoint scheme and REJECTS scheme-less non-loopback endpoints (they
	// historically defaulted to plaintext). An explicit false requests
	// plaintext, which is only honored for loopback peers and conflicts with an
	// https:// endpoint. Every caller/provider/operation must pass either a
	// scheme-ful endpoint or an explicit Secure — plaintext-by-default is gone.
	Secure *bool

	// Object lock / worm retention. Empty mode = disabled.
	ObjectLockMode          string // "governance" or "compliance"
	ObjectLockRetentionDays int    // retention period in days. 0 = no lock.
}

// NewDriver creates a storage driver from the given configuration.
// Provider "oss" uses Aliyun OSS; "posix" uses local filesystem (no transport,
// no TLS surface); "s3" (default) uses minio-go for hot path; "backup_s3" uses
// aws-sdk-go-v2 for backup with full WORM support.
//
// Every object-storage provider resolves its transport-TLS posture through
// ResolveEndpointTLS (tls.go) — https:// endpoints force TLS, scheme-less
// non-loopback endpoints are rejected fail-closed, and explicit loopback HTTP
// remains the supported local compatibility case.
func NewDriver(cfg DriverConfig) (Driver, error) {
	switch cfg.Provider {
	case "oss":
		return NewOSDriver(cfg)
	case "posix":
		return NewPOSIXDriver(cfg.Bucket) // Bucket = root path for POSIX
	case "backup_s3":
		return NewBackupS3Driver(cfg)
	case "s3", "":
		hostPort, useTLS, err := ResolveEndpointTLS(cfg.Endpoint, cfg.Secure)
		if err != nil {
			return nil, err
		}
		if hostPort == "" {
			return nil, fmt.Errorf("storage: s3 endpoint is required")
		}
		return newS3HotDriver(cfg.Endpoint, cfg.AccessKey, cfg.SecretKey, cfg.Bucket, hostPort, useTLS)
	default:
		return nil, fmt.Errorf("storage: unknown provider %q", cfg.Provider)
	}
}
