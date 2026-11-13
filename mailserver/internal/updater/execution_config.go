package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/mailserver/internal/recoveryset"
)

const ExecutionConfigVersion = 1

var recoveryBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type ExecutionConfig struct {
	Version          int    `json:"version"`
	Enabled          bool   `json:"enabled"`
	InstallRoot      string `json:"installRoot,omitempty"`
	RecoveryProvider string `json:"recoveryProvider,omitempty"`
	RecoveryEndpoint string `json:"recoveryEndpoint,omitempty"`
	RecoveryRegion   string `json:"recoveryRegion,omitempty"`
	RecoveryBucket   string `json:"recoveryBucket,omitempty"`
}

// ReadExecutionConfig reads a root-owned, non-secret configuration document.
// Missing or explicitly-disabled configuration keeps the daemon in observer
// mode; malformed enabled configuration fails closed before any claim.
func ReadExecutionConfig(path string) (ExecutionConfig, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ExecutionConfig{Version: ExecutionConfigVersion}, nil
	}
	if err != nil {
		return ExecutionConfig{}, fmt.Errorf("stat updater execution config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
		return ExecutionConfig{}, errors.New("updater execution config must be a bounded root-controlled regular file")
	}
	// The path is fixed by the root-owned systemd unit and was checked above.
	//nolint:gosec // G304: not request-controlled.
	raw, err := os.ReadFile(path)
	if err != nil {
		return ExecutionConfig{}, fmt.Errorf("read updater execution config: %w", err)
	}
	var config ExecutionConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return ExecutionConfig{}, errors.New("invalid updater execution config JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ExecutionConfig{}, errors.New("invalid trailing updater execution config JSON")
	}
	if err := config.Validate(); err != nil {
		return ExecutionConfig{}, err
	}
	return config, nil
}

func (config ExecutionConfig) Validate() error {
	if config.Version != ExecutionConfigVersion {
		return errors.New("unsupported updater execution config version")
	}
	if !config.Enabled {
		return nil
	}
	if !filepath.IsAbs(config.InstallRoot) || filepath.Clean(config.InstallRoot) != config.InstallRoot || config.InstallRoot == "/" {
		return errors.New("enabled updater execution requires a safe absolute install root")
	}
	if config.RecoveryProvider != "s3" || !recoveryBucketPattern.MatchString(config.RecoveryBucket) {
		return errors.New("enabled updater execution requires an S3 recovery store and valid bucket")
	}
	if len(config.RecoveryRegion) > 128 || strings.ContainsAny(config.RecoveryRegion, "\r\n\x00") {
		return errors.New("invalid recovery region")
	}
	if _, _, err := normalizeRecoveryEndpoint(config.RecoveryEndpoint); err != nil {
		return err
	}
	return nil
}

type recoveryS3Store struct {
	client *minio.Client
	bucket string
}

func NewRecoveryStore(config ExecutionConfig, accessKey, secretKey string) (recoveryset.Store, error) {
	if err := config.Validate(); err != nil || !config.Enabled {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("updater execution is disabled")
	}
	if accessKey == "" || secretKey == "" || strings.ContainsAny(accessKey+secretKey, "\r\n\x00") {
		return nil, errors.New("recovery store credentials are invalid")
	}
	endpoint, secure, err := normalizeRecoveryEndpoint(config.RecoveryEndpoint)
	if err != nil {
		return nil, err
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure, Region: config.RecoveryRegion,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize recovery S3 client: %w", err)
	}
	return recoveryS3Store{client: client, bucket: config.RecoveryBucket}, nil
}

// normalizeRecoveryEndpoint validates the recovery S3 endpoint and reports
// whether it requires TLS. Cleartext http:// is accepted ONLY for loopback
// targets (127.0.0.1, ::1, localhost) — mirroring the appmarket
// AllowInsecureTestTransport rule and the updater's own one-shot
// office-app-test-direct-http rail. On-host SeaweedFS over loopback is the
// supported cleartext case; http:// to any remote host is rejected so a
// root-written config cannot silently ship the recovery-set envelope and
// manifest (HMAC-authenticated, but not confidential) across the network in
// plaintext (D-MAILSERVER-CMD-SETJOIN-UPDATER-P2-001).
func normalizeRecoveryEndpoint(value string) (string, bool, error) {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", false, errors.New("invalid recovery endpoint")
	}
	secure := true
	endpoint := value
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", false, errors.New("invalid recovery endpoint")
		}
		endpoint = parsed.Host
		secure = parsed.Scheme == "https"
		if !secure {
			host := strings.ToLower(parsed.Hostname())
			switch host {
			case "127.0.0.1", "::1", "localhost":
				// loopback: the supported cleartext case
			default:
				return "", false, errors.New("recovery endpoint must use https unless it targets loopback (127.0.0.1, ::1, localhost)")
			}
		}
	}
	if strings.ContainsAny(endpoint, "/@?#") {
		return "", false, errors.New("invalid recovery endpoint")
	}
	return endpoint, secure, nil
}

func (store recoveryS3Store) HeadObject(ctx context.Context, key string) (recoveryset.ObjectInfo, error) {
	info, err := store.client.StatObject(ctx, store.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return recoveryset.ObjectInfo{}, err
	}
	return recoveryset.ObjectInfo{Size: info.Size}, nil
}

func (store recoveryS3Store) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	return store.client.GetObject(ctx, store.bucket, key, minio.GetObjectOptions{})
}

func (store recoveryS3Store) PutObject(context.Context, string, io.Reader, int64) error {
	return errors.New("updater recovery store is read-only")
}
