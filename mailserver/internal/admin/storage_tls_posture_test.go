package admin

import (
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestBackupDriverFromRequest_TLSPosture pins the setup-restore SOURCE leg of
// the storage TLS matrix (D-MAILSERVER-INTERNAL-STORAGE-F-001): the
// request-supplied backup endpoint resolves through storage.ResolveEndpointTLS
// — remote targets must state https://, loopback HTTP stays available for
// local rehearsal, and scheme-less non-loopback endpoints are rejected
// fail-closed (they previously constructed plaintext drivers).
func TestBackupDriverFromRequest_TLSPosture(t *testing.T) {
	base := restoreRequest{
		Provider:  "backup_s3",
		Region:    "us-east-1",
		Bucket:    "restore-src",
		AccessKey: "k",
		SecretKey: "s",
	}

	cases := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{name: "https remote accepted", endpoint: "https://backup.internal:9000"},
		{name: "scheme-less remote rejected fail-closed", endpoint: "backup.internal:9000", wantErr: true},
		{name: "http remote rejected", endpoint: "http://backup.internal:9000", wantErr: true},
		{name: "http loopback accepted for local rehearsal", endpoint: "http://127.0.0.1:9000"},
		{name: "scheme-less loopback accepted (deploy convention)", endpoint: "127.0.0.1:9000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.Endpoint = tc.endpoint
			d, err := backupDriverFromRequest(req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("backupDriverFromRequest(%q) succeeded, want fail-closed error", tc.endpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("backupDriverFromRequest(%q): %v", tc.endpoint, err)
			}
			if d == nil {
				t.Fatal("driver is nil")
			}
		})
	}
}

// TestMigrationSourceDriverHonorsClientTLSPosture pins the storage-migrate
// SOURCE fix (D-MAILSERVER-INTERNAL-STORAGE-F-001): the source driver is built
// from the shared client's scheme-ful EndpointURL, so its TLS posture follows
// S3_SECURE. A remote-plaintext shared client (S3_SECURE=false against a
// non-loopback endpoint) refuses to start a migration instead of silently
// copying blob traffic in the clear — the exact hardcoded-false behavior the
// finding called out.
func TestMigrationSourceDriverHonorsClientTLSPosture(t *testing.T) {
	creds := credentials.NewStaticV4("k", "s", "")

	t.Run("secure client (S3_SECURE=true) yields a TLS source driver", func(t *testing.T) {
		mc, err := minio.New("minio.internal:9000", &minio.Options{Creds: creds, Secure: true})
		if err != nil {
			t.Fatalf("minio.New: %v", err)
		}
		if got := mc.EndpointURL().Scheme; got != "https" {
			t.Fatalf("precondition: EndpointURL scheme = %q, want https", got)
		}
		d, err := migrationSourceDriver(mc, "k", "s", "blobs")
		if err != nil {
			t.Fatalf("migrationSourceDriver(secure client): %v", err)
		}
		if d == nil {
			t.Fatal("source driver is nil")
		}
	})

	t.Run("remote-plaintext client is rejected fail-closed", func(t *testing.T) {
		mc, err := minio.New("minio.internal:9000", &minio.Options{Creds: creds, Secure: false})
		if err != nil {
			t.Fatalf("minio.New: %v", err)
		}
		if got := mc.EndpointURL().Scheme; got != "http" {
			t.Fatalf("precondition: EndpointURL scheme = %q, want http", got)
		}
		if _, err := migrationSourceDriver(mc, "k", "s", "blobs"); err == nil {
			t.Fatal("migrationSourceDriver(remote plaintext client) succeeded, want fail-closed rejection")
		}
	})

	t.Run("loopback-plaintext client remains a supported compatibility case", func(t *testing.T) {
		mc, err := minio.New("127.0.0.1:9000", &minio.Options{Creds: creds, Secure: false})
		if err != nil {
			t.Fatalf("minio.New: %v", err)
		}
		if _, err := migrationSourceDriver(mc, "k", "s", "blobs"); err != nil {
			t.Fatalf("migrationSourceDriver(loopback plaintext client): %v", err)
		}
	})
}
