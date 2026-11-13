package storage

import (
	"strings"
	"testing"
)

// driverTLSPosture extracts the RESOLVED transport-TLS posture of a concrete
// driver (same-package field access, no I/O). posix has no transport surface
// and reports ok=false.
func driverTLSPosture(t *testing.T, d Driver) (useTLS, ok bool) {
	t.Helper()
	switch drv := d.(type) {
	case *s3HotDriver:
		return drv.ssl, true
	case *ossDriver:
		return drv.useTLS, true
	case *backupS3Driver:
		return drv.useTLS, true
	default:
		return false, false
	}
}

// TestDriverProviderTLSMatrix is the constructor × provider transport-TLS
// matrix (D-MAILSERVER-INTERNAL-STORAGE-F-001): every object-storage
// constructor resolves its posture through ResolveEndpointTLS — https forces
// TLS, plaintext is loopback-only, scheme-less remote is fail-closed.
func TestDriverProviderTLSMatrix(t *testing.T) {
	tru, fals := true, false

	type construct struct {
		name     string
		provider string // for NewDriver; direct constructors bypass the factory
		direct   func(cfg DriverConfig) (Driver, error)
	}

	constructors := []construct{
		{name: "NewDriver(s3)", provider: "s3"},
		{name: "NewDriver(default)", provider: ""},
		{name: "NewDriver(oss)", provider: "oss"},
		{name: "NewDriver(backup_s3)", provider: "backup_s3"},
		{name: "NewOSDriver direct", direct: NewOSDriver},
		{name: "NewBackupS3Driver direct", direct: NewBackupS3Driver},
	}

	cases := []struct {
		name     string
		endpoint string
		secure   *bool
		wantTLS  bool
		wantErr  bool
	}{
		// provider/endpoint grid — the SAME verdict for every constructor:
		{endpoint: "https://minio.internal:9000", secure: nil, wantTLS: true},
		{endpoint: "https://minio.internal:9000", secure: &tru, wantTLS: true},
		{endpoint: "https://minio.internal:9000", secure: &fals, wantErr: true}, // scheme+Secure conflict
		{endpoint: "http://127.0.0.1:9000", secure: nil, wantTLS: false},        // loopback HTTP compat
		{endpoint: "http://127.0.0.1:9000", secure: &fals, wantTLS: false},
		{endpoint: "http://10.9.8.7:9000", secure: nil, wantErr: true},  // remote plaintext
		{endpoint: "minio.internal:9000", secure: nil, wantErr: true},   // scheme-less remote fail-closed
		{endpoint: "minio.internal:9000", secure: &fals, wantErr: true}, // scheme-less remote explicit plaintext
		{endpoint: "minio.internal:9000", secure: &tru, wantTLS: true},  // explicit TLS opt-in
		{endpoint: "127.0.0.1:9000", secure: nil, wantTLS: false},       // loopback compat
		{endpoint: "127.0.0.1:9000", secure: &fals, wantTLS: false},     // deploy/config.env.sample shape
		{endpoint: "127.0.0.1:9000", secure: &tru, wantTLS: true},       // loopback TLS opt-in
		{endpoint: "https://oss-cn-hangzhou.aliyuncs.com", secure: &fals, wantErr: true},
		{endpoint: "https://s3.us-east-1.amazonaws.com", secure: nil, wantTLS: true},
	}

	for _, c := range constructors {
		for _, tc := range cases {
			t.Run(c.name+"/"+tc.endpoint, func(t *testing.T) {
				cfg := DriverConfig{
					Provider:  c.provider,
					Endpoint:  tc.endpoint,
					Bucket:    "matrix-bucket",
					AccessKey: "k",
					SecretKey: "s",
					Secure:    tc.secure,
				}
				var d Driver
				var err error
				if c.direct != nil {
					d, err = c.direct(cfg)
				} else {
					d, err = NewDriver(cfg)
				}
				if tc.wantErr {
					if err == nil {
						t.Fatalf("constructor(%s, %q) succeeded, want fail-closed error", c.name, tc.endpoint)
					}
					return
				}
				if err != nil {
					t.Fatalf("constructor(%s, %q): %v", c.name, tc.endpoint, err)
				}
				useTLS, ok := driverTLSPosture(t, d)
				if !ok {
					t.Fatalf("constructor(%s) returned unexpected concrete type %T", c.name, d)
				}
				if useTLS != tc.wantTLS {
					t.Fatalf("constructor(%s, %q) TLS posture = %v, want %v", c.name, tc.endpoint, useTLS, tc.wantTLS)
				}
			})
		}
	}
}

// TestBackupS3DriverBaseEndpointScheme pins the aws-sdk-go-v2 leg: the
// resolved posture is stated explicitly in BaseEndpoint's scheme, never left
// to SDK scheme-defaulting.
func TestBackupS3DriverBaseEndpointScheme(t *testing.T) {
	d, err := NewBackupS3Driver(DriverConfig{
		Endpoint: "minio.internal:9000", Bucket: "b", AccessKey: "k", SecretKey: "s",
		Secure: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("NewBackupS3Driver explicit TLS: %v", err)
	}
	b := d.(*backupS3Driver)
	base := b.client.Options().BaseEndpoint
	if base == nil || !strings.HasPrefix(*base, "https://") {
		t.Fatalf("BaseEndpoint = %v, want https:// prefix", base)
	}

	d, err = NewBackupS3Driver(DriverConfig{
		Endpoint: "http://127.0.0.1:9000", Bucket: "b", AccessKey: "k", SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewBackupS3Driver loopback plaintext: %v", err)
	}
	b = d.(*backupS3Driver)
	base = b.client.Options().BaseEndpoint
	if base == nil || !strings.HasPrefix(*base, "http://") {
		t.Fatalf("BaseEndpoint = %v, want http:// prefix for loopback plaintext", base)
	}
}

// TestNewDriverPOSIXHasNoTLSVector pins the fourth provider: POSIX is local
// filesystem — no transport, no TLS posture to resolve, and it must keep
// constructing under every configuration.
func TestNewDriverPOSIXHasNoTLSVector(t *testing.T) {
	tru, fals := true, false
	for _, secure := range []*bool{nil, &tru, &fals} {
		d, err := NewDriver(DriverConfig{Provider: "posix", Bucket: t.TempDir(), Secure: secure})
		if err != nil {
			t.Fatalf("NewDriver(posix, secure=%v): %v", secure, err)
		}
		if d.ProviderName() != "posix" {
			t.Fatalf("ProviderName = %q, want posix", d.ProviderName())
		}
		if _, ok := driverTLSPosture(t, d); ok {
			t.Fatalf("posix driver unexpectedly reports a transport TLS posture")
		}
	}
}

func boolPtr(b bool) *bool { return &b }

// TestCallerOperationTLSMatrix is the OPERATION leg of the matrix: every
// production caller/operation, expressed as the EXACT DriverConfig shape its
// call site builds (mailserverd main.go, startup/worm.go, admin_storage_migrate.go,
// admin_setup.go), asserted across the primary-config grid. Operations on the
// PRIMARY store must honor S3_SECURE (Secure: &cfg.S3Secure); operations on
// separate stores carry the posture in their endpoint scheme.
func TestCallerOperationTLSMatrix(t *testing.T) {
	// operation → the DriverConfig shape its call site constructs.
	operations := []struct {
		operation string
		authority string
		provider  string
		// buildIgnoresS3Secure marks operations on SEPARATE stores whose
		// transport posture is carried by their endpoint scheme, not S3_SECURE.
		buildIgnoresS3Secure bool
		build                func(endpoint string, s3Secure bool) DriverConfig
	}{
		{
			operation: "blob hot path config source", provider: "",
			authority: "main.go (blob.NewMinIOClient consumes the same cfg fields)",
			build: func(endpoint string, s3Secure bool) DriverConfig {
				return DriverConfig{Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s", Secure: &s3Secure}
			},
		},
		{
			operation: "drive retention (P5 WORM lock-apply)", provider: "",
			authority: "main.go driveRetention",
			build: func(endpoint string, s3Secure bool) DriverConfig {
				return DriverConfig{Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s", Secure: &s3Secure}
			},
		},
		{
			operation: "backup primary", provider: "",
			authority: "main.go primaryDriver",
			build: func(endpoint string, s3Secure bool) DriverConfig {
				return DriverConfig{Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s", Secure: &s3Secure}
			},
		},
		{
			operation: "setup restore primary", provider: "",
			authority: "main.go setupPrimary",
			build: func(endpoint string, s3Secure bool) DriverConfig {
				return DriverConfig{Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s", Secure: &s3Secure}
			},
		},
		{
			operation: "WORM/legal-hold startup", provider: "",
			authority: "startup/worm.go InitWORM",
			build: func(endpoint string, s3Secure bool) DriverConfig {
				return DriverConfig{Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s", Secure: &s3Secure}
			},
		},
		{
			operation: "storage-migrate target", provider: "oss",
			authority:            "admin_storage_migrate.go StartMigrate (posture carried by STORAGE_ENDPOINT scheme)",
			buildIgnoresS3Secure: true,
			build: func(endpoint string, _ bool) DriverConfig {
				return DriverConfig{Provider: "oss", Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s"}
			},
		},
		{
			operation: "setup restore backup source", provider: "backup_s3",
			authority:            "admin_setup.go backupDriverFromRequest (posture carried by request endpoint scheme)",
			buildIgnoresS3Secure: true,
			build: func(endpoint string, _ bool) DriverConfig {
				return DriverConfig{Provider: "backup_s3", Endpoint: endpoint, Bucket: "b", AccessKey: "k", SecretKey: "s"}
			},
		},
	}

	grid := []struct {
		name        string
		endpoint    string
		s3Secure    bool
		wantTLS     bool
		wantErr     bool
		primaryOnly bool // only operations whose DriverConfig consumes S3_SECURE
	}{
		{name: "loopback default (deploy convention) stays plaintext", endpoint: "127.0.0.1:9000", s3Secure: false, wantTLS: false},
		{name: "S3_SECURE=true forces TLS", endpoint: "127.0.0.1:9000", s3Secure: true, wantTLS: true, primaryOnly: true},
		{name: "https endpoint forces TLS even with S3_SECURE=true", endpoint: "https://minio.internal:9000", s3Secure: true, wantTLS: true},
		{name: "scheme-less remote with S3_SECURE=false rejected", endpoint: "minio.internal:9000", s3Secure: false, wantErr: true},
		{name: "http remote rejected regardless of S3_SECURE", endpoint: "http://minio.internal:9000", s3Secure: true, wantErr: true},
	}

	for _, op := range operations {
		for _, g := range grid {
			if g.primaryOnly && op.buildIgnoresS3Secure {
				continue
			}
			t.Run(op.operation+"/"+g.name, func(t *testing.T) {
				d, err := NewDriver(op.build(g.endpoint, g.s3Secure))
				if g.wantErr {
					if err == nil {
						t.Fatalf("%s: constructed with %q (S3_SECURE=%v), want fail-closed rejection", op.operation, g.endpoint, g.s3Secure)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s: NewDriver(%q, S3_SECURE=%v): %v", op.operation, g.endpoint, g.s3Secure, err)
				}
				useTLS, ok := driverTLSPosture(t, d)
				if !ok {
					t.Fatalf("%s: unexpected concrete type %T", op.operation, d)
				}
				if useTLS != g.wantTLS {
					t.Fatalf("%s: TLS posture = %v, want %v (endpoint %q, S3_SECURE=%v)", op.operation, useTLS, g.wantTLS, g.endpoint, g.s3Secure)
				}
			})
		}
	}
}

// TestNewS3HotDriverDirectCaller closes the direct-constructor leg: the bool
// is a TLS assertion (true forces TLS; false = unasserted, scheme-derived), so
// a scheme-ful endpoint can no longer be silently downgraded the way the old
// TrimPrefix-then-Secure=false path did.
func TestNewS3HotDriverDirectCaller(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		useSSL   bool
		wantTLS  bool
		wantErr  bool
	}{
		{name: "https endpoint upgraded even with useSSL=false", endpoint: "https://minio.internal:9000", useSSL: false, wantTLS: true},
		{name: "https endpoint with useSSL=true", endpoint: "https://minio.internal:9000", useSSL: true, wantTLS: true},
		{name: "loopback http stays plaintext", endpoint: "http://127.0.0.1:9000", useSSL: false, wantTLS: false},
		{name: "scheme-less loopback stays plaintext", endpoint: "127.0.0.1:9000", useSSL: false, wantTLS: false},
		{name: "scheme-less remote rejected", endpoint: "minio.internal:9000", useSSL: false, wantErr: true},
		{name: "remote TLS opt-in via useSSL=true", endpoint: "minio.internal:9000", useSSL: true, wantTLS: true},
		{name: "http remote rejected", endpoint: "http://minio.internal:9000", useSSL: false, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewS3HotDriver(tc.endpoint, "k", "s", "b", tc.useSSL)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewS3HotDriver(%q, %v) succeeded, want error", tc.endpoint, tc.useSSL)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewS3HotDriver(%q, %v): %v", tc.endpoint, tc.useSSL, err)
			}
			useTLS, ok := driverTLSPosture(t, d)
			if !ok || useTLS != tc.wantTLS {
				t.Fatalf("TLS posture = %v (ok=%v), want %v", useTLS, ok, tc.wantTLS)
			}
			// The original (possibly scheme-ful) endpoint is preserved for status surfaces.
			if d.Endpoint() != tc.endpoint {
				t.Fatalf("Endpoint() = %q, want original %q", d.Endpoint(), tc.endpoint)
			}
		})
	}
}

// TestNewDriverEmptyS3EndpointRejected keeps minio-based providers honest
// about the empty endpoint (the resolver reports the AWS-default TLS posture;
// minio paths must reject it explicitly).
func TestNewDriverEmptyS3EndpointRejected(t *testing.T) {
	if _, err := NewDriver(DriverConfig{Bucket: "b", AccessKey: "k", SecretKey: "s"}); err == nil {
		t.Fatal("NewDriver(s3, empty endpoint) succeeded, want error")
	}
	if _, err := NewS3HotDriver("", "k", "s", "b", false); err == nil {
		t.Fatal("NewS3HotDriver(empty endpoint) succeeded, want error")
	}
}

// TestOSDriverEmptyEndpointRejectsExplicitPlaintext closes the region-derived
// default-endpoint leg (Astra HOLD, storage-s3-plaintext-downgrade): with an
// empty endpoint the OSS SDK derives one from the region, and DisableSSL=true
// would make that derivation plaintext (http://oss-<region>.aliyuncs.com) —
// plaintext to a REMOTE peer. An explicit Secure=false must therefore be
// rejected before the SDK client exists, consistent with NewBackupS3Driver;
// nil/true keep the TLS-by-default posture. Covered for both direct
// construction and the NewDriver factory.
func TestOSDriverEmptyEndpointRejectsExplicitPlaintext(t *testing.T) {
	tru, fals := true, false

	constructors := []struct {
		name   string
		direct bool
	}{
		{name: "NewDriver(oss)"},
		{name: "NewOSDriver direct", direct: true},
	}

	cases := []struct {
		name    string
		secure  *bool
		wantTLS bool
		wantErr bool
	}{
		{name: "nil Secure stays TLS", secure: nil, wantTLS: true},
		{name: "Secure=true stays TLS", secure: &tru, wantTLS: true},
		{name: "Secure=false rejected fail-closed", secure: &fals, wantErr: true},
	}

	for _, c := range constructors {
		for _, tc := range cases {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				cfg := DriverConfig{
					Provider:  "oss",
					Endpoint:  "", // region-derived default endpoint
					Region:    "cn-hangzhou",
					Bucket:    "b",
					AccessKey: "k",
					SecretKey: "s",
					Secure:    tc.secure,
				}
				var (
					d   Driver
					err error
				)
				if c.direct {
					d, err = NewOSDriver(cfg)
				} else {
					d, err = NewDriver(cfg)
				}
				if tc.wantErr {
					if err == nil {
						t.Fatal("empty endpoint with Secure=false succeeded, want fail-closed rejection")
					}
					if !strings.Contains(err.Error(), "requires an explicit endpoint") {
						t.Fatalf("error = %v, want the explicit-endpoint requirement", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("empty endpoint (Secure=%v): %v", tc.secure, err)
				}
				useTLS, ok := driverTLSPosture(t, d)
				if !ok {
					t.Fatalf("unexpected concrete type %T", d)
				}
				if useTLS != tc.wantTLS {
					t.Fatalf("TLS posture = %v, want %v for the region-derived default endpoint", useTLS, tc.wantTLS)
				}
			})
		}
	}
}
